import ast
import json
import re
import time
from datetime import datetime

import avi_objects.infra_utils as infra_utils
import avi_objects.logger_utils as logger_utils
import avi_objects.traffic_manager as traffic_manager
import lib.json_utils as json_utils
import lib.tcp_lib as tcp_lib
import lib.vs_lib as vs_lib
from avi_objects.suite_vars import suite_vars
from avi_objects.logger import logger
from avi_objects.logger_utils import calc_exc_time
from lib.common import _bool_value


def format_validations(url, status_code, **kwargs):
    allowed_validations = [
        'header_equals', 'header_contains', 'header_range_in',
        'header_contains', 'header_not_equals',
        'key_in_headers', 'header_starts_with',
        'header_ends_with', 'header_not_contains',
        'body_equals', 'body_contains', 'body_not_contains',
        'file_equals', 'status_code', 'key_not_in_headers', 'get_file_equals']

    allowed_prints = [
        'print_headers', 'print_cookies', 'print_body', 'print_length']

    validations = {}
    prints = {}
    validations['status_code'] = status_code

    for param, value in kwargs.iteritems():
        if param in allowed_validations:
            validations[param] = kwargs[param]
        elif param in allowed_prints:
            if param.lower() == 'print_headers' and \
                    str(kwargs[param]).lower() != 'true':
                prints[param[6:]] = str(kwargs[param]).split(',')
            else:
                prints[param[6:]] = None

    # Remove validations from kwargs
    for key in kwargs.keys():
        if key in allowed_validations or key in allowed_prints:
            kwargs.pop(key)

    return kwargs, validations, prints


def get_url(vs_name, vport, uris, skip_exc=0, vip_id='0', to_floating_vip=None):
    """Returns a URL for making http request"""
    if to_floating_vip:
        vip = vs_lib.get_floating_vip(vs_name, vip_id)
    else:
        vip = vs_lib.get_vip(vs_name, vip_id)
    vport = int(vport)
    proto = vs_lib.get_protocol(vs_name, vport, skip_exc)
    if suite_vars.spdy_enabled and proto == 'https://':
        key = '%s,%s' % (vip, vport)
        # FixMe: to get fromm avi_config
        #shrpx_proxy = config.shrpx_vs_map[key]
        #vip, vport = tuple(shrpx_proxy.split(','))

    uris = [uris] if not isinstance(uris, list) else uris
    urls = []
    for uri in uris:
        url_elms = [proto, vip, ':', str(vport), uri.replace('&amp;', '&')]
        urls.append("".join(url_elms))
    return urls


def parse_input(urls, status_code=200, **kwargs):
    """ Seperate out the actual arguments to requests library and
        custom validations params passed to the function
    """
    prints = {}
    validations = {}
    req_params = {}

    if len(urls) != len(str(status_code).split(',')):
        status_codes = [str(status_code)] * len(urls)
    else:
        status_codes = str(status_code).split(',')

    for url, status_code in zip(urls, status_codes):

        kwargs, validations[url], prints[url] = format_validations(url, status_code, **kwargs)

        req_params[url] = {}
        for param, value in kwargs.iteritems():
            try:
                req_params[url][param] = ast.literal_eval(str(value))
                if not isinstance(req_params[url][param], dict):
                    req_params[url][param] = str(req_params[url][param])
            except Exception:
                # Doesn't match anything. Just assign the ascii value.
                req_params[url][param] = str(value).encode('ascii')

    return (str(req_params).replace('"', '\\"').replace("'", '"'),
            str(validations).replace("'", '"'),
            str(prints).replace("'", '"'))


def start_http_traffic(client_range, vs_name, vport, method, stop_on_failure,
                       concurrent_conn_per_client=1, uri='/', **kwargs):
    """
    Starts http traffic on range of clients specified in client_range
    Arguments:
    client_range                Number of clients for the the traffic
                                generation
    vs_name                     Virtualservice to balance the traffic
                                between backend servers
    vport                       Listener port on virtual service
    stop_on_failure             Flag to exit on first IO failure.
                                Set it to 1 if you need
    concurrent_conn_per_client  Concurrent connections per client
    uri                         URI of page to be requested
                                exact state of the system while failure
    kwargs                      parameters passed to requests and
                                validations need to be
                                done
    """

    skip_exc = kwargs.pop('skip_exception', 0)
    think_time = kwargs.pop('think_time', None)
    status_code = int(kwargs.pop('status_code', 200))
    no_of_req_per_conn = int(kwargs.pop('no_of_req_per_conn', 1))
    set_cookie_session = _bool_value(kwargs.pop('cookie_session', 'False'))
    set_cookies_per_request = _bool_value(kwargs.pop('cookies_per_request', 'False'))
    to_floating_vip = kwargs.pop('to_floating_vip', None)

    random_urls = int(kwargs.pop('random_urls', 0))
    random_urls_repeat = int(kwargs.pop('random_urls_repeat', 0))
    if random_urls:
        if not random_urls_repeat:
            random_urls_repeat = 1

        uri = []
        for i in range(random_urls):
            for j in range(random_urls_repeat):
                uri.append('/randomurl' + str(i))

    urls = get_url(vs_name, vport, uri, skip_exc=skip_exc, vip_id=kwargs.pop('vip_id', '0'),
                   to_floating_vip=to_floating_vip)
    client_vm, client_ips = traffic_manager.get_client_handles(client_range,
                                               concurrent_conn_per_client)

    if to_floating_vip:
        vip = vs_lib.get_floating_vip(vs_name)
    else:
        vip = vs_lib.get_vip(vs_name)

    out = client_vm.execute_command('arp -a | grep %s' % vip)
    logger.debug('Arptable on client: %s' % out)
    req_params, validations, prints = parse_input(urls, status_code, **kwargs)
    time_stamp = time.strftime("%Y%m%d%H%M%S") + str(time.clock())

    logger.info('Start traffic at' + str(datetime.now()))
    log_file = '/tmp/httptest_io_error_' + time_stamp + client_range + '.log'
    cmd = '/root/client/tools/httptest.py '
    cmd += '--urls \'%s\' ' % '\' \''.join(urls)
    cmd += '--clients %s ' % ' '.join(client_ips)
    cmd += '--stop-on-failure %s ' % stop_on_failure
    cmd += '--log-file %s ' % log_file
    cmd += '--method %s ' % method
    cmd += '--concurrent 1 '
    cmd += '--requests %s ' % no_of_req_per_conn
    cmd += '--req-params \'%s\' ' % req_params
    cmd += '--validations \'%s\' ' % validations
    cmd += '--prints \'%s\' ' % prints
    if set_cookie_session:
        cmd += '--cookie-session '
    if set_cookies_per_request:
        cmd += '--cookies-per-request '
    if think_time:
        cmd += '--think-time %s ' % think_time
    cmd += '&> /tmp/httptest &'
    logger.trace(cmd)
    #out = client_vm.execute_command("rm -rf /tmp/httptest_traffic_check ", noerr=True)
    out = client_vm.execute_command(cmd)

    # Started Http Traffic check
    #search_str = "Started Http Traffic on client"
    #res = start_traffic_check("/tmp/httptest_traffic_check", search_str)
    #if res:
    #    logger.error("HTTP Traffic is not started something went wrong")
    #    reason = client_vm.execute_command(" tail -5 %s" % log_file)
    #    logger.error(" %s" % (reason))
    #    reason = client_vm.execute_command(" tail -5 /tmp/httptest ")
    #    logger.error(" %s" % (reason))
    #    raise RuntimeError("HTTP Request Traffic not started")
    #logger.info("HTTP Traffic is running, responses are logged in file: /tmp/httptest_resp_summary_time_stamp")

    logger.debug('End traffic at %s' % str(datetime.now()))
    logger.trace('out: %s' % out)
    return log_file


def verify_no_traffic_errors_on_client_side():
    for vm in infra_utils.get_vm_of_type('client'):
        vm.execute_command('rm -rf /tmp/httptest_io_*')
        time.sleep(10)
        resp = vm.execute_command('ls -ltr /tmp/httptest_io_error_* | wc -l')
        logger.debug('response is %s' % resp)
        if int(resp[0]) > 0:
            logger_utils.fail('Errors are generated on client side %s' % resp)


@calc_exc_time
def get_pages_in_loop(vs_name, vport, page_name, loop, client='default1'):
    """

    :param vs_name:
    :param vport:
    :param page_name:
    :param loop:
    :param client:
    :return:
    """

    request('get', vs_name, vport, page_name, client_range=client,
            sequential_conn_per_client=int(loop))


@calc_exc_time
def request(method, vs_name, vport, uri, status_code=200,
            client_range='default1', no_of_req_per_conn=1,
            concurrent_conn_per_client=1,
            sequential_conn_per_client=1, concurrent_clients='True', **kwargs):
    """
        Request the selected pages from server. Internally calls the httptest
        process running on clients
        Arguments:
        method                      GET, PUT, POST, DELETE?
        vs_name                     virtual service name
        vport                       Virtual service listener port
        uri                         URI for the request
        status_code                 status_code expected from request
        client_range                clients from where the request needs to be
                                    sent
        no_of_req_per_conn          No of requests per http connection
        concurrent_conn_per_client  No of concurrent connections per client
        sequential_conn_per_client  No of sequential connections per client
        timeout                     Timeout for every connection
        concurrent_clients          Concurrent connections from clients or
                                    sequential.

        Note: This function can generate exponential traffic patterns. For eg.
        If concurrent_conn_per_client=5, sequential_conn_per_client=10 and
        no_of_req_per_conn=5, it will create 5 concurrent connections for each
        client with 5 seqeuntial connections for each concurrent connection (
        IP, port combination) and 5 requests per connection.
        Total = 5 * 10 * 5= 250 requests!
    """

    skip_error = json_utils.str2bool(kwargs.pop('expect_error', 'False'))
    think_time = kwargs.pop('think_time', None)
    cps = kwargs.pop('cps', None)
    rps = kwargs.pop('rps', None)
    stop_traffic = kwargs.pop('stop_traffic', False)
    parallel = int(ast.literal_eval(concurrent_clients.title()))
    content = kwargs.get('body_contains', None)
    set_cookie_session = json_utils.str2bool(kwargs.pop('cookie_session', 'False'))
    set_cookies_per_request = json_utils.str2bool(kwargs.pop('cookies_per_request', 'False'))
    skip_exc = kwargs.pop('skip_exception', 0)
    custom = kwargs.pop('custom', None)
    to_floating_vip = kwargs.pop('to_floating_vip', None)

    if content:
        traffic_obj = traffic_manager.HTTPTraffic(**kwargs)
        kwargs['body_contains'] = traffic_obj.may_be_replace_vars_with_ips(content)

    urls = get_url(vs_name, vport, uri, skip_exc=skip_exc, vip_id=kwargs.pop('vip_id', '0'), to_floating_vip=to_floating_vip)
    client_vm, client_ips = traffic_manager.get_client_handles(client_range,
                                               concurrent_conn_per_client)

    if to_floating_vip:
        vip = vs_lib.get_floating_vip(vs_name)
    else:
        vip = vs_lib.get_vip(vs_name)

    out = client_vm.execute_command('arp -a | grep %s' % vip)
    logger.debug('Arptable on client: %s' % out)

    req_params, validations, prints = parse_input(urls, status_code, **kwargs)

    time_stamp = time.strftime("%Y%m%d%H%M%S") + str(time.clock())
    log_file = '/tmp/httptest_io_error_' + time_stamp + '.log'
    cmd = '/root/client/tools/httptest.py '
    cmd += '--urls \'%s\' ' % '\' \''.join(urls)
    cmd += '--clients %s ' % ' '.join(client_ips)
    cmd += '--log-file %s ' % log_file
    cmd += '--method %s ' % method
    cmd += '--req-params \'%s\' ' % req_params
    cmd += '--validations \'%s\' ' % validations
    cmd += '--prints \'%s\' ' % prints
    cmd += '--requests %s ' % no_of_req_per_conn
    cmd += '--connections %s ' % sequential_conn_per_client
    cmd += '--concurrent %s ' % parallel
    if cps:
        cmd += '--connections-per-sec %s ' % cps
    if rps:
        cmd += '--requests-per-sec %s ' % rps
    if set_cookie_session:
        cmd += '--cookie-session '
    if set_cookies_per_request:
        cmd += '--cookies-per-request '
    if think_time:
        cmd += '--think-time %s ' % think_time
    if custom:
        _custom = custom.split(' ')
        for i in range(0, len(_custom)):
            if not i % 2:
                cmd += '--custom %s ' % (''.join(get_url(vs_name, vport, _custom[i],
                                                         skip_exc=skip_exc, vip_id=kwargs.pop('vip_id', '0'))))
            else:
                cmd += '%s ' % _custom[i]

    #out = client_vm.execute_command("rm -rf /tmp/httptest_traffic_check ", noerr=True)
    logger.info('REQUEST cmd: %s' % cmd)
    out = client_vm.execute_command(cmd, noerr=True)

    # Start Http Traffic check
    #search_str = "Started Http Traffic on client"
    #res = start_traffic_check("/tmp/httptest_traffic_check", search_str)
    #if res:
    #    logger.error("Traffic is not started something went wrong")
    #    reason = client_vm.execute_command(" tail -5 %s" % log_file)
    #    logger.error(" %s" % (reason))
    #    raise RuntimeError("Request Traffic not started")
    #logger.info("Request Traffic is running, responses are logged in file: /tmp/httptest_resp_summary_time_stamp")

    if skip_error is False:
        is_there_IO_error(client_range, log_file, raise_exception=True)

    if stop_traffic:
        stop_http_traffic(client_range)
    out = traffic_obj.parse_response(out)
    return out

# This is a simple api for the request, when we just want to validate
# if the traffic flows or not. TCPSTAT validation is included.


@calc_exc_time
def is_there_IO_error(client_range, log_file='httptest_io_error*',
                      raise_exception=False):
    """
        While traffic genearation IO errors are generally logged at
        /tmp/httptest_<timestamp>.log. The function checks if
        the log file is present or not.
    """

    if isinstance(log_file, basestring):
        logs = [log_file]
    else:
        logger_utils.fail('HttpTest failed. Error - Log file should be of type string, but got : %s' % log_file)

    for _log_file in logs:

        logger.info('is_there_IO_error: %s\n' % log_file)

        clients = get_clients_from_range(client_range)
        vm, ip = traffic_manager.get_client_by_handle(clients[0])
        logger.debug('VM IP, NAME, CLIENT: %s, %s, %s' % (vm.ip, vm.name, ip))
        cmd = 'tail -5 %s' % log_file
        resp = vm.execute_command(cmd)
        if len(resp) > 0 and raise_exception:
            error_msg = 'Get request failed\n'
            for error in resp:
                try:
                    msg = json.loads(error)
                except Exception:
                    # When httptest fails, it doesn't write error log in json
                    # format.
                    logger_utils.error('HttpTest failed. Error - %s' % error)
                error_msg += 'Client: %s\nValidation: %s\nExpected: %s\nActual: ' \
                             '%s\n\n' % (msg['client'], msg['error_code'],
                                         msg['expected'], msg['actual'])
            # Cleaning up before raising exception
            vm.execute_command('rm %s &> /tmp/httptest' % log_file)
            logger_utils.error(error_msg)
        else:
            if len(resp) == 0:
                return 'False'
            else:
                logger.info('Failures: %s' % resp)
                return 'True'


def get_clients_from_range(client_range):
    match = re.search("^(.+?)(\d+)(?:-(\d+))?$", client_range)
    client_prefix = match.group(1)
    clients = []
    if match.group(3):
        clients = [client_prefix + str(n) for n in range(
            int(match.group(2)), int(match.group(3)) + 1)]
    else:
        clients = [client_prefix + str(match.group(2))]
    return clients


@calc_exc_time
def stop_http_traffic(client_range, delete_httptest_files=1,
                      log_file=''):

    clients = get_clients_from_range(client_range)
    vm, ip = traffic_manager.get_client_by_handle(clients[0])

    if log_file != '':
        vm.execute_command('pkill -9 -f ' + log_file)
    else:
        vm.execute_command('pkill -9 -f httptest.py')
    if bool(delete_httptest_files):
        vm.execute_command('rm -rf /tmp/httptest_io_*')
    for vm in infra_utils.get_vm_of_type('server'):
        vm.execute_command('rm -rf /usr/share/nginx/www/uploads/*')


def verify_traffic_can_flow(vs_name, vport, num_conns, retry=5):
    """

    :param vs_name:
    :param vport:
    :param num_conns:
    :param retry:
    :return:
    """

    num_connections = int(num_conns)
    retry = int(retry)
    try:
        tcpstat_pre = tcp_lib.tcpstat(vs_name)
    except Exception:
        logger_utils.fail('tcpstat not got before flow starts')
    request('get', vs_name, vport, '/',
            concurrent_conn_per_client=num_connections, skip_exception=1)
    time.sleep(3)
    # retry another 10 sec to wait for connection finished
    while retry > 0:
        try:
            tcpstat_post = tcp_lib.tcpstat(vs_name)
        except Exception:
            logger_utils.fail('tcpstat not got after flow starts')
        tcps_num_conns = json_utils.json_diff(
            tcpstat_post, tcpstat_pre, 'connections_closed')
        logger.info('conn diff:', tcps_num_conns, '--- expected:', str(num_connections * 2))
        if tcps_num_conns < num_connections * 2:
            logger.info('Not all connections went through. Retrying..')
            retry -= 1
            logger_utils.asleep(delay=10)
            continue
        else:
            break
    if retry <= 0:
        logger_utils.fail('Not all connections went through!')
