from avi_objects.logger import logger

import avi_objects.traffic_manager as traffic_manager
import lib.common as common
import lib.vs_lib as vs_lib


def run_ab_on_client(client_handles, vs_name, vs_port, path, c, n):
    """
    Runs on the main interface of the client vm
    :param client_handles:
    :param vs_name:
    :param vs_port:
    :param path:
    :param c:
    :param n:
    :return:
    """

    client_handles = traffic_manager.get_client_handles_from_range(client_handles)
    vip = vs_lib.get_vip(vs_name)
    vip_port = "%s:%s" % (vip, vs_port)
    kill_ab = "pkill -9 -f ab"
    run_ab = "ab -c %s -n %s http://%s/%s&> /tmp/ab.txt &" % \
        (c, n, vip_port, path)
    logger.info('start_apache_bench run_ab:'+ run_ab)
    logger.info('vip_port'+ vip_port)
    for client_handle in client_handles:
        vm, ip = traffic_manager.get_client_by_handle(client_handle)
        vm.execute_command(kill_ab, log_error=False)
        vm.execute_command(run_ab)


def start_httperf_on_client(client_handles, vs_name, vs_port, uri, rate, num_conns, requests_per_session, **kwargs):
    """
    Runs on the main interface of the client vm
    :param client_handles:
    :param vs_name:
    :param vs_port:
    :param uri:
    :param rate:
    :param num_conns:
    :param requests_per_session:
    :param kwargs:
    :return:
    """

    method = kwargs.get('method', 'GET')
    client_handles = traffic_manager.get_client_handles_from_range(client_handles)
    vip = kwargs.get('vip', None)
    if not vip:
        vip = vs_lib.get_vip(vs_name)
    command = 'httperf '
    # --timeout 0.5
    command += '--hog --server %s --port %s --wsess %s,%s,0 --rate %s --uri "%s" --method %s  --recv-buffer 1240000 --send-buffer 1240000 &> /tmp/httperf.txt &' % (
        vip, vs_port, num_conns, requests_per_session, rate, uri, method)
    logger.info('start_httperf_on_client:'+command)
    for client_handle in client_handles:
        vm, ip = traffic_manager.get_client_by_handle(client_handle)
        vm.execute_command(command)


def stop_ab_on_client(client_handles):
    """

    :param client_handles:
    :return:
    """

    client_handles = traffic_manager.get_client_handles_from_range(client_handles)
    for client_handle in client_handles:
        client_vm, ip = traffic_manager.get_client_by_handle(client_handle)
        client_vm.execute_command('pkill -9 -f ab', log_error=False)
        client_vm.execute_command('pkill -9 -f run_ab.sh', log_error=False)
        client_vm.execute_command('rm -rf /tmp/ab.log')


def stop_httperf_on_client(client_handles):
    """

    :param client_handles:
    :return:
    """

    client_handles = common.parse_handles(client_handles)
    for client_handle in client_handles:
        client_vm, ip = traffic_manager.get_client_by_handle(client_handle)
        client_vm.execute_command('pkill -9 -f httperf', log_error=False)
