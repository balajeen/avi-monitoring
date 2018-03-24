import ipaddress
import ast
import re
import json
import time
import random
import os
from prettytable import PrettyTable

from rest import get

from infra_utils import get_vm_of_type,  get_client_vm
from logger import logger
from logger_utils import error, fail
from avi_objects.avi_config import AviConfig
from avi_objects.infra_utils import get_cloud_context_type

from avi_objects.logger import adb

class HTTPTraffic(object):
    """
    HTTP Traffic lib
    """
    instances = []
    uuids = []
    def __init__(self, form_cmd=True, **kwargs):
        """ init function does get the all the virtual service details and form traffic command
        Kwargs:
            :param form_cmd: The form_cmd to use make decision to form Traffic cmd or not.
            :type form_cmd: boolean
            :param kwargs: kwargs contains list traffic related parms
            :type kwargs: kwargs
        """
        HTTPTraffic.instances.append(self)

        self.parse_vs_details()
        self.cmd = None
        if form_cmd:
            self._form_traffic_cmd(**kwargs)

    def _form_traffic_cmd(self, **kwargs):
        """ This function does form the traffic command based on user inputs, if no input from user
            it will take default values
        """
        mode = kwargs.pop('mode', 'continuous')
        self.vs_names = kwargs.pop('vs_names', None)
        client_range = kwargs.pop('client_range',None)
        uris = kwargs.pop('uri',None)
        vport = kwargs.pop('vport',None)
        vip_id = kwargs.pop('vip_id', None)
        self.to_floating_vip = kwargs.pop('to_floating_vip', None)
        self.addr_type = kwargs.pop('addr_type', 'V4')
        floating_addr_type = kwargs.pop('floating_addr_type', 'V4')

        #Traffic related
        method = kwargs.pop('method','get')
        status_code = kwargs.pop('status_code', 200)
        set_cookie_session = kwargs.pop('cookie_session', False)
        set_cookies_per_request = kwargs.pop('cookies_per_request', False)
        content = kwargs.get('body_contains', None)
        think_time = kwargs.pop('think_time', None)
        cps = kwargs.pop('cps', None)
        rps = kwargs.pop('rps', None)
        custom = kwargs.pop('custom', None)
        ping_time_out = kwargs.pop('ping_time_out', None)
        self.ping = kwargs.pop('ping',True)
        
        client_network = kwargs.pop('network', 'net')
        num_clients = kwargs.pop('num_clients', None)
        sequential_conn_per_client = kwargs.pop('sequential_conn_per_client', 1)
        concurrent_clients = kwargs.pop('concurrent_clients', True)
        parallel = int(concurrent_clients)
        no_of_req_per_conn = int(kwargs.pop('no_of_req_per_conn', 1))
        concurrent_conn_per_client = int(kwargs.pop('concurrent_conn_per_client', 1))

        stop_on_failure = int(kwargs.pop('stop_on_failure', 0))
        skip_exc = kwargs.pop('skip_exception', 0)

        self.floating_addr_type = 'floating_ip6' if floating_addr_type == 'V6' else 'floating_ip'
        self.vm = get_vm_of_type('client')[0]

        if content:
            kwargs['body_contains'] = self.may_be_replace_vars_with_ips(content)
        random_urls = int(kwargs.pop('random_urls', 0))
        random_urls_repeat = int(kwargs.pop('random_urls_repeat', 0))
        if random_urls:
            if not random_urls_repeat:
                random_urls_repeat = 1
            uris = []
            for i in range(random_urls):
                for j in range(random_urls_repeat):
                    uris.append('/randomurl' + str(i))
        if not uris:
            uris = ['/index.html', '/echo_server', '/1b.txt', '/100b.txt', '/1kb.txt', '/100kb.txt', '/echo_http_host']

        if not self.vs_names:
            self.vs_names = self.all_vs.keys()
        
        #Client Range calculation
        start_idx = 1
        config = AviConfig.get_instance()
        for appclient in config.appclient.keys():
            match = re.search('tsc(\d*)', appclient)
            if match:
                if start_idx <= int(match.group(1)):
                    start_idx = int(match.group(1)) + 1
        if num_clients:
            client_range = "tsc%s-%s" % (start_idx, str(start_idx + int(num_clients) - 1))
            logger.info(" Create Clients for this range: %s " % client_range)
            create_clients(len(self.vs_names),'tsc', client_network, 'httptest', start_idx=start_idx)
        elif not client_range and not num_clients:
            client_range = "tsc%s-%s" % (start_idx, str(start_idx+len(self.vs_names)-1))
            logger.info(" Create Clients for this range: %s " % client_range)
            create_clients(len(self.vs_names),'tsc', client_network, 'httptest', start_idx=start_idx)

        self.traffic_client_hadles = get_client_handles_from_range(client_range)

        self.cloud_type = get_cloud_context_type()

        cmd = '/root/client/tools/httptest_v2.py '
        self.sni_names = []

        url_list = []
        if mode != 'continuous':
            msg_vip_vs_name = ''
            vs_name = self.vs_names[0]
            vips = self.get_vip_from_vsname(vs_name)
            for vip in vips:
                msg_vip_vs_name += " "+vip+"$"+vs_name+"_"+str(vip_id)+"$"+str(vport)
            urls = self.get_url(vs_name, vport, uris, skip_exc=skip_exc, vip_id=vip_id)
            url_list.extend(urls)

            req_params, validations, prints = self._parse_input(urls, status_code, mode=mode, **kwargs)
            cmd += '--method %s ' % method
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
                    if not i%2:
                        cmd += '--custom %s ' %''.join(self.get_url(vs_name, vport, _custom[i], skip_exc=skip_exc, vip_id=vip_id))
                    else:
                        cmd += '%s ' %_custom[i]
            cmd += '--req-params \'%s\' ' % req_params
            cmd += '--validations \'%s\' ' % validations
            cmd += '--prints \'%s\' ' % prints
            cmd += '--vip_vs_names \'%s\' ' % msg_vip_vs_name
        else:
            client_ips = []
            vs_names, sni_names = self._normalise_vs_names(self.vs_names)
            self.sni_names = sni_names
            self.vs_names = vs_names
            self.sni_dns_names = []
            vip_list = []
            self.sni_vip_vs_name = ''
            msg_vip_vs_name = ''
            for vs in sni_names:
                sni_obj = self.all_vs[vs]['obj']
                self.sni_dns_names.extend(sni_obj['vh_domain_name'])
                for dns_name in sni_obj['vh_domain_name']:
                    self.sni_vip_vs_name += " "+dns_name+":"+vs
                parent_vs_uuid = sni_obj['vh_parent_vs_ref'].split('/')[-1]
                vip = ''
                for vs_name, vs_details in self.all_vs.iteritems():
                    if 'uuid' in vs_details.keys():
                        if parent_vs_uuid == vs_details['uuid']:
                            vip = vs_details['vips'][0]['ip_address']['addr']

                for hostname in sni_obj['vh_domain_name']:
                    self.vm.execute_command('echo "' + vip + ' ' + hostname + ' #snihost " >> /etc/hosts')
            for vs_name_idx in vs_names:
                vs_name, vip_id = self._get_vs_vid(vs_name_idx)
                if not vport:
                    service_ports = self._get_service_ports_for_vs(vs_name=vs_name)
                else:
                    service_ports = str(vport).split()
                vip_id_dict = self._get_vips_with_ids(vs_name)
                vip = vip_id_dict[vip_id]
                vip_list.append(vip)
                for s_vport in service_ports:
                    urls = self.get_url(vs_name, s_vport, uris[random.randint(0, len(uris)-1)], vip_id=vip_id)
                    url_list.extend(urls)
                service_ports = map(lambda i: str(i), service_ports)
                msg_vip_vs_name += " "+vip+"$"+vs_name+"_"+vip_id+"$"+",".join(service_ports)

            if method != 'get':
                cmd += '--method %s ' % method

            if no_of_req_per_conn != 1:
                cmd += '--requests %s ' % no_of_req_per_conn

            if len(kwargs):
                req_params, validations, prints = self._parse_input(url_list, status_code, **kwargs)
                cmd += '--req-params \'%s\' ' % req_params
                cmd += '--validations \'%s\' ' % validations
                cmd += '--prints \'%s\' ' % prints
            if stop_on_failure:
                cmd += '--stop-on-failure %s ' % stop_on_failure
            if set_cookie_session:
                cmd += '--cookie-session '
            if set_cookies_per_request:
                cmd += '--cookies-per-request '
            if think_time:
                cmd += '--think-time %s ' % think_time
            if ping_time_out:
                cmd += '--ping-time %s ' % ping_time_out
            if self.ping:
                if self.cloud_type not in ['azure']:
                    vip_list_set = set(vip_list)
                    vip_list = list(vip_list_set)
                    cmd += '--ping \'%s\' ' % '\' \''.join(vip_list)
            cmd += '--vip_vs_names \'%s\' ' % msg_vip_vs_name.strip()

        client_vm, client_ips = get_client_handles(client_range, concurrent_conn_per_client)

        client_vm.cloud_obj.add_remove_ip_rules(vm=client_vm)

        time_stamp = time.strftime('%H_%M_%S', time.gmtime())
        log_file = '/tmp/httptest_io_error_' + time_stamp + '.log'

        cmd += '--clients %s ' % ' '.join(client_ips)
        cmd += '--urls \'%s\' ' % '\' \''.join(url_list)
        cmd += '--log-file %s ' % log_file

        self.cmd = cmd
        self.log_file = log_file

    def start_traffic(self, background=False):
        """This function starts traffic on client
        Args:
            :param background: The background to use make decision to run continuous or non-continuous.
            :type background: boolean
        Returns:
            a dictionary in case of non-continuous traffic.
        """
        uuid_list = HTTPTraffic.uuids
        if len(uuid_list):
            uuid = 'http-'+str(int(uuid_list[-1].split('-')[-1])+1)
        else:
            uuid = 'http-1'
        self.uuid = uuid

        HTTPTraffic.uuids.append(uuid)
        self.cmd += '--uuid %s '%uuid

        self.vm = get_vm_of_type('client')[0]

        self.vm.execute_command("rm -rf /tmp/httptest_traffic_check ", log_error=False)
        if self.sni_names:
            self.start_sni_traffic(self.sni_dns_names, self.sni_vip_vs_name)
        if background:
            self.set_tcp_syn_retries()
            self.cmd += "&> /tmp/httptest_start_traffic_log "
            self.vm.execute_command(self.cmd, background=True)
        else:
            output = self.vm.execute_command(self.cmd)
            return output

    def stop_traffic(self, clear_logs=True, release_ips=True):
        """This function does stop traffic on client
        Kwargs:
            :param clear_logs: The clear_logs to use whether logs wants to delete or not.
            :type clear_logs: boolean
            :param release_ips: The release_ips to use whether release_ips the IPs once traffic test done.
            :type release_ips: boolean
        Returns:
            None
        """
        pids = self.vm.execute_command("ps -aux |grep \"%s\" | awk '{print $2;}'" % self.uuid)
        pids = ' '.join(pids).replace('\n', '')
        if pids: 
            self.vm.execute_command("sudo kill -9 %s" % pids, log_error=False)
        else:
            self.vm.execute_command('sudo pkill -9 -f ping', log_error=False)
            self.vm.execute_command('sudo pkill -9 -f httptest.py', log_error=False)
            self.vm.execute_command('sudo pkill -9 -f httptest_v2.py', log_error=False)
            self.vm.execute_command('sudo pkill -9 -f snitest.py', log_error=False)
        if clear_logs:
            self.vm.execute_command('rm -rf /tmp/httptest*')
            self.vm.execute_command('rm -rf /tmp/snitest*')
        else:
            time_stamp = time.strftime("%Y%m%d_%H%M%S")
            dir_name = "http_bkp_%s" % time_stamp
            mv_cmd = "mv /tmp/httptest* /tmp/%s" % dir_name
            zip_cmd = "cd /tmp ; tar -zcvf %s.tar.gz %s" % (dir_name, dir_name)
            self.vm.execute_command("mkdir /tmp/%s" % dir_name)
            self.vm.execute_command(mv_cmd)
            self.vm.execute_command(zip_cmd)
            self.vm.execute_command("rm -rf /tmp/%s" % dir_name)

        self.server_cleanup()
        self.client_cleanup()
        if release_ips:
            _clear_clients(self.vm, self.traffic_client_hadles)

        return self

    def __exit__(self, *err):
        """ Helps to stop the traffic in abnormal error exit also """
        traffic_stop()

    def parse_response(self, response):
        """This function parse request response. 
        Args:
            :param response: The response to use pass request response.
            :type response: str
        Returns:
            a dictionary of response value.
        Raises:
            ValueError, AttributeError, KeyError
        """
        return_vals = []
        other_prints = []
        req = {}
        key = None
        key2 = None
        val = None
        for item in response:
            if re.search('\$@\$@ Request Details Start \$@\$@', item):
                req = {}
                key = None
                key2 = None
                val = None
                continue
            if re.search('\$@\$@ Request Details End \$@\$@', item):
                if req:
                    return_vals.append(req)
                continue
            pattern = '\$@\$@ (.*) = (.*)'
            match = re.search(pattern, item)
            if match:
                keys = match.group(1).split('.')
                val = match.group(2)
                if len(keys) == 1:
                    key = keys[0]
                    key2 = None
                    req[key] = val
                else:
                    key2 = keys[1]
                    key = keys[0]
                    if key in req:
                        req[key][key2] = val
                    else:
                        req[key] = {}
                        req[key][key2] = val
            else:
                if key:
                    if key2:
                        req[key][key2] += item
                    else:
                        req[key] += item
                else:
                    other_prints.append(item)
        if not return_vals:
            return_vals = other_prints
        return return_vals

    def may_be_replace_vars_with_ips(self, content):
        """This function does convertion of body content as net_ip to actual IP address.
        Args:
            :param content: The content to use take body content as net_ip.
            :type content: str
        Returns:
            ip address as string
        """
        #Need to enhance once IP and net code Done
        original_content = content
        return original_content


    def server_cleanup(self):
        """This function does cleanup on server side related to traffic uploads """
        for server_vm in get_vm_of_type('server'):
            server_vm.execute_command('rm -rf /usr/share/nginx/www/uploads/*')

    def client_cleanup(self):
        """This function does cleanup on client side related to traffic """
        clear_sni_hostnames()

    def start_traffic_check():
        """This function does start traffic check """
        #Taken care this check as part of Execute Command, if anything needs will take care in feature.
        pass

    def is_there_errors(self, log_file, threshold=0):
        """This function does checks for errors in a given file on client.
        Args:
            :param log_file: The log_file to use pass log file name with full path
            :type log_file: str
        Returns:
            int. The return codes:
                0 - No Traffic Errors/Failures found.
                1 - Traffic Errors found/No log file found
        """
        ls_out = self.vm.execute_command("ls %s " % log_file, log_error=False)
        ls_out = " ".join(ls_out)
        ls_out = ls_out.strip().split()
        if ls_out:
            output = self.vm.execute_command("tail -10 %s " % log_file, log_error=False)
            output_len = len(output)
            output = " ".join(output)
            output = output.strip().split()
            if output:
                if threshold:
                    if 'snitest' in log_file or 'ping' in log_file:
                        if output_len <= (threshold + 1):
                            logger.warning("Errors seen. but below threshold:%s values" % threshold)
                            logger.info(output)
                            return 0
                logger.info(" Errors are there in log file: %s " % log_file)
                logger.info(output)
                return 1
            else:
                logger.info("No Traffic errors in log file: %s " % log_file)
                return 0
        else:
            logger.info("No such file or directory exists :: %s" % log_file)
            return 1

    def set_tcp_syn_retries(self, interval=3):
        """This function does modifies TCP Sync retrie interval
        Kwargs:
            :param interval: Current interval to be in, default value is 1.
            :type interval: None
        """
        self.vm.execute_command('echo %s > /proc/sys/net/ipv4/tcp_syn_retries' % interval)
        
    def reset_tcp_syn_retries(self):
        """This function does reset tcp syn retrie time interval to default. """
        self.vm.execute_command('echo 5 > /proc/sys/net/ipv4/tcp_syn_retries' % interval)

    def start_sni_traffic(self, sni_vs_list, sni_vip_vs_name):
        """This function start SNI Traffic(CURL Traffic and Ping)
        Args:
            :param self: The self to use.
            :type self: str
            :param sni_vs_list: The sni_vs_list to use.
            :type sni_vs_list: str
            :param sni_vip_vs_name: The sni_vip_vs_name to use.
            :type sni_vip_vs_name: str
        """
        time_stamp = time.strftime('%H_%M_%S', time.gmtime())
        sni_log_file = '/tmp/snitest_error_' + time_stamp + '.log'
        cmd = '/root/client/tools/snitest.py '
        cmd += '--sni_vs \'%s\' ' % '\' \''.join(sni_vs_list)
        cmd += '--log-file %s ' % sni_log_file
        if self.ping:
            if self.cloud_type in ['azure']:
                cmd += '--ping 0 '
        cmd += '--vip_vs_names \'%s\' ' % sni_vip_vs_name.strip()
        cmd += '--uuid %s ' % self.uuid
        cmd += '&> /tmp/snitest_start_traffic_log &'

        output = self.vm.execute_command(cmd)

    def _normalise_vs_names(self, vs_names=[]):
        """This function does normalise vs names along with vip index id. """
        self.sni_vs_list = []
        self.vs_name_list = [] 
        for vs_name in vs_names:
            if vs_name in self.all_vs and self.all_vs[vs_name]['type'] == 'VS_TYPE_VH_CHILD':
                self.sni_vs_list.append(vs_name)
            else:
                match = re.search('^(.+?)(?::(\d+))?$', vs_name)
                vs = match.group(1)
                if vs in self.all_vs and (self.all_vs[vs]['type'] == 'VS_TYPE_NORMAL'\
                                          or self.all_vs[vs]['type'] == 'VS_TYPE_VH_PARENT'):
                    vip_id = match.group(2)
                    if match.group(2):
                        self.vs_name_list.append(vs+"_"+vip_id)
                    else:
                        for vip in self.all_vs[vs_name]['obj']['vip']:
                            self.vs_name_list.append(vs+"_"+vip['vip_id'])
        return self.vs_name_list, self.sni_vs_list

    def _get_vs_vid(self, vsname_id):
        """This function provides vs name and vip id. """
        vs_detail = vsname_id.split("_")
        vs = "_".join(vs_detail[:-1])
        vip_id = vs_detail[-1]
        return vs, vip_id

    def _get_service_ports_for_vs(self, vs_name):
        """This function does get all service ports for a given virtual service name. """
        vports = []
        if vs_name in self.all_vs:
            for service in self.all_vs[vs_name]['services']:
                vports.append(service['port'])
        return vports
        

    def verify_ping_stats(self, vs_names=None, threshold=0):
        """This function does verify ping errors are there or not for given vs names.
        Kwargs:
            :param vs_names: vs_names to check ping errors/stats, default value is [].
            :type vs_names: list
        Returns:
            status codes, ping error vs names.
            0 - No ping errors.
            1 - Ping errors seen.
        Raise:
            ValueError
        """
        if not vs_names:
            vs_names = self.all_vs.keys()
        vs_names, sni_vs_names = self._normalise_vs_names(vs_names)

        ping_logs = {}
        if vs_names:
            vs_logs = self._form_log(vs_names, level='ping', traffic_type='httptest')
            ping_logs = dict(ping_logs, **vs_logs)
        if sni_vs_names:
            sni_vs_logs = self._form_log(sni_vs_names, level='ping', traffic_type='snitest')
            ping_logs = dict(ping_logs, **sni_vs_logs)

        res = 0
        ping_err_vs = []
        for vs_name, log_file in ping_logs.iteritems():
            out_first_log = self.vm.execute_command("head -2 %s" % log_file, log_error=False)
            logger.info('First Ping start details :: \n%s' % ''.join(out_first_log))
            output = self.vm.execute_command("grep \"ERROR\" %s" % log_file, log_error=False)
            if not output:
                logger.info(" No Ping drop happend for Virtual Service:%s "% vs_name)
                continue
            else:
                if len(output) <= threshold:
                    logger.warning("Errors seen. but below threshold:%s values"% threshold)
                    logger.info("\n%s" % ''.join(output))
                    continue
                logger.info("Ping errors are there for Virtual Service:%s "% vs_name)
                logger.info("\n%s" % ''.join(output))
                res = 1
                ping_err_vs.append(vs_name)

            self.reset_logs(log_file=log_file)

        return res, ping_err_vs

    def _form_log(self, vs_names, level='error', traffic_type='httptest', vports=[]):
        """This function does form the log file name for a given vs names, vports based  on
           log level and traffic type.
        """
        vs_log_name = {}
        for vs_idx in vs_names:
            if traffic_type == 'httptest':
                vs, vip_id = self._get_vs_vipid(vs_idx)
                vips = self.get_vip_from_vsname(vs_name=vs, vip_id=vip_id)
            else:
                vips = [None]
            for vip in vips:
                if level == 'ping':
                    if traffic_type == 'httptest':
                        log_name = vs+"_"+vip_id+"_"+vip+"_22"
                        log_file = "/tmp/%s_%s_%s" % (traffic_type, level, log_name)
                        vs_log_name[log_name] = log_file
                    if traffic_type == 'snitest':
                        log_file = "/tmp/%s_%s_%s" % (traffic_type, level, vs_idx)
                        vs_log_name[vs_idx] = log_file
                else:
                    if traffic_type == 'snitest':
                        log_file = "/tmp/%s_%s_%s" % (traffic_type, level, vs_idx)
                        vs_log_name[vs_idx] = log_file
                    else:
                        log_name = vs+"_"+vip_id+"_"+vip
                        if vports:
                            for vport in vports:
                               log_name += '_'+vport
                               vs_log_name[log_name] = log_file
                        else:
                            for services in self.all_vs[vs]['obj']['services']:
                               full_log_name = "%s_%s" % (log_name, str(services['port']))
                               log_file = "/tmp/%s_%s_%s" % (traffic_type, level, full_log_name)
                               vs_log_name[full_log_name] = log_file
        return vs_log_name

    def reset_logs(self, vs_names=[], vports=[], log_file=None):
        """This function does reset the log for given vs name, vport or given log file.
        Kwargs:
            :param vs_names: vs_names to reset logs, default value is [].
            :type vs_names: list
            :param vports: vports, default value is [].
            :type vports: list
            :param log_file: log file name to reset, default value is None.
            :type log_file: str
        """
        if not log_file:
            if not vs_names:
                reset_cmd = "cd /tmp ; for i in httptest* ; do echo "" > $i ; done"
                self.vm.execute_command(reset_cmd)
            else:
                vs_names, sni_vs_names = self._normalise_vs_names(vs_names)
                logs = {}
                if vs_names:
                    vs_logs = _form_log(vs_names, level='ping', traffic_type='httptest', vports=vports)
                    logs = dict(logs, **vs_ping_logs)
                    vs_logs = _form_log(vs_names, level='error', traffic_type='httptest', vports=vports)
                    logs = dict(logs, **vs_ping_logs)

                if sni_vs_names:
                    for sni_vs in sni_vs_names:
                        sni_ping = sni_vs+'_ping'
                        sni_traffic = sni_vs+'_error'
                        logs[sni_traffic] = "/tmp/snitest_error_%s" % sni_vs
                        logs[sni_ping] = "/tmp/snitest_ping_%s" % sni_vs

                for log_name, log_file in logsiteritems():
                    self.vm.execute_command("echo "" > %s" % log_file)
                    logger.info(" Reset successful for log_file: %s " % log_file)
        else:
            self.vm.execute_command("echo "" > %s" % log_file)
            logger.info(" Reset successful for log_file: %s " % log_file)

    def _get_vs_vipid(self, vsname_id):
        """ separates vs name and vip index value"""
        vs_detail = vsname_id.split("_")
        vs = "_".join(vs_detail[:-1])
        vip_id = vs_detail[-1]
        return vs, vip_id

    def _verify_traffic_stats(self, log_file='/tmp/httptest_summary'):
        """ Helps to verify the traffic stats on client """
        attempts = 0
        output = ""
        while attempts < 3:
            if output:
                break
            else:
                output = self.vm.execute_command("tail -1 %s " % log_file, log_error=False)
                attempts += 1

        count_dict = {}
        timestamp = 0
        if output:
            timestamp = " ".join(output[0].split()[:2])
            count_dict = ast.literal_eval("".join(output[0].split()[3:]))
        return count_dict, timestamp

    def traffic_get_all_stats(self, log_file='/tmp/httptest_summary'):
        """This function does display all traffic starts
        Kwargs:
            :param log_file: traffic stats log_file, default value is '/tmp/httptest_summary'.
            :type log_file: str
        Returns:
            a dict have per vs traffic stats
        Raises:
            ValueError, KeyError
        """
        vs_vip_dict = {}
        vs_list = self.all_vs.keys()
        for vs_name in vs_list:
            vip_id_dict = self._get_vips_with_ids(vs_name)
            for vip_id, vip in vip_id_dict.iteritems():
                if vip in vs_vip_dict:
                    vs_vip_dict[vip] = [vs_vip_dict[vip]] if not isinstance(vs_vip_dict[vip], list) else vs_vip_dict[vip]
                    vs_vip_dict[vip].append(vs_name + "_"+vip_id)
                else:
                    vs_vip_dict[vip] = vs_name + "_"+vip_id

        log_file += '_'+self.uuid
        count_dict, timestamp = self._verify_traffic_stats(log_file=log_file)
        logger.info(" Client stats at timestamp :: %s" % timestamp)
        msg = PrettyTable()
        msg.field_names = ["Virtual service", "Success Req#", "Failed Req# (resp_code>300)", "Connection Error Req#"]
        total_count_dict = {}
        vip_list = count_dict.keys()
        vip_list.sort()
        for vip in vip_list:
            count = 0
            for vs_port in count_dict[vip].keys():
                if vip in vs_vip_dict:
                    vs_name = str(vs_vip_dict[vip])
                else:
                    vs_name = ''
                vs_details = "[" + vs_name + ":" + vip +":"+ vs_port + "]"
                if 'success_req' in count_dict[vip][vs_port]:
                    success = str(count_dict[vip][vs_port]['success_req']['count'])
                    count += count_dict[vip][vs_port]['success_req']['count']
                else:
                    success = "0"
                if 'failed_req' in count_dict[vip][vs_port]:
                    failed = str(count_dict[vip][vs_port]['failed_req']['count'])
                    count += count_dict[vip][vs_port]['failed_req']['count']
                else:
                    failed = "0"
                if 'error_req' in count_dict[vip][vs_port]:
                    error = str(count_dict[vip][vs_port]['error_req']['count'])
                    count += count_dict[vip][vs_port]['error_req']['count']
                else:
                    error = "0"
                msg.add_row([vs_details, success, failed, error])
            total_count_dict[vip] = count
        logger.info("\n %s"%msg)
        return total_count_dict

    def _get_vips_with_ids(self, vs_name):
        """ Helps to get all vip for all vip indexes for a given vs names """
        vip_vip_id_dict = {}
        if vs_name in self.all_vs.keys():
            if 'VS_TYPE_VH_CHILD' == self.all_vs[vs_name]['type']:
                return vip_vip_id_dict
            else:
                for vip_obj in self.all_vs[vs_name]['vips']:
                    vip_id = vip_obj['vip_id']
                    if 'ip_address' in vip_obj:
                        vip = vip_obj['ip_address']['addr']
                    if 'ip6_address' in vip_obj:
                        vip = vip_obj['ip6_address']['addr']
                    vip_vip_id_dict[vip_id] = vip
        return vip_vip_id_dict

    def _get_vs_names_with_vip(self, vs_list=None):
        """ Returns vs_name:vip_id list for given vs names """
        vs_vip_list = []
        normal_vs, sni_vs = self._normalise_vs_names(vs_list)
        for vs in normal_vs:
            li = vs.rsplit('_',1)
            vs_vip_list.append(":".join(li))
        vs_vip_list.extend(sni_vs)
        return vs_vip_list

    def traffic_expect_errors(self, vs_names=None, skip_vs_list=None, internal_traffic_check=True, ping_check=True):
        """This function does expect traffic errors on provided vs names, if wont provide consider all vs names."""
        if not vs_names:
            vs_names = self.all_vs.keys()

        #Traffic implicit check for no errors
        vs_names = self._get_vs_names_with_vip(vs_names[:])
        remain_vs = []
        if skip_vs_list:
            remain_vs = self._get_vs_names_with_vip(skip_vs_list[:])
            for skip_vs in remain_vs:
                if skip_vs in vs_names:
                    vs_names.remove(skip_vs)
        else:
            all_vs_names = self.all_vs.keys()
            all_vs_names = self._get_vs_names_with_vip(all_vs_names[:])
            for vs in all_vs_names:
                if vs not in vs_names:
                    remain_vs.append(vs)

        logger.info('Traffic Expect Errors on: %s' % ' '.join(vs_names))
        if remain_vs and internal_traffic_check:
            logger.info('Traffic Expect No Errors on: %s' % ' '.join(remain_vs))
            self.traffic_expect_no_errors(vs_names=remain_vs, internal_traffic_check=False)
        #Traffic implicit check for no errors ends

        traffic_status = self.traffic_should_be_running(vs_names)

        normal_vs_names, sni_vs_names = self._normalise_vs_names(vs_names)

        raise_error = 0
        msg = ""
        logs = {}
        if normal_vs_names:
            vs_logs = self._form_log(normal_vs_names, level='error', traffic_type='httptest')
            logs = dict(logs, **vs_logs)
        if sni_vs_names:
            total_dict = self.traffic_get_all_stats('/tmp/snitest_summary')
            sni_vs_logs = self._form_log(sni_vs_names, level='error', traffic_type='snitest')
            logs = dict(logs, **sni_vs_logs)

        for log_name, log_file in logs.iteritems():
            res = self.is_there_errors(log_file)
            if res:
                logger.info("vs_details: %s has traffic errors, as expected" % (log_name))
            else:
                msg += "Traffic errors expected, but no errors seen for vs:%s \n" % log_name
                raise_error = 1
            self.reset_logs(log_file=log_file)

        # In Azure cloud ICMP wont support
        if self.cloud_type in ['azure']:
            res=1
        else:
            res, ping_err_vs = self.verify_ping_stats(vs_names)

        res = res if vs_names else 1

        if raise_error or not res:
            if ping_check:
                temp_msg = 'Ping errors expected, but no errors seen on vs: %s ' % ping_err_vs
                msg = msg+temp_msg if not res else msg
            if len(msg):
                error(msg)

    def traffic_expect_no_errors(self, vs_names=None, skip_vs_list=None, internal_traffic_check=True, threshold=5):
        """This function does expect traffic no errors on provided vs names, if wont provide consider all vs names."""
        if not vs_names:
            vs_names = self.all_vs.keys()

        #Traffic implicit check for traffic expect errors
        vs_names = self._get_vs_names_with_vip(vs_names[:])
        remain_vs = []
        if skip_vs_list:
            remain_vs = self._get_vs_names_with_vip(skip_vs_list[:])
            for skip_vs in remain_vs:
                if skip_vs in vs_names:
                    vs_names.remove(skip_vs)
        else:
            all_vs_names = self.all_vs.keys()
            all_vs_names = self._get_vs_names_with_vip(all_vs_names[:])
            for vs in all_vs_names:
                if vs not in vs_names:
                    remain_vs.append(vs)

        logger.info('Traffic Expect No Errors on: %s' % ' '.join(vs_names))
        if remain_vs and internal_traffic_check:
            logger.info('Traffic Expect Errors on: %s' % ' '.join(remain_vs))
            self.traffic_expect_errors(vs_names=remain_vs, internal_traffic_check=False)
        #Traffic implicit check ends

        traffic_status = self.traffic_should_be_running(vs_names)

        normal_vs_names, sni_vs_names = self._normalise_vs_names(vs_names)

        raise_error = 0
        msg = ""
        logs = {}
        if normal_vs_names:
            vs_logs = self._form_log(normal_vs_names, level='error', traffic_type='httptest')
            logs = dict(logs, **vs_logs)

        if sni_vs_names:
            total_dict = self.traffic_get_all_stats('/tmp/snitest_summary')
            sni_vs_logs = self._form_log(sni_vs_names, level='error', traffic_type='snitest')
            logs = dict(logs, **sni_vs_logs)

        for log_name, log_file in logs.iteritems():
            res = self.is_there_errors(log_file, threshold=threshold)
            if not res:
                logger.info("No Traffic errors for vs details:%s" % log_name)
            else:
                msg += "Traffic errors seen, but not expected on vs details:%s \n" % log_name
                raise_error = 1
            self.reset_logs(log_file=log_file)

        # In Azure cloud ICMP wont support
        if self.cloud_type in ['azure']:
            res=0
        else:
            res, ping_err_vs = self.verify_ping_stats(vs_names, threshold=threshold)

        if raise_error or res:
            temp_msg = 'Ping errors seen %s '%ping_err_vs
            msg = msg+temp_msg if res else msg
            error(msg)

    def traffic_should_be_running(self, vs_names=[]):
        """This function does check for traffic is running on client for given VS or not.
        Kwargs:
            :param vs_names: list of vs_names check for traffic running or not, default value is [].
            :type vs_names: list
        Returns:
            0 - success
            1 - failure
        Raises:
            ValueError, KeyError
        """
        vs_names = vs_names[:]
        if not vs_names:
            vs_names = self.all_vs.keys()
        vs_names, sni_vs_names = self._normalise_vs_names(vs_names)
        previous_dict = self.traffic_get_all_stats()
        msg = ''
        for vs_name in vs_names:
            vs, vip_id = self._get_vs_vid(vs_name)
            vip_id_dict = self._get_vips_with_ids(vs)
            vip = vip_id_dict[vip_id]
            cur_time = int(time.time())
            end_time = cur_time + 65
            while True:
                ts = int(time.time())
                if ts > end_time:
                    error(" Traffic is not running .. on %s" % vs_name)
                    msg += ''+vs_name
                    break
                else:
                    cur_dict = self.traffic_get_all_stats()
                    if vip not in cur_dict:
                        msg += " "+vs_name
                        break
                    if vip not in previous_dict:
                        previous_dict = cur_dict
                        continue
                    else:
                        if cur_dict[vip] != previous_dict[vip]:
                            logger.info(" Traffic is running on : %s" % vs_name)
                            logger.info(" Total no. of requests till now :%s" % cur_dict[vip])
                            break
                        else:
                            time.sleep(1)
                            continue
        if msg:
            error(" Traffic is not running on %s" % msg)
        return 0

    def parse_vs_details(self):
        """This function does parse the all virtual serices details"""
        status_code, resp = get('virtualservice')

        if not resp['count']:
            error("No Virtual Services found on Controller to start Traffic")
            return

        vs_objs = resp['results']

        self.all_vs = {}
        self.vs_objs = vs_objs
        vs_obj_list = vs_objs

        for vs_obj in vs_obj_list:
            if vs_obj['east_west_placement']:
                continue
            self.all_vs[vs_obj['name']] = {}
            self.all_vs[vs_obj['name']]['type'] = vs_obj['type']
            self.all_vs[vs_obj['name']]['uuid'] = vs_obj['uuid']
            self.all_vs[vs_obj['name']]['obj'] = vs_obj
            if 'type' in vs_obj and vs_obj['type'] == 'VS_TYPE_NORMAL':
                self.all_vs[vs_obj['name']]['vips'] = vs_obj['vip']
                self.all_vs[vs_obj['name']]['services'] = vs_obj['services']
            elif 'type' in vs_obj and vs_obj['type'] == 'VS_TYPE_VH_PARENT':
                self.all_vs[vs_obj['name']]['vips'] = vs_obj['vip']
                self.all_vs[vs_obj['name']]['services'] = vs_obj['services']
                self.all_vs[vs_obj['name']]['vh_child_vs_uuid'] = vs_obj['vh_child_vs_uuid']
            elif 'type' in vs_obj and vs_obj['type'] == 'VS_TYPE_VH_CHILD':
                self.all_vs[vs_obj['name']]['vh_domain_name'] = vs_obj['vh_domain_name']

    def get_vip_from_vsname(self, vs_name, vip_id=0):
        """This function provides vip for a given virtual service and vip index.
        Args:
            :param vs_name: The vs_name to find the vip
            :type vs_name: str
        Kwargs:
            :param vip_id: vip index value, default value is 0.
            :type vip_id: int
        Returns:
            Virtual IP Address as string.
        Raises:
            ValueError, KeyError
        """
        vips = []
        if vs_name in self.all_vs.keys():
            vips_obj = self.all_vs[vs_name]['obj']['vip']
            for vip in vips_obj:
                if 'vip_id' in vip and str(vip['vip_id']) == str(vip_id):
                    if self.addr_type == 'V4' and 'ip_address' in vip:
                        vips.append(vip['ip_address']['addr'])
                    if self.addr_type == 'V6' and 'ip6_address' in vip:
                        vips.append(vip['ip6_address']['addr'])
                if self.to_floating_vip and self.floating_addr_type in vip:
                    return [vip[self.floating_addr_type]['addr']]
                    #vips.append(vip[self.floating_addr_type]['addr'])
            return vips

    def get_vs_vip(self, vs_name, vip_id=0, addr_type='V4', floating_addr=False):
        """ Helps to get the vip details for a given VS with default values """
        self.addr_type = addr_type
        self.to_floating_vip = False
        if floating_addr:
            self.to_floating_vip = True
            self.floating_addr_type = 'floating_ip6' if addr_type == 'V6' else 'floating_ip'
        return self.get_vip_from_vsname(vs_name, vip_id)

    def get_floating_vip_from_vsname(self, vs_name, vip_id=0):
        """This function provides vip for a given virtual service and vip index.
        Args:
            :param vs_name: The vs_name to find the vip
            :type vs_name: str
        Kwargs:
            :param vip_id: vip index value, default value is 0.
            :type vip_id: int
        Returns:
            Floating Virtual IP Address as string.
        Raises:
            ValueError, KeyError
        """
        if vs_name in self.all_vs.keys():
            vips_obj = self.all_vs[vs_name]['obj']['vip']
            for vip in vips_obj:
                if 'vip_id' in vip and int(vip['vip_id']) == int(vip_id):
                    return vip['floating_ip']['addr']

    def get_listener_port_enable_ssl(self, vs_name, vport, skip_exc=0):
        """This function does checks on listener port ssl enable or not.
        Args:
            :param vs_name: vs name to find all listener ports.
            :type vs_name: str
            :param vport: Listener port to check on weather ssl enable or not.
            :type vport: str
        Kwargs:
            :param skip_exc: skip exception if raises while get listener port enable ssl,
                             default value is 0.
            :type skip_exc: int
        Returns:
            None
        Raises:
            ValueError, AttributeError, KeyError
        """

        logger.debug('Lookup for vport %s' %vport)
        services = self.all_vs[vs_name]['services']
        for service in services:
            if vport >= service['port'] and vport <= service['port_range_end']:
                return service['enable_ssl']
        if skip_exc == 0:
            raise RuntimeError('ERROR did not find listener port %s' % vport)

    def get_protocol(self, vs_name, port, skip_exec=0):
        """This function does get the protocol and return.
        Args:
            :param vs_name: vs name to find all listener ports
            :type vs_name: str
            :param port: listener port to check on weather ssl enable or not.
            :type port: str
        Kwargs:
            :param skip_exc: skip exception if raises while get listener port enable ssl,
                             default value is 0.
            :type skip_exec: inte
        Returns:
            protocol as a string.
        Raises:
            ValueError, AttributeError, KeyError
        """
        if self.get_listener_port_enable_ssl(vs_name, port, skip_exec):
            return 'https://'
        else:
            return 'http://'

    def get_url(self, vs_name, vport, uris, skip_exc=0, vip_id=0):
        """This function does forms urls and retun.
        Args:
            :param vs_name: vs name to form url
            :type vs_name: str
            :param vport: listener port to form url
            :type vport: str
            :param uris: uri to form url.
            :type uris: str
        Kwargs:
            :param skip_exc: skip exception if raises while get listener port enable ssl,
                             default value is 0.
            :type skip_exc: int
            :param vip_id: virtual seevice vip_id, default value is 0.
            :type vip_id: int
        Returns:
            list of urls
        """
        vips = self.get_vip_from_vsname(vs_name, vip_id=int(vip_id))
        vport = int(vport)

        proto = self.get_protocol(vs_name, vport, skip_exc)
#        if suite_vars.spdy_enabled and proto == 'https://':
#            key = '%s,%s' % (vip, vport)
#            shrpx_proxy = config.shrpx_vs_map[key]
#            vip, vport = tuple(shrpx_proxy.split(','))

        uris = [uris] if not isinstance(uris, list) else uris
        urls = []
        for uri in uris:
            for vip in vips:
                if type(ipaddress.ip_address(unicode(vip))) == ipaddress.IPv6Address:
                    url_elms = [proto, '[', vip, ']', ':', str(vport), uri.replace('&amp;', '&')]
                else:
                    url_elms = [proto, vip, ':', str(vport), uri.replace('&amp;', '&')]
                urls.append("".join(url_elms))
        return urls

    def _parse_input(self, urls, status_code=200, mode='continuous', **kwargs):
        """This function does parse the given input parameters to request related parameters.
        Args:
            :param urls: urls to parse according to validations and prints.
            :type urls: list
        Kwargs:
            :param status_code: request parm status_code, default value is 200.
            :type status_code: int
            :param kwargs: kwargs use to optional parameters to request traffic.
            :type kwargs: kwargs
        Returns:
            req_params, validations, prints
        Raises:
            ValueError, KeyError
        """
        prints = {}
        validations = {}
        req_params = {}

        if len(urls) != len(str(status_code).split(',')):
            status_codes = [str(status_code)] * len(urls)
        else:
            status_codes = str(status_code).split(',')
        for url, status_code in zip(urls, status_codes):

            kwargs, validations[url], prints[url] = self._format_validations(
                url, status_code, mode, **kwargs)

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
                str(validations).replace('"', '\\"').replace("'", '"'),
                str(prints).replace('"', '\\"').replace("'", '"'))
        
    def _format_validations(self, url, status_code, mode, **kwargs):
        """This function does format request validation parameters
        Args:
            :param url: The url to use format the validations per url based.
            :type url: str
            :param status_code: The status_code to use.
            :type status_code: int
        Kwargs:
            :param kwargs: kwargs use to optional parameters to request traffic.
            :type kwargs: kwargs
        Returns:
            kwargs, validations, prints
        Raises:
            ValueError, AttributeError, KeyError
        """
        allowed_validations = [
            'header_equals',
            'header_contains', 'header_not_equals',
            'key_in_headers', 'header_starts_with',
            'header_ends_with', 'header_not_contains',
            'body_equals', 'body_contains', 'body_not_contains',
            'file_equals', 'status_code', 'key_not_in_headers', 'get_file_equals']

        allowed_prints = [
            'print_headers', 'print_cookies', 'print_body', 'print_length']

        validations = {}
        prints = {}
        if not kwargs.pop('ignore_status_code', False):
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

        if not prints and mode != 'continuous':
            prints['all'] = None

        return kwargs, validations, prints




def request(**kwargs):
    """This function does send non-continuous traffic i,e requests
    Kwargs:
        :param kwargs: kwargs use to optional parameters to request traffic.
        :type kwargs: kwargs
    Returns:
        a traffic class object and request response output
    """
    vip_id = kwargs.pop('vip_id', 0)
    kwargs['vip_id'] = vip_id
    kwargs['mode'] = 'requests'
    stop_traffic = kwargs.pop('stop_traffic', True)
    skip_error = kwargs.pop('expect_error', False)

    traffic_obj = HTTPTraffic(**kwargs)
    output = traffic_obj.start_traffic()

    logger.info("Request Output: \n%s \n" % ''.join(output))

    traffic_obj.traffic_get_all_stats()

    if skip_error is False:
        err_output = traffic_obj.vm.execute_command("cat %s" % traffic_obj.log_file, log_error=False)
        if err_output:
            error(''.join(err_output))
    if stop_traffic:
        traffic_stop(traffic_obj)

    out = traffic_obj.parse_response(output)

    return traffic_obj, out

def traffic_start(**kwargs):
    """This function does send continuous traffic
    Kwargs:
        :param kwargs: kwargs use to optional parameters to send traffic.
        :type kwargs: kwargs
    Returns:
        a traffic class object
    """
    traffic_obj = HTTPTraffic(**kwargs)
    traffic_obj.start_traffic(background=True)

    return traffic_obj


def traffic_stop(traffic_obj=None, clear_logs=True, release_ips=True):
    """This function does stop traffic on client.

    Args:
    Kwargs:
        :param traffic_obj: The traffic_obj to use to call stop_traffic, default value is None.
        :type traffic_obj: class object
        :param clear_logs: Current clear_logs to be in, default value is True.
        :type clear_logs: boolean
        :param release_ips: Release ip address to clean up clients, default value is True.
        :type release_ips: boolean
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    if traffic_obj:
        traffic_obj.stop_traffic(clear_logs, release_ips)
    else:
        _stop_traffic_all(clear_logs)
        if release_ips:
            _clear_clients(client_handles=[])
def _stop_traffic_all(clear_logs=True):
    """ Stop Traffic on client for all flows """
    for client_vm in get_vm_of_type('client'):
        client_vm.execute_command('sudo pkill -9 -f ping', log_error=False)
        client_vm.execute_command('sudo pkill -9 -f httptest_v2.py', log_error=False)
        client_vm.execute_command('sudo pkill -9 -f snitest.py', log_error=False)
        if clear_logs:
            client_vm.execute_command('rm -rf /tmp/httptest*')
            client_vm.execute_command('rm -rf /tmp/snitest*')

    #Clean up SNI host names
    clear_sni_hostnames()

    for server_vm in get_vm_of_type('server'):
        server_vm.execute_command('rm -rf /usr/share/nginx/www/uploads/*')

def _clear_clients(vm=None, client_handles=None):
    """ Function clear clients i,e clear sub interfaces on client, release ip for network.

    Kwargs:
        :param vm: The vm to use to delete interface, app client for the same.
        :type vm: vm class  object
        :param client_handles: client handles to delete, default value is [].
        :type client_handles: list
    Returns:
        None
    """
    if not vm:
        vm = get_vm_of_type('client')[0]

    config = AviConfig.get_instance()
    mode = config.get_mode()
    site_name = mode['site_name']
    if not client_handles:
        client_handles = []
        for appclient in config.appclient.keys():
            if re.match("tsc\d+", appclient):
                client_handles.append(appclient)
    
    eth_infs = set()
    context_key = config.get_context_key()
    for handle in client_handles:
        for client in vm.app_clients.get(context_key,[]):
            if client.handle == handle:
                logger.info('Delete Client: %s , Eth details: %s:%s IP: %s ' % (handle, \
                            client.eth_int, client.eth_index, client.ip))
                config.testbed[site_name].networks[client.network].release_ip_for_network(client.ip)
                eth_infs.add(client.eth_int)
                ip_addr_idx = 0
                if type(ipaddress.ip_address(unicode(client.ip))) == ipaddress.IPv6Address:
                    ip_addr_idx = 1
                    vm.execute_command('ifconfig %s inet6 del %s/64'%(client.eth_int, client.ip), log_error=False)
                else:
                    vm.execute_command('ifconfig %s:%s down'%(client.eth_int, client.eth_index), log_error=False)
                for net_name, networks in vm.vm_info["networks"][ip_addr_idx].items():
                    logger.trace("netname: %s, networks: %s" % (net_name, networks))
                    if client.eth_int in networks:
                        # To handle in case of Baremetal Cloud to support inband mgmt
                        if int(client.eth_index) in networks[client.eth_int]['used_sub_ints']:
                            networks[client.eth_int]['used_sub_ints'].remove(int(client.eth_index))
                vm.app_clients[context_key].remove(client)
        del config.appclient[handle]

    vm.cloud_obj.add_remove_ip_rules(vm=vm, eth_infs=eth_infs)

def clear_sni_hostnames():
    """ Clear SNI host names on client  """
    for client_vm in get_vm_of_type('client'):
        client_vm.execute_command('mv /etc/hosts /etc/hosts.bak')
        client_vm.execute_command('sed /#snihost/d /etc/hosts.bak >> /etc/hosts')

def traffic_expect_errors(traffic_obj, vs_names=None, skip_vs_list=None, internal_traffic_check=True):
    """This function does expect traffic errors on provided vs names, if wont provide consider all vs names.
    Args:
        :param traffic_obj: The traffic_obj to use to call expect no errors func.
        :type traffic_obj: class object
    Kwargs:
        :param vs_names: Traffic errors expected vs_names.
        :type vs_names: list
        :param skip_vs_list: [ vs5,vs6]
                            check for traffic expect error on skip vs list,
                            check for traffic expect no errors on rest of all vs\
                            by remove/skip vs in sikp_vs_list
        :type skip_vs_list: list
        :param internal_traffic_check: internally will check for traffic expect no errors, default True
        :type internal_traffic_check: boolean
    Returns:
        None
    """
    vs_names = vs_names if vs_names else []
    traffic_obj.traffic_expect_errors(vs_names, skip_vs_list, internal_traffic_check)

def traffic_expect_no_errors(traffic_obj, vs_names=None, skip_vs_list=None, internal_traffic_check=True, threshold=5):
    """This function does expect traffic no errors on provided vs names, if wont provide consider all vs names.
    Args:
        :param traffic_obj: The traffic_obj to use to call expect no errors func.
        :type traffic_obj: class object
    Kwargs:
        :param vs_names: list of vs_names which expect no errors.
        :type vs_names: list
        :param skip_vs_list: [ vs5,vs6]
                            check for traffic expect error on skip vs list,
                            check for traffic expect no errors on rest of all vs\
                            by remove/skip vs in sikp_vs_list
        :type skip_vs_list: list
        :param internal_traffic_check: internally will check for traffic expect errors, default True
        :type internal_traffic_check: boolean
    Returns:
        None
    """
    vs_names = vs_names if vs_names else []
    traffic_obj.traffic_expect_no_errors(vs_names, skip_vs_list, internal_traffic_check, threshold=threshold)

def traffic_get_stats(traffic_obj):
    """This function does get all traffic stats
    Args:
        :param traffic_obj: The traffic_obj to use to call traffic get all starts.
        :type traffic_obj: class object
    Returns:
        None
    """
    traffic_stats = traffic_obj.traffic_get_all_stats()
    return traffic_stats

def create_clients(how_many, prefix, network='net', app_type='', vm_id=None, **kwargs):
    """This function does Create Client
    Args:
        :param how_many: Number of client want to create
        :type how_many: int
        :param prefix: prefix name to which want to create the handle
        :type prefix: str
        :param network: under which network want to create
        :type network: str
    Kwargs:
        :param app_type: what kind of application want to create
        :type app_type: str
        :param vm_id: vm_id is client name under which want to create
        :type vm_id: str
        :param kwargs: kwargs use to optional parameters to create client.
        :type kwargs: kwargs
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    start_idx = kwargs.get('start_idx', 1)
    if kwargs.get('ip'):
        r = kwargs.get('ip').split('-')
        ip_addrs = range(int(r[0]), int(r[1]) + 1) if (len(r) > 1) \
            else [kwargs.get('ip')]
        logger.trace('Client Ip Addresses:: %s' % ip_addrs)
    else:
        ip_addrs = [None] * int(how_many)

    vm = get_client_vm(vm_id, **kwargs)
    vm.create_client_context(how_many, network, prefix, app_type, ip_addrs, start_idx)
    vm.cloud_obj.add_remove_ip_rules(vm=vm)

def get_client_by_handle(handle):
    """This function does get client for given handle
    Args:
        :param handle: The handle to get the corresponding handle details.
        :type handle: str
    Returns:
        a client vm object and client vm subinterface ip
    Raises:
        ValueError, AttributeError, KeyError
    """
    logger.debug('handle: %s' % handle)
    config = AviConfig.get_instance()
    retval = config.appclient.get(handle)
    if retval:
        return retval
    else:
        raise Exception('Client handle "%s" does not exist' % handle)

def get_client_handles(client_range, conn_per_client):
    """This function does get the client handles for a given client range and connecetion per client.
    Args:
        :param client_range: The client_range use to get number of clients.
        :type client_range: str
        :param conn_per_client: no of connections per client.
        :type conn_per_client: int
    Returns:
        client_vm object
        list of client ips i,e sub interface ips.
    Raises:
        ValueError, AttributeError, KeyError
    """
    match = re.search('^(.+?)(\d+)(?:-(\d+))?$', client_range)
    end = None
    client_prefix = match.group(1)
    start = int(match.group(2))
    if match.group(3):
        end = int(match.group(3))

    logger.info("client_prefix: %s , start: %s " % (client_prefix, start))
    client_ips = []
    if end:
        for i in range(start, end + 1):
            client_vm, client_ip = get_client_by_handle(
                client_prefix + str(i))
            client_ips.extend([client_ip] * int(conn_per_client))
    else:
        try:
            client_vm, client_ip = get_client_by_handle(
                client_prefix + str(start))
            if not client_vm.check_if_ip_exists(client_ip):
                raise
        except Exception as e:
            logger.trace('got exp: %s' % str(e))
            # If client is not present, create one!
            create_clients(1, client_prefix, 'net', 'httptest')

            client_vm, client_ip = get_client_by_handle(
                client_prefix + str(start))

        client_ips.extend([client_ip] * int(conn_per_client))
    return client_vm, client_ips

def get_client_handles_from_range(client_range):
    """ Function gets individual client from client range
    Args:
        :param client_range: The client_range use to get number of clients.
        :type client_range: str
    Returns:
        client_handles as list, i,e [c1, c2, c3]
    Raises:
        ValueError, AttributeError, KeyError
    """
    match = re.search('^(.+?)(\d+)(?:-(\d+))?$', client_range)
    end = None
    client_prefix = match.group(1)
    start = int(match.group(2))
    if match.group(3):
        end = int(match.group(3))
    client_handles = []
    if end:
        for client in range(start, end + 1):
            client_handles.append("%s%s" % (client_prefix, client))
    else:
        client_handles.append("%s%s" % (client_prefix, start))
    return client_handles

def check_process_status(client_range='', process='httptest.py'):
    """This function does checks given process is running on client or not
    Kwargs:
        :param client_range: The client handle range to get the corresponding client vm details.
        :type client: str
        :param process: process name to check weather its running or not.
        :type process: str
    Returns:
        a boolean
        True - process is running
        False - process is not running
    """
    if not client_range:
        client_vm = get_vm_of_type('client')[0]
    else:
        client_vm, client_ips = get_client_handles(client_range, 1)
    retry = 4
    while retry:
        out = client_vm.execute_command(
            'ps -aef | grep %s | grep -v grep | wc -l' % process)
        logger.info('check_process_status: Process: %s ,No.of Process running:%s ' % (process, out[0]))
        if int(out[0]) != 0:
            return True
        else:
            retry -=1
    return False

# CURL Requests Related APIs
def start_curl(vs_name, vport, client_range='c1', uri='/', **kwargs):
    """This function does starts http curl traffic on range of clients specified in client_range.
    Args:
        :param vs_name: The vs_name use to Virtualservice to balance the traffic between backend servers.
        :type vs_name: str
        :param vport: The vport use listener port on virtual service.
        :type vport: str/int
    Kwargs:
        :param client: Number of clients for the the traffic generation, default value is 'c1'.
        :type client: str
        :param uri: URI of page to be requested uri in CURL request, default value is '/'.
        :type uri: str
        :param kwargs: kwargs use to optional parameters to start curl.
        :type kwargs: kwargs
            :param Forward_proxy: True if sending forward proxy traffic to the VIP.
            :type kwargs: boolean
            :param scheme: Scheme used to send forward proxy traffic.
            :type scheme: str
            :param host_fp: forward proxy host name
            :type host_fp: str
            :param host_port_fp: forward proxy host port
            :type host_port_fp: str
            :param options: CURL options
            :type options: str
            :param foreground: To run command in foreground. Default is False.
            :type foreground: boolean
    Returns:
        None
    """

    options = kwargs.get('options')
    Forward_proxy = kwargs.get('Forward_proxy')
    scheme = kwargs.get('scheme')
    host_fp = kwargs.get('host_fp')
    host_port_fp = kwargs.get('host_port_fp')
    foreground = kwargs.get('foreground', False)
    to_floating_vip = kwargs.pop('to_floating_vip', None)

    client_vm, client_ips = get_client_handles(client_range, 1)

    traffic_obj = HTTPTraffic(form_cmd=False, **kwargs)
    if to_floating_vip:
        vip = traffic_obj.get_floating_vip_from_vsname(vs_name)
    else:
        vip = traffic_obj.get_vs_vip(vs_name)[0]


    out = client_vm.execute_command('arp -a | grep %s' % vip, log_error=False)
    logger.debug('Arptable on client: %s' % out)
    time_stamp = time.strftime("%Y%m%d%H%M%S") + str(time.clock())
    if foreground:
        pre_cmd = ''
        post_cmd = ''
    else:
        pre_cmd = 'nohup '
        post_cmd = ' >& /dev/null < /dev/null &'

    for ip in client_ips:
        if Forward_proxy is None:
            if options is None:
                cmd = pre_cmd + 'curl --interface %s http://%s:%s%s' % (ip, vip, vport, uri) + post_cmd
            else:
                cmd = pre_cmd + 'curl --interface %s %s http://%s:%s%s' % (ip, options, vip, vport, uri) + post_cmd
        else:
            if options is None:
                cmd = pre_cmd + 'curl --interface %s -x %s:%s %s://%s:%s/%s' % (ip, vip, vport, scheme, host_fp, host_port_fp, uri) + post_cmd
            else:
                cmd = pre_cmd + 'curl --interface %s %s -x %s:%s %s://%s:%s/%s' % (ip, options, vip, vport, scheme, host_fp, host_port_fp, uri) + post_cmd
        logger.info("CURL cmd: %s "% cmd)
        out = client_vm.execute_command(cmd)

    #TBD: This check is not efficient, have to capture nohup.out and verify it or some other way - in progress
    #if not check_process_status(process='curl'):
    #    error(" CURL Traffic not started please checek the logs")
    return

def stop_curl(client_range=''):
    """ Stop CURL
    kwrgs:
        :param client: Client from which the script needs to be executed, default value is ''.
        :type client: str
    """
    if not client_range:
        client_vm = get_vm_of_type('client')[0]
    else:
        client_vm, client_ips = get_client_handles(client_range, 1)
    client_vm.execute_command('pkill -9 curl', log_error=False)


# Openssl Related APIs
def s_client_connect(vs_name, vport, client='c1', **kwargs):
    """This function does Connects to given VIP using openssl s_client library
    Args:
        :param vs_name: The vs_name use to which vs to connect using openssl.
        :type vs_name: str
        :param vport: The vport to use on which port to connect.
        :type vport: str/int
    Kwargs:
        :param client: Client from which the script needs to be executed, default value is 'c1'.
        :type client: str
        :param kwargs: kwargs use to optional parameters to openssl s_client.
        :type kwargs: kwargs
    Returns:
        a string of open ssl connect output.
    """
    ip_as_name = kwargs.pop('ip_as_name', 'false')
    if ip_as_name.lower() == 'true':
        ip_as_name = True
    else:
        ip_as_name = False

    if ip_as_name:
        vip = vs_name
    else:
        traffic_obj = HTTPTraffic(form_cmd=False, **kwargs)
        vip = traffic_obj.get_vs_vip(vs_name)[0]

    vport = int(vport)
    client, ip = get_client_handles(client, 1)

    cmd = 'openssl s_client -connect %s:%s' % (vip, vport)
    for k, v in kwargs.iteritems():
        cmd = cmd + ' -%s %s' % (k, v)
    cmd = cmd + ' < /dev/null'
    logger.info('s_client_connect cmd: %s' % cmd)

    response = client.execute_command(cmd)
    logger.info('output: %s' % response)

    return parse_s_client_output(response)

def s_client_connect_request(vs_name, vport, request, client='default1', **kwargs):
    """This function does Connects to given VIP using openssl s_client library and sends http request.
    Args:
        :param vs_name: The vs_name to take Virtual service name.
        :type vs_name: str
        :param vport: The vport to take Virtual service port.
        :type vport: str
        :param request: The request use to Request to send to VS.
        :type request: str
    Kwargs:
        :param client: Current client to be in, default value is 'default1'.
        :type client: str
        :param kwargs: kwargs use to optional parameters to openssl s_client.
        :type kwargs: kwargs
    Returns:
        a string of open ssl http request output.
    """
    ip_as_name = kwargs.pop('ip_as_name', 'false')
    if ip_as_name.lower() == 'true':
        ip_as_name = True
    else:
        ip_as_name = False

    if ip_as_name:
        vip = vs_name
    else:
        traffic_obj = HTTPTraffic(form_cmd=False, **kwargs)
        vip = traffic_obj.get_vs_vip(vs_name)[0]

    vport = int(vport)
    client, ip = config.get_client_by_handle(client)

    cmd = 'echo -e \"%s\" | openssl s_client -connect %s:%s -ign_eof' % (request, vip, vport)
    for k, v in kwargs.iteritems():
        cmd = cmd + ' -%s %s' % (k, v)
    cmd = cmd + ' < /dev/null'
    logger.info('s_client_connect cmd: %s' % cmd)

    response = client.execute_command(cmd)
    logger.info('output: %s' % response)

    return parse_s_client_output(response)

def parse_s_client_output(response):
    """This function does Parse openssl output
    Args:
        :param response: The response to use take open ssl output.
        :type response: str
    Returns:
        a string contains parsed output of the Open ssl traffic
    Raises:
        ValueError, KeyError
    """
    valid_keys = ['Protocol', 'Cipher', 'Session-ID',
                  'TLS session ticket lifetime hint',
                  'TLS session ticket',
                  'Master-Key', 'Compression', 'Expansion',
                  'Start Time', 'Timeout', 'Verify return code',
                  'PSK identity', 'PSK identity hint', 'SRP username',
                  'Key-Arg']

    is_matching = any(s for s in response if "CONNECTED" in s)
    if not is_matching:
        return False
    ret = {'status': 'connected'}
    #Temporary fix. Defination not found for retrieve_cert
    #ret['cert'] = retrieve_cert(response)
    for substr in response:
        kv = substr.split(':')
        if len(kv) == 2:
            key = kv[0].strip()
            if key in valid_keys:
                key = key.lower()
                ret[key] = kv[1].strip().replace('\n', '')
    logger.info('Parse s_client_output, return dict:\n%s'%ret)
    return ret

def setup_hostnames(vs_name):
    """This function does setup host names on client
    Args:
        :param vs_name: The vs_name to use setup host name on Client.
        :type vs_name: str
    """
    traffic_obj = HTTPTraffic(form_cmd=False, **kwargs)
    vips = traffic_obj.get_vs_vip(vs_name)

    for client_vm in config.cloud.get_vm_of_type('client'):
        for vip in vips:
            client_vm.setup_hostname(vip)
        client_vm.service_restart('hostname')

def run_webreplay(vs_name, vport, client_range='w1'):
    """This function does start the web replay traffic on client.
    Args:
        :param vs_name: The vs_name to use pass virtual services name.
        :type vs_name: str
        :param vport: The vport to use pass virtual services port.
        :type vport: str
    Kwargs:
        :param client_range: Current client_range to be in, default value is 'w1'.
        :type client_range: str
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    vip = config.get_vip(vs_name)
    proto = get_protocol(vs_name, vport)
    url = proto + vip + ':' + str(vport)

    client_vm, client_ips = get_client_handles(client_range, 1)
    cmd = '/usr/local/bin/httparchive play /var/www/archive.wpr --host=' + url
    out = client_vm.execute_command(cmd, False)

    logger.info("webreplay cmd: %s" % cmd)
    logger.info("webreplay output: %s" % out)

    return out[0]

#def post_file_upload(client, vs, vport, uri, s, ifile, form, compare_file, chunking, headers=None):
def post_file_upload(vs, vport, uri, s, ifile, form, compare_file, chunking, headers=None):
    client_vm = get_vm_of_type('client')[0]

    status_code, data = get('virtualservice', name=vs)
    vip = data['vip'][0]['ip_address']['addr']
    logger.debug('vip %s' %vip)

    proto = 'http'
    if vport == 443:
        proto = 'https'
    cmd = 'curl -w "%{http_code}" -s -o /dev/null -k '
    cmd = cmd + ' ' + proto + '://'
    cmd = cmd + vip + ':' + str(vport) + '/'
    cmd = cmd + uri

    if form == 'yes':
        cmd = cmd + " --form  'userfile=@" + \
              '/mnt/this_is_obfuscated_uploads/pybot/functional/' + ifile + "'"
    else:
        cmd = cmd + '?filename=' + ifile + " --data-binary  '@" + \
              '/mnt/this_is_obfuscated_uploads/pybot/functional/' + ifile + "'"

    if chunking == 'yes':
        cmd = cmd + " --header \"Transfer-Encoding: chunked\" "

    if headers:
        cmd = cmd + " --header " + '"' + headers + '"'

    logger.debug(cmd)
    resp = client_vm.execute_command(cmd)
    if resp[0] != str(s):
        fail('Post Request Failed. Received=%s, Expected=%s' %(resp[0], s))

    if compare_file != 'yes':
        return

    #download the file
    cmd = 'curl -w "%{http_code}" -s -k '
    cmd = cmd + ' ' + proto + '://'
    cmd = cmd + vip + ':' + str(vport) + '/uploads/' + ifile + ' -o /tmp/download'
    if headers:
        cmd = cmd + " --header " + '"' + headers + '"'
    print cmd
    resp = client_vm.execute_command(cmd)
    print 'resp %s' %resp
    if resp[0] != str(s):
        fail('Get Request Failed.Received=%s, Expected=%s' %(resp[0], s))

    cmd = 'diff /tmp/download ' + \
          '/mnt/this_is_obfuscated_uploads/pybot/functional/' + ifile
    resp = client_vm.execute_command(cmd)
    if resp:
         fail('Input and uploaded file differ')

def traffic_should_be_running(traffic_obj, vs_names=[]):
    """This function checks traffic is running or not on given Virtual Services.
    Args:
        :param traffic_obj: The traffic_obj to use to call expect no errors func.
        :type traffic_obj: class object
    Kwargs:
        :param vs_names: Current vs_names to be in, default value is [].
        :type vs_names: list
    Returns:
        None
    """
    traffic_obj.traffic_should_be_running(vs_names=vs_names)


def get_kwargs_for_request(method, vs_names, vport, uris, status_code,
                           headers=None, body_contains=None, files=None, no_of_req_per_conn=None,
                           stop_on_failure=None, concurrent_conn_per_client=None,
                           client_range=None):
    req_args = {}
    req_args['method'] = method
    req_args['vs_names'] = vs_names
    req_args['vport'] = vport
    req_args['uri'] = uris
    req_args['status_code'] = status_code
    if body_contains:
        req_args['body_contains'] = body_contains
    if headers:
        req_args['headers'] = headers
    if files:
        req_args['files'] = files
    if no_of_req_per_conn:
        req_args['no_of_req_per_conn'] = no_of_req_per_conn
    if stop_on_failure:
        req_args['stop_on_failure'] = stop_on_failure
    if concurrent_conn_per_client:
        req_args['concurrent_conn_per_client'] = concurrent_conn_per_client
    if client_range:
        req_args['client_range'] = client_range

    return req_args
    

if __name__ == "__main__":
    """ Helps to test stand alone it self"""
    #traffic_obj=HTTPTraffic()
    #traffic_obj.start_traffic()
    #traffic_obj.stop_traffic()
    pass
