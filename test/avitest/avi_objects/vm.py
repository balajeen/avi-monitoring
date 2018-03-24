"""
    Module defines all VM objects defined in the test infrastructure.
"""

import paramiko
import re
import socket
import ipaddress
import struct
import random
import os
import datetime
import subprocess
import yaml
from socket import error as socket_error
import common_utils
import StringIO

from logger import logger, ErrorError, FailError
from suite_vars import suite_vars
from logger_utils import error, fail, asleep, aretry
import string


class Vm(object):
    """
        Base class for vm
    """

    def __init__(self, **kwargs):

        # VM config

        self.ip = kwargs.get('ip', '')
        self.port = int(kwargs.get('port', 22))
        self.user = kwargs.get('user', 'root')
        self.password = kwargs.get('password', 'avi123')
        self.type = kwargs.get('type', None)
        self.name = kwargs.get('name', '')
        self.child = None
        self.key_filename = kwargs.get('key_filename', None)
        self.networks = kwargs.get('networks', None)
        # Connection details
        self.ssh_timeout = kwargs.get('ssh_timeout', 60)
        self.api_port = kwargs.get('api_port', 443)
        self.processes = {}
        self.vm_info = {"networks": [{}, {}]}
        # Set deployment/platform
        self.deployment = kwargs.get('deployment', None)
        self.platform = kwargs.get('platform', None)
        self._cloud_obj = None
        self.cloud_name = kwargs.get('cloud_name', 'Default-Cloud')

        if not self.ip:
            vm_cloud_sdk_conn = kwargs.get('vm_cloud_sdk_conn', None)
            if not vm_cloud_sdk_conn:
                fail("can't resolve ip of the vm: %s sdk none, can't determine cloud for the vm", self.name)
            try:
                self.ip = vm_cloud_sdk_conn.get_vm_ip_for_name()
            except Exception as e:
                logger.warning("Could not find a VM: Exp: %s", e.message)
                return None
            logger.info('Find ip: vm name %s ip %s', self.name, self.ip)
            vm_cloud_sdk_conn.disconnect()

        if not self.ip:
            fail('can not determine ip for %s' %self.name)

    @property
    def cloud_obj(self):
        if self._cloud_obj == None:
            from avi_config import AviConfig
            config = AviConfig.get_instance()
            cloud_name = self.cloud_name
            mode = config.get_mode()
            site_name = mode['site_name']
            self._cloud_obj = config.testbed[site_name].cloud_obj[cloud_name]
        return self._cloud_obj

    def get_all_interfaces(self):
        """ Returns list of all interfaces (Does not include eth0)
        """
        # TBD: Do we need to store interface information or dynamically get
        for network in self.vm_info["networks"][0]:
            all_intf = self.vm_info["networks"][0][network].copy()
        for network in self.vm_info["networks"][1]:
            all_intf.update(self.vm_info["networks"][1][network].copy())
        return all_intf.keys()

    def get_all_networks(self):
        """ Returns list of all networks (Does not include eth0)
        """
        # TBD: Do we need to store interface information or dynamically get
        all_intf = self.vm_info["networks"][0].copy()
        all_intf.update(self.vm_info["networks"][1].copy())
        return all_intf.keys()

    def check_if_ip_exists(self, ip):
        check_str_cmd = "ifconfig -a|grep '" + ip + " '"
        out = self.execute_command(check_str_cmd, log_error=False)
        if len(out) == 0:
            return False
        return True

    def connect(self, **kwargs):
        """ Connect to VM using SSH paramiko """

        user = kwargs.get('user', self.user)
        passwd = kwargs.get('password', self.password)
        key_filename = kwargs.get('key_filename', self.key_filename)
        logger.debug('Spawn SSH: %s:%s %s %s' % (self.ip, self.port, user, passwd))
        self.child = paramiko.SSHClient()
        self.child.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        if key_filename:
            pkey = paramiko.RSAKey.from_private_key_file(key_filename)
            try:
                if isinstance(self.child, paramiko.client.SSHClient):
                    self.child.close()
            except Exception as e:
                pass
            self.child = paramiko.SSHClient()
            self.child.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logger.debug('Spawn SSH: %s:%s %s %s' % (self.ip, self.port, user, key_filename))
            try:
                self.child.connect(self.ip, self.port, username=user,
                                   pkey=pkey, timeout=self.ssh_timeout)
            except socket_error as serr:
                fail(serr)
        else:
            try:
                self.child.connect(self.ip, self.port, username=user,
                                   password=passwd, timeout=self.ssh_timeout)
            except socket_error as serr:
                fail(serr)
        self.child.get_transport().window_size = 3 * 1024 * 1024
        return self.child

    def disconnect(self):
        """ Disconnect from SSH paramiko connection """
        self.child.close()
        logger.debug('closing ssh connection on vm %s, %s' % (
            self.ip, self.name))

    def execute_command(self, cmd, log_error=True, **kwargs):
        """ Runs given command on VM
            Arguments:
                cmd         User given command
                log_error       Don't raise any exception even when there are
                            errors on stderr
        """
        __tracebackhide__ = True
        err = None

        username = kwargs.get('username', self.user)
        password = kwargs.get('password', self.password)
        key_filename = kwargs.get('key_filename', self.key_filename)
        log_response = kwargs.get('log_response', True)
        skip_output = kwargs.get('skip_output', False)
        sudoless = kwargs.get('sudoless', False)
        background = kwargs.get('background', False)
        host = kwargs.get('host', False)
        sudoenv = ''
        usesudo = kwargs.get('usesudo', True)
        if ((not 'cd ' in cmd) and usesudo):
            cmd = 'sudo ' + sudoenv + cmd
        if background:
            cmd = cmd.replace('sudo', "sudo -b")
        logger.debug('[%s, %s] CMD:: %s' % (self.ip, self.name, cmd))

        # if vm is in docker mode
        if self.deployment == str('docker'):
            if not host:
                cmd = (
                          'export UPSTART_SESSION="unix:abstract=/com/ubuntu/upstart-session/0/1"; '
                          if kwargs.get('upstart_session', False) else '') + cmd
                filter_command = kwargs.get('filter_command', '')
                keyword = self.type + ":"
                basecmd = " docker exec $(docker ps | grep %s | awk '{print $1}') " % (keyword)
                logger.info('command is %s' % (cmd))
                exec_cmd = basecmd + " /bin/bash -c \'" + cmd + "\'"
                if filter_command:
                    exec_cmd = exec_cmd + filter_command
                cmd = exec_cmd
                logger.info('%s [%s] docker Executing cmd %s' % (self.ip, self.name, cmd))
            username = kwargs.get('username', 'root')
            password = kwargs.get('password', self.password)

        child = self.child
        if username and password and not self.child:
            child = self.connect(user=username, password=password,
                                 key_filename=key_filename)
        if not sudoless and self.type in ['se', 'controller'] and re.search(r'^sudo', cmd):
            basecmd = "echo '" + password + "'| "
            cmd = cmd.replace('sudo', 'sudo -S -p ""')
            cmd = basecmd + cmd
        try:
            chan = self.child._transport.open_session()
        except Exception:
            try:
                # If we have a stale connection because of a reboot, re-connect
                # and open a new session.
                child = self.connect(user=username, password=password,
                                     key_filename=key_filename)

            except Exception:
                raise
            chan = child._transport.open_session()

        chan.exec_command(cmd)
        if skip_output:
            return None
        stdout = chan.makefile('rb', -1)
        stderr = chan.makefile_stderr('rb', -1)
        err = chan.recv_exit_status()
        # chan.close()
        out = stdout.readlines()
        if out:
            logger.debug('CMD out:: %s' % out)
        error_msg = stderr.readlines()

        if err:
            logger.debug("Status %d - command %s on %s" % (err, cmd, self.ip))
            # We need to return the error output so that caller can parse
            # it and decide to proceed further or raise an exception to stop.
            # return stderr.readlines()

        if len(error_msg) and re.search('sudo: no tty present and no askpass program specified', str(error_msg[0])):
            fail('You may have to remove --sudoless option')
        else:
            pass
        if error_msg and log_response:
            logger.debug("[%s, %s] Error: %s" % (
                self.ip, self.name, str(error_msg)))
        if err and log_error:
            fail(
                '\nERROR! Command failed on %s: %s - %s' % (
                    self.ip, cmd, error_msg))
        return out

    def reboot(self, force=False, wait_and_verify=True):
        cmd = "reboot"
        if force:
            cmd = cmd + ' -f'
        self.execute_command(cmd, skip_output=True)
        if wait_and_verify:
            asleep("Rebooting...", delay=60, period=15)
            out = self.execute_command('uptime')
            match = re.search('up\s+(\d+)\s+min', str(out))
            if match:
                up_time = match.group(1)
                if int(up_time) > 2:
                    fail("Uptime is greater than expected 2 min. uptime = %s" % up_time)
            else:
                fail("Could not match expected uptime. Received= %s" % out)
        logger.info('reboot vm %s DONE' % self.ip)

    def verify_error_execute_command(self, out, error_type='default'):
        err = 0
        error_msg = []
        for each_reg in error_regexp[error_type]:
            match = re.search(each_reg, str(out))
            if match:
                err = 1
                error_msg = out
                break
        return err, error_msg

    def scp_file(self, local_path, remote_path, method='put', **kwargs):
        """ SCP file from one source to destination VM"""

        uname = kwargs.get('username', self.user)
        passwd = kwargs.get('password', self.password)
        logger.debug('scp %s, %s, %s, %s, %s' % (self.ip, local_path, remote_path, uname, passwd))
        logger.debug('pkey %s' % self.key_filename)

        ssh = paramiko.SSHClient()

        if self.key_filename:
            pkey = paramiko.RSAKey.from_private_key_file(self.key_filename)
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(self.ip, self.port, username=self.user, pkey=pkey, timeout=self.ssh_timeout)
            except socket_error as serr:
                fail("Failed to do ssh to %s with %s" % (self.ip, serr))
        else:
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh.connect(self.ip, self.port, uname, passwd)
            except paramiko.SSHException:
                try:
                    ssh.connect(self.ip, self.port, username=self.user, password='avi123')
                except paramiko.SSHException:
                    try:
                        ssh.connect(self.ip, self.port, username=self.user, password='admin')
                    except paramiko.SSHException:
                        fail("Failed to do ssh to %s" % (self.ip))

        try:
            sftp = ssh.open_sftp()
            if method == 'put':
                sftp.put(local_path, remote_path)
            else:
                sftp.get(local_path, remote_path)
            ssh.close()
        except Exception as e:
            fail("Failed to scp file with error message %s" % e)

    def scp_file_get(self, local_path, remote_path, **kwargs):
        """ SCP file from one source to destination VM"""
        self.scp_file(local_path, remote_path, method='get', **kwargs)

    def set_time(self, new_time):
        """ Set time on VM """
        logger.debug('Setting time: %s', new_time)
        self.execute_command('date +%%T -s "%s"' % new_time)
        return

    def setup_hostname(self, hostname=None):
        """ Setup hostname on VM"""
        if hostname is None:
            hostname = self.name
        self.execute_command("sudo sh -c 'echo '%s' > /etc/hostname'" % hostname)

        hostname_full = '%s.avi.local' % hostname
        self.execute_command(
            'sudo sh -c "sed -i \"/%s/d\" /etc/hosts"' % hostname_full)
        self.execute_command(
            'sudo sh -c "echo 127.0.0.1   %s  %s >> /etc/hosts"'
            % (hostname_full, hostname))
        self.execute_command('sudo hostname %s' % hostname)

    def used_disk_space(self, fs_type='ext4', format='percent'):
        """ Returns used disk space on VM (default format is in percentage) """

        cmd = 'df --type %s --print-type' % (fs_type)
        out = self.execute_command(cmd)
        match = re.search(r'([\d]+)%', out[1])
        if match:
            return match.group(1)
        fail('No output could not be parsed for disk space: %s' % out)

    def get_cpu_use(self):
        """ Get current CPU utilization of VM"""

        cmd = 'python -c "import psutil; print psutil.cpu_percent(interval=5)"'
        out = self.execute_command(cmd)
        match = re.search(r'([\d\.]+)', out[0])
        if match:
            return match.group(1)
        fail('Unexpected output for get_cpu_use: %s' % (out))

    def start_cpu_use(self):
        """ Consume CPU """
        cmd = 'dd if=/dev/zero of=/dev/null &'
        self.execute_command(cmd)

    def stop_cpu_use(self):
        """ Stop CPU consumption """
        cmd = 'killall -9 dd'
        self.execute_command(cmd)

    def get_memory_info(self):
        """ Return memory information for a VM """

        cmd = 'free -m'
        out = self.execute_command(cmd)
        match = re.search(
            r'Mem:[ ]+([\d]+)[ ]+([\d]+)[ ]+([\d]+)[ ]+([\d]+)[ ]+' +
            r'([\d]+)[ ]+([\d]+)', out[1])
        if match:
            mem_dic = {
                'total': int(match.group(1)),
                'used': int(match.group(2)),
                'free': int(match.group(3)),
                'buffers': int(match.group(5)),
                'cached': int(match.group(6)),
            }
            mem_dic['actual_free'] = mem_dic['free'] + mem_dic['buffers'] + \
                                     mem_dic['cached']
            mem_dic['percent_used'] = round((float(mem_dic['total']) -
                                             float(mem_dic['actual_free'])) /
                                            float(mem_dic['total']) * 100)
            return mem_dic
        fail('Unexpected output for get_cpu_use: %s' % (out))

    def use_memory(self, how_long, how_much=512000000):
        """ Start consuming lot of memory """

        cmd = 'python -c "import time;s=%s*%s;time.sleep(%s)" &> /tmp/use_mem &' \
              % ("' '", how_much, how_long)
        out = self.execute_command(cmd)
        logger.debug('use_memory out: %s' % out)

    def read_file(self, file_path, retries=5):
        """ Read file on VM """

        @aretry(retry=retries, delay=30, period=10)
        def read_file_with_retry():
            try:
                resp = ''.join(self.execute_command('cat %s' % file_path))
                return resp
            except (Exception, SystemExit) as ex:
                fail('read_file fail with Exception in command: %s' % ex)

        return read_file_with_retry()

    def write_file(self, file_path, content_str):
        """ Write contents to file on VM """
        self.execute_command('cat "%s" > %s' % (content_str, file_path))

    def create_file_of_size(self, name, size):
        """ Create file """
        cmd = 'fallocate -l %s /tmp/%s' % (size, name)
        self.execute_command(cmd)

    def remove_tmp_file(self, name):
        """ Remove tmp file """
        cmd = 'rm /tmp/%s' % (name)
        self.execute_command(cmd)

    def cleanup(self):
        """ Cleanup tmp directory on vm """
        cmd = 'rm -rf /tmp/*'
        self.execute_command(cmd)

    def upstart_job_running(self, name):
        """ Check if upstart job is running or not """

        try:
            if ':' in name:
                service, instance = name.split(':')
                output = self.execute_command(
                    'status %s INSTANCE=%s' % (service, instance))
            else:
                output = self.execute_command('status %s' % name)
        except (ErrorError, FailError):
            return False
        logger.info('status of upstart job %s is %s' % (name, output))
        return 'start/running' in string.join(output, '\n')

    def start_upstart_job(self, name):
        """ Start upstart job """
        output = self.execute_command('start %s' % name)
        return 'start/running' in string.join(output, '\n')

    def stop_upstart_job(self, name):
        """ Stop upstart job """
        if self.upstart_job_running(name):
            output = self.execute_command('stop %s' % name)
            return 'stop/waiting' in string.join(output, '\n')
        return True

    def service_stop(self, service_name, log_error=True):
        """ Stop service """

        cmd = 'service %s stop' % service_name
        out = self.execute_command(cmd, log_error=log_error)
        logger.debug('service stop: cmd: %s out: %s ' % (cmd, out))

        if service_name == 'networking':
            if not re.search(r'networking stop/waiting', "".join(out)):
                fail('ERROR! service networking has not started!!!')

        if service_name == 'nginx':
            if re.search(r'already in use', "".join(out), re.IGNORECASE):
                netstat_out = self.execute_command('netstat -plan')
                logger.debug('netstat -plan. out: %s ' % (netstat_out))
                nginx_conf_status = self.execute_command('nginx -t')
                logger.debug('nginx configuration status:\n %s ' % (nginx_conf_status))
                fail('ERROR! service ngix restart failed, %s' % out)

    def service_start(self, service_name):
        """ Start a service """

        cmd = 'service %s start' % service_name
        out = self.execute_command(cmd)
        logger.debug('service_start: cmd: %s out: %s ' % (cmd, out))

        if service_name == 'networking':
            if not re.search(r'networking start/running', "".join(out)):
                fail('ERROR! service networking has not started!!!')
        if service_name == 'nginx':
            if re.search(r'already in use', "".join(out), re.IGNORECASE):
                netstat_out = self.execute_command('netstat -plan')
                logger.debug('netstat -plan. out: %s ' % (netstat_out))
                nginx_conf_status = self.execute_command('nginx -t')
                logger.debug('nginx configuration status:\n %s ' % (nginx_conf_status))
                fail('ERROR! service ngix restart failed, %s' % out)

    def service_restart(self, service_name):
        """ Restart a service """

        cmd = 'service %s restart' % service_name
        out = self.execute_command(cmd)
        logger.debug('service_restart: cmd: %s out: %s ' % (cmd, out))

        if service_name == 'networking':
            stop = re.search(r'networking stop/waiting', "".join(out))
            start = re.search(r'networking start/running', "".join(out))
            if not stop or not start:
                fail('ERROR! service networking has not started!!!')

        if service_name == 'nginx':
            match1 = re.search(r'already in use', "".join(out), re.IGNORECASE)
            match2 = re.search(r'fail', "".join(out), re.IGNORECASE)
            match3 = re.search(r'Unknown instance', "".join(out), re.IGNORECASE)
            if match1 or match2 or match3:
                netstat_out = self.execute_command('netstat -plan')
                logger.debug('netstat -plan. out: %s ' % (netstat_out))
                nginx_conf_status = self.execute_command('nginx -t')
                logger.debug('nginx configuration status:\n %s ' % (nginx_conf_status))
                fail('ERROR! service ngix restart failed, %s' % out)

    def block_port(self, port):
        """ Block port on VM
        :param start: starting port
        :param end: end port
        """
        self.execute_command('iptables -A INPUT -p tcp --destination-port %s '
                             '-j DROP' % port)
        self.execute_command('iptables -A OUTPUT -p tcp --destination-port %s '
                             '-j DROP' % port)

    def block_port_range(self, start, end):
        """ Block port range on VM
        :param start: starting port
        :param end: end port
        """
        self.execute_command('iptables -A INPUT -p tcp --dport %s:%s -j DROP' %
                             (start, end))
        self.execute_command('iptables -A OUTPUT -p tcp --dport %s:%s -j DROP' %
                             (start, end))

    def rate_limit_traffic(self, rate, interface='eth0'):
        """ Rate limits all outgoing traffic from this vm.
        :param rate: the rate limit in mbps (as an integer)
        :param interface: name of interface to rate limit
        """
        self.execute_command('tc qdisc del dev %s root' % interface)
        self.execute_command('tc qdisc add dev %s root handle 1: cbq avpkt '
                             '1000 bandwidth %dmbit' % (interface, rate))
        self.execute_command('tc class add dev %s parent 1: classid 1:1 cbq '
                             'rate 256kbit allot 1500 prio 5 bounded isolated' % interface)
        self.execute_command('tc filter add dev %s parent 1: protocol ip prio '
                             '16 u32 match ip src X.X.X.X flowid 1:1' % interface)
        self.execute_command('tc qdisc add dev %s parent 1:1 sfq perturb 10' %
                             interface)

    def clear_rate_limit(self, interface='eth0'):
        """ Clear ratelimit set on VM
        :param interface: interface on vm to run tc disc
        """
        self.execute_command('tc qdisc del dev %s root' % interface)

    def flush_arp_cache_entries(self):
        """ Flush ARP cache entries on linux
        """
        for eth in self.get_all_interfaces():
            cmd = 'ip neigh flush dev ' + eth
            logger.debug('flush_arp_cache_entries')
            self.execute_command(cmd)
        self.execute_command('arp -n')

    def clear_tcpdump(self):
        """ Cleanup tcptump files """
        self.execute_command('rm -rf /tmp/dump.pcap')
        self.execute_command('rm -rf /root/tcptest*')
        self.execute_command('killall -9 tcpdump')

    def get_eth_ip_intf_details(self):
        '''
        Method helps to know what are all ips associated with sub/main interface
        *** Returns ***:
           - Dict look like { ip : eth name }
        '''
        intf_dict = {}
        output = self.execute_command("ip a | grep \"global\"")
        for line in output:
            line_l = line.split()
            ip, mask = line_l[1].split("/")
            eth = line_l[-1]
            intf_dict[ip] = eth
        return intf_dict


class ProductVm(Vm):
    """ Common functions inherited by both client and servers """

    def __init__(self, **kwargs):
        vm_json = kwargs.pop('vm_json', {})
        kwargs.update(vm_json)
        Vm.__init__(self, **kwargs)
        self.latest_core = None
        self.user = kwargs.get('user','admin')
        workspace = suite_vars.workspace
        key_filename = workspace + \
                       '/test/robot/new/lib/tools/id_sysadmin'
        self.key_filename = kwargs.get('key_filename', key_filename)
        if 'key_filename' not in kwargs:
            kwargs['key_filename'] = self.key_filename

    def version(self):
        """ Return version running on system """
        txt = string.join(self.execute_command('cat /bootstrap/VERSION'), '')
        obj = yaml.load(txt)
        return "%s %s" % (obj['Version'], obj['Date'])

    def get_version_tag(self):
        """ Return version with build running on system """
        txt = string.join(self.execute_command('cat /bootstrap/VERSION'), '')
        obj = yaml.load(txt)
        return "%s " % (obj['Tag'])

    def connect(self, **kwargs):
        """ Connect to VM using SSH paramiko """

        user = kwargs.get('user', self.user)
        key_filename = kwargs.get('key_filename', self.key_filename)
        try:
            pkey = paramiko.RSAKey.from_private_key_file(key_filename)
        except IOError:
            pkey = None
        try:
            if isinstance(self.child, paramiko.client.SSHClient):
                self.child.close()
        except Exception as e:
            pass
        self.child = paramiko.SSHClient()
        self.child.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        logger.debug('Spawn SSH: %s:%s %s %s %s' % (self.ip, self.port, user, self.password, key_filename))
        try:
            self.child.connect(self.ip, self.port, username=user, password=self.password,
                               pkey=pkey, timeout=self.ssh_timeout)
        except socket_error as serr:
            fail(serr)
        self.child.get_transport().window_size = 3 * 1024 * 1024
        return self.child

    def scp_file(self, local_path, remote_path, method='put', **kwargs):
        """ SCP file from one source to destination VM"""

        uname = kwargs.get('username', self.user)
        passwd = kwargs.get('password', self.password)
        logger.debug('scp %s, %s, %s, %s, %s' % (self.ip, local_path, remote_path, uname, passwd))
        logger.debug('pkey %s' % self.key_filename)

        ssh = paramiko.SSHClient()
        pkey = paramiko.RSAKey.from_private_key_file(self.key_filename)
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(self.ip, self.port, uname, passwd)
        except paramiko.SSHException:
            try:
                ssh.connect(self.ip, self.port, username=self.user, pkey=pkey, timeout=self.ssh_timeout)
            except socket_error as serr:
                fail(serr)
            except paramiko.SSHException:
                try:
                    ssh.connect(self.ip, self.port, username=self.user, password='avi123')
                except paramiko.SSHException:
                    try:
                        ssh.connect(self.ip, self.port, username=self.user, password='admin')
                    except paramiko.SSHException:
                        fail("Failed to do ssh to %s" % (self.ip))

        try:
            sftp = ssh.open_sftp()
            if method == 'put':
                sftp.put(local_path, remote_path)
            else:
                sftp.get(local_path, remote_path)
            ssh.close()
        except Exception as e:
            fail("Failed to scp file with error message %s" % e)


class TestVm(Vm):
    """ Common functions inherited by both client and servers """

    def __init__(self, apps, **kwargs):
        vm_json = kwargs.pop('vm_json', {})
        kwargs.update(vm_json)
        Vm.__init__(self, **kwargs)
        self.networks_detail = kwargs.pop('networks_detail', {})
        self.apps = apps
        self.max_sub_ints = 1000
        self.tc_root = 0
        self.populate_interface_info()

    @staticmethod
    def __find_network_for_addr(addr, networks):
        """ Returns a network name given address
            :param :addr    Ip address of the VM
            :param :networks List of networks
        """
        logger.debug('find_network_for_addr: addr [%s]' % addr)
        net_netmask = []
        for net, net_obj in networks.items():
            subnet = str(net_obj.ip_addr) + '/' + str(net_obj.mask)
            logger.debug(
                "Net: %s, subnet: %s" % (net, subnet))
            if ipaddress.ip_address(unicode(addr)) in ipaddress.ip_network(unicode(subnet)):
                # return net
                logger.debug('ip %s is in subnet %s' % (addr, subnet))
                net_netmask.append(net)

        if len(net_netmask):
            logger.debug('network for addr %s is %s' % (addr, net_netmask))
            return net_netmask
        else:
            return False

    def populate_interface_info(self):
        """ Builds interface: network mapping dictionary. """

        if not self.networks:
            logger.info("No networks specified. Return")
            return

        out = self.execute_command("ifconfig -a")
        eth_int = ''
        logger.trace('Captured Output \n %s' % ''.join(out))
        for line in out:
            # Find interface name
            match = re.search(
                r"(\S+)\s+Link encap.*\s((?:[\da-f]{2}[:-]){5}[\da-f]{2})",
                line)
            if match:
                eth_int = str(match.group(1))
                eth_addr = ''
                mac_addr = str(match.group(2))
                continue

            if ":" in eth_int or "lo" in eth_int:
                logger.debug('Found sub or lo interface, continue')
                eth_int = ''
                continue
            if eth_int:
                # Find the IP address
                match = re.search(
                    r'inet addr:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', line)
                if match:
                    eth_addr = match.group(1)
                    logger.debug('eth pop %s, %s' % (eth_int, eth_addr))
                    nets = self.__find_network_for_addr(eth_addr, self.networks_detail)
                    if not nets:
                        continue
                    for net in nets:
                        network_info = {
                            "network": net,
                            "intf": eth_int,
                            "addr": eth_addr,
                            "mac_addr": mac_addr,
                            "used_sub_ints": []
                        }
                        if net in self.vm_info["networks"][0]:
                            self.vm_info["networks"][0][net][eth_int] = network_info
                        else:
                            self.vm_info["networks"][0][net] = {eth_int:network_info}
                # Find the IPv6 address
                match = re.search(
                    r'inet6 addr:\s*([0-9a-f:]+)\/(\d+)\s*Scope:Global', line)
                if match:
                    eth_addr = match.group(1)
                    logger.debug('eth pop %s, %s' % (eth_int, eth_addr))
                    nets = self.__find_network_for_addr(eth_addr, self.networks_detail)
                    if not nets:
                        continue
                    for net in nets:
                        ipv6_network = ipaddress.IPv6Network(unicode(self.networks_detail[net].ip_addr) + '/' + \
                                                             unicode(self.networks_detail[net].mask))
                        if ipaddress.IPv6Address(unicode(eth_addr)) > ipv6_network[60]:
                            logger.debug('Linguring IPv6 %d address found. Ignoring in interface_info')
                            continue
                        network_info = {
                            "network": net,
                            "intf": eth_int,
                            "addr": eth_addr,
                            "mac_addr": mac_addr,
                            "used_sub_ints": []
                        }
                        if net in self.vm_info["networks"][1]:
                            self.vm_info["networks"][1][net][eth_int] = network_info
                        else:
                            self.vm_info["networks"][1][net] = {eth_int:network_info}
        logger.trace('[%s, %s] Interfaces: %s' % (
            self.name, self.ip, self.vm_info))

    def is_network_present(self, network):
        """ Return if network preset on VM or not """
        for ip_network in self.vm_info["networks"]:
            for info in ip_network.values():
                if str(network) in ip_network.keys():
                    return True
        return False

    def get_interface_details(self, network):
        """ Return interface details given a network """
        for ip_network in self.vm_info["networks"]:
            if str(network) in ip_network.keys():
                for eth_int, interface in ip_network[str(network)].iteritems():
                    if len(interface["used_sub_ints"]) < self.max_sub_ints:
                        return (eth_int,
                                interface["mac_addr"],
                                interface["addr"])
        fail("Failed to find interface on %s for network %s" % (self.name, network))

    def get_ethernet_index(self, eth_int, network):
        """ Return next allowed interface
            :param :network network on the VM
            :param :eth_int interface on the VM
        """
        if str(network) in self.vm_info["networks"][0].keys() and \
                eth_int in self.vm_info["networks"][0][str(network)]:
            ip_network = self.vm_info["networks"][0][str(network)]
        elif str(network) in self.vm_info["networks"][1].keys() and \
                eth_int in self.vm_info["networks"][1][str(network)]:
            ip_network = self.vm_info["networks"][1][str(network)]
        else:
            fail("intf %s does not exists in network %s" % (eth_int, network))
        available_interfaces = list(
            set(range(1, self.max_sub_ints)) -
            set(ip_network[eth_int]["used_sub_ints"]))

        if not available_interfaces:
            fail("No more sub interfaces available for %s: %s" % (
                self.name, eth_int))
        interface = available_interfaces[0]
        ip_network[eth_int]["used_sub_ints"].append(interface)
        return str(interface)

    def execute_command_tcptest(self, cmd):
        """ Execute tecptest related commands"""
        chan = self.child.get_transport().open_session()
        chan.settimeout(10800)
        try:
            chan.exec_command(cmd)
            contents = StringIO.StringIO()
            error = StringIO.StringIO()
            while not chan.exit_status_ready():
                if chan.recv_ready():
                    data = chan.recv(1024)
                    while data:
                        contents.write(data)
                        data = chan.recv(1024)
                if chan.recv_stderr_ready():
                    error_buff = chan.recv_stderr(1024)
                    while error_buff:
                        error.write(error_buff)
                        error_buff = chan.recv_stderr(1024)
            exit_status = chan.recv_exit_status()
        except socket.timeout:
            raise socket.timeout
        output = contents.getvalue()
        if not exit_status:
            return output

    def get_dotted_netmask_for_cidr(self, mask):
        """ Return dotted mask """
        bits = 0
        for i in xrange(32 - int(mask), 32):
            bits |= (1 << i)
        return socket.inet_ntoa(struct.pack('>I', bits))

    def killtcptest(self):
        """ Cleanup tcptest """

        cmd = 'killall -9 tcptest'
        self.execute_command(cmd, log_error=False)

    def delete_netem_config(self):
        # TBD To get the intf based data networks
        return
        self.execute_command(
            'tc qdisc del dev ' + intf + ' root handle 1: htb')

    def cleanup_sub_ints(self):
        """ Cleanup sub interfaces"""
        logger.info("Cleaning sub interface on %s" % self.name)
        # TBD: Fixup the routes of the interface before cleanup
        self.cloud_obj.cleanup_secondary_ips(self.name)

        ints = []
        eth_int = ''
        ints_ipv6 = []
        out = self.execute_command('ifconfig -a | egrep \'eth|ens\' -A 3')
        for line in out:
            match = re.search(r'((eth|ens)[0-9]+(:[0-9]+)+)', line)
            if match:
                ints.append(match.group(1))
                continue
            # Find interface name
            match = re.search(
                r"(\S+)\s+Link encap.*", line)
            if match:
                eth_int = match.group(1)
                continue
            if eth_int:
                match = re.search(r'inet6 addr:\s*([0-9a-f:]+)\/(\d+)\s*Scope:Global', line)
                if match:
                    ints_ipv6.append(eth_int)
        logger.info('cleanup_any_lingering_sub_ints %s' % ints)
        for i in ints:
            self.execute_command('ifconfig %s down' % i, log_error=False)
        logger.info('IPv6: cleanup_any_lingering_sub_ints %s' % ints_ipv6)
        if ints_ipv6:
            for i in ints_ipv6:
                cmd = 'ifdown %s; killall -9 dhclient; ifup %s' %(i,i)
                self.execute_command(cmd, log_error=False)
                # TODO: Disable if we have IPV6 DHCP Support
                # self.execute_command('/etc/init.d/networking restart')

        out = self.execute_command('ifconfig -a | egrep \'eth|ens\'')
        for line in out:
            match = re.search(r'((eth|ens)[0-9]+)', line)
            if match:
                self.execute_command(
                    'tc qdisc del dev %s root' % match.group(1), log_error=False)

    def apply_net_emulation(self, handle, machine_type, **kwargs):
        direction = kwargs.get('direction')
        delay = kwargs.get('delay')
        loss = kwargs.get('loss')
        delay_val = common_utils.get_value_verify_unit(delay, ['ms', 's'])
        loss_str = ''

        if loss is None:
            loss_val = 0
        else:
            loss_val = common_utils.get_value_verify_unit(loss, '%')
            loss_str = 'loss %s' % (loss)

        handle_found = False
        netem_applied = False
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for app in self.apps[context_key]:
            logger.debug("app.handle " + app.handle)
            logger.debug("handle " + handle)
            if app.handle == handle:
                handle_found = True
                ip = app.ip
                index = int(app.eth_index)
                qdisc_num = 10 + index
                ifb_index = index - 1  # eth1:1 => ifb0, eth1:5 => ifb4, etc
                if app.app_type == 'httperf':
                    eth_int = app.eth_int
                else:
                    eth_int = '%s:%s' % (
                        app.eth_int, app.eth_index)

                if direction == 'ingress' or direction == 'both':
                    netem_applied = True
                    logger.info('apply ingress netem on %s' % (self.ip))

                    if delay_val > 0 or loss_val > 0:
                        max_sim = 5
                        if ifb_index > max_sim:
                            fail(
                                'Max number of simulated ingress is %d' % (
                                    max_sim))

                        cmd = 'modprobe ifb numifbs=%d' % (max_sim)
                        self.execute_command(cmd, log_error=False)

                        cmd = 'tc qdisc add dev %s ingress' % (eth_int)
                        self.execute_command(cmd, log_error=True)

                        cmd = 'tc qdisc add dev ifb%d root netem' % (ifb_index)
                        self.execute_command(cmd, log_error=True)

                        cmd = 'ip link set dev ifb%d up' % (ifb_index)
                        self.execute_command(cmd, log_error=False)

                        cmd = 'tc filter add dev %s parent ffff: protocol' + \
                              ' ip u32 match ip dst %s/32 flowid 1:%d' + \
                              ' action mirred egress redirect dev ifb%d'
                        cmd = cmd % (eth_int, ip, ifb_index, ifb_index)
                        self.execute_command(cmd, log_error=False)

                        cmd = 'tc qdisc change dev ifb%d root netem delay %s %s' % (
                            ifb_index, delay, loss_str)
                        self.execute_command(cmd, log_error=False)
                    else:
                        logger.debug('delete ingress netem on %s' % (self.ip))

                        cmd = 'tc qdisc del dev %s ingress' % (eth_int)
                        self.execute_command(cmd, log_error=False)

                        cmd = 'tc qdisc del dev ifb%d root' % (ifb_index)
                        self.execute_command(cmd, log_error=False)

                if direction == 'egress' or direction == 'both':
                    netem_applied = True
                    logger.debug('apply egress netem on %s' % (self.ip))

                    if delay_val > 0 or loss_val > 0:

                        cmd = 'tc qdisc add dev %s root handle 1: htb' % (
                            eth_int)
                        self.execute_command(cmd, log_error=True)

                        cmd = 'tc class add dev %s parent 1: classid 1:%s htb rate 4096Mbps' % (
                            eth_int, index)
                        self.execute_command(cmd, log_error=True)

                        cmd = 'tc class change dev %s parent 1: classid 1:%s htb rate 4096Mbps' % (
                            eth_int, index)
                        self.execute_command(cmd, log_error=False)

                        cmd = 'tc filter add dev %s protocol ip parent 1: prio 1 u32 match ip src %s/32 flowid 1:%s' % (
                            eth_int, ip, index)
                        self.execute_command(cmd, log_error=True)

                        cmd = 'tc qdisc add dev %s parent 1:%s handle %s: netem delay %s %s' % (
                            eth_int, index, qdisc_num, delay, loss_str)
                        self.execute_command(cmd, log_error=True)

                        cmd = 'tc qdisc change dev %s parent 1:%s handle %s: netem delay %s %s' % (
                            eth_int, index, qdisc_num, delay, loss_str)
                        self.execute_command(cmd, log_error=False)

                    else:
                        cmd = 'tc qdisc del dev %s parent 1:%s handle %s: netem' % (
                            eth_int, index, qdisc_num)
                        self.execute_command(cmd, log_error=False)

                if not netem_applied:
                    fail(
                        'direction kwarg must be either ingress, egress or both')

        if not handle_found:
            fail(
                'ERROR! Did not find app %s to apply ingress netem' % handle)


class Client(TestVm):
    """ Class for client related functions """

    def __init__(self, **kwargs):
        vm_json = kwargs.pop('vm_json', {})
        kwargs.update(vm_json)
        self.app_clients = {}
        TestVm.__init__(self, self.app_clients, **kwargs)
        self.type = 'client'

    def client_handle_must_be_unique(self, handle):
        """ Client handle must be unique"""
        logger.debug("client_handle_must_be_unique: %s" % handle)
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for client in self.app_clients.get(context_key, []):
            if client.handle == handle:
                if self.check_if_ip_exists(client.ip):
                    fail('ERROR: client handle %s present already! use another '
                         'one' % handle)
                else:
                    return client
        return None

    def get_eth_of_app_client(self, handle):
        """ Return eth index of the VM for given handle """
        for app in self.app_clients:
            if app.handle == handle:
                return app.eth_int + ':' + str(app.eth_index)

    def create_client_context(self, how_many, network, prefix, app_type, ip_addrs, start_idx):
        """ Creates a client context on VM"""
        return self.cloud_obj.create_client_context_all(self, how_many, network, prefix, app_type, ip_addrs, start_idx)


class Server(TestVm):
    """ Class for server related functions """

    def __init__(self, **kwargs):

        vm_json = kwargs.pop('vm_json', {})
        kwargs.update(vm_json)
        self.app_servers = {}
        TestVm.__init__(self, self.app_servers, **kwargs)
        self.type = 'server'
        key_filename = None
        self.key_filename = kwargs.get('key_filename', key_filename)
        self.nginx_policy_loc = None
        self.nginx_default_loc = None
        self.browser_runner_loc = None
        self.__initialize_vars()

    def __generate_cookie_exp_uri(self):
        """ Generate URI locations for cookie expiry """
        lines = []
        lines.append('location /cookieexp1 {\n')
        current = datetime.datetime.now()
        exp_time = current + datetime.timedelta(hours=6)
        exp_time_str = exp_time.strftime("%a, %d %b %Y %H:%M:%S")
        lines.append("""\tadd_header Set-Cookie "appcookiehdr=cookieexp1;expires=%s";\n""" % exp_time_str)
        lines.append('\treturn 200 $server_port;\n')
        lines.append('}\n')

        lines.append('location /cookieexp2 {\n')
        current = datetime.datetime.now()
        exp_time = current + datetime.timedelta(minutes=15)
        exp_time_str = exp_time.strftime("%a, %d %b %Y %H:%M:%S")
        lines.append("""\tadd_header Set-Cookie "appcookiehdr=cookieexp2;expires=%s";\n""" % exp_time_str)
        lines.append('\treturn 200 $server_port;\n')
        lines.append('}\n')

        return lines

    def __generate_apache_loc(self, app):
        """ Generate server location for apache defaults file"""

        ports = app.server.port()
        if not isinstance(ports, list):
            ports = [ports]

        logger.debug(
            'Handle:%s, IP:%s, PORT:%s, App Type: %s' % (
                app.handle, app.ip, ports, app.app_type))

        if app.app_type != 'fwd_proxy':
            return

        lines = []
        port_lines = []
        for port in ports:
            lines.append('<VirtualHost %s:%s>\n' %(app.ip, port))
            lines.append('    ServerAdmin webmaster@localhost\n')
            lines.append('    DocumentRoot /home/aviuser\n')
            lines.append('    <Directory />\n')
            lines.append('        Options FollowSymLinks\n')
            lines.append('        AllowOverride None\n')
            lines.append('    </Directory>\n')
            lines.append('    <Directory /home/aviuser/>\n')
            lines.append('        Options Indexes FollowSymLinks MultiViews\n')
            lines.append('        AllowOverride None\n')
            lines.append('        Order allow,deny\n')
            lines.append('        allow from all\n')
            lines.append('    </Directory>\n')
            lines.append('    ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/\n')
            lines.append('    <Directory "/usr/lib/cgi-bin">\n')
            lines.append('        AllowOverride None\n')
            lines.append('        Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch\n')
            lines.append('        Order allow,deny\n')
            lines.append('        Allow from all\n')
            lines.append('    </Directory>\n')
            lines.append('    ErrorLog ${APACHE_LOG_DIR}/error.log\n')
            lines.append('    ProxyRequests On\n')
            lines.append('    # Possible values include: debug, info, notice, warn, error, crit,\n')
            lines.append('    # alert, emerg.\n')
            lines.append('    LogLevel warn\n')
            lines.append('    CustomLog ${APACHE_LOG_DIR}/access.log combined\n')
            lines.append('</VirtualHost>\n')


            port_lines.append('NameVirtualHost %s:%s\n' %(app.ip, port))
            port_lines.append('Listen %s:%s\n' %(app.ip, port))
        return (lines , port_lines)

    def __generate_server_loc(self, app):
        """ Generate server location for nginx defaults file"""

        ports = app.server.port()
        if not isinstance(ports, list):
            ports = [ports]

        logger.debug(
            'Handle:%s, IP:%s, PORT:%s, App Type: %s' % (
                app.handle, app.ip, ports, app.app_type))

        lines = []
        if app.app_type == 'python':
            return []

        if type(ipaddress.ip_address(unicode(app.ip))) == ipaddress.IPv6Address:
            app_ip = '[' + app.ip + ']'
        else:
            app_ip = app.ip
        logger.debug('App ip string for nginx configuration %s' % app_ip)
        if app.app_type == 'autobahntest':
            if app.server.json_data.get('autobahn_nginx') != 'true':
                return []

            wsbackend_prefix = 'wsbackend-' + app.handle
            lines.append('upstream ' + wsbackend_prefix + '-c {\n')
            lines.append('\tserver 127.0.0.1:80;\n')
            lines.append('}\n')
            lines.append('upstream ' + wsbackend_prefix + '-f {\n')
            lines.append('\tserver 127.0.0.1:80;\n')
            lines.append('}\n')
            lines.append('upstream ' + wsbackend_prefix + '-r {\n')
            lines.append('\tserver 127.0.0.1:80;\n')
            lines.append('}\n')
            lines.append('upstream ' + wsbackend_prefix + '-m {\n')
            lines.append('\tserver 127.0.0.1:80;\n')
            lines.append('}\n')

        lines.append('server {\n')

        if app.app_type == 'autobahntest' and app.server.json_data.get('autobahn_nginx') == 'true':
            port = 443
            lines.append('\tlisten %s:%s;\n' % (app_ip, port))
        else:
            for port in ports:
                lines.append('\tlisten %s:%s;\n' % (app_ip, port))

        lines.append('\tserver_name %s:%s;\n' % (app_ip, port))

        if app.app_type == 'contenttest':
            lines.append(self.browser_runner_loc)
        elif app.app_type in ['httptest', 'policytest', 'autobahntest', 'sslpolicyupdatetest', 'reselecttest']:
            logger.debug('app._pool.ssl_enabled %s' % app.ssl_enabled)
            if app.ssl_enabled or app.server.json_data.get('autobahn_nginx') == 'true':
                cert_file = app.server.get_ssl_cert_filename()
                privkey_file = app.server.get_ssl_privkey_filename()
                if cert_file and privkey_file:
                    lines.append('\tssl on;\n')
                    logger.debug('ssl_protocols %s' % app.server._pool.json_data.get('tls_version'))
                    _str = ''
                    _str = '\tssl_protocols '
                    if app.app_type == 'sslpolicyupdatetest' or app.app_type == 'reselecttest':
                        tls_version = ['TLSv1.1']
                    elif not app.server._pool.json_data.get('tls_version'):
                        tls_version = ['TLSv1', 'TLSv1.1', 'TLSv1.2']
                    else:
                        tls_version = app.server._pool.json_data.get('tls_version')
                    _str += ' '.join(tls_version)
                    lines.append(_str + ';\n')
                    lines.append('\tssl_session_cache builtin:1000 shared:SSL:10m;\n')
                    if app.app_type == 'sslpolicyupdatetest':
                        lines.append('\tssl_ciphers RC4-MD5;\n')

                    lines.append('\tssl_certificate /root/server/ssl_certs/%s;\n' % (
                        cert_file))
                    lines.append('\tssl_certificate_key /root/server/ssl_certs/%s;\n' % (
                        privkey_file))
                    client_cert = app.server.get_ssl_validate_client_cert()
                    if client_cert:
                        lines.append(
                            '\tssl_client_certificate /root/server/ssl_certs/%s; \n' % (
                                client_cert))
                        lines.append('\tssl_verify_client on;\n')
                        lines.append('\tssl_verify_depth 10;\n')

            lines.append(self.nginx_default_loc)
            lines.extend(self.__generate_cookie_exp_uri())

            if app.app_type == 'autobahntest' and app.server.json_data.get('autobahn_nginx') == 'true':
                lines.append('location /c {\n')
                lines.append('\tproxy_pass http://' + wsbackend_prefix + '-c;\n')
                lines.append('\tproxy_set_header Upgrade $http_upgrade;\n')
                lines.append('\tproxy_set_header Connection "upgrade";\n')
                lines.append('}\n')
                lines.append('location /f {\n')
                lines.append('\tproxy_pass http://' + wsbackend_prefix + '-f;\n')
                lines.append('\tproxy_set_header Upgrade $http_upgrade;\n')
                lines.append('\tproxy_set_header Connection "upgrade";\n')
                lines.append('}\n')
                lines.append('location /r {\n')
                lines.append('\tproxy_pass http://' + wsbackend_prefix + '-r;\n')
                lines.append('\tproxy_set_header Upgrade $http_upgrade;\n')
                lines.append('\tproxy_set_header Connection "upgrade";\n')
                lines.append('}\n')
                lines.append('location /m {\n')
                lines.append('\tproxy_pass http://' + wsbackend_prefix + '-m;\n')
                lines.append('\tproxy_set_header Upgrade $http_upgrade;\n')
                lines.append('\tproxy_set_header Connection "upgrade";\n')
                lines.append('}\n')

            if app.app_type == 'reselecttest':
                lines.append('location /status1/ {\n')
                lines.append('\ttry_files $uri =503;\n')
                lines.append('}\n')
                lines.append('location /status2/ {\n')
                lines.append('\ttry_files $uri =401;\n')
                lines.append('}\n')
                lines.append('location /status3/ {\n')
                lines.append('\ttry_files $uri =504;\n')
                lines.append('}\n')
                lines.append('location /status4/ {\n')
                lines.append('\ttry_files $uri =502;\n')
                lines.append('}\n')
            else:
                lines.append('location /status1/ {\n')
                lines.append('\treturn 200 $server_addr:$server_port;\n')
                lines.append('}\n')
                lines.append('location /status2/ {\n')
                lines.append('\treturn 200 $server_addr:$server_port;\n')
                lines.append('}\n')
                lines.append('location /status3/ {\n')
                lines.append('\treturn 200 $server_addr:$server_port;\n')
                lines.append('}\n')
                lines.append('location /status4/ {\n')
                lines.append('\treturn 200 $server_addr:$server_port;\n')
                lines.append('}\n')
                lines.append('location /status5/ {\n')
                lines.append('\treturn 200 $server_addr:$server_port;\n')
                lines.append('}\n')

            if app.app_type == 'policytest':
                # Append only if the app type is policy
                lines.append(self.nginx_policy_loc)
        lines.append('}')

        return lines

    def __initialize_vars(self):
        """ Intialize nginx variables """

        source_path = suite_vars.workspace + \
                      '/test/robot/new/files/server/nginx/'
        if self.nginx_policy_loc and self.nginx_default_loc \
                and self.browser_runner_loc:
            return
        with open(source_path + 'nginx.default', 'r') as file_handle:
            self.nginx_default_loc = file_handle.read()

        with open(source_path + 'nginx.policy', 'r') as file_handle:
            self.nginx_policy_loc = file_handle.read()

        self.browser_runner_loc = """
                          root /mnt/cores/pybot/browser_runner;
                          index index.html index.htm;
                          location / {
                            try_files $uri $uri/ =404;
                          }\n
                        """
        self.nginx_default_loc = self.nginx_default_loc.replace(
            'rand_int', str(random.randint(1, 50)) + '.000')

    def get_eth_of_app_server(self, handle):
        """ Return eth index of the VM for given handle """
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for app in self.app_servers.get(context_key, []):
            if app.handle == handle:
                return app.eth_int

    def start_node(self, ip, port, file_name='start_node.sh'):
        """ Start node on server """
        command = 'cd /usr/share/nginx/www;./%s "%s" "%s" &> /tmp/node.txt &' % (
            file_name, ip, port)
        out = self.execute_command(command)
        logger.info('service start: cmd: %s out: %s ' % (command, out))
        if re.search(r'already in use', "".join(out)):
            fail('ERROR! service node start failed, %s' % out)

    def start_python(self):
        """ Start python server on server """
        command = 'cd /root; python httptest_svr.py >& /tmp/httptest_svr.out &'
        out = self.execute_command(command)
        logger.info('start_python(): start python server script code: cmd: %s out: %s ' % (command, out))
        if re.search(r'already in use', "".join(out)):
            fail('ERROR! service python start failed, %s' % out)

    def start_go_server(self, ip, port, server_location='/root/goServer'):
        """ Start the gorilla websockets server """
        ssl_port = 443
        if port == ssl_port:
            server_port = 80
        else:
            server_port = port

        command = """ cd %s/src/github.com/gorilla/websocket/examples/autobahn;
                   export GOPATH=%s;/usr/local/go/bin/go run server.go %s >& /tmp/tmp &""" % (
            server_location, server_location, server_port)
        out = self.execute_command(command)

        logger.info('service start: cmd: %s out: %s ' % (command, out))
        if re.search(r'address already in use', "".join(out)):
            fail('ERROR! gorilla server start failed, %s' % out)

    def stop_node(self):
        """ Start node on server """
        command = 'killall node'
        out = self.execute_command(command)
        logger.info('service node stop: cmd: %s out: %s ' % (command, out))

    def start_php5fpm(self, workspace):
        """ Start php5fpm on server """
        self.execute_command("sudo service php5-fpm restart")

    def cleanup_uploads(self):
        ''' Delete contents of the uploads directory'''
        remote_path = '/usr/share/nginx/www/uploads/*'
        cmd = 'rm -f ' + remote_path
        logger.debug('deleting uploads directory contents: %s' % cmd)
        self.execute_command(cmd)

    def bring_nginx_server_up(self, handle):
        """ Bring nginx server up """
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for i in range(0, len(self.app_servers.get(context_key, []))):
            logger.debug('bring_nginx_server_up: %s' % self.app_servers[context_key][i].handle)
            if self.app_servers[context_key][i].handle == handle:
                self.app_servers[context_key][i].nginx_status = 1
                return
        fail('bring_nginx_server_up> Did not find matching server %s ' % (handle))

    def bring_nginx_server_down(self, handle):
        """ Bring nginx server down """
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for i in range(0, len(self.app_servers.get(context_key, []))):
            logger.debug('bring_nginx_server_down: %s' %
                         self.app_servers[context_key][i].handle)
            if self.app_servers[context_key][i].handle == handle:
                self.app_servers[context_key][i].nginx_status = 0
                return
        fail('bring_nginx_server_down> Did not find matching server %s ' % (handle))

    def send_nginx_signal(self, signal):
        '''Sends signal to master nginx process
          signal options: stop, quit, reopen, reload
        '''
        cmd = 'service nginx status'
        out = self.execute_command(cmd)
        logger.debug('send_nginx_signal out: %s' % out)
        for line in out:
            logger.debug('send_nginx_signal line: %s' % line)
            if re.search('nginx is not running', line):
                logger.debug('send_nginx_signal restart nginx')
                self.service_restart('nginx')
                break

        cmd = 'nginx -s %s' % signal
        logger.debug('sending nginx signal command: %s' % cmd)
        out = self.execute_command(cmd)
        if len(out) > 1:
            if 'warn' not in str(out):
                fail('ERROR! sending nginx signal %s gives error %s' % (
                    cmd, str(out)))

    def send_apache_signal(self, signal):
        '''Sends signal to master nginx process
          signal options: stop, quit, reopen, reload
        '''
        cmd = 'service apache2 status'
        out = self.execute_command(cmd)
        for line in out:
            if re.search('apache2 is not running', line):
                logger.debug('send_apache_signal restart apache2')
                self.service_restart('apache2')
                break

        cmd = 'service apache2 %s' % signal
        logger.debug('sending apache command: %s', cmd)
        out = self.execute_command(cmd)
        if len(out) > 1:
            if 'warn' not in str(out):
                fail('ERROR! sending nginx signal %s gives error %s', cmd, out)

    def reload_server_context_nginx(self, restart=False):
        """ Reload nginx after changing defaults file """
        self.create_nginx_default_file(restart=restart)

        @aretry(retry=5, delay=5)
        def nginx_restart_retry():
            logger.debug('Restarting Nginx')
            self.service_restart('nginx')

        if restart:
            nginx_restart_retry()
        else:
            logger.debug('Reloading Nginx conf file')
            self.send_nginx_signal('reload')

    def reload_server_context_apache(self, restart=False):
        """ Reload nginx after changing defaults file """
        self.create_apache_default_file()
        if restart:
            retry_count = 1
            # Enable Proxy Module
            self.execute_command('sudo a2enmod proxy')
            @aretry(retry=5, delay=5)
            def apache_restart():
                logger.debug('Restarting Apache')
                self.service_restart('apache2')
            apache_restart()
        else:
            logger.debug('Reloading Apache2 conf file')
            self.send_apache_signal('reload')

    def load_server_context_haproxy_vsftpd(self, restart=False, uname="aviuser", passwd="aviuser"):
        """ Load haproxy setting and launch it
            Install vsftpd """

        local_path = suite_vars.workspace + '/test/robot/new/files/server/haproxy/haproxy-1.6.4.tar.gz'
        remote_path = '/tmp/haproxy-1.6.4.tar.gz'
        self.scp_file(local_path, remote_path, username=uname, password=passwd)

        cmd = 'tar -xzf /tmp/haproxy-1.6.4.tar.gz -C /tmp/'
        logger.debug('scp haproxy local_path:%s, remote_path:%s, cmd:%s' % (local_path, remote_path, cmd))
        out = self.execute_command(cmd)
        logger.debug('haproxy setup cmd: %s.  out: %s' % (cmd, out))

        cmd = 'sudo apt-get install vsftpd'
        logger.debug('scp vsftpd cmd:%s' % cmd)
        out = self.execute_command(cmd)
        logger.debug('vsftpd install cmd: %s, out: %s' % (cmd, out))

        local_path = suite_vars.workspace + '/test/robot/new/files/server/vsftpd/vsftpd.conf'
        remote_path = '/tmp/vsftpd.conf'
        logger.debug('scp vsftpd conf local_path:%s, remote_path:%s' % (local_path, remote_path))
        self.scp_file(local_path, remote_path, username=uname, password=passwd)

        cmd = 'sudo cp /tmp/vsftpd.conf /etc/vsftpd.conf'
        logger.debug('vsftpd local copy:%s' % cmd)
        out = self.execute_command(cmd)
        logger.debug('vsftpd local copy cmd: %s, out: %s' % (cmd, out))

    def check_if_servers_up(self, num_of_retries=10):
        ''' Once we push backend configs to nginx.conf, just make
            a get request to check if server is up.
            This is required for aggresive HM checks.
        '''
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for app in self.app_servers.get(context_key, []):
            if not app.server.json_data.get('enabled'):
                logger.info('Server %s handle %s is in disabled state, \
                    skip "up" check' % (app.ip, app.handle))
                continue
            protocol = 'http://'
            if (app.ssl_enabled and app.server.get_ssl_cert_filename()
                and app.server.get_ssl_privkey_filename()):
                protocol = ''
                if app.server.get_ssl_validate_client_cert():
                    if app.server.get_pki_validate_client_cert():
                        client_cert = app.server.get_pki_validate_client_cert()
                        protocol = '-E /root/server/ssl_certs/' + client_cert + ' '
                    else:
                        protocol = '-E /root/server/ssl_certs/https_hm_client.pem '
                protocol += '-k https://'
            if not isinstance(app.server.port(), list):
                ports = [app.server.port()]
            else:
                ports = app.server.port()

            for port in ports:
                if type(ipaddress.ip_address(unicode(app.ip))) == ipaddress.IPv6Address:
                    ip_addrs = '[' + app.ip + ']'
                    cmd = 'curl -g ' + protocol + ip_addrs + ':' + str(port)
                else:
                    cmd = 'curl ' + protocol + app.ip + ':' + str(port)

                cmd = cmd + ' -sL -w "%{http_code}" --max-time 1 -o /dev/null'

                if app.app_type == 'httptest' and app.nginx_status != 0 and \
                                app.reachability != 0:

                    @aretry(retry=num_of_retries, delay=1, period=10)
                    def checking_server_port():
                        resp = self.execute_command(cmd)
                        if resp and resp[0] != '200':
                            fail('Server %s (IP: %s) is not responding properly; response code %s' % (
                                app.handle, app.ip, resp[0] if resp else None))

                    checking_server_port()

    def send_haproxy_start_signal(self, ip, backend_ip):
        '''Start haproxy server.  '''
        cmd = "sudo killall haproxy;sudo service vsftpd stop; sed -i -- 's/XXX.XXX.XXX.XXX/" + backend_ip + \
              "/g' /tmp/haproxy-1.6.4/haproxy.cfg; sed -i -- 's/bind\ \*:/bind\ " + ip + ":/g' /tmp/haproxy-1.6.4/haproxy.cfg; \
           sed -i -- 's/#accept-proxy/accept-proxy/g' /tmp/haproxy-1.6.4/haproxy.cfg;\
           sudo /tmp/haproxy-1.6.4/haproxy -C /tmp/haproxy-1.6.4/ -D -- haproxy.cfg"
        out = self.execute_command(cmd)
        logger.debug('send_haproxy_signal start out: %s' % out)

    def send_haproxy_stop_expect_proxy(self):
        '''Stop haproxy expect proxy header  '''
        cmd = "sudo killall haproxy;sed -i -- 's/accept-proxy/#accept-proxy/g' /tmp/haproxy-1.6.4/haproxy.cfg;\
           sudo /tmp/haproxy-1.6.4/haproxy -C /tmp/haproxy-1.6.4/ -D -- haproxy.cfg"
        out = self.execute_command(cmd)
        logger.debug('haproxy stop expecting proxy header.  cmd: %s. out: %s' % (cmd, out))

    def send_haproxy_stop_signal(self):
        '''Stop haproxy server.  '''
        cmd = 'sudo killall haproxy'
        out = self.execute_command(cmd)
        logger.debug('send_haproxy_signal stop out: %s' % out)

    def send_vsftpd_signal(self, signal, ip=""):
        '''Sends signal to backend vsftpd process
          signal options: stop, start, restart
        '''
        cmd = "sudo service vsftpd stop; sudo sed -i -- 's/XXX.XXX.XXX.XXX/" + ip + \
              "/g' /etc/vsftpd.conf; sudo service vsftpd " + signal
        out = self.execute_command(cmd)
        logger.debug('send_vsftpd_signal out: %s' % out)

    def server_eth_int(self, handle):
        """ Get server's eth intf """
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for i in range(0, len(self.app_servers.get(context_key, []))):
            if self.app_servers[context_key][i].handle == handle:
                app = self.app_servers[context_key][i]
                eth_intf_name = app.eth_int + ':' + app.eth_index
                return eth_intf_name

    def server_unreachable(self, handle):
        """ Make server unreachable """
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for i in range(0, len(self.app_servers.get(context_key, []))):
            if self.app_servers[context_key][i].handle == handle:
                self.app_servers[context_key][i].reachability = 0

                app = self.app_servers[context_key][i]
                cmd = 'ifconfig ' + app.eth_int + \
                      ':' + app.eth_index + ' ' + 'down'
                logger.debug('Making Server Unreachable %s ' % cmd)
                out = self.execute_command(cmd)
                return
        fail('server_unreachable> Did not find matching server %s ' % handle)

    def server_reachable(self, handle):
        """ Make server reachable """
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for i in range(0, len(self.app_servers.get(context_key, []))):
            if self.app_servers[context_key][i].handle == handle:
                self.app_servers[context_key][i].reachability = 1

                app = self.app_servers[context_key][i]
                netmask = str(self.get_dotted_netmask_for_cidr(app.mask))
                cmd = 'ifconfig ' + app.eth_int + ':' + app.eth_index + ' ' + app.ip + \
                      ' netmask ' + netmask + ' ' + 'up'
                logger.debug('server_reachable %s' % cmd)
                out = self.execute_command(cmd)
                return

        fail('server_reachable> Did not find matching server %s ' % handle)

    def delete_server_context(self, handle, cleanup_backend=True):
        """ Delete server context """
        server = None
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for i in range(0, len(self.app_servers.get(context_key, []))):
            logger.debug('delete_server_context print all %s' % self.app_servers[context_key][i].handle)
            if self.app_servers[context_key][i].handle == handle:
                server = self.app_servers[context_key][i]
        logger.debug("Found Server: %s" % server)
        if server is None:
            logger.debug('Unable to find app_server by handle %s. Maybe a non-app_server type?' % handle)
            return
        if len(self.app_servers[context_key]) > 1:
            self.app_servers[context_key].remove(server)
        else:
            # Don't see how this is being asserted from the current code, need to
            # get a handle to all pools (across all vm's) and then check they are empty
            # Only execute the command if it is the last server in all pools
            if cleanup_backend:
                cmd = ('ifconfig ' + server.eth_int + ':' + server.eth_index + ' ' +
                       'down')
                logger.debug('delete_server_context ', cmd)
                out = self.execute_command(cmd)
            self.app_servers[context_key].remove(server)
        if self.platform == 'aws':
            if not self.cloud_obj:
                fail('Server:%s in AWS doesnt have AWS handler' % (self.name))
            self.cloud_obj.unassign_secondary_ip(self.name, server.net_name, server.ip)
        logger.info('delete server context %s' % self.app_servers[context_key])
        return

    def create_apache_default_file(self):
        """create etc apache sites enabled default file"""
        pid = str(os.getpid())
        local_path = '/tmp/apache-' + str(pid)
        remote_path = '/etc/apache2/sites-enabled/000-default.conf'
    
        local_path_ports = '/tmp/apache-ports' + str(pid)
        remote_path_ports = '/etc/apache2/ports.conf'

        lines = []
        port_lines = []
        for server in self.app_servers:
            if server.app_type != 'fwd_proxy':
                continue
            lines_ext, port_ext = self.__generate_apache_loc(server)
            lines.extend(lines_ext)
            port_lines.extend(port_ext)

        logger.debug(
            'apache default Conf File::\n<pre>%s</pre>' % "".join(lines))
        logger.debug(
            'apache Ports Conf File::\n<pre>%s</pre>' % "".join(port_lines))
        with open(local_path, 'w') as f:
            f.write("".join(lines))

        with open(local_path_ports, 'w') as f:
            f.write("".join(port_lines))
        ## First, stop the apache service on the apache nginx server
        ## before overwrting the sites-enabled/default file and ports.conf with a new files.
        self.service_stop('apache2')
        self.scp_file(local_path, remote_path)
        self.scp_file(local_path_ports, remote_path_ports)
        try:
            subprocess.check_output(['rm', local_path])
        except subprocess.CalledProcessError, e:
            fail('ERROR! removing file %s failed, msg %s' %
                          (local_path, e.output))
        try:
            subprocess.check_output(['rm', local_path_ports])
        except subprocess.CalledProcessError, e:
            fail('ERROR! removing file %s failed, msg %s' %
                          (local_path_ports, e.output))

    def create_nginx_default_file(self, restart=False):
        """create etc nginx sites enabled default file"""
        pid = str(os.getpid())
        local_path = '/tmp/nginx-' + str(pid)
        remote_path = '/etc/nginx/sites-enabled/default'

        lines = []
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for apps in self.app_servers:
            for server in self.app_servers.get(apps, []):

                if not server.server.json_data.get('enabled'):
                    msg = 'server %s handle %s is in disabled state,' % (
                        server.ip, server.handle)
                    msg = msg + 'Don\'t add it to nginx config'
                    logger.debug(msg)
                    continue

                if not server.nginx_status:
                    continue
                if server.app_type in ['webreplay', 'scapytest',
                                       'nodejs', 'nodejs_ws']:
                    continue
                else:
                    lines.extend(self.__generate_server_loc(server))

        logger.trace(
            'Nginx Conf File::\n<pre>%s</pre>' % "".join(lines))
        with open(local_path, 'w') as f:
            f.write("".join(lines))

        # First, stop the nginx service on the backend nginx server
        # before overwrting the sites-enabled/default file with a new file.
        if restart:
            self.service_stop('nginx', log_error=False)
        self.scp_file(local_path, remote_path)
        try:
            subprocess.check_output(['rm', local_path])
        except subprocess.CalledProcessError, e:
            fail('ERROR! removing file %s failed, msg %s' % (local_path, e.output))

    def copy_ssl_cert_to_servers(self, workspace):
        return

    def restore_apache_default_file(self, log_error=True):
        """ Copy original apache file back"""
        self.execute_command(
            "cp /root/server/apache2/apache2_default.orig /etc/apache2/sites-enabled/000-default.conf", log_error=log_error)
        self.execute_command(
            "cp /root/server/apache2/apache2_ports.orig /etc/apache2/ports.conf", log_error=log_error)

    def restore_nginx_default_file(self):
        """ Copy original nginx file back"""
        self.execute_command(
            "cp /root/server/nginx/nginx.orig /etc/nginx/sites-enabled/default")

    def cleanup_server_context_nginx(self, restart):
        logger.info("Inside cleanup nginx")
        self.restore_nginx_default_file()
        self.app_servers = {}  # REVIEW if delete_server_context is called correctly, won't need this
        self.cleanup_uploads()
        if restart:
            self.service_restart('nginx')

    def cleanup_server_context_apache(self, restart):
        logger.info("Inside cleanup apache")
        self.restore_apache_default_file(log_error=False)
        self.service_stop('apache2', log_error=False)
        if restart:
            self.service_restart('apache2')

    def create_server_context(self, server):
        """create_server_context """
        self.cloud_obj.create_server_context(self, server)

    def create_server_context_ip_addrs(self):
        """ Create a server context """
        self.cloud_obj.create_server_context_ip_addrs(self)


class Router(Server):
    # Router vm
    def __init__(self, **kwargs):
        vm_json = kwargs.pop('vm_json', {})
        kwargs.update(vm_json)
        Server.__init__(self, **kwargs)
        self.type = 'router'


class Controller(ProductVm):
    """ Class for controller related functions """

    def __init__(self, **kwargs):
        vm_json = kwargs.pop('vm_json', {})
        kwargs.update(vm_json)
        ProductVm.__init__(self, **kwargs)
        self.type = 'controller'
        self.https_port = kwargs.get('https_port', 443)


class Se(ProductVm):
    """ Class for SE related functions """

    def __init__(self, **kwargs):
        vm_json = kwargs.pop('vm_json', {})
        kwargs.update(vm_json)
        ProductVm.__init__(self, **kwargs)
        self.type = 'se'


class App(object):
    def __init__(self):
        self.server = None
        self.handle = None
        self.ip = None
        self.net = None
        self.eth_index = None
        self.eth_int = None
        self.network = None
        self.mask = None
        self.mac = None
        self.reachability = 1
        self.nginx_status = 1
        self.app_type = ''
        self.eth_ip_configured = 0
        self.delay_set = 0
        self.ssl_enabled = False

    def __repr__(self):
        return "app_server > handle: %s, ip: %s" % (self.handle, self.ip)
