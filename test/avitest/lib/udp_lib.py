#standard python module imports
import re
from time import sleep

#Objects imports
from avi_objects.traffic_manager import get_client_by_handle
from avi_objects.infra_utils import get_server_by_handle, get_all_server_handle
from avi_objects.logger import logger
from avi_objects.logger_utils import error, fail
from lib.vs_lib import get_vs_vip
#Lib imports
from lib.dispatcher_lib import get_dst_mac

def stop_udp_clients_and_servers(client=None, servers=None, server_handle=None):
    """
    API helps to stop udp on client and servers

    Args:
        :param client: client handles to send UDP Traffic
        :type client: str
        :param servers: list of server handles want to Listen on Server
        :type servers: List
        :param server_handle: server handles want to stop udp listen,
                              if case want to stop on signle server
        :type server_handle: str

    Raises:
        KeyError

    """
    kill_client_command = 'pkill -9 -f udp_client.py'
    if client:
        client_vm, client_ip = get_client_by_handle(client)
        client_vm.execute_command(kill_client_command, log_error=False)


    if not servers:
        servers = get_all_server_handle()
    elif isinstance(servers, basestring):
        servers = [servers]
    for server in servers:
        server_vm = get_server_by_handle(server).vm()
        if server_handle == server:
            pids = 'ps -aux |grep \"%s\" | grep -v grep |awk \"{print $2;}\"' % server
            pids = ' '.join(pids).replace('\n', '')
            kill_server_command = 'sudo kill -9 %s' % pids
        else:
            kill_server_command = 'pkill -9 -f udp_server.py'
        server_vm.execute_command(kill_server_command, log_error=False)

def udp_client(client, vs_name, **kwargs):
    """
    API Helps to start UDP from Client for given vs, addr_type, vip_idx, port

    Args:
        :param client: client handles to send UDP Traffic
        :type client: str
        :param vs_name: vs name on which we want to send UDP Traffic
        :type vs_name: str


    Kwargs:
        :param addr_type:VIP Address type, in case of Dual VIP
        :type addr_type: str, default 'V4'
        :param vip_id: VS VIP index value
        :type vip_id: int, default 0

    Raises:
        KeyError

    """
    addr_type = kwargs.get('addr_type', 'V4')
    vip_id = kwargs.get('vip_id', 0)

    port = kwargs.get('port', 8000)
    data = kwargs.get('data', 512)
    no_of_udp_req = kwargs.get('no_of_udp_req', 1)
    print_resp = kwargs.get('print_resp', 0)

    vip = get_vs_vip(vs_name, addr_type, vip_id)
    cmd = 'python /root/client/tools/udp_client.py --ip %s --p %s --data %s --n %s\
    --print_resp %s &> /tmp/upd_out &' % (vip, port, data, no_of_udp_req, print_resp)
    logger.info("UDP client command: %s" % cmd)
    client_vm, client_ip = get_client_by_handle(client)
    client_vm.execute_command(cmd)
    sleep(1)
    out = client_vm.execute_command('cat /tmp/upd_out')
    logger.info("UDP Traffic CMD out: %s " % ''.join(out))
    if not out:
        client_vm.execute_command(cmd)
        sleep(1)
        out = client_vm.execute_command('cat /tmp/upd_out')
        logger.info("UDP Traffic CMD out: %s " % ''.join(out))

    out = ''.join(out).replace('\n', '-').split('-')
    return out

def udp_server(servers, port, **kwargs):
    """
    API Helps to start UDP Listen on given Server and Port

    Args:
        :param servers: list of server handles want to Listen on Server
        :type servers: List
        :param port: listener port
        :type port: int/str

    Raises:
        KeyError
    """
    if not servers:
        servers = get_all_server_handle()
    elif isinstance(servers, basestring):
        servers = [servers]
    for server_handle in servers:
        server = get_server_by_handle(server_handle)
        server_vm = server.vm()
        server_ip = server.ip()
        
        cmd = 'python /root/common/scripts/udp_server.py --ip %s --p %s &> /tmp/udp_server_out_%s &' % (server_ip, port, server_ip)
        logger.info("udp_server command: %s" % cmd)
        server_vm.execute_command(cmd, log_error=False)
        sleep(10)
        out = server_vm.execute_command('ps aux | grep \'udp_server.py\' | grep -v grep ')
        if not out:
            fail("UDP Server Process not started .. %s " % out)
        out = server_vm.execute_command('cat /tmp/udp_server_out_%s' % server_ip)
        if 'starting' not in ''.join(out):
            error("UDP Server not started .. %s " % out)

