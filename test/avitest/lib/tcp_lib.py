#standard python module imports
import re
from time import sleep

#Objects imports
from avi_objects.traffic_manager import get_client_by_handle
from avi_objects.infra_utils import get_server_by_handle
from avi_objects.logger import logger
from avi_objects.logger_utils import error, fail
from lib.vs_lib import get_vs_vip
from lib.se_lib import se_get_ip_for_server
#Lib imports
from lib.dispatcher_lib import get_dst_mac
import avi_objects.rest as rest
import avi_objects.logger_utils as logger_utils


def stop_scapy_clients_and_servers(client, server):
    """
    API helps to stop scapy on client and servers

    Args:
        :param client: client handles to stop Scapy Traffic
        :type client: str
        :param server: server handles to stop scapy Listen on Server
        :type server: str

    Raises:
        KeyError

    """
    reset_iptables_command = 'iptables -F'
    kill_client_command = 'pkill -9 -f scapy'
    client_vm, client_ip = get_client_by_handle(client)
    client_vm.execute_command(kill_client_command, log_error=False)
    client_vm.execute_command(reset_iptables_command)

    kill_server_command = 'pkill -9 -f scapy'
    server_vm = get_server_by_handle(server).vm()
    server_vm.execute_command(kill_server_command, log_error=False)
    server_vm.execute_command(reset_iptables_command)

def scapy_listen(servers, port, **kwargs):
    """
    API helps to start scapy listen on servers for given port

    Args:
        :param server: server handles want to Listen on Server
        :type server: str
        :param port: On which port Scapy listen
        :type port: str

    Raises:
        KeyError

    """
    out = []
    params = []

    for key in kwargs:
        found = re.match('(.*)_(delay|drop|upon)', key)
        params.append('-' + found.group(1))
        params.append(found.group(2))
        if found.group(2) == 'delay' or found.group(2) == 'upon':
            params.append(kwargs.get(key))

    found = re.match('([^\d]+)([\d]+)-?([\d]+)?', servers)
    if found is None:
        fail('ERROR! Example server range format s1 or s1-10')

    server_prefix = found.group(1)
    server_start = int(found.group(2))
    if found.group(3):
        server_end = int(found.group(3))
    else:
        server_end = 1

    tmp_args = "-server -H"

    server_vm = 0
    eth_int = ''
    for i in range(server_start, server_end + 1):
        server = get_server_by_handle(server_prefix + str(i))
        server_vm = server.vm()
        server_ip = server.ip()
        tmp_args = tmp_args + ' ' + server_ip
        iptable_cmd = 'iptables -A OUTPUT -p tcp --tcp-flags RST RST -s ' + \
            server_ip + ' -j DROP'
        server_vm.execute_command(iptable_cmd)
        eth_int = server_vm.get_eth_of_app_server(server_prefix + str(i))
    tmp_args = tmp_args + ' -P ' + str(port) + ' -i ' + eth_int + ' '.join(params)
    logger.info('nohup /root/common/scapy/scapy_terminals.py %s >& /tmp/tmp &' % tmp_args)
    server_vm.execute_command_tcptest(
        'nohup /root/common/scapy/scapy_terminals.py %s >& /tmp/tmp &' % tmp_args)
    tmp_out = server_vm.execute_command('pgrep scapy')
    proc_infos = tmp_out
    try:
        procId = proc_infos[0]
    except:
        logger.warning('Cannot get process id for scapy server')
        procId = 'None'
    out.append(procId)
    return out

def scapy_connect(clients, vs_name, port, **kwargs):
    """
    API helps to start scapy connect from client for given vs and port

    Args:
        :param client: client handles to connect sacpy
        :type client: str
        :param vs_name: vs name to connect sacpy from client
        :type vs_name: str
        :param port: On which port Scapy start from client
        :type port: str

    Return:
        process grep of scapy

    Raises:
        KeyError

    """
    out = []
    params = []

    vip = get_vs_vip(vs_name)
    # port = config.get_vport(service)

    for key in kwargs:
        found = re.match('(.*)_(delay|drop)', key)
        params.append('-' + found.group(1))
        params.append(found.group(2))
        if found.group(2) == 'delay':
            params.append(kwargs.get(key))

    found = re.match('([^\d]+)([\d]+)-?([\d]+)?', clients)
    if found is None:
        fail('ERROR! Example client range format c1 or c1-10')

    client_prefix = found.group(1)
    client_start = int(found.group(2))
    if found.group(3):
        client_end = int(found.group(3))
    else:
        client_end = 1

    client_vm = 0
    tmp_args = '-client -H'
    eth_int = ''
    dst_mac = ''
    for i in range(client_start, client_end + 1):
        client_vm, client_ip = get_client_by_handle(
            client_prefix + str(i))
        logger.debug('client_ip is: %s ' % client_ip)
        dst_mac = get_dst_mac(client_vm, client_ip, vip)
        tmp_args = tmp_args + ' ' + client_ip
        iptable_cmd = 'iptables -A OUTPUT -p tcp --tcp-flags RST RST -s ' + \
            client_ip + ' -j DROP'
        client_vm.execute_command(iptable_cmd)
        eth_int = client_vm.get_eth_of_app_client(client_prefix + str(i))
    tmp_args = tmp_args + ' -D ' + vip + ' -P ' + str(port)
    tmp_args = tmp_args + ' -F ' + dst_mac + \
        ' -i ' + eth_int + ' ' + ' '.join(params)
    logger.info('/root/common/scapy/scapy_terminals.py %s >& /tmp/tmp &' % tmp_args)
    client_vm.execute_command_tcptest(
        '/root/common/scapy/scapy_terminals.py %s >& /tmp/tmp &' % tmp_args)
    tmp_out = client_vm.execute_command('pgrep scapy')
    proc_infos = tmp_out
    try:
        procId = proc_infos[0]
    except:
        logger.info('Cannot get process id for scapy client')
        procId = 'None'
    out.append(procId)
    return out

def scapy_client(client, command):
    """
    API Helps to start scapy from Client by executing given scapy command

    Args:
        :param client: client handles to send scapy traffic
        :type client: str
        :param command: sacpy command to send
        :type command: str

    """
    cmd = 'echo "%s\n">>/tmp/scapy_cmd && touch /tmp/scapy_cmd_done' % command
    logger.info("scapy_client command: %s" % cmd)
    client_vm, client_ip = get_client_by_handle(client)
    out = client_vm.execute_command(cmd)
    sleep(1)
    logger.info("Started scapy on client : %s" % out)

def scapy_server(server, command):
    """
    API Helps to start scapy from Client by executing given scapy command

    Args:
        :param server: server handles to send scapy traffic
        :type server: server
        :param command: sacpy command to send
        :type command: str

    """
    cmd = 'echo "%s\n">>/tmp/scapy_cmd && touch /tmp/scapy_cmd_done' % command
    logger.info("scapy_server command: %s" % cmd)
    server_vm = get_server_by_handle(server).vm()
    out = server_vm.execute_command(cmd)
    sleep(1)
    logger.info("Started scapy on server : %s" % out)


def server_drop_icmp_pkts(se, svr_vm_hdl, svr_ip):
    # Get server side IP for the SE
    se_back_ip = se_get_ip_for_server(se, svr_ip)
    server_vm = get_server_by_handle(svr_vm_hdl).vm()
    cmd = 'iptables -A INPUT -p icmp -s %s -j DROP' % se_back_ip
    logger.debug('command: %s' % cmd)
    out = server_vm.execute_command(cmd)
    logger.debug('Cmd %s Output: %s' % (cmd, out))


def server_allow_icmp_pkts(se, svr_vm_hdl, svr_ip):
    # Get server side IP for the SE
    se_back_ip = se_get_ip_for_server(se, svr_ip)
    server_vm = get_server_by_handle(svr_vm_hdl).vm()
    cmd = 'iptables -D INPUT -p icmp -s %s -j DROP' % se_back_ip
    out = server_vm.execute_command(cmd)
    logger.debug('Cmd %s Output: %s' % (cmd, out))


def tcpstat(vs_name, core=0, **kwargs):
    # tcpstat is only aggregate for now.
    # When per core stats are supported on SE, we'll add
    # per core api.

    if kwargs.get('disable_aggregate') == 'se':
        api = 'virtualservice/' + vs_name + '/tcpstat?disable_aggregate=SE'
    elif kwargs.get('disable_aggregate') == 'core':
        api = 'virtualservice/' + vs_name + '/tcpstat?disable_aggregate=CORE'
    elif kwargs.get('primary') == 'yes':
        api = 'virtualservice/' + vs_name + '/tcpstat?primary'
    elif kwargs.get('backend') == 'yes':
        api = 'virtualservice/' + vs_name + '/tcpstat?type=BACKEND'
    elif kwargs.get('frontend') == 'yes':
        api = 'virtualservice/' + vs_name + '/tcpstat?type=FRONTEND'
    else:
        api = 'virtualservice/' + vs_name + '/tcpstat'

    resp_code, data = rest.get(api) # tshanks: kwargs also contains all of the tcpstat options here.  Should we be mixing the two?

    # since proc_id is not printed for tcpstat, just return first
    # element for now bug#137 (applicable for disable_aggregate=CORE)
    if kwargs.get('disable_aggregate') == 'core' or kwargs.get('disable_aggregate') == 'se':
        json_data = data
    else:
        json_data = data[0]

    # data = json_data['resource']['tcp_stat_runtime']
    if not json_data:
        logger_utils.fail("ERROR! Data NULL for %s " % api)

    if kwargs.get('key'):
        key = kwargs.get('key')
        return json_data.get(key)

    return json_data