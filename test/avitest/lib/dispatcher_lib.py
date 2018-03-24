import ipaddress
from time import sleep

from avi_objects.logger import logger
from avi_objects.logger_utils import fail
from lib.vs_lib import get_se_uuids_from_vs_name,  vs_get_primary_se_name, get_vs_secondary_se_list
from lib.se_lib import get_se_info, get_interface_mim_stats_for_se
import avi_objects.rest as rest
import avi_objects.infra_utils as infra_utils


def get_ip_mac_addr(ip, vm, retry):
    """ This function is to get the mac address for a given ip within
    the subnet. We have this function because our router is responding
    our arp request really slowwww....

    Args:
        :param ip: IP Address for which you want to find MAC Address
        :type ip: str
        :param vm: VM Object on which you want to check
        :type vm: Object
        :param retry: Number of retrys
        :type retry: int

    Return:
        MAC Address for Given IP address 

    """
    retry_sec = retry
    cmd = 'rm /tmp/ping_out'
    vm.execute_command(cmd)
    if type(ipaddress.ip_address(unicode(ip))) == ipaddress.IPv6Address:
        cmd = 'ping6 -c 10 ' + ip + ' &> /tmp/ping_out &'
    else:
        cmd = 'ping -c 10 ' + ip + ' &> /tmp/ping_out &'
    logger.info(cmd)
    vm.execute_command(cmd)
    cmd = 'cat /tmp/ping_out'
    # retry until ping is successful.
    while retry_sec > 0:
        last_line = ''
        vm.execute_command(cmd)
        out = vm.execute_command('cat /tmp/ping_out')
        if out:
            last_line = out[-1]
            logger.trace('last line is: %s' % last_line)
        if 'rtt' in last_line:
            break

        sleep(1)
        retry_sec -= 1

        if retry_sec < 1:
            fail('not able to connect to next hop! Please check by pinging gateway')

    # trying to get mac address from arp table
    if ":" in ip:
        cmd = 'ip -6 neigh | grep "' + ip + ' " | awk \'{print $5}\''
    else:
        cmd = 'arp -n | grep "' + ip + ' " | awk \'{print $3}\''
    out = vm.execute_command(cmd)
    if out == '':
        fail('Still doesn\'t get Arp entry! Please check by pinging gateway')
    return out[0][:-1]


def get_dst_mac(client_vm, client_ip, vip):
    """
    API helps to get destination MAC Address

    Args:
        :param client_vm: Client VM Object
        :type client_vm: Object
        :param client_ip: Client VM IP
        :type client_ip: str
        :param vip: VIP IP address
        :type vip: str

    Return:
        Destination MAC Address for VIP
    
    """
    if ":" in client_ip:
        return get_ip_mac_addr(vip, client_vm, 60)
    else:
        cip_mask = '.'.join(client_ip.split('.')[0:3])
        vip_mask = '.'.join(vip.split('.')[0:3])
        gateway_ip = cip_mask + '.1'
        logger.info("cip_mask: %s, vip_mask: %s" % (cip_mask, vip_mask))
        if cip_mask == vip_mask:
            return get_ip_mac_addr(vip, client_vm, 60)


def clear_dispatcher_stat(vs_name):
    se_uuids = get_se_uuids_from_vs_name(vs_name)
    for se_uuid in se_uuids:
        rest.post('serviceengine', uuid=se_uuid, path='flowtablestat/clear')


def get_all_vnic_flow_create_on_primary_se(vs_name):
    se_name = vs_get_primary_se_name(vs_name)
    logger.debug('get_all_dispatcher_stats_on_primary_se: %s' % se_name)
    se_info = get_se_info(se_name, connected=True)
    d_stats = []
    for vnic in se_info['data_vnics']:
        if_name = vnic['if_name']
        params = {'intfname': if_name}
        resp_code, json_data = rest.get('serviceengine', name=se_name, path='flowtablestat', params=params)
        for dsr in json_data:
            if 'dispatch' in dsr:
                d_stats.append(dsr['dispatch'][0])

    if infra_utils.get_cloud_context_type() == 'baremetal':
        vnic = se_info['mgmt_vnic']
        if_name = vnic['if_name']
        params = {'intfname': if_name}
        resp_code, json_data = rest.get('serviceengine', name=se_name, path='flowtablestat', params=params)
        for dsr in json_data:
            if 'dispatch' in dsr:
                d_stats.append(dsr['dispatch'][0])

    c = 0
    for stats in d_stats:
        c = c + stats['flow_rx_create']
    return c


def get_interface_mim_stats_for_vs(vs):
    se = vs_get_primary_se_name(vs)
    logger.debug('primary: %s' % se)
    c = get_interface_mim_stats_for_se(se)
    se_list = get_vs_secondary_se_list(vs)
    for se in se_list:
        logger.info('primary: %s' % se)
        c += get_interface_mim_stats_for_se(se)
    return c


def get_all_vnic_flows_created_on_all_secondary_se(virtualservice):
    se_name_list = get_vs_secondary_se_list(virtualservice)
    logger.info('get dispatcher stats on secondary: se_name_list %s' % se_name_list)
    c = 0
    for se_name in se_name_list:
        se_info = get_se_info(se_name, connected=True)
        d_stats = []
        for vnic in se_info['data_vnics']:
            if_name = vnic['if_name']
            params = {'intfname': if_name}
            resp_code, json_data = rest.get('serviceengine', name=se_name, path='flowtablestat', params=params)
            for dsr in json_data:
                if 'dispatch' in dsr:
                    d_stats.append(dsr['dispatch'][0])

        if infra_utils.get_cloud_context_type() == 'baremetal':
            vnic = se_info['mgmt_vnic']
            if_name = vnic['if_name']
            params = {'intfname': if_name}
            resp_code, json_data = rest.get('serviceengine', name=se_name, path='flowtablestat', params=params)
            for dsr in json_data:
                if 'dispatch' in dsr:
                    d_stats.append(dsr['dispatch'][0])

        for stats in d_stats:
            c = c + stats['flow_rx_create']

    return c
