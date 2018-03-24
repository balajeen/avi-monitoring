import json

import avi_objects.infra_utils as infra_utils
import avi_objects.logger_utils as logger_utils
import lib.common as common
import avi_objects.rest as rest
from avi_objects.logger import logger


def create_configured_subnet(subnet):
    configured_subnet = {}
    configured_subnet['prefix'] = {}
    configured_subnet['prefix']['mask'] = subnet['mask']
    configured_subnet['prefix']['ip_addr'] = {}
    configured_subnet['prefix']['ip_addr']['addr'] = subnet['ip_addr']
    configured_subnet['prefix']['ip_addr']['type'] = "V4"
    return configured_subnet


def create_static_range(static_range_begin, static_range_end):
    # TODO: this could be a list if multiple begin-end pairs
    static_range = {}
    if static_range_begin:
        static_range['begin'] = {}
        static_range['begin']['addr'] = static_range_begin
        static_range['begin']['type'] = "V4"
    if static_range_end:
        static_range['end'] = {}
        static_range['end']['addr'] = static_range_end
        static_range['end']['type'] = "V4"
    return static_range


def network_set_subnet_static_range(net_name,
                                    ip_begin_octet, ip_end_octet):
    import string
    _, json_data = rest.get('network', name=net_name)
    json_subnet_found = None
    if 'configured_subnets' not in json_data:
        json_data['configured_subnets'] = list()
    if len(json_data['configured_subnets']) > 0:
        json_subnet_found = json_data['configured_subnets'][0]
    '''
    for json_subnet in json_data['configured_subnets']:
        if (json_subnet['prefix']['ip_addr']['addr'] == subnet_ip) and \
            (json_subnet['prefix']['mask'] == subnet_mask):
            json_subnet_found = json_subnet
    '''
    config = infra_utils.get_config()
    if json_subnet_found:
        ip = json_data['configured_subnets'][0]['prefix']['ip_addr']['addr']
    else:
        for network_name, network_data in config.testbed[config.site_name].networks_json.iteritems():
            if net_name == network_data.get('name'):
                ip = network_data.get('ip')
                break

    ip_parts = ip.split('.')[:-1]
    subnet_ip = string.join(ip_parts, '.') + '.0'

    if not json_subnet_found:
        json_subnet = dict()
        json_subnet['prefix'] = {'mask': 24,
                                 'ip_addr': {'addr': subnet_ip,
                                             'type': 'V4'
                                             }
                                 }
        json_data['configured_subnets'].append(json_subnet)
        json_subnet_found = json_subnet
    if 'static_ranges' in json_subnet_found.keys():
        del json_subnet_found['static_ranges']
    if 'static_ips' in json_subnet_found.keys():
        del json_subnet_found['static_ips']
    json_subnet_found['static_ranges'] = list()
    ip_range_begin = string.join(ip_parts, '.') + '.' + str(ip_begin_octet)
    ip_range_end = string.join(ip_parts, '.') + '.' + str(ip_end_octet)
    json_subnet_found['static_ranges'].append({'begin': {'addr': ip_range_begin,
                                                         'type': 'V4'
                                                         },
                                               'end': {'addr': ip_range_end,
                                                       'type': 'V4'
                                                       }
                                               })
    rest.put('network', name=net_name, data=json_data)


def network_create(name, configured_subnet, static_range_list=None, check_status_code=True):
    """

    :param name:
    :param configured_subnet:
    :param static_range_list:
    :param check_status_code:
    :return:
    """

    if not configured_subnet:
        logger_utils.fail('Must specify configured subnet')

    network_data = {}
    network_data['name'] = name
    network_data['uuid'] = name
    network_data['configured_subnets'] = []

    if static_range_list:
        static_ips = []
        for static_range in static_range_list:
            static_ips.append({'type': 'V4', 'addr': static_range})

        configured_subnet = {
            'prefix': configured_subnet, 'static_ips': static_ips
        }

    network_data['configured_subnets'].append(configured_subnet)
    return rest.post('network', data=json.dumps(network_data), check_status_code=check_status_code)


def network_update(name, tenant='admin', **kwargs):
    """

    :param name:
    :param tenant:
    :param kwargs:
    :return:
    """
    status_code, json_network_data = rest.get('network', name=name)
    subnet_ip           = kwargs.get('subnet_ip',None)
    subnet_mask         = kwargs.get('subnet_mask',None)
    stat_ip             = kwargs.get('static_ip', None)
    old_begin_ip        = kwargs.get('old_begin_ip', None)
    new_begin_ip        = kwargs.get('new_begin_ip', None)
    old_end_ip          = kwargs.get('old_end_ip', None)
    new_end_ip          = kwargs.get('new_end_ip', None)
    update_static_range = kwargs.get('update_static_range', False)

    if subnet_ip and subnet_mask:
        add_configured_subnets = {
            'prefix': {
                'mask':subnet_mask,
                'ip_addr': {
                    'type':0,'addr':subnet_ip
                }
            }
        }
        json_network_data['configured_subnets'].append(add_configured_subnets)

    if stat_ip:
        stat_ip_dict = {
            'type': "V4",
            'addr': stat_ip
        }
        if 'configured_subnets' in json_network_data.keys():
            json_network_data['configured_subnets'].append(add_configured_subnets)
        else:
            json_network_data['configured_subnets'] = [add_configured_subnets]

        json_network_data['static_ips'].append(stat_ip_dict)

    if update_static_range:
        for static_range in json_network_data['configured_subnets'][0]['static_ranges']:
            if static_range['begin'] == old_begin_ip and static_range['end'] == old_end_ip:
                static_range['begin'] = new_begin_ip
                static_range['end'] = new_end_ip

    rest.put('network', name=json_network_data['name'], data=json_network_data)


def network_delete(name, **kwargs):
    """

    :param name:
    :param kwargs:
    :return:
    """

    logger.info('kwargs in delete_network:%s' % kwargs)
    rest.delete('network', name=name)
    common.validate_after_delete('network', name)


def get_ip_count(nw_name, **kwargs):
    """

    :param nw_name:
    :param kwargs:
    :return:
    """

    _, json_data = rest.get('networkruntime', name=nw_name)
    count_type = kwargs.get('count_type', None)
    subnet_ip = kwargs.get('subnet_ip', None)
    subnet_mask = kwargs.get('subnet_mask', None)

    if subnet_ip and subnet_mask:
        subnet_mask = int(subnet_mask)
        for subnet in json_data['subnet_runtime']:
            if subnet['prefix']['ip_addr']['addr'] == subnet_ip and subnet['prefix']['mask'] == subnet_mask:
                if count_type == 'total_ip':
                    return subnet['total_ip_count']
                if count_type == 'used_ip':
                    return subnet['used_ip_count']
                if count_type == 'free_ip':
                    return subnet['free_ip_count']
                if not count_type:
                    ip_count = {}
                    ip_count['total_ip'] = subnet['total_ip_count']
                    ip_count['used_ip'] = subnet['used_ip_count']
                    ip_count['free_ip'] = subnet['free_ip_count']
                    return ip_count
    else:
        if count_type == 'total_ip':
            return json_data['subnet_runtime'][0]['total_ip_count']
        if count_type == 'used_ip':
            return json_data['subnet_runtime'][0]['used_ip_count']
        if count_type == 'free_ip':
            return json_data['subnet_runtime'][0]['free_ip_count']
        if not count_type:
            ip_count = dict()
            ip_count['total_ip'] = json_data['subnet_runtime'][0]['total_ip_count']
            ip_count['used_ip'] = json_data['subnet_runtime'][0]['used_ip_count']
            ip_count['free_ip'] = json_data['subnet_runtime'][0]['free_ip_count']
            return ip_count


def set_network_key_value(net_name, key, value):
    """

    :param net_name:
    :param key:
    :param value:
    :return:
    """
    if len(net_name.split('-')) == 1:
        net_name = get_network_name_by_alias(net_name)
    else:
        net_name = net_name
    _, json_data = rest.get('network', name=net_name)
    if json_data.get('results'):
        json_data = json_data['results'][0]
    if key == 'vrf_context_ref':
        json_data['vrf_context_ref'] = '/api/vrfcontext?name=%s' % value
    else:
        json_data[key] = value
    rest.put('network', name=net_name, data=json_data)


def network_disable_dhcp(net_name):
    """

    :param net_name:
    :return:
    """
    set_network_key_value(net_name, 'dhcp_enabled', False)


def block_ips_on_network(network, ip_last_octet_start, ip_last_octet_end):
    """
    Block bunch on IP's on this network as used
    :param self:
    :param network:
    :param ip_last_octet_start:
    :param ip_last_octet_end:
    :return:
    """
    config = infra_utils.get_config()
    mode = config.get_mode()
    site_name = mode['site_name']

    for network_name, network_data in config.testbed[
        site_name].networks_json.iteritems():
        if network == network_data.get('name'):
            ip = network_data.get('ip')
            ip_last_octet = ip.split('.')[-1]
            if ip_last_octet_start <= ip_last_octet <= ip_last_octet_end:
                config.testbed[site_name]['networks_json']['ip'] = ""
            break
    else:
        logger_utils.fail(
            'Network name not in network address dict of vcenter: %s' % network)


def get_network_subnet(testbed_net):
    config = infra_utils.get_config()
    mode = config.get_mode()
    site_name = mode['site_name']
    ip = infra_utils.get_ip_for_network(testbed_net)
    logger.info("##ip =%s" %ip)
    static_ip = ip.rsplit(".", 1)[0] + ".254"
    logger.info("##ip addr =%s static ip=%s" %(ip, static_ip))
    return ip, static_ip


def get_test_subnet_networkprefix(subnet):
    # Get the network details from vcenter object
    config = infra_utils.get_config()
    dvpgnw = config.testbed[config.site_name].networks_json[subnet]
    nw, mask = dvpgnw['ip'], dvpgnw['mask']
    # Convert 10.50.0.0 -> 10.50
    # TODO: Implement in clean way
    subnet = '.'.join([s for s in nw.split('.') if s != '0'])
    return subnet


def delete_subnet_from_network(name,  tenant='admin', **kwargs):
    status_code, json_data = rest.get('network', name=name)
    subnet_ip = kwargs.get('subnet_ip', None)
    subnet_mask = kwargs.get('subnet_mask', None)
    is_all_subnet = kwargs.get('remove_all', False)
    if is_all_subnet:
        json_data['configured_subnets'] = []
    else:
        subnet_mask = int(subnet_mask)
        for subnet in json_data['configured_subnets']:
            if subnet['prefix']['mask'] == subnet_mask and subnet['prefix']['ip_addr']['addr'] == subnet_ip:
                json_data['configured_subnets'].remove(subnet)
    rest.put('network', name=json_data['name'], data=json_data)


def is_subnet_discovered(nw_name):
    _, json_data = rest.get('vimgrnwruntime', name=nw_name)
    #json_data = json_data['results'][0]
    return 'ip_subnet' in json_data.keys()


def wait_till_subnet_removed(nw_name, timeout=120):
    retry_count = timeout/10

    @logger_utils.aretry(retry=retry_count, period=timeout)
    def retry_action():
        return not is_subnet_discovered(nw_name)

    return retry_action()


def wait_till_subnet_discovered(nw_name, timeout=120):
    retry_count = timeout/10

    @logger_utils.aretry(retry=retry_count, period=timeout)
    def retry_action():
        return not is_subnet_discovered(nw_name)

    return retry_action()


def resize_subnet(name, **kwargs):
    _, json_data = rest.get('network', name=name)
    subnet_ip = kwargs.get('subnet_ip', None)
    s_mask = kwargs.get('subnet_mask', None)
    new_subnet_mask = kwargs.get('new_subnet_mask', None)
    stat_ip = kwargs.get('static_ip', None)
    del_stat_ip = kwargs.get('delete_stat_ip', None)
    subnet_mask = int(s_mask)
    for index, subnet in enumerate(json_data['configured_subnets']):
        if subnet['prefix']['mask'] == subnet_mask and subnet['prefix']['ip_addr']['addr'] == subnet_ip:
            if new_subnet_mask:
                json_data['configured_subnets'][index]['prefix'][
                    'mask'] = new_subnet_mask
            if stat_ip:
                stat_ip_dict = {'type': "V4", 'addr': stat_ip}
                if 'static_ips' in subnet.keys():
                    json_data['configured_subnets'][index][
                        'static_ips'].append(stat_ip_dict)
                else:
                    json_data['configured_subnets'][index]['static_ips'] = [
                        stat_ip_dict]
            if del_stat_ip:
                for static_ip in subnet['static_ips']:
                    if static_ip['addr'] == del_stat_ip:
                        json_data['configured_subnets'][index][
                            'static_ips'].remove(static_ip)
    rest.put('network', name=json_data['name'], data=json_data)


def validate_se_static_ips_on_network(nw_name):
    """

    :param nw_name:
    :return:
    """
    retry = 6
    _, json_data = rest.get('networkruntime', name=nw_name)
    json_data = json_data['results'][0] if json_data.get('results',
                                                         None) else json_data
    for val in json_data['subnet_runtime'][0]['ip_alloced']:
        mac_found = False
        ip_found = False
        se_ref = val['se_ref']
        se_uuid = rest.get_uuid_from_ref(se_ref)
        mac = val['mac']
        while retry > 0:
            logger_utils.asleep(delay=10)
            _, se_json = rest.get('serviceengine', uuid=se_uuid)
            for data_vnic in se_json.get('data_vnics', []):
                if data_vnic['mac_address'] == mac:
                    mac_found = True
                    for vnic_network in data_vnic.get('vnic_networks', []):
                        if (vnic_network['mode'] == 'STATIC' and
                                vnic_network['ip']['ip_addr']['addr'] == val['ip']['addr']):
                            ip_found = True
            retry -= 1
            if mac_found and ip_found:
                break
        if not mac_found:
            logger_utils.fail('Mac address %s not found on SE %s' % (mac, se_uuid))
        if not ip_found:
            logger_utils.fail('IP %s not found on mac address %s on SE %s' %
                              (val['ip']['addr'], mac, se_uuid))


def get_network_name_by_alias(net_alias):
    """

    :param net_alias:
    :return:
    """
    config = infra_utils.get_config()
    for net, net_data in config.testbed[
        config.site_name].networks_json.iteritems():
        if net == net_alias:
            return net_data.get('name')
    return None


def network_enable_exclude_discovered_subnets(net_name):
    """

    :param net_name:
    :return:
    """
    set_network_key_value(net_name, 'exclude_discovered_subnets', True)


def network_disable_exclude_discovered_subnets(net_name):
    """

    :param net_name:
    :return:
    """
    set_network_key_value(net_name, 'exclude_discovered_subnets', False)


def network_enable_dhcp(net_name):
    """

    :param net_name:
    :return:
    """
    set_network_key_value(net_name, 'dhcp_enabled', True)


def get_ip_for_last_octet(network, last_octet):
    """

    :param self:
    :param network:
    :param last_octet:
    :return:
    """
    config = infra_utils.get_config()
    mode = config.get_mode()
    site_name = mode['site_name']
    addr_dict = config.testbed[site_name].networks_json
    for network_name, network_data in addr_dict.iteritems():
        if network == network_data.get('name'):
            _tmp = (addr_dict[network_name]['ip'].split(".")[:-1])
            _tmp.append(str(last_octet))
            ip = ".".join(_tmp)
            return ip
    else:
        logger_utils.fail(
                'Network name not in network address dict of vcenter: %s' %
            network)


def get_mask_for_network(network):
    """

    :param self:
    :param network_name:
    :return:
    """
    config = infra_utils.get_config()
    mode = config.get_mode()
    site_name = mode['site_name']
    addr_dict = config.testbed[site_name].networks_json
    for network_name, network_data in addr_dict.iteritems():
        if network == network_data.get('name'):
            return network_data.get('mask')
    else:
        logger_utils.fail(
            "vcenter get_mask_for_network error: not found network name: %s" % network)


def restart_network_mgr(vm):
    """

    :param vm:
    :return:
    """
    vm.execute_command('restart aviportalnetworkmgr')


def get_prefix_and_mask_of_nw(nw):
    config = infra_utils.get_config()
    mode = config.get_mode()
    site_name = mode['site_name']
    ip = config.testbed[site_name].networks_queue.get_ip_for_network(nw)
    mask = get_mask_for_network(nw)
    return ip, mask


def get_gateway_nw(testbed_net):
    ip = infra_utils.get_ip_for_network(testbed_net)
    gateway = ip.rsplit(".",1)[0] + ".1"
    return gateway


def network_set_vrf_context(net_name, vrf_name):
    set_network_key_value(net_name, 'vrf_context_ref', vrf_name)
