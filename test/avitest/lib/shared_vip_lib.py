from avi_objects.rest import (ApiNode, post)
from avi_objects.infra_utils import get_testbed_variable
import json


def create_auto_allocate_subnet(subnet_info):
    subnet = {}
    subnet['mask'] = int(subnet_info.split('/')[1])
    subnet['ip_addr'] = {}
    subnet['ip_addr']['addr'] = subnet_info.split('/')[0]
    subnet['ip_addr']['type'] = 'V4'
    return subnet

def create_vips_for_ips(ip_list):
    vip_index = 0
    vip_list = []
    subnet_uuid = get_testbed_variable(variable='subnet_uuid')
    for ip in ip_list:
        vip_data = {}
        vip_data['vip_id'] = vip_index
        if ip == 'auto_allocate_ip':
            vip_data['auto_allocate_ip'] = True
        else:
            vip_data['ip_address'] = {}
            vip_data['ip_address']['addr'] = ip
            vip_data['ip_address']['type'] = 'V4'
        if subnet_uuid:
            vip_data['subnet_uuid'] = subnet_uuid
        vip_list.append(vip_data)
        vip_index += 1
    return vip_list

def create_vsvip(vsvip_name, dns_info_list=None, vip_list=None, network=None,
                 auto_allocate_ip=False, auto_allocate_network=None, auto_allocate_subnet=None,
                 vrf_context=None, check_status_code=True):
    vsvip_data = {}
    vsvip_data['name'] = vsvip_name
    vsvip_data['uuid'] = vsvip_name
    if dns_info_list:
        vsvip_data['dns_info'] = dns_info_list
    if vrf_context:
        vsvip_data['vrf_context_ref'] = '/api/vrfcontext/?name=%s' %vrf_context
    vsvip_data['vip'] = []

    # TODO: handle auto_allocate_ips, auto_allocate_networks plural forms
    if auto_allocate_ip:
        vip_data = {}
        vip_data['auto_allocate_ip'] = True
        vip_data['avi_allocated_vip'] = True
        subnet_uuid = get_testbed_variable(variable='subnet_uuid')
        if subnet_uuid:
            vip_data['subnet_uuid'] = subnet_uuid
        vsvip_data['vip'].append(vip_data)
        if network: # REVIEW do we need this? we don't actually use the value
            vsvip_data['ipam_network_subnet'] = {}
            if auto_allocate_network:
                vsvip_data['ipam_network_subnet']['network_ref'] = '/api/network/?name=%s' %auto_allocate_network
            if auto_allocate_subnet:
                vsvip_data['ipam_network_subnet']['subnet'] = auto_allocate_subnet
    elif vip_list:
        vsvip_data['vip'] = vip_list
    else:
        # TODO
        pass
    return post('vsvip', data=json.dumps(vsvip_data), check_status_code=check_status_code)

def update_vs_vip(vsvip_name, vip_index=0, ip_address=None,
                  network_uuid=None, allocate_network=None, vs_ref=None,
                  check_status_code=True):
    '''
    Function to update vsvip object
    @param vsvip_name: VsVip object name which need to be updated
    @param vip_index: Index of vip object to operate on
    @param ip_address: Ip Address of vip to update to
    @param network_uuid: network_uuid to update to
    @param allocate_network: set allocate_network
    @param vs_ref: vs_ref to set
    '''

    vsvip_obj = ApiNode('vsvip', name=vsvip_name)
    _, vsvip_data = vsvip_obj.get(check_status_code=check_status_code)

    vsvip = vsvip_data['vip'][vip_index]
    if ip_address:
        vsvip.pop('ipam_network_subnet', None)
        vsvip['ip_address']['addr'] = ip_address
        vsvip['auto_allocate_ip'] = False
        vsvip['avi_allocated_vip'] = False
    else:
        vsvip['auto_allocate_ip'] = True
    if network_uuid:
        vsvip['network_uuid'] = network_uuid
    if allocate_network:
        vsvip['ipam_network_subnet']['network_uuid'] = allocate_network
    if vs_ref:
        vsvip_data['vs_refs'] = [vs_ref]

    return vsvip_obj.put(data=vsvip_data, check_status_code=check_status_code)
