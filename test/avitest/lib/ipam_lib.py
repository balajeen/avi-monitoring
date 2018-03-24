import json

from avi_objects.logger import logger
from dns import resolver
import avi_objects.rest as rest
import avi_objects.logger_utils as logger_utils
import lib.controller_lib as controller_lib
import lib.network_lib as network_lib
import avi_objects.infra_utils as infra_utils


def create_basic_ipam_profile(name, ipam_type, **kwargs):
    """

    :param name:
    :param ipam_type:
    :param kwargs:
    :return:
    """
    if ipam_type not in IpamDnsType.keys():
        e_str = "%s: not in one of %s"%(ipam_type, IpamDnsType.keys())
        logger.info(e_str)
        logger_utils.fail(e_str)

    tenant = kwargs.get('tenant', infra_utils.get_mode()['tenant'])
    ipam_data = {
        'name': name,
        'type': IpamDnsType.Value(ipam_type)
    }
    rest.post('ipamdnsproviderprofile', data=json.dumps(ipam_data),
              tenant=tenant)


def create_ipamdns_profile(name, ipam_type, usable_network=None, check_status_code=True, service_domain=None):
    ''' basic version of ipam create '''
    # if ipam_type not in IpamDnsType.keys():
    #    logger_utils.fail('ipam_type %s not in one of %s' % (ipam_type, IpamDnsType.keys()))

    ipam_data = {}
    ipam_data['name'] = name
    ipam_data['type'] = ipam_type
    if ipam_type in ['IPAMDNS_TYPE_INTERNAL', 'IPAMDNS_TYPE_INTERNAL_DNS']:
        ipam_data['internal_profile'] = {}
        if usable_network:
            usable_networks = []
            if type(usable_network) == list:
                for network in usable_network:
                    usable_networks.append('/api/network/?name=%s' % network)
            else:
                usable_networks.append('/api/network/?name=%s' % usable_network)
            ipam_data['internal_profile']['usable_network_refs'] = usable_networks
        if service_domain:
            dns_service_domain = []
            obj = {
                "num_dns_ip": 1,
                "domain_name": service_domain,
                "pass_through": True
            }
            dns_service_domain.append(obj)
            ipam_data['internal_profile']['dns_service_domain'] = dns_service_domain

            # TODO handle svc_domain_name, svc_domain_list
    # TODO: handle other ipam types

    ipamprofile = rest.ApiNode('ipamdnsproviderprofile')
    return ipamprofile.post(data=json.dumps(ipam_data), check_status_code=check_status_code)


def update_ipam_profile(ipam_name, **kwargs):
    """

    :param ipam_name:
    :param kwargs:
    :return:
    """
    new_username = kwargs.get('new_username')
    new_password = kwargs.get('new_password')
    json_ipam_data = rest.get('ipamdnsproviderprofile', name=ipam_name)

    if new_username and new_password:
        json_ipam_data['username'] = new_username
        json_ipam_data['password'] = new_password

        if json_ipam_data.get('openstack_profile'):
            json_ipam_data.get('openstack_profile')['username'] = new_username
            json_ipam_data.get('openstack_profile')['password'] = new_password

        if json_ipam_data.get('infoblox_profile'):
            json_ipam_data.get('infoblox_profile')['username'] = new_username
            json_ipam_data.get('infoblox_profile')['password'] = new_password

        rest.get('ipamdnsproviderprofile', name=ipam_name, data=json_ipam_data)


def add_ipam_and_dns_to_cloud(ipam_name=None, dns_name=None, **kwargs):
    cloud_name = kwargs.get('cloud', infra_utils.get_mode()['cloud'])
    cloud_obj = rest.ApiNode('cloud', name=cloud_name)
    status_code, json_data = cloud_obj.get()

    if ipam_name:
        json_data['ipam_provider_ref'] = '/api/ipamdnsproviderprofile?name=%s' % ipam_name
    if dns_name:
        json_data['dns_provider_ref'] = '/api/ipamdnsproviderprofile?name=%s' % dns_name
    logger.trace('JSON data: %s' % json_data)
    cloud_obj.put(data=json.dumps(json_data))


def del_ipam_and_dns_from_cloud(ipam_name=None, dns_name=None, **kwargs):
    cloud_name = kwargs.get('cloud', infra_utils.get_mode()['cloud'])
    cloud_obj = rest.ApiNode('cloud', name=cloud_name)
    status_code, json_data = cloud_obj.get()

    if ipam_name:
        json_data.pop('ipam_provider_ref', None)
    if dns_name:
        json_data.pop('dns_provider_ref', None)
    cloud_obj.put(data=json.dumps(json_data))


def validate_vs_dns_info(vs_name, retries=5, **kwargs):
    """

    :param vs_name:
    :param retries:
    :param kwargs:
    :return:
    """

    dns_vs_vip = kwargs.get('dns_vs_vip', '')
    if not dns_vs_vip:
        logger.info("[SKIPPING] DNS check for VS as no DNS vip provided. Note, "
                    "controller based DNS is not supported anymore.")
        return True
    import lib.vs_lib as vs_lib
    vs_json = vs_lib.get_vs(vs_name, tenant=kwargs.get('tenant', 'admin'))
    if vs_json['type'] == 'VS_TYPE_VH_CHILD':
        if rest.get_cloud_type() != 'openshift':
            logger.info("[SKIPPING] DNS check for VS as SNI child are not "
                        "currently supported for non-openshift clouds")
            return True
        parent_ref = vs_json['vh_parent_vs_ref']
        parent_uuid = parent_ref.split('/')[-1]
        _, parent_vs = rest.get('virtualservice', uuid=parent_uuid)
        parent_vs_name = parent_vs['name']

        logger.info('SNI child VS detected; doing DNS on parent VS %s' %
                    parent_vs_name)
        child_fqdn = vs_json['vh_domain_name']
        parent_fqdns = [t['fqdn'] for t in parent_vs['dns_info']]
        if child_fqdn not in parent_fqdns:
            return False
        vs_name = parent_vs_name  # REVIEW should it be parent or child name?
        vs_json = parent_vs
        dns_name = child_fqdn
    else:
        dns_name = vs_json['ipam_dns_records'][0]['fqdn']

    logger.trace('vs_json: %s' % vs_json)
    if 'floating_ip' in vs_json:
        ip = vs_json['vip'][0]['floating_ip']['addr']
    else:
        ip = vs_json['vip'][0]['ip_address']['addr']

    ports = sorted([srv['port'] for srv in vs_json['services']])
    logger.info("VS [%s]: IP %s, DNS %s, Ports: %s" % (
        vs_name, ip, dns_name, ports))
    count = retries
    while count:
        if vs_lib.vs_check_ip_ports(vs_name, ip, dns_name, ports,
                             dns_vs_vip=dns_vs_vip):
            return True
        count -= 1
        logger_utils.asleep(delay=5)
        logger_utils.fail("DNS check failed!!")


def dns_get_resolver(ns_list=[], append=False, use_controller=True,
                     dns_vs_vip=None):
    """

    :param ns_list:
    :param append:
    :param use_controller:
    :param dns_vs_vip:
    :return:
    """

    dns_resolver = resolver.Resolver()
    # Review: reduce the default timeout of 30 seconds
    # so checking deleted entries will return faster
    # checking for existing entries may time out spuriously but generally we
    # have a separate retry mechanism on them
    dns_resolver.lifetime = 5
    if not append:
        dns_resolver.nameservers = []
    dns_resolver.nameservers.extend(ns_list)
    if dns_vs_vip: # prefer dns vs
        dns_resolver.nameservers.append(dns_vs_vip)
    elif use_controller: # fallback to controller
        dns_resolver.nameservers.append(controller_lib.get_controller_ip())
    logger.info("DNS resolvers: %s" % dns_resolver.nameservers)
    return dns_resolver


def dns_get_ips_for_fqdn(dns_resolver, qname):
    """

    :param dns_resolver:
    :param qname:
    :return:
    """

    try:
        rsp = dns_resolver.query(qname, 'A')
    except Exception as e:
        # Try with a different port 8053, in case
        #  of controller running as a container
        dns_resolver.port = 8053
        try:
            rsp = dns_resolver.query(qname, 'A')
        except Exception as e:
            # Reset the port for every query fail
            dns_resolver.port = 53
            logger.info("DNS get IPs returned: %s:%s" % (type(e), str(e)))
            return []
    ips = []
    for record in rsp:
        ips.append(record.address)
    return sorted(ips)


def dns_get_ip_ports_for_fqdn(dns_resolver, qname):
    ips = dns_get_ips_for_fqdn(dns_resolver, qname)
    if not ips:
        logger.info("No IPs found for '%s'" % qname)
        return [], []
    ports = dns_get_ports_for_fqdn(dns_resolver, qname)
    return ips, ports


def dns_get_ports_for_fqdn(dns_resolver, qname):
    """

    :param dns_resolver:
    :param qname:
    :return:
    """

    try:
        rsp = dns_resolver.query(qname, 'SRV')
    except Exception as e:
        # Try with a different port 8053, in case
        #  of controller running as a container
        dns_resolver.port = 8053
        try:
            rsp = dns_resolver.query(qname, 'SRV')
        except Exception as e:
            # Reset the port for every query fail
            dns_resolver.port = 53
            logger.info("DNS get Ports returned: %s" % str(e))
            return []
    ports = []
    for record in rsp:
        ports.append(record.port)
    return sorted(ports)


def validate_vs_dns_deleted(vs_dns_name, retries=5, dns_vs_vip=None, **kwargs):
    """

    :param vs_dns_name:
    :param retries:
    :param dns_vs_vip:
    :param kwargs:
    :return:
    """

    if not dns_vs_vip:
        logger.info("[SKIPPING] DNS check for VS as no DNS vip provided. Note,"
                    " controller based DNS is not supported anymore.")
        return True

    count = retries
    while count:
        ipl, portl = dns_get_ip_ports_for_fqdn(dns_get_resolver(
            dns_vs_vip=dns_vs_vip), vs_dns_name)
        if ipl or portl:
            count -= 1
            logger_utils.asleep(delay=5)
        else:
            return True
        logger_utils.fail("Unexpected[%s]: DNS entries %s, %s found" % (
        vs_dns_name, ipl, portl))


def delete_ipam_profile(ipam_name, **kwargs):
    """

    :param ipam_name:
    :param kwargs:
    :return:
    """

    rest.delete('ipamdnsproviderprofile', name=ipam_name)


def create_internal_ipam_profile():
    """

    :return:
    """

    static_addr= network_lib.get_network_subnet("net1")
    subnet = {'ip_addr': {"type": "V4", "addr": static_addr[0]}, 'mask':24}
    network_lib.network_create("nw-autoallocate", subnet, static_range_list=[static_addr[1]])
    create_ipamdns_profile("ipam_dns_profile", 'IPAMDNS_TYPE_INTERNAL', usable_network="nw-autoallocate")
    add_ipam_to_cloud("ipam_dns_profile")


def add_ipam_to_cloud(ipam_name, tenant='admin', **kwargs):
    """

    :param ipam_name:
    :param tenant:
    :param kwargs:
    :return:
    """

    cloud_name = kwargs.get('cloud', infra_utils.get_mode()['cloud'])
    status_code, json_data = rest.get('cloud', name=cloud_name)
    logger.info('add ipam: %s to cloud: %s' % (ipam_name, json_data['name']))
    json_data['ipam_provider_ref'] = '/api/ipamdnsproviderprofile?name=%s' % ipam_name
    rest.put('cloud', name=json_data['name'], data=json_data)


def del_ipam_from_cloud(ipam_name=None, **kwargs):
    """

    :param ipam_name:
    :param kwargs:
    :return:
    """
    cloud_name = kwargs.get('cloud', infra_utils.get_mode()['cloud'])
    cloud_obj = rest.ApiNode('cloud', name=cloud_name)
    status_code, json_data = cloud_obj.get()

    if ipam_name:
        json_data.pop('ipam_provider_ref', None)

    cloud_obj.put(data=json.dumps(json_data))


def del_internal_ipam_profile():
    del_ipam_and_dns_from_cloud(ipam_name="ipam_dns_profile")
    delete_ipam_profile("ipam_dns_profile")
    network_lib.network_delete("nw-autoallocate")


def add_network_in_ipamprofile(ipamprofile_name, network_to_add):
    ipam_status_code, ipam_status_data = rest.get('ipamdnsproviderprofile', name=ipamprofile_name)
    networks_to_add = []
    if type(network_to_add) == list:
        for network in network_to_add:
            networks_to_add.append('/api/network/?name=%s' % network)
    else:
        networks_to_add.append('/api/network/?name=%s' % network_to_add)
    ipam_status_data['internal_profile']['usable_network_refs'].extend(networks_to_add)
    rest.put('ipamdnsproviderprofile', name=ipamprofile_name, data=ipam_status_data)


def remove_network_from_ipamprofile(ipamprofile_name, networks_to_remove):
    ipam_status_code, ipam_status_data = rest.get('ipamdnsproviderprofile', name=ipamprofile_name)
    if type(networks_to_remove) == list:
        for network in networks_to_remove:
            usable_network_status, network_remove_ref = rest.get('network', name=network)
            ipam_status_data['internal_profile']['usable_network_refs'].remove(network_remove_ref['url'])
    else:
        usable_network_status, usable_network_ref = rest.get('network',
                                                             name=networks_to_remove)
        ipam_status_data['internal_profile']['usable_network_refs'].remove(
            usable_network_ref['url'])

    rest.put('ipamdnsproviderprofile', name=ipamprofile_name, data=ipam_status_data)


def add_east_west_to_cloud(ipam_name=None, dns_name=None, **kwargs):
    """

    :param ipam_name:
    :param dns_name:
    :param tenant:
    :param kwargs:
    :return:
    """
    cloud_name = kwargs.get('cloud', infra_utils.get_mode()['cloud'])
    tenant = kwargs.get('tenant', infra_utils.get_mode()['tenant'])
    status_code, json_data = rest.get('cloud', name=cloud_name)
    logger.info('add ipam: %s to cloud: %s' % (ipam_name, json_data['name']))

    if ipam_name:
        logger.info(
            'add ipam: %s to cloud: %s' % (ipam_name, json_data.get('name')))
        json_data['east_west_ipam_provider_ref'] = '/api/ipamdnsproviderprofile?name=%s' % ipam_name

    if dns_name:
        logger.info(
            'add dns: %s to cloud: %s' % (dns_name, json_data.get('name')))
        json_data['east_west_dns_provider_ref'] = '/api/ipamdnsproviderprofile?name=%s' % dns_name

    rest.put('cloud', name=json_data.get('name'), data=json_data, tenant=tenant)


def del_east_west_from_cloud(ipam_name=None,dns_name=None,**kwargs):
    """

    :param ipam_name:
    :param dns_name:
    :param tenant:
    :param kwargs:
    :return:
    """
    cloud_name = kwargs.get('cloud', infra_utils.get_mode()['cloud'])
    tenant = kwargs.get('tenant', infra_utils.get_mode()['tenant'])
    status_code, json_data = rest.get('cloud', name=cloud_name)
    logger.info('add ipam: %s to cloud: %s' % (ipam_name, json_data['name']))

    if ipam_name:
        json_data.pop('east_west_ipam_provider_ref', None)

    if dns_name:
        json_data.pop('east_west_dns_provider_ref', None)

    rest.put('cloud', name=json_data['name'], data=json_data, tenant=tenant)


def del_domain_from_profile(ipam_name, **kwargs):
    """

    :param ipam_name:
    :param tenant:
    :param kwargs:
    :return:
    """
    tenant = kwargs.get('tenant', infra_utils.get_mode()['tenant'])
    status_code, json_data = rest.get('ipamdnsproviderprofile', name=ipam_name,
                                      tenant=tenant)
    try:
        json_data.get('internal_profile').get('dns_service_domain').pop(0)
    except Exception as e:
        pass

    rest.put('ipamdnsproviderprofile', name=ipam_name, data=json_data, **kwargs)
