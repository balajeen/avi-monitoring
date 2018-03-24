from lib.se_validations_lib import se_check
from lib.se_lib import (get_se_in_group, wait_for_se_vnic_to_disconnect,
                        get_se_list_in_group, move_se_to_segroup_by_uuid,
                        get_se_name_from_uuid, se_get_data_vnic_nw_uuid)
from lib.vs_lib import vs_get_se_list
from avi_objects.logger import logger
import avi_objects.rest as rest
import avi_objects.infra_utils as infra_utils
import avi_objects.logger_utils as logger_utils
import json


def vrf_get(vrf_name='admin', **kwargs):
    """

    :param vrf_name:
    :param kwargs:
    :return:
    """
    uri_specific = kwargs.get('uri_specific', None)
    if uri_specific:
        resp_code, json_data = rest.get('vrfcontext', name=vrf_name, path='uri_specific')
    else:
        resp_code, json_data = rest.get('vrfcontext', name=vrf_name)
    return json_data


def vrf_add_ibgp_profile_peer(vrf_name, asnum, nw_name, md5):
    """

    :param vrf_name:
    :param asnum:
    :param nw_name:
    :param md5:
    :return:
    """
    json_data = vrf_get(vrf_name)
    if 'bgp_profile' not in json_data:
        json_data['bgp_profile'] = dict()
    json_data['bgp_profile']['local_as'] = int(asnum)
    json_data['bgp_profile']['ibgp'] = True
    peer = dict()
    peer['remote_as'] = int(asnum)

    config = infra_utils.get_config()
    import lib.network_lib as network_lib
    peer_ip = network_lib.get_ip_for_last_octet(nw_name, '1')
    peer['peer_ip'] = {'addr': peer_ip, 'type': 'V4'}
    peer['subnet'] = {'ip_addr': {'addr': peer_ip, 'type': 'V4'},
                      'mask': int(network_lib.get_mask_for_network(nw_name))}
    peer['network_ref'] = '/api/network?name=' + nw_name
    peer['md5_secret'] = md5
    peer['bfd'] = True

    if 'peers' not in json_data['bgp_profile']:
        json_data['bgp_profile']['peers'] = []

    for peer_data in json_data['bgp_profile']['peers']:
        if peer_data['peer_ip']['addr'] == peer_ip:
            logger.debug('Peer %s already configured' % peer_ip)
            return

    json_data['bgp_profile']['peers'].append(peer)
    rest.put('vrfcontext', name=vrf_name, data=json_data)


def check_all_se_in_group(segroup_name, oper_state, timeout=0):
    segroup_data = get_se_in_group(segroup_name)
    for se_data in segroup_data:
        se_uuid = se_data['uuid']
        se_check(se_uuid, oper_state, timeout)


def wait_for_all_se_vnic_to_disconnect(segroup_name, timeout=300):
    se_list = get_se_list_in_group(segroup_name)
    for se_uuid in se_list:
        se_name = get_se_name_from_uuid(se_uuid)
        wait_for_se_vnic_to_disconnect(se_name, retry_timeout=timeout)


def move_all_se_to_segroup(from_sg_name, to_sg_name):
    se_list = get_se_list_in_group(from_sg_name)
    for se_uuid in se_list:
        move_se_to_segroup_by_uuid(se_uuid, to_sg_name)


def check_used_se_have_expected_nw(vs_names=[], se_interface=[]):
    se_list = []
    nw_name = []
    for vs in vs_names:
        se = vs_get_se_list(vs)
        se_list.extend(se)
    se_uuids = list(set(se_list))
    for se_uuid in se_uuids:
        se_name = get_se_name_from_uuid(se_uuid)
        nw_uuid_vnic = se_get_data_vnic_nw_uuid(se_name)
        for nw_uuid in nw_uuid_vnic:
            status_code, nw_resp = rest.get("network/%s" % nw_uuid)
            nw_name.append(nw_resp['name'])
        if not (all(nw_expected in nw_name for nw_expected in se_interface)):
            logger.info("The expected networks %s were not found on SE %s" % (nw_name, se_interface))


def tenant_create(name, tenant_vrf=False):
    """

    :param name:
    :param kwargs:
    :return:
    """
    import avi_objects.rest as rest

    json_tenant_data = {
        'uuid': name,
        'name': name
    }
    if tenant_vrf:
        json_tenant_data['config_settings'] = {
            'tenant_vrf' : tenant_vrf
        }
    rest.post('tenant', data=json.dumps(json_tenant_data))


def validate_no_vrf_in_tenant(name):
    """

    :param name:
    :return:
    """
    import avi_objects.rest as rest

    _, json_tenant_data = rest.get('tenant', name=name)

    tenant_vrf = json_tenant_data.get('config_settings').get('tenant_vrf')
    if tenant_vrf:
        logger_utils.fail("VRF is found in tenant")
    tenant_uuid = json_tenant_data.get('uuid')

    _, json_tenant_vrfcontext_data = rest.get('tenant', uuid=tenant_uuid,
                                          path='vrfcontext')
    if json_tenant_vrfcontext_data.get('count'):
        logger_utils.fail("validate no vrf in tenant is failed because "
                          "VRF-Context API returns result")


def vrf_get_num_static_routes(vrf_name):
    vrf = vrf_get(vrf_name)
    if not vrf.get('static_routes'):
        return 0
    return len(vrf['static_routes'])


def vrf_check(vrf_name, t_routes=0):
    t_routes = int(t_routes)
    num_routes = vrf_get_num_static_routes(vrf_name)
    if t_routes != num_routes:
        logger.debug('num routes mismatch current %d != %d' % (num_routes, t_routes))
        logger_utils.fail('num routes mismatch current %d != %d' % (num_routes, t_routes))


def vrf_add_static_route(vrf_name, prefix, mask, nh, route_id):
    import lib.network_lib as network_lib
    json_data = vrf_get(vrf_name)
    json_data['static_routes'] = []
    json_data['static_routes']['route_id'] = route_id
    prefix_ip = infra_utils.get_ip_for_network(prefix)
    json_data['static_routes']['prefix']['ip_addr']['addr'] = prefix_ip
    json_data['static_routes']['prefix']['ip_addr']['type'] = 0
    json_data['static_routes']['prefix']['mask'] = int(mask)
    nh_ip = infra_utils.get_ip_for_network(nh)
    json_data['static_routes']['next_hop']['addr'] = nh_ip
    json_data['static_routes']['next_hop']['type'] = 0
    rest.put('vrfcontext', name=vrf_name, data=json_data)


def vrf_add_static_route_with_nh_ip(vrf_name, prefix_ip, mask, nh_ip, route_id):
    json_data = vrf_get(vrf_name)
    json_data['static_routes'] = []
    json_data['static_routes']['route_id'] = route_id
    json_data['static_routes']['prefix']['ip_addr']['addr'] = prefix_ip
    json_data['static_routes']['prefix']['ip_addr']['type'] = 0
    json_data['static_routes']['prefix']['mask'] = int(mask)
    json_data['static_routes']['next_hop']['addr'] = nh_ip
    json_data['static_routes']['next_hop']['type'] = 0
    rest.put('vrfcontext', name=vrf_name, data=json_data)


def create_vrf(name):
    try:
        data={"uuid": "uuid",
              "name": name}
        datas= json.dumps(data)
        resp, code = rest.post("vrfcontext", name=name, data=datas)
        return resp
    except Exception:
        logger_utils.fail("Unable to create VRF! ...")


def vrf_del_ibgp_profile_peers(vrf_name, nw_names):
    """

    :param vrf_name:
    :param nw_names:
    :return:
    """
    json_data = vrf_get(vrf_name)
    if 'bgp_profile' not in json_data:
        logger.debug('No BGP Profile configured')
        return
    if 'peers' not in json_data['bgp_profile']:
        logger.debug('No BGP Peers configured')
        return
    config = infra_utils.get_config()
    import lib.network_lib as network_lib
    for nw_name in nw_names:
        peer_ip = network_lib.get_ip_for_last_octet(nw_name, '1')
        for i, peer_data in enumerate(json_data['bgp_profile']['peers']):
            if peer_data['peer_ip']['addr'] == peer_ip:
                logger.debug('Peer %s found for delete' % peer_ip)
                json_data['bgp_profile']['peers'].pop(i)
                break
    rest.put('vrfcontext', name=vrf_name, data=json_data)


def vrf_add_ibgp_profile_peers(vrf_name, asnum, nw_names, md5):
    """

    :param vrf_name:
    :param asnum:
    :param nw_names:
    :param md5:
    :return:
    """
    json_data = vrf_get(vrf_name)
    if 'bgp_profile' not in json_data:
        json_data['bgp_profile'] = dict()
    json_data['bgp_profile']['local_as'] = int(asnum)
    json_data['bgp_profile']['ibgp'] = True
    if 'peers' not in json_data['bgp_profile']:
        json_data['bgp_profile']['peers'] = []
    config = infra_utils.get_config()
    import lib.network_lib as network_lib
    for nw_name in nw_names:
        peer = dict()
        peer['remote_as'] = int(asnum)
        peer_ip = network_lib.get_ip_for_last_octet(nw_name, '1')
        peer['peer_ip'] = {'addr': peer_ip, 'type': 'V4'}
        peer['subnet'] = {'ip_addr': {'addr': peer_ip, 'type': 'V4'},
                          'mask': int(network_lib.get_mask_for_network(nw_name))}
        peer['network_ref'] = '/api/network?name=' + nw_name
        peer['md5_secret'] = md5
        peer['bfd'] = True

        peer_found = False
        for peer_data in json_data['bgp_profile']['peers']:
            if peer_data['peer_ip']['addr'] == peer_ip:
                print 'Peer %s already configured' % peer_ip
                peer_found = True
                break
        if not peer_found:
            json_data['bgp_profile']['peers'].append(peer)
    rest.put('vrfcontext', name=vrf_name, data=json_data)


def vrf_add_default_route(vrf_name, route_id, **kwargs):
    """

    :param vrf_name:
    :param route_id:
    :param kwargs:
    :return:
    """
    nh = kwargs.get('nh', None)
    network = kwargs.get('network', None)
    next_hop_last_octet = kwargs.get('next_hop_last_octet', '.1')
    json_data = vrf_get(vrf_name, **kwargs)
    json_data['vrf']['static_routes'] = {}
    json_data['vrf']['static_routes']['rt']['route_id'] = route_id
    json_data['vrf']['static_routes']['rt']['prefix']['ip_addr']['addr'] = '0.0.0.0'
    json_data['vrf']['static_routes']['rt']['prefix']['ip_addr']['type'] = 0
    json_data['vrf']['static_routes']['rt']['prefix']['mask'] = 0
    if nh:
        json_data['vrf']['static_routes']['rt']['next_hop']['addr'] = nh
    else:
        config = infra_utils.get_config()
        mode = config.get_mode()
        site_name = mode['site_name']
        nw_ip = config.testbed[site_name].networks_json[network]['ip']
        default_nh = ".".join(nw_ip.split('.')[0:3]) + next_hop_last_octet
        json_data['vrf']['static_routes']['rt']['next_hop']['addr'] = default_nh
        json_data['vrf']['static_routes']['rt']['next_hop']['type'] = 0
    rest.put('vrfcontext', data=json_data)


def vrf_del_static_route(vrf_name, route_id, **kwargs):
    """
     Pass kwargs: site_name for multisite usage: (gslb)
    :param vrf_name:
    :param route_id:
    :param kwargs:
    :return:
    """
    #vrf = VrfContext()
    json_data = vrf_get(vrf_name, **kwargs)
    #json2pb(vrf, json_data)
    if not json_data.get('static_routes'):
        return
    logger.info('num routes:%d' % len(json_data['static_routes']))
    logger.info("vrf= ", json_data['static_routes'])
    for i in range(len(json_data['static_routes'])):
        # A route_id of -1 will delete all routes. This magic value is only meant
        # to be used by vrf_del_all_static_routes(); please call that function
        # instead.
        if 'gcp' in kwargs:
            if str(route_id) == str(-1):
                print 'i=%d route[i]=%s' % (i, json_data['static_routes'][0])
                json_data['static_routes'][0] = {}
            else:
                if str(json_data['static_routes'][i]['route_id']) == str(route_id):
                    logger.info('i=%d route[i]=%s' % (i, json_data['static_routes'][i]))
                    json_data['static_routes'][i] = {}
                    break
        else:
            if route_id == -1:
                logger.info('i=%d route[i]=%s' % (i, json_data['static_routes'][0]))
                json_data['static_routes'][0] = {}
            else:
                if int(json_data['static_routes'][i].route_id) == int(route_id):
                    logger.info('i=%d route[i]=%s' % (i, json_data['static_routes'][i]))
                    json_data['static_routes'][i] = {}
                    break
    rest.put('vrfcontext', data=json_data)


def vrf_del_ibgp_profile(vrf_name):
    """

    :param vrf_name:
    :return:
    """
    json_vrf_data = vrf_get(vrf_name)
    del json_vrf_data['bgp_profile']
    rest.put('vrfcontext', name=vrf_name, data=json_vrf_data)
