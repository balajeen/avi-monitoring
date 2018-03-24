from avi_objects.logger import logger
from avi.protobuf.network_policy_pb2 import (NetworkSecurityRule,
                                             NetworkSecurityPolicyActionType)
from avi.protobuf.common_pb2 import MatchOperation

import avi_objects.rest as rest
import avi_objects.logger_utils as logger_utils
import avi_objects.infra_utils as infra_utils
import lib.pool_lib as pool_lib
import lib.placement_lib as placement_lib
import lib.se_lib as se_lib
import lib.openshift_lib as openshift_lib

oshift_utils = openshift_lib.OpenshiftTestUtils()

# experimental
def protobuf_value(package, name, path, value):
    """ A safety check to validate our hardcoded values usage, if we have access to the protobufs.
        This allows the library to not depend on having access to the protobufs, while signaling
        if the protobuf definitions do change.
    """
    try:
        imported = getattr(__import__(package, fromlist=[name]), name)
        if eval(path.replace(name, 'imported')) != value:
            fail('Protobuf %s.%s no longer matches hardcoded values. Please verify and update.'
                 %(package, name))
    except ImportError:
        # assume that we don't have access to protobufs in this environment
        pass
    return value

def add_security_policy_to_vs(vs_name, ms_name=[], **kwargs):
    """

    :param vs_name:
    :param ms_name:
    :param kwargs:
    :return:
    """
    policy_name = vs_name + '-networksecuritypolicy'
    msg_name = 'vs-msg-' + vs_name
    create_microservice_group(msg_name, ms_name)
    path = 'networksecuritypolicy'
    http_code, nsp_policy = rest.get(path, name=policy_name)
    #create_network_security_policy('default', name=policy_name)

    rule = {
        'match': {
            'microservice': {}
        }
    }

    _, rsp = rest.get('microservicegroup', name=msg_name)
    msg_uuid = rsp['uuid']
    rule['match']['microservice']['group_uuid'] = msg_uuid
    rule['match']['microservice']['match_criteria'] = 'IS_IN'

    rule['enable'] = True
    deny = int(kwargs.get('deny', 0))
    if not nsp_policy.get('rules'):
        nsp_policy['rules'] = []

    if deny:
        rule['name'] = 'rule-42'
        rule['index'] = 42
        rule['action'] = NetworkSecurityPolicyActionType.DESCRIPTOR.values_by_name[
                         "NETWORK_SECURITY_POLICY_ACTION_TYPE_DENY"].number
        #experimental
        #rule['action'] = protobuf_value('avi.protobuf.network_policy_pb2', 'NetworkSecurityPolicyActionType',
        #                                ('NetworkSecurityPolicyActionType.DESCRIPTOR.values_by_name['
        #                                 '"NETWORK_SECURITY_POLICY_ACTION_TYPE_DENY"].number'), 2)
        rule['match']['microservice']['match_criteria'] = \
            MatchOperation.DESCRIPTOR.values_by_name["IS_IN"].number
        nsp_policy['rules'].append(rule)
    else:
        rule['name'] = 'rule-9990'
        rule['index'] = 9990
        rule['action'] = NetworkSecurityPolicyActionType.DESCRIPTOR.values_by_name[
                        "NETWORK_SECURITY_POLICY_ACTION_TYPE_ALLOW"].number
        # add default rule.
        rule['match']['microservice']['match_criteria'] = \
            MatchOperation.DESCRIPTOR.values_by_name["IS_IN"].number
        nsp_policy['rules'].append(rule)
        rule = {
            'match': {
                'client_ip': {
                    'prefixes': []
                }
            }
        }
        rule['index'] = 9999
        rule['enable'] = True
        rule['name'] = 'drop all'
        rule['match']['client_ip']['match_criteria'] = \
            MatchOperation.DESCRIPTOR.values_by_name["IS_IN"].number
        prefix = {
            'mask': 0,
            'ip_addr': {
                'addr': '0.0.0.0',
                'type': 'V4'
            }
        }
        rule['match']['client_ip']['prefixes'].append(prefix)
        rule['action'] = \
            NetworkSecurityPolicyActionType.DESCRIPTOR.values_by_name[
                "NETWORK_SECURITY_POLICY_ACTION_TYPE_DENY"].number
        nsp_policy['rules'].append(rule)

    http_code, _ = rest.put('networksecuritypolicy', name=nsp_policy['name'], data=nsp_policy)
    logger.info('updating %s %s %s' % (nsp_policy['name'], http_code, nsp_policy))


def create_microservice_group(msg_name, ms_name=[], **kwargs):
    """

    :param msg_name:
    :param ms_name:
    :param kwargs:
    :return:
    """

    tenant = infra_utils.get_config().get_mode(key='tenant')
    msg = {
        'name': msg_name,
        'tenant_uuid': rest.get_uuid_by_name('tenant', tenant),
        'service_uuids': []
    }

    for ms in ms_name:
        msg['service_uuids'].append(rest.get_uuid_by_name('microservice', ms))
    try:
        rest.post('microservicegroup', name=msg_name, data=msg) # REVIEW why was this tenant_uuid?
    except Exception as e:
        if 'Micro service group with this Name and Tenant ref ' \
           'already exists' in str(e):
            logger.info('microservice group already exists, ignoring error')
        else:
            raise
    return msg_name



def delete_microservice_group(msg_name, **kwargs):
    """

    :param msg_name:
    :param kwargs:
    :return:
    """

    rest.delete('microservicegroup', name=msg_name)


def check_ms(ms_name, pool_name, **kwargs):
    """

    :param ms_name:
    :param pool_name:
    :param kwargs:
    :return:
    """

    ms_internal = get_ms_internal(ms_name, **kwargs)
    server_detail = pool_lib.get_server_runtime(pool_name, **kwargs)
    for s in server_detail:
        s_ip = s['ip_addr']['addr']
        s_port = str(s['port'])
        found = False
        for cn in ms_internal[0]['containers']:
            if cn['nat_ip_addr'] == s_ip or cn['ip_addr'] == s_ip:
                found = True  # only require ips to match
                if 'ports' not in cn:
                    continue
                elif 'ports' in cn and s_port in cn['ports']:
                    # but if ports specified, check they match
                    break
                else:  # if not matching, then check next container
                    found = False
        if not found:
            logger.info(ms_internal[0], s)
            logger_utils.fail('Server %s:%s not found in ms-list' % (s_ip, s_port))

    for cn in ms_internal[0]['containers']:
        if 'ports' not in cn:
            continue
        found = False
        for s in server_detail['results']:
            s_ip = s['ip_addr']['addr']
            s_port = str(s['port'])
            if cn['nat_ip_addr'] == s_ip or cn['ip_addr'] == s_ip:
                if s_port in cn['ports']:
                    found = True
                    break
        if not found:
            logger.info(server_detail, cn)
            logger_utils.fail('MS %s:%s not found in server-list' % (
                ms_internal[0]['name'], cn['name']))

def get_ms_internal(ms_name, **kwargs):
    """

    :param ms_name:
    :param kwargs:
    :return:
    """
    resp_code, resp_data = rest.get("microservice", name=ms_name, path='runtime/internal')
    return resp_data


def verify_ew_vs_placement(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """

    placement_count = placement_lib.placement_get_vs_se_used(vs_name, **kwargs)
    se_count = len(se_lib.get_all_se_uuid())
    if placement_count != se_count:
        logger_utils.fail('E/W VS %s only placed on %d of %d SEs'
                           % (vs_name, placement_count, se_count))


def check_ms_deleted(ms_name, **kwargs):
    """

    :param ms_name:
    :param kwargs:
    :return:
    """

    retry_timeout = int(kwargs.get('retry_timeout', 30))
    retry_interval = int(kwargs.get('retry_interval', 5))
    try:
        retries = retry_timeout / retry_interval

        @logger_utils.aretry(retry=retries, delay=2)
        def retry_action():
            return is_ms_deleted(ms_name, **kwargs)

    except Exception as e:
        raise Exception('MS was not deleted after retry timeout of %i'
                                   % retry_timeout, e)


def is_ms_deleted(ms_name, **kwargs):
    """

    :param ms_name:
    :param kwargs:
    :return:
    """

    resp_code, resp_data = rest.get('microservice', name=ms_name)
    return resp_data


def get_ms_config(ms_name):
    """

    :param ms_name:
    :param tenant:
    :return:
    """
    ms_uuid = rest.get_uuid_by_name('microservice', ms_name)
    resp_code, resp_data = rest.get("microservice", uuid=ms_uuid)
    return resp_data


def check_microservice_in_microservice_group(msg_name, app_name, tenant='admin'):
    """

    :param msg_name:
    :param app_name:
    :param tenant:
    :return:
    """

    resp_data = get_microservice_group(msg_name, tenant=tenant)
    microservices_refs = resp_data['service_refs']
    ms_name = app_name + '-microservice'  # NB naming convention
    microservice_resp = get_ms_config(ms_name)
    microservice_ref = microservice_resp['url']
    assert microservice_ref in microservices_refs, \
        'microservice %s with ref %s not in group %s; msg has %s' % (
            ms_name, microservice_ref, msg_name, microservices_refs)


def get_microservice_group(msg_name, tenant='admin'):
    """

    :param msg_name:
    :param tenant:
    :return:
    """

    ms_uuid = rest.get_uuid_by_name('microservicegroup', msg_name)
    resp_code, resp_data = rest.get("microservicegroup", uuid=ms_uuid)
    return resp_data


def get_vs_cltrack(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """
    resp_code, resp_data = rest.get('virtualservice', name=vs_name, path='cltrack')
    return resp_data


def clear_cltrack(vs_name, **kwargs):
    status_code, data = rest.post('virtualservice', name=vs_name, path='/cltrack/clear')


def check_microservicegroup_for_tenant(tenant):
    msg_name = tenant + '-avi-microservicegroup' # NB naming convention
    get_microservice_group(msg_name, tenant=tenant)
    return msg_name


def check_microservice_group_microservice_count(msg_name, ms_count, tenant='admin'):
    resp_data = get_microservice_group(msg_name, tenant=tenant)
    microservices = resp_data['service_refs']
    assert len(microservices) == int(ms_count), \
        'microservicegroup %s has %d microservices but we expected %s' % (msg_name, len(microservices), ms_count)


#TODO: Incomplete
def check_vs_cltrack(vs_name):
    return 1

