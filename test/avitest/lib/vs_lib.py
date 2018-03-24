import copy
import json
import time

import avi_objects.logger_utils as logger_utils
import avi_objects.rest as rest
import lib.cli_lib as cli_lib
import lib.common as common
import lib.webapp_lib as webapp_lib
from avi_objects import infra_utils
from avi_objects.logger import FailError, ForcedFailError
from avi_objects.logger import logger

DEFAULT_APPLICATION = {
    'name': ""}


def update_vs_enabled(vs_name, enable=True, check_status_code=True):
    vs = rest.ApiNode('virtualservice', name=vs_name)
    _, data = vs.get(check_status_code=check_status_code)
    data['enabled'] = enable
    for vip in data.get('vip', []):
        vip['enabled'] = enable

    return vs.put(data=json.dumps(data), check_status_code=check_status_code)


def enable_vs(vs_name, check_status_code=True):
    return update_vs_enabled(vs_name, enable=True,
                             check_status_code=check_status_code)


def disable_vs(vs_name, check_status_code=True):
    return update_vs_enabled(vs_name, enable=False,
                             check_status_code=check_status_code)


def disable_enable_vs(vs_name):
    """

    :param vs_name:
    :return:
    """
    disable_vs(vs_name)
    enable_vs(vs_name)


def get_vs(vs_name, **kwargs):
    resp_code, resp_data = rest.get("virtualservice", name=vs_name)
    return resp_data


def get_vs_runtime(vs_name, **kwargs):
    _, runtime = rest.get("virtualservice", name=vs_name, path='runtime')
    if not runtime:
        logger_utils.fail('ERROR! data NULL for %s' % runtime)
    return runtime


def get_vs_runtime_detail(vs_name, **kwargs):
    status_code, runtime = rest.get('virtualservice', name=vs_name,
                                    path='runtime/detail')
    if not runtime:
        logger_utils.fail(
            'ERROR! data NULL for virtualservice/%s/runtime/detail' % vs_name)
    return runtime[0]


def get_vip_summary(vs_name, vip_id, **kwargs):
    vs_runtime = get_vs_runtime(vs_name, **kwargs)
    vip_summary = None
    for vip_summary in vs_runtime.get('vip_summary', []):
        if vip_summary['vip_id'] == vip_id:
            break
    return vip_summary


def get_vs_network_by_name(vs_name, vip_id=1):
    vs_data = get_vs(vs_name)
    for vip in vs_data['vip']:
        if vip['vip_id'] == vip_id:
            return vip['ip_address']['addr']
    return None


def compare_vs_oper_status(vs_name, expected_oper_status, se_name=None,
                           num_se_assigned=-1, num_se_requested=-1,
                           vip_id="0", **kwargs):
    state = None
    vip_summary = get_vip_summary(vs_name, vip_id, **kwargs)

    try:
        state = vip_summary['oper_status']['state']
        logger.info("virtualservice %s state=%s" % (vs_name, state))
    except Exception as e:
        logger_utils.fail('## oper status not available: %s' % str(e))

    if state != expected_oper_status:
        logger_utils.fail('vs still in status: %s' % state)

    if 'num_se_requested' in vip_summary and num_se_requested >= 0:
        if num_se_requested != vip_summary['num_se_requested']:
            logger_utils.fail('num_se_requested not as expected')

    if 'num_se_assigned' in vip_summary and num_se_assigned >= 0:
        if num_se_assigned != vip_summary['num_se_assigned']:
            logger_utils.fail('num_se_assigned not as expected, retry')

    return True


def vs_should_be_in_status(vs_name, expected_oper_status,
                           se_name=None, oper_down=False,
                           vip_id="0", **kwargs):
    # is actually num retries
    retry_timeout = int(kwargs.get('retry_timeout', 2))
    num_se_assigned = int(kwargs.get('num_se_assigned', -1))
    num_se_requested = int(kwargs.get('num_se_requested', -1))
    no_of_retries = retry_timeout / 2

    @logger_utils.aretry(retry=no_of_retries, delay=2)
    def retry_action():
        return compare_vs_oper_status(vs_name, expected_oper_status,
                                      se_name, num_se_assigned=num_se_assigned,
                                      num_se_requested=num_se_requested,
                                      vip_id=vip_id)

    return retry_action()


def vs_scaleout_in_progress(vs_name, exp=True, vip_index=0):
    vip_summary = get_vs_runtime(vs_name)['vip_summary'][
        vip_index]  # REVIEW why not get_vip_summary(vs_name, vip_index)?
    if u'scaleout_in_progress' in vip_summary.keys():
        if vip_summary['scaleout_in_progress'] is True:
            return True
    if exp:
        logger_utils.fail('VS not in scaleout_in_progress')
    return False


def vs_scaleout_complete(vs_name):
    if vs_scaleout_in_progress(vs_name, exp=False):
        logger_utils.fail('VS[%s] scaleout not completed' % vs_name)
    return True


def wait_till_scaleout_complete(vs, retry_timeout=600, retry_interval=5,
                                **kwargs):
    logger.info('wait till scaleout complete')
    retries = retry_timeout / retry_interval

    @logger_utils.aretry(retry=retries, delay=retry_interval)
    def retry_action():
        if not vs_scaleout_complete(vs):
            logger_utils.fail('vs %s scaled out not complete' % vs)

    retry_action()


def scale_out_vs(vs_name, wait=False, sleep=False, **kwargs):
    """
    :param vs_name:
    :param wait:
    :param sleep:
    :param kwargs:
    :return:
    """
    data = {'vip_id': '0'}
    if 'vip_id' in kwargs:
        data['vip_id'] = kwargs['vip_id']
    rest.post('virtualservice', name=vs_name, path='scaleout', data=data)
    logger_utils.asleep("5 Seconds Wait", delay=5)
    if sleep:
        logger_utils.asleep("Another 15 Seconds Wait", delay=15)
    if wait:
        wait_till_scaleout_complete(vs_name)


def scale_in_vs(vs_name, is_primary=False, sleep=True, **kwargs):
    """
    This function does Scale in VS across SEs
    Args:
        :param vs_name: Virtual Service name which want to Scale in.
        :type vs_name: str
    Kwargs:
        :param is_primary: If primary is True, one of the existing Secondaries
                           will become the new primary.
        :type is_primary: boolean, default True
        :param sleep: Sleep after Scale in Operation.
        :type sleep: int
    Returns:
        None
    """
    data = {'vip_id': '0'}
    if 'vip_id' in kwargs:
        data['vip_id'] = kwargs['vip_id']

    data['scalein_primary'] = False
    if is_primary:
        data['scalein_primary'] = True

    rest.post('virtualservice', name=vs_name, path='scalein', data=data)
    logger.info('VS Scale_in  in_progress ...')

    logger_utils.asleep("5 Seconds Wait", delay=5)
    if sleep:
        logger_utils.asleep("Another 30 Seconds Wait", delay=30)


def switchover_vs(vs_name, **kwargs):
    data = {'vip_id': '0'}
    if 'vip_id' in kwargs:
        data['vip_id'] = kwargs['vip_id']

    if 'se_uuid' in kwargs:
        data['se_uuid'] = kwargs['se_uuid']

    rest.post('virtualservice', name=vs_name, path='switchover',
              data=json.dumps(data))


def verify_vs_selist_count(vs_name, expected_count):
    _, data = rest.get('virtualservice', name=vs_name, path='runtime/internal')
    count = 0
    for vs_internal in data:
        if vs_internal.get('virtualservice_runtime'):
            # info from controller
            for vip_runtime in vs_internal['virtualservice_runtime']['vip_runtime']:
                c_se_list = vip_runtime['se_list']
                for c_se in c_se_list:
                    count += 1

    logger.info(
        'count is ' + str(count) + ' expected is ' + str(expected_count))
    if int(count) != int(expected_count):
        logger_utils.fail('ERROR! vs selistcount is ' + str(count) +
                          ' should be ' + str(expected_count))


# REVIEW do we really need this function?
def clear_all_stats_for_vs(vs_name):
    rest.post('virtualservice', name=vs_name, path='stats/clear')


def is_vs_up(vs_uuid):
    _, data = rest.get('virtualservice', uuid=vs_uuid, path='runtime')
    return data['oper_status']['state'] == 'OPER_UP'


@logger_utils.aretry(retry=20, delay=60, period=10)
def wait_for_vs_up(vs_names=[]):
    _, all_vs = rest.get('virtualservice')
    vs_uuids = []
    for result in all_vs['results']:
        if not vs_names or (vs_names and result['name'] in vs_names):
            vs_uuids.append((result['name'], result['uuid']))
    if len(vs_names) and (len(vs_names) != len(vs_uuids)):
        msg_str = 'ERROR! wait_for_vs_up: Not all VSs are present on the controller. '
        msg_str += 'Expected uuids for VSs: %s ' % vs_names
        msg_str += 'uuids on the controller: %s' % [i[0] for i in vs_uuids]
        # TODO: What's the alternative to raising a generic python
        # exception here? logger.fail or logger.error allow retry to continue
        raise Exception('wait_for_vs_up: %s' % msg_str)

    for vs_name, vs_uuid in vs_uuids:
        if not is_vs_up(vs_uuid):
            logger_utils.error(
                "vs with name %s uuid %s is not up" % (vs_name, vs_uuid))
        else:
            vs_uuids.remove((vs_name, vs_uuid))


def update_vs_ssl_policy(vs_name, profile, certkey):
    vs = rest.ApiNode('virtualservice', name=vs_name)
    _, vs_data = vs.get()
    certs = certkey.split(',')
    vs_data["ssl_key_and_certificate_refs"] = []
    for cert in certs:
        vs_data["ssl_key_and_certificate_refs"].append(
            "/api/sslkeyandcertificate?name=%s" % certkey)

    ssl_profile_uuid = rest.get_uuid_by_name("sslprofile", profile)
    vs_data["ssl_profile_ref"] = "/api/sslprofile/%s" % ssl_profile_uuid
    vs.put(data=json.dumps(vs_data))


def start_packet_capture(vs_name, tenant='admin', **params):
    uuid = rest.get_uuid_by_name('virtualservice', vs_name)
    obj_data = {'name': vs_name,
                'uuid': uuid,
                'capture': True,
                'capture_params': params}
    debugVirService_uuid = rest.get_uuid_by_name('debugvirtualservice', vs_name)
    rest.put('debugvirtualservice', uuid=debugVirService_uuid, data=obj_data)


def stop_packet_capture(vs_name, **params):
    _, vs_data = rest.get('virtualservice', name=vs_name)
    obj_data = {'name': vs_name,
                'uuid': vs_data['uuid'],
                'capture': False}
    rest.put('debugvirtualservice', name=vs_name, data=obj_data)


def check_packet_capture_status(vs_name, should_be_on=True):
    _, vs_data = rest.get('debugvirtualservice', name=vs_name)
    capture = vs_data.get('capture', False)
    if capture != common._bool_value(should_be_on):
        logger.info('DEBUGVS', vs_data)
        logger_utils.fail('Unexpect status for packet capture')


def get_packet_capture_progress(vs_name, should_pass=True):
    _, vs_data = rest.get('virtualservice', name=vs_name)
    try:
        rest.get('api/debugvirtualservice/%s/progress' % vs_data['uuid'], should_pass=should_pass)
    except:
        if should_pass:
            logger_utils.fail("Error: debugvirtualservice %s not in progress" % vs_name)


def get_vs_controller_internal(vs_name):
    status_code, internal = rest.get('virtualservice', name=vs_name,
                                     path='runtime/internal')
    if not internal:
        logger_utils.fail('ERROR! data NULL for '
                          'virtualservice/%s/runtime/internal' % vs_name)
        # raise RuntimeError('ERROR! data NULL for %s' % api)
    for data in internal:
        if u'virtualservice_runtime' in data.keys():
            return data['virtualservice_runtime']


def vs_get_se_info(vs_name, vip_index=0):
    vs_data = get_vs_controller_internal(vs_name)
    if vs_data['vip_runtime'][vip_index].get('se_list'):
        return vs_data['vip_runtime'][vip_index]['se_list']


def vs_get_se_list(vs_name, vip_id='0', **kwargs):
    vip_summary = get_vip_summary(vs_name, vip_id, **kwargs)
    se_list = []
    if vip_summary.get('service_engine'):
        for se in vip_summary['service_engine']:
            if kwargs.get('primary') and not se.get('primary'):
                continue
            if kwargs.get('standby') and not se.get('standby'):
                continue
            if kwargs.get('secondary') and (se.get('primary') or se.get('standby')):
                continue
            se_list.append(se['uuid'])
    return se_list


def is_vs_placed(vs_name, vip_id = '0', **kwargs):
    status_code, vs_runtime = rest.get('virtualservice', name=vs_name,
                                    path='runtime', check_status_code=False)
    for vip in vs_runtime.get('vip_summary', []):
        if vip.get('vip_id') == vip_id:
            if 'service_engine' not in vip.keys():
                return False
    else:
        return True


def vs_get_primary_se_info(vs_name, vip_id="0", **kwargs):
    if is_vs_placed(vs_name, **kwargs) is False:
        logger_utils.fail('VS %s not assigned to SE' % vs_name)
    status_code, runtime = rest.get('virtualservice', name=vs_name,
                                    path='runtime')
    primary_se = None
    try:
        vip_summary = None
        for vip_summary in runtime['vip_summary']:
            if vip_summary['vip_id'] == str(vip_id):
                break
        for se in vip_summary['service_engine']:
            if se['primary'] is True:
                primary_se = se
                break
    except KeyError, Argument:
        logger_utils.fail(
            'Rest result did not have required field: %s' % Argument)
    return primary_se


def is_vs_assigned(vs_name, se_name=None, vip_index=0, **kwargs):
    import lib.se_lib as se_lib
    status_code, runtime = rest.get("virtualservice", name=vs_name,
                                    path='runtime')
    if status_code != 200:
        logger.info('vs %s not assigned yet for reason: %s' % (vs_name, str(runtime)))
        return False

    if u'config_status' in runtime.keys():
        if runtime['config_status']['state'] == 'CONFIG_DOWN':
            logger.debug('config_status state is CONFIG_DOWN')
            return False
    try:
        state = runtime['vip_summary'][0]['oper_status']['state']
    except KeyError as e:
        return False

    if kwargs.get('oper_down', False):
        # Hack to get openstack working. VS is assigned but in OPER_DOWN state
        # if all servers in pool are disabled.
        if state != 'OPER_UP' or state != 'OPER_DOWN':
            logger.debug('vs[%s] oper state is %s' % (vs_name, state))
            return False
    else:
        if state != 'OPER_UP':
            logger.info('vs[%s] oper state != OPER_UP' % vs_name)
            return False
    if 'num_se_requested' in runtime.keys():
        if runtime['num_se_requested'] != runtime.get('num_se_assigned', 0):
            logger.info('num se requested != num se assigned')
            return False

    if se_name is None:
        return True

    for se_iter in runtime['vip_summary'][vip_index]['service_engine']:
        se_ref = se_iter['url']
        if se_ref:
            ref = se_ref.split('/')
            uuid = ref[len(ref) - 1]
            if se_name == se_lib.get_se_name_from_uuid(uuid):
                return True

    logger_utils.fail(
        'ERROR! Virtualservice %s is not assigned to se %s' % (vs_name,
                                                               se_name))


def vs_get_primary_se_uuid(vs_name, **kwargs):
    try:
        primary_se = vs_get_primary_se_info(vs_name, **kwargs)
        se_uuid = rest.get_uuid_from_ref(url_ref=primary_se['url'])
        logger.info('primary se uuid: %s' % se_uuid)
        return se_uuid
    except Exception as e:
        logger.debug(str(e))


def vs_get_primary_se_name(vs_name, vip_id="0", **kwargs):
    try:
        primary_se = vs_get_primary_se_info(vs_name, vip_id, **kwargs)
        se_uuid = rest.get_uuid_from_ref(url_ref=primary_se['url'])
        logger.info('primary se uuid: %s' % se_uuid)
        _, se_info = rest.get('serviceengine', uuid=se_uuid)
        return se_info['name']
    except Exception as e:
        logger.debug(str(e))


def vs_has_primary_se(vs_name, exc=True, vip_index=0):
    status_code, runtime = rest.get('virtualservice', name=vs_name,
                                    path='runtime', check_status_code=False)
    if status_code != 200:
        logger.debug(
            'vs %s not assigned yet for reason: %s' % (vs_name, str(runtime)))
        return False

    if 'service_engine' not in runtime['vip_summary'][vip_index].keys():
        return False
    for se_iter in runtime['vip_summary'][vip_index]['service_engine']:
        if 'primary' in se_iter and se_iter['primary']:
            return True

    if not exc:
        return False
    logger_utils.fail('ERROR! Virtualservice %s does not have primary se' % vs_name)


@logger_utils.aretry(retry=50, delay=2)
def vs_should_have_primary_se(vs_name, **kwargs):
    # is actually num retries
    retry_timeout = int(kwargs.get('retry_timeout', 5))
    if not vs_has_primary_se(vs_name, exc=False):
        logger_utils.error(
            'vs %s not assigned after retry timeout of 40s' % vs_name)


@logger_utils.aretry(retry=50, delay=10)
def get_vs_runtime_and_wait_till_expected_status(vs_name, vs_status, vip_id='0',
                                                 **kwargs):
    if vs_should_be_in_state_in_runtime(vs_name, vs_status, vip_id, **kwargs):
        logger.info('VS[%s] in expected state: %s' % (vs_name, vs_status))
        return True
    else:
        logger_utils.fail('VS[%s] not in expected state %s ' % (vs_name, vs_status))


def vs_should_be_in_state_in_runtime(vs_name, vs_status, vip_id='0', **kwargs):
    vs_summary = get_vs_runtime(vs_name)

    if 'vip_summary' not in vs_summary:
        return False

    vip_summary = None
    for vip_summary in vs_summary['vip_summary']:
        if vip_id == vip_summary['vip_id']:
            break
    if not vip_summary:
        logger_utils.fail(
            'ERROR! get %s(%s) summary failed while checking vs state' %
            (vs_name, vip_id))

    oper_state = vip_summary['oper_status']['state']
    return oper_state == vs_status


def update_vs_se_group(vs_name, se_grp_name, **kwargs):
    """

    :param vs_name:
    :param se_grp_name:
    :param kwargs:
    :return:
    """
    _, json_data = rest.get('virtualservice', name=vs_name)
    json_data['se_group_ref'] = '/api/serviceenginegroup/?name=%s' % se_grp_name
    rest.put('virtualservice', name = vs_name, data = json_data)


def vs_get_secondary_se_info(vs_name, vip_index='0'):
    if is_vs_placed(vs_name) is False:
        logger_utils.fail('VS %s not assigned to SE' % vs_name)
    status_code, runtime = rest.get('virtualservice', name=vs_name,
                                    path='runtime')
    sec_se = []
    try:
        for vip_data in runtime['vip_summary']:
            if vip_data['vip_id'] == vip_index:
                sec_se = [se_info for se_info in vip_data['service_engine'] if
                          not se_info['primary']]
                break
    except KeyError, Argument:
        logger_utils.fail(
            'Rest result did not have required field: %s' % Argument)
    logger.info(sec_se)
    return sec_se


def vs_get_secondary_se_uuid(vs_name, index=0):
    try:
        sec_se = vs_get_secondary_se_info(vs_name)
        se = sec_se[int(index)]
        se_uuid = rest.get_uuid_from_ref(url_ref=se['url'])
        logger.info('secondary se uuid: %s' % se_uuid)
        return se_uuid
    except Exception as e:
        logger_utils.fail(str(e))


def vs_get_secondary_se_name(vs_name, index=0):
    try:
        sec_se = vs_get_secondary_se_info(vs_name)
        se = sec_se[int(index)]
        url = se['url']
        se_api = '/'.join(url.split('/')[-2:])
        se_data = rest.get(se_api)
        return se_data[1]['name']
    except Exception as e:
        logger_utils.fail(str(e))


def scale_out_vs_manual(vs_name, se_uuid=None, to_new_se=False,
                        host_name=None, retry=1, vip_index=0):
    data = {}
    data['vip_id'] = str(vip_index)
    data['to_se_ref'] = se_uuid
    if se_uuid is not None:
        data['to_se_ref'] = se_uuid
    if to_new_se:
        data['to_new_se'] = True
    else:
        data['to_new_se'] = False
    if host_name is not None:
        data['to_host_ref'] = host_name

    if not data:
        logger.info('not a good config! only for test purpose! data:%s' % data)
    retry = int(retry)

    @logger_utils.aretry(retry=retry, delay=5)
    def retry():
        logger.info('request data:%s' % data)
        resp_code, resp_data = rest.post('virtualservice', name=vs_name,
                                         path='scaleout', data=data)
        logger.info('scaleout request sent to controller')
        logger.info(resp_code, resp_data)
        if resp_code == 200:
            return resp_code

    resp_code = retry()
    if resp_code != 200:
        logger.info('Failed to scaleout for VS: %s' % vs_name)
    return resp_code


def vs_scaleout_should_be_done(vs_name, se_name=None, oper_down=False,
                               **kwargs):
    # is actually num retries
    retry_timeout = int(kwargs.get('retry_timeout', 1))
    try:
        @logger_utils.aretry(retry=retry_timeout * 12, delay=3)
        def retry():
            vs_scaleout_complete(vs_name)

        retry()
    except Exception as e:
        logger_utils.fail(
            'vs %s not scaledout after retry timeout of %s - %s' % (
                vs_name, retry_timeout, e))


def is_vs_migrate(vs_name, vip_index=0):
    """Is vs migrate"""
    vip_summary = get_vs_runtime(vs_name)['vip_summary'][vip_index]
    if u'migrate_in_progress' in vip_summary.keys():
        if vip_summary['migrate_in_progress'] is False:
            return True
    if u'scale_status' in vip_summary.keys():
        scale_status = vip_summary['scale_status']
        if u'reason' in scale_status.keys():
            return True
        if vip_summary['scale_status']['reason']:
            return True
    if u'last_scale_status' in vip_summary.keys():
        last_scale_status = vip_summary['last_scale_status']
        if u'reason' in last_scale_status.keys():
            return True
        if vip_summary['last_scale_status']['reason']:
            return True
    return False


def get_vs_se_num_total(vs_name):
    selist = vs_get_se_info(vs_name)
    l_selist = len(selist) if selist else 0
    logger.info('## Num SE=%d' % l_selist)
    return l_selist


def delete_all_vs():
    resp_code, vs_list = rest.get('virtualservice')
    for vs in vs_list['results']:
        if vs['type'] == 'VS_TYPE_VH_CHILD':
            logger.info("Deleting vs_name:%s" % vs['name'])
            rest.delete('virtualservice', name=vs['uuid'])
    resp_code, vs_list = rest.get('virtualservice')
    for vs in vs_list['results']:
        logger.info("Deleting vs_name: " + str(vs['name']))
        rest.delete('virtualservice', uuid=vs['uuid'])
    resp_code, vs_list = rest.get('virtualservice')
    return vs_list['count']


def get_vip(vs_name, vip_id='0'):
    """

    :param vs_name:
    :param vip_id:
    :return:
    """
    ip_addr = None
    resp_code, json_vs_data = rest.get('virtualservice', name=vs_name)
    for vip_data in json_vs_data.get('vip', []):
        if vip_data.get('vip_id') == vip_id:
            ip_addr = vip_data.get('ip_address').get('addr')
    else:
        if json_vs_data.get('type') == 'VS_TYPE_VH_CHILD':
            parent_vs_name = \
                rest.get_name_from_ref(json_vs_data.get('vh_parent_vs_ref'))
            resp_code, json_parent_vs_data = \
                rest.get('virtualservice', name=parent_vs_name)
            if json_parent_vs_data and json_parent_vs_data.get('vip'):
                for vip_data in json_parent_vs_data.get('vip', []):
                    if vip_data.get('vip_id') == vip_id:
                        ip_addr = vip_data.get('ip_address').get('addr')
    return ip_addr


def replace_vs_policy_set(vs_name, old_hps_name, new_hps_name):
    status_code, vs = rest.get('virtualservice', name=vs_name)

    old_hps_uuid = rest.get_uuid_by_name('httppolicyset', name=old_hps_name)

    for policy in vs['http_policies']:
        http_policy_name = webapp_lib.get_name_from_ref(
            policy['http_policy_set_ref'])
        if old_hps_uuid == http_policy_name:
            new_hps_uuid = rest.get_uuid_by_name('httppolicyset',
                                                 name=new_hps_name)
            policy['http_policy_set_ref'] = '/api/httppolicyset/' + new_hps_uuid

    rest.put('virtualservice', name=vs_name, data=vs)


def add_listener_port_to_vs(vs_name, port, ssl=False, expect_status_code=None):
    status_code, vs = rest.get('virtualservice', name=vs_name)

    service = {}
    service['port_range_end'] = int(port)
    service['port'] = int(port)
    vs['services'] = vs.get('services', [])
    vs['services'].append(service)
    vs['enable_ssl'] = ssl in [True, 1]

    if expect_status_code:
        status_code, data = rest.put('virtualservice', name=vs_name, data=json.dumps(vs), \
            check_status_code= False)
        logger_utils.verify(status_code == expect_status_code, \
            "Expected status code didnt match. status_code=%s expect_status_code=%s" %(status_code, expect_status_code))
    else:
        rest.put('virtualservice', name=vs_name, data=json.dumps(vs))


def update_vs_analytics_policy(vs_name, client_insights):
    status_code, vs = rest.get('virtualservice', name=vs_name)

    if client_insights.lower() == 'active':
        vs['analytics_policy']['client_insights'] = 'ACTIVE'
    if client_insights.lower() == 'passive':
        vs['analytics_policy']['client_insights'] = 'PASSIVE'
    else:
        vs['analytics_policy']['client_insights'] = 'NO_INSIGHTS'

    status_code, data = rest.put('virtualservice', name=vs_name, data=vs)


def update_vsvip(vs_name, vip_ip=None, network=None, vip_id=0):
    """ Update vip using VSVIP Object for given vs_name and vip_ip"""

    cloud_type = infra_utils.get_cloud_context_type()
    if vip_ip:
        new_ip = vip_ip
        network = None
    elif network:
        config = infra_utils.get_config()
        mode = config.get_mode()
        site_name = mode['site_name']
        try:
            network_obj = config.testbed[site_name].networks[network]
            new_ip = network_obj.get_ip_for_network()
        except KeyError as e:
            logger_utils.fail('Could not find the requested Network: %s , \
            Please check testbed networks, Exception: %s' % (network, str(e)))
    else:
        logger_utils.fail("Need to Pass VIP_IP or Subnet to update VIP for "
                          "given VS: %s" % vs_name)

    status_code, vs = rest.get('virtualservice', name=vs_name)
    vsvip_uuid = rest.get_uuid_from_ref(vs['vsvip_ref'])
    status_code, vsvip = rest.get('vsvip', uuid=vsvip_uuid)

    try:
        vsvip['vip'][vip_id]['ip_address']['addr'] = new_ip
        if cloud_type in ['gcp']:
            if network:
                vsvip['vip'][vip_id]['auto_allocate_ip'] = True
            else:
                vsvip['vip'][vip_id]['auto_allocate_ip'] = False
    except IndexError as e:
        logger_utils.fail("Can't find vip object with vip_id: %s for vs: %s"
                          % (vip_id, vs_name))
    status_code, data = rest.put('vsvip', uuid=vsvip_uuid, data=vsvip)


def set_listener_port_enable_ssl(vs_name, vport, ssl=False,
                                 expect_non_200_status=False):
    """Enable/Disable SSL for a given VS Listener port

    Args:
        :param vs_name: VirtualService name
        :param type: str
        :param vport: VirtualService Listener Port
        :param type: int

    Kwargs:
        :param ssl: SSL to enable/disable (default - false)
        :param

    """
    port_found = 0
    status_code, vs = rest.get('virtualservice', name=vs_name)

    for service in vs['services']:
        if service['port'] == int(vport):
            service['enable_ssl'] = ssl in [True, 1]
            port_found = 1
    if not port_found:
        logger_utils.fail('ERROR did not find listener port %s' % vport)

    status_code, data = rest.put('virtualservice', name=vs_name, data=vs,
                                 check_status_code=not expect_non_200_status)

    if expect_non_200_status:
        if status_code == 200:
            logger_utils.fail("Expected For Non 200 status, but got status as 200, while \
                 set_listener_port_enable_ssl to VS: %s " % vs_name)
            # XXX TODO setup shrpx clients needed?


def get_ip_from_net(network='net1'):
    config = infra_utils.get_config()
    mode = config.get_mode()
    site_name = mode['site_name']
    try:
        network_obj = config.testbed[site_name].networks[network]
        new_ip = network_obj.get_ip_for_network()
        return new_ip
    except KeyError as e:
        logger_utils.fail('Could not find the requested Network: %s , \
        Please check testbed networks, Exception: %s' % (network, str(e)))


def add_vip_address(vs_name, addr_type='V4', vip_idx=0, network='net1'):
    return configure_vip_address(vs_name=vs_name, addr_type=addr_type,
                                 vip_idx=vip_idx, operation='add',
                                 network=network)


def remove_vip_address(vs_name, addr_type='V4', vip_idx=0):
    return configure_vip_address(vs_name=vs_name, addr_type=addr_type,
                                 vip_idx=vip_idx, operation='remove')


def configure_vip_address(vs_name, addr_type='V4', vip_idx=0, operation=None,
                          network='net1'):
    """ API Helps to verify VIP is there in VS VIP data
    Args:
        :param vs_name: vs name
        :type vs_name: string
        :param addr_type: IP address type
        :type addr_type: string
        :param vip_idx: VIP index
        :type vip_idx: int
        :param operation: IP Address operation (add/remove)
        :type operation: string
        :param network: network, from which net want pick ip
        :type network: string
    Returns:
        VIP address
    """
    status_code, vs_data = rest.get('virtualservice', name=vs_name)

    addr = None
    if operation == 'add':
        if addr_type.upper() == 'V4':
            ip_address = 'ip_address'
            addr_type = 'V4'
        else:
            ip_address = 'ip6_address'
            addr_type = 'V6'
        addr = get_ip_from_net(network=network)
        ip_addr = {'type': addr_type, 'addr': addr}
        try:
            vs_data['vip'][vip_idx][ip_address] = ip_addr
        except Exception as e:
            logger_utils.error(
                "Error while adding IP Address type: %s i,e: %s" % (
                    addr_type, str(e)))
    elif operation == 'remove':
        if addr_type.upper() == 'V4':
            ip_addr_type = 'ip_address'
        else:
            ip_addr_type = 'ip6_address'
        try:
            addr = vs_data['vip'][vip_idx][ip_addr_type]['addr']
            del vs_data['vip'][vip_idx][ip_addr_type]
        except Exception as e:
            logger_utils.error(
                "Error while removing IP Address type: %s i,e: %s" % (
                    addr_type, str(e)))

    rest.put('virtualservice', name=vs_name, data=vs_data)
    return addr


def verify_vs_vip_address(vs_name, vip_address, addr_type, operation,
                          addr_should_be_in=True):
    """ API Helps to verify VIP is there in VS VIP data
    Args:
        :param vs_name: vs name
        :type vs_name: String
        :param vip_address: vip address want to check in vs.
        :type vip_address: srt
        :param addr_type: IP address type
        :type addr_type: String
        :param operation: IP Address operation (add/remove)
        :type operation: String
    Returns:
        boolean
    Raises:
        KeyError
    """
    status, data = rest.get('virtualservice', name=vs_name)
    logger.info(
        " VS VIP abject after operation %s: %s " % (operation, data['vip']))

    ip_address = 'ip_address'
    if addr_type.upper() == 'V6':
        ip_address = 'ip6_address'

    ip_present = False
    for each_vip in data['vip']:
        if ip_address in each_vip and each_vip[ip_address]['addr'] == vip_address:
            ip_present = True

    if addr_should_be_in and ip_present:
        logger.info(
            "IP Address: %s present as expected. in vs vip" % vip_address)
        return True
    elif not addr_should_be_in and not ip_present:
        logger.info(
            "IP Address: %s not there as expected. in vs vip" % vip_address)
        return True
    else:
        logger_utils.error("VIP Address check failed in VS vip obj. \n\
                        Expected state addr_should_be_in: %s\n \
                        Given IP address:%s\n VS VIP info:\n%s" %
                           (addr_should_be_in, vip_address, data['vip']))


def get_vs_vip(vs_name, addr_type='V4', vip_id='0', ignore_error=False):
    """
    API Helps to get vip for a given VS, vip id and address type
    Args:
        :param vs_name: vs name to get the vip address
        :type vs_name: str
        :param addr_type: IP address type, incase dual vip, default 'V4'
        :type addr_type: str
        :param vip_id: VS VIP index value, default '0'
        :type vip_id: str
    Raises:
        KeyError
    Return:
        True - Success
        False - Fail
    """
    vs_data = get_vs(vs_name)
    ip_address = 'ip_address' if addr_type == 'V4' else 'ip6_address'
    vip_dict = {}
    for vip in vs_data['vip']:
        if vip['vip_id'] == str(vip_id):
            if 'ip_address' in vip:
                vip_dict['ip_address'] = vip['ip_address']['addr']
            if 'ip6_address' in vip:
                vip_dict['ip6_address'] = vip['ip6_address']['addr']
    if addr_type:
        if ip_address in vip_dict:
            return vip_dict[ip_address]
        elif not ignore_error:
            logger_utils.error("Could not able to find VIP for given VS: %s,\
                   vip_idx: %s, addr_type: %s" % (vs_name, vip_id, addr_type))


def verify_vs_httpstats(vs_name, expected_httpstats):
    """
    API Helps to Verify HTTP stats for a given VS
    Args:
        :param vs_name: vs name to check TCP stats
        :type vs_name: str
        :param expected_httpstats: expected HTTP stats to check
        :type expected_httpstats: dict
    Return:
        True - Success
        False - Fail
    """
    status, data = rest.get('virtualservice', name=vs_name, path='httpstats')
    logger.info("VS : %s , HTTP stats details : %s" % (vs_name, data))
    vs_httpstats = data[0]
    result_list = []

    for stats in vs_httpstats:
        if stats in expected_httpstats:
            if expected_httpstats[stats] == vs_httpstats[stats]:
                result_list.append('True')
            else:
                result_list.append('False')
    if 'False' in result_list:
        logger_utils.error("VS HTTP stats Miss Match Expected: %s \
                     Actual data from vs http stats: %s" % (
            expected_httpstats, vs_httpstats))
        return False
    logger.info("Success: Expected HTTP stats Matched with Actual")
    return True


def verify_vs_tcpstats(vs_name, expected_tcpstats):
    """
    API Helps to Verify TCP stats for a given VS
    Args:
        :param vs_name: vs name to check TCP stats
        :type vs_name: str
        :param expected_tcpstats: expected TCP stats to check
        :type expected_tcpstats: dict
    Return:
        True - Success
        False - Fail
    """
    status, data = rest.get('virtualservice', name=vs_name, path='tcpstat')
    logger.info("VS : %s , TCP stats details : %s" % (vs_name, data))
    vs_tcpstat = data[0]

    result_list = []
    for tcp_stat in vs_tcpstat:
        if 'connection_stats' == tcp_stat:
            for con_stats in vs_tcpstat[tcp_stat]:
                if con_stats in expected_tcpstats:
                    if vs_tcpstat[tcp_stat][con_stats] == expected_tcpstats[con_stats]:
                        result_list.append('True')
                    else:
                        result_list.append('False')
    if 'False' in result_list:
        logger.info("result_list: %s" % result_list)
        logger_utils.error("VS TCP stats Miss Match Expected: %s \
                     Actual data from vs TCP stats: %s" % (
            expected_tcpstats, vs_tcpstat))
        return False
    logger.info("Success: Expected TCP stats Matched with Actual")
    return True


def verify_vs_udpstats(vs_name, expected_udpstats):
    """
    API Helps to Verify UPD stats for a given VS
    Args:
        :param vs_name: vs name to check UDP stats
        :type vs_name: str
        :param expected_udpstats: expected UDP stats to check
        :type expected_udpstats: dict
    Return:
        True - Success
        False - Fail
    """
    status, data = rest.get('virtualservice', name=vs_name, path='udpstat')
    logger.info("VS : %s , UDP stats details : %s" % (vs_name, data))
    vs_udpstats = data[0]

    result_list = []
    for udp_stat in vs_udpstats:
        if udp_stat in expected_udpstats:
            if vs_udpstats[udp_stat] == expected_udpstats[udp_stat]:
                result_list.append('True')
            else:
                result_list.append('False')

    if 'False' in result_list:
        logger.info("result_list: %s" % result_list)
        logger_utils.error("VS UDP stats Miss Match Expected: %s \
                     Actual data from vs UDP stats: %s" % (
            expected_udpstats, vs_udpstats))
        return False
    logger.info("Success: Expected UDP stats Matched with Actual")
    return True


def get_vs_type(vs_name):
    """

    :param vs_name:
    :return:
    """

    status_code, vs = rest.get('virtualservice', name=vs_name)
    uuid = rest.get_uuid_from_ref(vs['application_profile_ref'])
    status_code, applicationprofile = rest.get('applicationprofile', uuid=uuid)
    vs_type = applicationprofile['type']
    return vs_type


def check_for_vs(vs_list, timeout=180, check_present=True,
                 verify_dns=True, dns_suffix='', **kwargs):
    """
    Check if the list of vs are present or not
    :param vs_list:
    :param timeout:
    :param check_present:
    :param verify_dns:
    :param dns_suffix:
    :param kwargs:
    :return:
    """
    import lib.ipam_lib as ipam_lib
    timeout = int(timeout)
    vs_list = set(vs_list)
    start_time = time.time()
    round_timeout = 15
    while ((time.time() - start_time) < timeout) and vs_list:
        vs_changed = []
        for vs in vs_list:
            try:
                http_code, vs_objs = rest.get('virtualservice', name=vs)
                if check_present and not vs_objs:
                    continue
                if not check_present and vs_objs:
                    continue
                if check_present and (not is_vs_assigned(vs, **kwargs)):
                    logger.trace('vs %s not up' % vs)
                    continue
                vs_changed.append(vs)
                if check_present and verify_dns:
                    ipam_lib.validate_vs_dns_info(vs, retries=5, **kwargs)
                elif verify_dns and dns_suffix:
                    ipam_lib.validate_vs_dns_deleted(vs + '.' + dns_suffix,
                                                     retries=5,
                                                     **kwargs)
            except:
                if not check_present:
                    vs_changed.append(vs)
                continue

        for vs in vs_changed:
            vs_list.remove(vs)
        if vs_list:
            logger_utils.asleep(delay=round_timeout)
    if vs_list:
        # still have some apps that are not changed
        predicate = 'not' if check_present else 'still'
        logger_utils.fail(
            'VS(es): %s %s present or up' % (str(vs_list), predicate))


def vs_check_ip_ports(vs_name, ip, dns_name, ports, dns_vs_vip=None):
    """

    :param vs_name:
    :param ip:
    :param dns_name:
    :param ports:
    :param dns_vs_vip:
    :return:
    """
    import lib.ipam_lib as ipam_lib
    resolver = ipam_lib.dns_get_resolver(dns_vs_vip=dns_vs_vip)

    # If we're using a DNS VS, only check SRV record (ports) for E/W and
    # A record (ips) for N/S
    if dns_vs_vip:
        if ip == '0.0.0.0':
            # Unsupported from 17.1 onwards
            """
            portl = dns_get_ports_for_fqdn(resolver, dns_name)
            logger.info("DNS info for E/W VS %s: Ports %s"%(dns_name, portl))
            if portl == ports:
                return True
            else:
                logger.warning("%s: Ports mismatch: cfg %s, dns %s"%(vs_name, ports, portl))
                return False
            """
            return True
        else:
            ipl = ipam_lib.dns_get_ips_for_fqdn(resolver, dns_name)
            logger.info("DNS info for N/S VS %s: IPs %s" % (dns_name, ipl))
            if len(ipl) == 1 and ipl[0] == ip:
                return True
            else:
                if len(ipl) != 1:
                    logger.warning(
                        "VS %s: Too many/less ips: cfg %s, dns %s" % (
                            vs_name, ip, ipl))
                elif ipl[0] != ip:
                    logger.warning("VS %s: IP mismatch: cfg %s, dns %s" % (
                        vs_name, ip, ipl[0]))
                return False
    else:
        ipl, portl = ipam_lib.dns_get_ip_ports_for_fqdn(resolver, dns_name)
        logger.info("DNS info for VS %s: IPs %s, Ports %s" % (
            dns_name, ipl, portl))
        if portl != ports:
            logger.warning("VS %s: Ports mismatch: cfg %s, dns %s" % (
                vs_name, ports, portl))
            return False
        if len(ipl) != 1:
            logger.warning("VS %s: Too many/less ips: cfg %s , dns %s" % (
                vs_name, ip, ipl))
            return False
        if ipl[0] != ip:
            logger.warning("VS %s: IP mismatch: cfg %s, dns %s" % (
                vs_name, ip, ipl[0]))
            return False
        return True


def check_vs_created(vs_name, num_tries=60, session='default_session',
                     tenant='admin', **kwargs):
    """

    :param vs_name:
    :param num_tries:
    :param session:
    :param tenant:
    :param kwargs:
    :return:
    """

    while num_tries > 0:
        if is_vs_assigned(vs_name, tenant=tenant, **kwargs):
            return
        if num_tries > 1:
            # else it doesn't matter since we will error out anyways
            logger_utils.asleep(delay=15)
        num_tries -= 1
    logger_utils.fail('VS %s is not up' % vs_name)


def get_vs_listener_port_from_runtime(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """

    port_list = []
    s_list = get_vs_from_runtime(vs_name, **kwargs)['services']
    for i in s_list:
        port_list.append(i['port'])
    logger.info(port_list)
    return port_list


# REVIEW this doesn't seem like it gets from runtime; and is a copy of get_vs()
def get_vs_from_runtime(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """

    resp_code, resp_data = rest.get('virtualservice', name=vs_name)
    json_data = resp_data
    logger.info('get_vs_runtime_detail %s' % resp_data)
    return resp_data


def pool_should_be_up_from_vs_runtime(vs_name, vip_index=0, **kwargs):
    """

    :param vs_name:
    :param vip_index:
    :param kwargs:
    :return:
    """

    vip_summary = get_vs_runtime(vs_name,
                                 **kwargs)  # ['vip_summary'][vip_index]
    pool_status = vip_summary['oper_status']['state']
    if pool_status != "OPER_UP":
        logger_utils.fail(
            'ERROR! Expected pool status in vs %s OPER_UP, but got %s' % (
                vs_name, pool_status))


# REVIEW the timing on this is really flaky, perhaps because it needs to
# acquire the update events from the logs?
def wait_for_vs_updates(app_name, expected_updates, timeout=300,
                        tenant='admin'):
    """
    Utility method to not have to blindly sleep waiting for updates
    :param app_name:
    :param expected_updates:
    :param timeout:
    :param tenant:
    :return:
    """

    start = time.time()
    while (time.time() - start) <= timeout:
        updates = get_vs_update_count(app_name, tenant=tenant)
        if updates > expected_updates:
            logger_utils.fail('Error! Got more updates %s than expected %s' % (
                updates, expected_updates))
        elif updates == expected_updates:
            return
        else:
            logger_utils.asleep(delay=15)
    logger_utils.fail(
        "Error! Waited for %d seconds but still didn't get expected number of "
        "updates: %s; only got: %s" % (timeout, expected_updates, updates))


def get_vs_update_count(app_name, tenant='admin'):
    """

    :param app_name:
    :param tenant:
    :return:
    """
    import lib.controller_lib as controller_lib
    # REVIEW: may need to support multiple/all tenants.
    # This may imply that avi_rest_lib.get shouldn't set X-Avi-Tenant if no
    # tenant is specified, since that appears to filter
    # the results (i.e. get without that header set will return all
    # tenants normally)
    vs_update_event_count = 0
    events_rsp = controller_lib.fetch_controller_events(fetch_all=True,
                                                        tenant=tenant)
    events = events_rsp['results']
    if events:
        update_events = [ev for ev in events
                         if ((ev['obj_type'] == 'VIRTUALSERVICE') and
                             (ev['event_id'] == 'CONFIG_UPDATE') and
                             (ev['obj_name'] == app_name))]
        logger.debug('VS_UPDATES: %s' % ('\n'.join(map(str, update_events))))
        vs_update_event_count = len(update_events)
    logger.debug('VS_UPDATE_COUNT: %d' % vs_update_event_count)
    return vs_update_event_count


def check_vs_deleted(vs_name):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """
    resp_code, resp_data = rest.get('virtualservice', name=vs_name, check_status_code=False)
    if resp_code != 404:
        logger.fail('ERROR! VS %s not deleted: resp_code %s resp_data %s'
                       % (vs_name, resp_code, resp_data))


def vs_get_vip(vs_name, vip_id='0', **kwargs):
    """
    get vip in vs
    :param vs_name:
    :param vip_id:
    :param kwargs:
    :return:
    """

    vs_data = get_vs(vs_name, **kwargs)
    for vip in vs_data['vip']:
        if vip_id == vip['vip_id']:
            return vip['ip_address']['addr']


def create_application_obj(app_name, **kwargs):
    """

    :param app_name:
    :param kwargs:
    :return:
    """

    app = copy.deepcopy(DEFAULT_APPLICATION)
    app['name'] = app_name
    rc, rsp = rest.post('application', name=app_name, data=app)
    logger.info('created application rc %d, rsp %s' % (rc, rsp))


def add_vs_to_application(app_name, vs_list=[], **kwargs):
    """
    :param app_name:
    :param vs_names:
    :param kwargs:
    :return:
    """

    vs_refs = []
    for vs in vs_list:
        rc, vs_obj = rest.get('virtualservice', name=vs)
        vs_refs.append(vs_obj['url'])
    rc, rsp = rest.get('application', name=app_name)

    if 'virtualservice_refs' in rsp:
        rsp['virtualservice_refs'].extend(vs_refs)
    else:
        rsp['virtualservice_refs'] = vs_refs
    app_uuid = rsp['uuid']
    rc, rsp = rest.put('application', uuid=app_uuid, data=rsp,)


def delete_application_obj(app_name, **kwargs):
    """

    :param app_name:
    :param kwargs:
    :return:
    """

    resp_code, response = rest.delete('application', name=app_name)
    logger.info('created application rc %d, rsp %s' % (resp_code, response))


def get_pool_group_for_vs(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """

    _, vs_obj = rest.get('virtualservice', name=vs_name)
    pg_ref = vs_obj.get('pool_group_ref', None)
    if not pg_ref:
        logger_utils.fail('Did not find pool_group_ref for vs %s' % vs_name)
    pg_uuid = pg_ref.split('poolgroup/')[1].split('#')[0]
    _, pg_obj = rest.get('poolgroup', uuid=pg_uuid)
    return pg_obj['name']


def wait_for_vs_to_not_be_assigned(vs_name, timeout=120, **kwargs):
    """

    :param vs_name:
    :param timeout:
    :param kwargs:
    :return:
    """

    start_time = time.time()
    while (time.time() - start_time) < timeout:
        if not is_vs_assigned(vs_name, **kwargs):
            return
        logger_utils.asleep(delay=10)
    logger_utils.fail(
        'ERROR! %s is still assigned after %s seconds' % (vs_name, timeout))


def vs_get_fqdn(vs_name, **kwargs):
    """
    get FQDN in VS
    :param vs_name:
    :param kwargs:
    :return:
    """
    vs_data = get_vs(vs_name, **kwargs)
    if not vs_data:
        logger_utils.fail('VS %s GET failed' % vs_name)
    dns_info = vs_data['dns_info']
    if len(dns_info) > 0:
        return dns_info[0]['fqdn']
    else:
        return None


def delete_vs(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """

    config = infra_utils.get_config()
    if config.testbed[config.site_name].cloud[0]['vtype'] == 'aws':
        try:
            se_name = vs_get_primary_se_name(vs_name)
            if se_name is not None:
                for se in infra_utils.get_vm_of_type('se'):
                    if se.ip == se_name:
                        se_name = se.name
                        # vs_info = config.vs_info[pb.name]
                        # config.cloud.unassign_secondary_ip(
                        #    se_name, vs_info['net'], vs_info['ip'])
        except Exception as e:
            logger.info(str(e))
            raise

    rest.delete('virtualservice', name=vs_name)
    webapp_lib.validate_after_delete('virtualservice', vs_name)


def vs_get_se_grp(vs_name, tenant="admin"):
    """
    get se_grp in vs
    :param vs_name:
    :param tenant:
    :return:
    """

    vs_data = get_vs(vs_name, tenant=tenant)
    return rest.get_uuid_from_ref(vs_data['se_group_ref'])


def get_last_modified(obj_type, obj_name, **kwargs):
    """

    :param obj_type:
    :param obj_name:
    :param kwargs:
    :return:
    """

    resp_code, response = rest.get(obj_type, name=obj_name)
    return response['_last_modified']


def get_vs_with_wait(vs_name, retry_count=0, retry_interval=0.1, **kwargs):
    """

    :param vs_name:
    :param retry_count:
    :param retry_interval:
    :param kwargs:
    :return:
    """

    retry_interval = float(retry_interval)
    if retry_interval <= 0:
        logger_utils.fail(
            'retry_interval <= 0 is not allowed, was: %s' %
            retry_interval)
    if retry_count < 0:
        logger_utils.fail(
            'retry_count < 0 is not allowed, was %s' % retry_count)
    retry_count = int(retry_count)

    logger.debug('Retry called with retry_count=%s, retry_interval=%s'
                 % (str(retry_count), str(retry_interval)))
    tries = 1
    obj_type = 'virtualservice'

    is_update = kwargs.get('is_update', False)
    _last_modified = kwargs.get('last_modified', None)
    is_delete = kwargs.get('is_delete', False)
    is_create = kwargs.get('is_create', False)

    for x in xrange(1, retry_count):
        tries += 1
        logger.debug('Attempting try no:%s' % str(tries))
        if is_update:
            new_last_modified = get_last_modified("virtualservice", vs_name,
                                                  **kwargs)
            if new_last_modified != _last_modified:
                return True
            else:
                logger_utils.asleep(delay=retry_interval)
        if is_delete:
            try:
                resp_code, resp_data = rest.get(obj_type, name=vs_name)
                logger_utils.asleep(delay=retry_interval)
                continue
            except:
                return True
        if is_create:
            try:
                resp_code, resp_data = rest.get(obj_type, name=vs_name)
            except:
                logger_utils.asleep(delay=retry_interval)
                continue
            return True

    logger_utils.fail('Failed after %s tries' % tries)


def vs_get_se_name_list(vs_name, vip_id='0', **kwargs):
    """

    :param vs_name:
    :param vip_id:
    :param kwargs:
    :return:
    """

    vip_summary = get_vip_summary(vs_name, vip_id, **kwargs)
    se_list = []
    if vip_summary.get('service_engine'):
        for se in vip_summary['service_engine']:
            if kwargs.get('primary') and not se.get('primary'):
                continue
            if kwargs.get('standby') and not se.get('standby'):
                continue
            if kwargs.get('secondary') and (
                        se.get('primary') or se.get('standby')):
                continue
            se_name = webapp_lib.get_name_by_uuid('serviceengine', se['uuid'])
            se_list.append(se_name)
    return se_list


def get_mesos_vs_se_num_total(vs_name):
    """

    :param vs_name:
    :return:
    """

    vs_data = get_vs_runtime(vs_name)
    if vs_data['vip_summary'][0]:
        return vs_data['vip_summary'][0]['num_se_assigned']


def get_vs_runtime_detail_agg(vs_name, field1='', field2=''):
    """

    :param vs_name:
    :param field1:
    :param field2:
    :return:
    """

    resp_code, resp_data = rest.get('virtualservice', name=vs_name,
                                    path='/runtime/detail')
    val = 0
    logger.info('Response: %s' % resp_data)
    for vip_data in resp_data[0]['vip_detail']:
        for json_data in vip_data[field1]:
            val += int(json_data[field2])

    logger.info('get_vs_runtime_detail_agg %s' % val)
    return val


def get_object_with_wait(obj_name, obj_type, tenant='default', retry_count=0,
                         retry_interval=0.1, **kwargs):
    """

    :param obj_name:
    :param obj_type:
    :param tenant:
    :param retry_count:
    :param retry_interval:
    :param kwargs:
    :return:
    """

    retry_interval = float(retry_interval)
    if retry_interval <= 0:
        logger_utils.fail('retry_interval <= 0 is not allowed, was: %d' % int(retry_interval))
    if retry_count < 0:
        logger_utils.fail('retry_count < 0 is not allowed, was %d' % int(retry_count))
    retry_count = int(retry_count)

    logger.debug('Retry called with retry_count=%s, retry_interval=%s'
                 % (str(retry_count), str(retry_interval)))
    tries = 1
    url = '%s/%s' % (obj_type, obj_name)

    is_update = kwargs.get('is_update', False)
    is_delete = kwargs.get('is_delete', False)

    for x in xrange(1, retry_count):
        tries = 1
        logger.debug('Attempting try no:%s' % str(tries))
        if is_update:
            try:
                resp_code, resp_data = rest.get(obj_type, name=obj_name)
                return resp_data
            except:
                logger_utils.asleep(delay=retry_interval)

        if is_delete:
            try:
                resp_code, resp_data = rest.get(obj_type, name=obj_name)
                return True
            except:
                logger_utils.asleep(delay=retry_interval)
    logger_utils.fail('Failed after %s tries' % tries)


def get_vs_ssl_certs(vs, **kwargs):
    """

    :param vs:
    :param kwargs:
    :return:
    """

    vs_resp = get_vs(vs, **kwargs)
    ssl_keycert_list = []
    for ssl_keycert_ref in vs_resp['ssl_key_and_certificate_refs']:
        ssl_keycert_list.append(rest.get_name_from_ref(ssl_keycert_ref))
    return ssl_keycert_list


def get_vs_listener_port_count_from_runtime(vs_name):
    """

    :param vs_name:
    :return:
    """
    port_list = get_vs_listener_port_from_runtime(vs_name)
    return len(port_list)


def get_vs_pool_server_count(vs_name):
    """

    :param vs_name:
    :return:
    """
    import lib.pool_lib as pool_lib
    _, vs_obj = rest.get('virtualservice', name=vs_name)
    kwargs = {}
    pool_ref = pool_lib._get_pool_from_vs(vs_obj, **kwargs)
    pool_uuid = rest.get_uuid_from_ref(pool_ref)
    rc, pool_obj = rest.get('pool', uuid=pool_uuid)
    return len(pool_obj['servers'])


def get_floating_vip(vs_name, vip_id='0'):
    """

    :param vs_name:
    :param vip_index:
    :return:
    """
    floating_ip_addr = None
    resp_code, json_vs_data = rest.get('virtualservice', name=vs_name)
    for vip_data in json_vs_data.get('vip', []):
        if vip_data.get('vip_id') == vip_id:
            floating_ip_addr = vip_data.get('floating_ip').get('addr')
    else:
        if json_vs_data.get('type') == 'VS_TYPE_VH_CHILD':
            parent_vs_name = \
                rest.get_name_from_ref(json_vs_data.get('vh_parent_vs_ref'))
            resp_code, json_parent_vs_data = \
                rest.get('virtualservice', name=parent_vs_name)
            if json_parent_vs_data and json_parent_vs_data.get('vip'):
                for vip_data in json_parent_vs_data.get('vip', []):
                    if vip_data.get('vip_id') == vip_id:
                        floating_ip_addr = vip_data.get('floating_ip').get('addr')
    return floating_ip_addr


def get_listener_port_enable_ssl(vs_name, vport, skip_exc=0):
    """

    :param vs_name:
    :param vport:
    :param skip_exc:
    :return:
    """
    _, json_vs_data = rest.get("virtualservice", name=vs_name)
    logger.trace('Lookup for vport %s' % vport)
    for service in json_vs_data['services']:
        logger.trace(' vs services %s' % service.get('port'))
        if service.get('port') <= int(vport) <= service.get('port_range_end'):
            return service.get('enable_ssl')
    if skip_exc == 0:
        logger_utils \
            .fail('ERROR did not find listener port %s' % vport)


def get_protocol(vs_name, port, skip_exec=0):
    """

    :param vs_name:
    :param port:
    :param skip_exec:
    :return:
    """
    if get_listener_port_enable_ssl(vs_name, port, skip_exec):
        return 'https://'
    else:
        return 'http://'


def vs_get_manual_candidate_list(vs_name, vip_id):
    """

    :param vs_name:
    :param vip_id:
    :return:
    """
    @logger_utils.aretry(retry=10, delay=30)
    def retry_action():
        return rest.get('virtualservice', name=vs_name,
                        path='candidatesehostlist', params={'vip_id': vip_id})
    resp_code, resp_data = retry_action()

    se_list = []
    try:
        se_list = [webapp_lib.get_uuid_from_ref(se['se_ref']) for se in
                   resp_data[0]['se']]
    except KeyError, Argument:
        logger_utils.error('Rest result did not have required field: %s' % Argument)
    return se_list


def update_virtualservice(vs_name, vip_index=0, **kwargs):
    """

    :param vs_name:
    :param vip_index:
    :param kwargs:
    :return:
    """
    # To do skip check when baremetal and east west vs
    # if config.cloud.type == 'baremetal':
    #     if pb.east_west_placement:
    #         print "baremetal, skip update for east_west vs:" + vs_name
    #         return

    resp_code, resp_data = rest.get("virtualservice", name=vs_name)
    skip_rest = kwargs.pop('skip_rest', None)
    http_policies = kwargs.pop('http_policies', None)
    subnet_ip = kwargs.pop('subnet_ip', None)
    subnet_mask = kwargs.pop('subnet_mask', None)
    auto_allocate_ip = kwargs.pop('auto_allocate_ip', False)
    network_uuid = kwargs.pop('network_uuid', None)

    fqdn_val = kwargs.get('fqdn', None)

    if fqdn_val:
        resp_data['dns_info'][0]['fqdn'] = fqdn_val

    for index, vip_data in enumerate(resp_data['vip']):
        if vip_data['vip_id'] == vip_index:
            if network_uuid:
                resp_data['vip'][index]['network_uuid'] = network_uuid
            if subnet_ip and subnet_mask:
                resp_data['vip'][index]['subnet']['ip_addr']['addr'] = subnet_ip
                resp_data['vip'][index]['subnet']['ip_addr']['type'] = 'V4'
                resp_data['vip'][index]['subnet']['mask'] = int(subnet_mask)

    vsvip_uuid = kwargs.get('pop_vsvip_uuid', False)
    if vsvip_uuid:
        del resp_data['vsvip_uuid']

    vip = kwargs.get('pop_vip', False)
    if vip:
        del resp_data['vip']

    vsvip_uuid = kwargs.get('vsvip_uuid', None)
    if vsvip_uuid:
        resp_data['vsvip_uuid'] = vsvip_uuid

    for index, vip_data in enumerate(resp_data['vip']):
        resp_data['vip'][index]['auto_allocate_ip'] = auto_allocate_ip
        ip_addr = kwargs.get('new_ip', None)
        if ip_addr:
            resp_data['vip'][index]['ip_address']['addr'] = ip_addr
            resp_data['vip'][index]['ip_address']['type'] = 'V4'

    auto_allocate_floating_ip = kwargs.pop('auto_allocate_floating_ip', None)
    if auto_allocate_floating_ip is not None:
        for index, vip_data in enumerate(resp_data['vip']):
            resp_data['vip'][index]['auto_allocate_floating_ip'] = \
                auto_allocate_floating_ip

    config = infra_utils.get_config()

    nw = kwargs.pop('vip_nw', None)
    if nw:
        new_vip = config.testbed[config.site_name].networks_json[nw]['ip']
        for index, vip_data in enumerate(resp_data['vip']):
            if vip_data['vip_id'] == vip_index:
                resp_data['vip'][index]['ip_address']['addr'] = new_vip
                resp_data['vip'][index]['ip_address']['type'] = 'V4'

    floating_ip_nw = kwargs.pop('floating_ip_nw', None)
    if floating_ip_nw == "Remove":
        for index, vip_data in enumerate(resp_data['vip']):
            if vip_data['vip_id'] == vip_index and resp_data['vip'][index]['floating_ip']:
                del resp_data['vip'][index]["floating_ip"]

    elif floating_ip_nw:
        new_floating_ip = config.testbed[config.site_name].networks_json[nw][
            'ip']
        for index, vip_data in enumerate(resp_data['vip']):
            if vip_data['vip_id'] == vip_index and resp_data['vip'][index]['floating_ip']:
                if not resp_data['vip'][index]['floating_ip']:
                    resp_data['vip'][index]['floating_ip'] = new_floating_ip

                resp_data['vip'][index]['floating_ip']['addr'] = new_floating_ip
                resp_data['vip'][index]['floating_ip']['type'] = 'V4'

    services_add = kwargs.pop('services_add', None)
    if services_add:
        _parse_services(resp_data, services_add)
        if len(resp_data['services']) > 1:
            override_np = kwargs.pop('override_np_uuid', None)
            if override_np:
                resp_data['services'][1]['override_network_profile_uuid'] = \
                    override_np

    services_delete = kwargs.pop('services_delete', None)
    if services_delete:
        _parse_services(resp_data, services_delete, services_del=True)

    static_dns_records_add = kwargs.pop('static_dns_records_add', [])
    if static_dns_records_add:
        for from_entry in static_dns_records_add:
            resp_data['static_dns_records']['fqdn'].append(from_entry[0])
            resp_data['static_dns_records']['fqdn'].append(from_entry[1])

            resp_data['static_dns_records']['ip_address']['type'] = 'V4'
            resp_data['static_dns_records']['ip_address']['addr'] = \
                from_entry[2]

    static_dns_records_del = kwargs.pop('static_dns_records_del', [])
    if static_dns_records_del:
        index = 0
        del_list = []
        for del_entry in static_dns_records_del:
            for entry in resp_data['static_dns_records']:
                if entry.fqdn[0] == del_entry[0]:
                    del_list.append(index)
                    break
                index += 1
        del_list.sort(reverse=True)
        for index in del_list:
            del resp_data['static_dns_records'][index]

    '''
    ToDo: add http_policy
    js = config.update_pb_obj(pb, kwargs)
    # this function accept only one policy set
    if http_policies:
        if isinstance(http_policies, list):
            http_policies = http_policies[0]
        js['http_policies'] = [{
            'index': 11,
            'http_policy_set_uuid': http_policies
        }]
    '''

    vsvip_uuid = kwargs.pop('vsvip_uuid', None)
    if vsvip_uuid:
        resp_data['vsvip_uuid'] = vsvip_uuid

    application_profile_name = kwargs.get('application_profile_name')
    if application_profile_name:
        resp_code, json_application_profile_data = rest.get(
            'applicationprofile', name=application_profile_name)
        resp_data['application_profile_ref'] = \
            json_application_profile_data.get('url')
    elif not resp_data['application_profile_ref']:
        resp_code, json_application_profile_data = rest.get(
            'applicationprofile', name='System-HTTP')
        resp_data['application_profile_ref'] = \
            json_application_profile_data.get('url')

    server_network_profile_name = kwargs.get('server_network_profile_name')
    if server_network_profile_name:
        resp_code, json_server_network_profile_data = rest.get('networkprofile',
                                                               name=server_network_profile_name)
        resp_data[
            'server_network_profile_ref'] = json_server_network_profile_data.get(
            'url')

    network_profile_name = kwargs.get('network_profile_name')
    if network_profile_name:
        resp_code, json_network_profile_data = rest.get('networkprofile',
                                                        name=network_profile_name)
        resp_data['network_profile_ref'] = json_network_profile_data.get(
            'url')

    if kwargs.get('pool_name'):
        pool_name = kwargs.get('pool_name')
        resp_code, json_pool_data = rest.get(
            'pool', name=pool_name)
        resp_data['pool_ref'] = json_pool_data.get('url')
    else:
        if resp_data.get('pool_group_uuid'):
            del kwargs['pool_uuid']
            resp_data['pool_group_uuid'] = ''

    subnet = kwargs.get("subnet", None)
    if subnet:
        for index, vip_data in enumerate(resp_data['vip']):
            if vip_data['vip_id'] == vip_index:
                resp_data['vip'][index]['subnet']['ip_addr']['addr'] = \
                    subnet.split('/')[0]
                resp_data['vip'][index]['subnet']['ip_addr']['type'] = 'V4'
                resp_data['vip'][index]['subnet']['mask'] = int(subnet.split(
                    '/')[1])

    vs_type = kwargs.get("type", None)
    if vs_type == 'VS_TYPE_VH_CHILD':
        del resp_data['vip'][:]

    ip = kwargs.pop('vip__addr', None)
    if ip:
        if not resp_data['vip']:
            resp_data['vip'][0].ip_address.addr = ip
            resp_data['vip'][0].ip_address.type = 'V4'
        else:
            resp_data['vip'][vip_index]['ip_address']['addr'] = ip

    if skip_rest:
        return resp_data
    else:
        kwargs.setdefault("tenant", config.tenant)
        rest.put('virtualservice', name=vs_name, data=resp_data)
    return


def _parse_services(pb, services, services_del=False):
    """
    services_del flag is used to delete entries
    :param pb:
    :param services:
    :param services_del:
    :return:
    """
    parsed_services = []
    if isinstance(services, basestring):
        split_services = services.split(' ')
        for port in split_services:
            parsed_services.append({'port': port})
    elif type(services) is list:
        parsed_services = services
    else:
        logger_utils.fail("Services kwarg must be string / list of "
                          "dictionaries")

    if not services_del:
        for service in parsed_services:
            p = dict()
            p['port'] = int(service['port'])
            p['port_range_end'] = int(service['port'])
            if service.get('ssl_enabled') is not None:
                p['enable_ssl'] = common._bool_value(str(service['ssl_enabled']))
            if service.get('override_network_profile_uuid') \
                    is not None:
                p['override_network_profile_uuid'] = \
                    service['override_network_profile_uuid']
            pb['services'].append(json.dumps(p))
    else:
        del_list = []
        for service in parsed_services:
            index = 0
            for entry in pb['services']:
                if entry['port'] == int(service['port']):
                    del_list.append(index)
                    break
                index += 1
        del_list.sort(reverse=True)
        for index in del_list:
            del pb['services'][index]
    return


def check_cache_vs_up_percent(vs_name, up_percent=0, vip_id=0):
    """

    :param vs_name:
    :param up_percent:
    :param vip_id:
    :return:
    """
    vs_summary = get_vs_runtime(vs_name)
    vip_id_existance = 0
    for vip_summary in vs_summary['vip_summary']:
        if int(vip_summary['vip_id']) == int(vip_id):
            vip_id_existance = 1
            break
    if vip_id_existance == 0:
        logger_utils.fail(
            'Supplied vip_id: %s does not exist in VS: %s' % (vip_id, vs_name))

    try:
        percent = vip_summary['percent_ses_up']
    except KeyError, Argument:
        logger_utils.fail('## percentage_up not available: %s' % Argument)

    if int(percent) != int(up_percent):
        logger_utils.fail('## Expected %d Got %d' % (up_percent, percent))


def update_vs_analytics_policy_full_logs(vs_name, skip_rest=False, **kwargs):
    """

    :param vs_name:
    :param skip_rest:
    :param kwargs:
    :return:
    """
    _, vs_data = rest.get('virtualservice', name=vs_name)
    if kwargs.get('enabled'):
        vs_data['analytics_policy']['full_client_logs']['enabled'] = True
    else:
        vs_data['analytics_policy']['full_client_logs']['enabled'] = False

    if kwargs.get('duration'):
        vs_data['analytics_policy']['full_client_logs']['duration'] = int(
            kwargs.get('duration'))
    else:
        vs_data['analytics_policy']['full_client_logs']['duration'] = 30

    if not skip_rest:
        rest.put('virtualservice', name=vs_name, data=vs_data)
    else:
        return vs_data


def update_vs_analytics_policy_metrics_realtime(vs_name, skip_rest=False,
                                                **kwargs):
    """

    :param vs_name:
    :param skip_rest:
    :param kwargs:
    :return:
    """
    _, vs_data = rest.get('virtualservice', name=vs_name)

    if kwargs.get('enabled'):
        vs_data['analytics_policy']['metrics_realtime_update']['enabled'] = True
    else:
        vs_data['analytics_policy']['metrics_realtime_update'][
            'enabled'] = False

    if kwargs.get('duration'):
        vs_data['analytics_policy']['metrics_realtime_update']['duration'] = \
            int(kwargs.get('duration'))
    else:
        vs_data['analytics_policy']['metrics_realtime_update']['duration'] = 30

    if not skip_rest:
        rest.put('virtualservice', name=vs_name, data=vs_data)
    else:
        return vs_data


def update_vs_analytics_policy_log_filter_duration(vs_name, filter_name,
                                                   skip_rest=False, **kwargs):
    """
    :param vs_name:
    :param filter_name:
    :param skip_rest:
    :param kwargs:
    :return:
    """
    found = False
    _, vs_data = rest.get('virtualservice', name=vs_name)

    for index, log_filter in enumerate(
            vs_data['analytics_policy']['client_log_filters']):
        if log_filter['name'] == filter_name:
            found = True
            if kwargs.get('enabled'):
                vs_data['analytics_policy']['client_log_filters'][index]['enabled'] = True
            else:
                vs_data['analytics_policy']['client_log_filters'][index]['enabled'] = False

            if kwargs.get('duration'):
                vs_data['analytics_policy']['client_log_filters'][index]['duration'] = int(kwargs.get('duration'))
            else:
                vs_data['analytics_policy']['client_log_filters'][index]['duration'] = 30

    if not found:
        logger_utils.fail(
            'client_log_filters with name[%s] not found for vs[%s]' % (
                filter_name, vs_name))

    if not skip_rest:
        rest.put('virtualservice', name=vs_name, data=vs_data)
    else:
        return vs_data


def set_vs_log_adf_throttling(vs_name, count):
    """

    :param vs_name:
    :param count:
    :return:
    """
    _, vs_data = rest.get('virtualservice', name=vs_name)
    vs_data['analytics_policy']['significant_log_throttle'] = count
    rest.put('virtualservice', name=vs_name, data=vs_data)


def set_vs_log_udf_throttling(vs_name, count):
    """

    :param vs_name:
    :param count:
    :return:
    """
    _, vs_data = rest.get('virtualservice', name=vs_name)
    vs_data['analytics_policy']['udf_log_throttle'] = count
    rest.put('virtualservice', name=vs_name, data=vs_data)


def set_vs_log_nf_throttling(vs_name, count):
    """

    :param vs_name:
    :param count:
    :return:
    """
    _, vs_data = rest.get('virtualservice', name=vs_name)
    vs_data['analytics_policy']['full_client_logs']['full_client_logs'] = True
    vs_data['analytics_policy']['full_client_logs']['throttle'] = count
    rest.put('virtualservice', name=vs_name, data=vs_data)


def set_vs_log_throttling(vs_name, count):
    """

    :param vs_name:
    :param count:
    :return:
    """
    count = int(count)
    set_vs_log_adf_throttling(vs_name, count)
    set_vs_log_udf_throttling(vs_name, count)
    set_vs_log_nf_throttling(vs_name, count)


def keys_should_rotate(old_keys, new_keys, rotate_count):
    """
    :param old_keys:
    :param new_keys:
    :param rotate_count:
    :return:
    """
    logger.info("old_keys: %s\nnew_keys: %s\n rotate_count: %d" % (
        old_keys, new_keys, rotate_count))

    if len(old_keys) == 3:
        common_keys = len([key for key in new_keys if key in old_keys])
        actual_rotation_count = 3 - common_keys if common_keys else 3
        if actual_rotation_count > rotate_count:
            # do not retry if rotation happens more than expected times
            return False, 'Expected rotation count[%d] lesser than actual rotation[%d]' % (
                rotate_count, actual_rotation_count)

        if actual_rotation_count != rotate_count:  # make sure keys rotaion count meets expected rotate_count
            return True, 'Expected rotation count[%d] != %d' % (
                rotate_count, actual_rotation_count)

        # verify keys got rotated from end of old_keys
        for i in range(rotate_count):
            if old_keys[::-1][i] in new_keys:
                return True, 'keys are not rotated from end of list, latest keys are replaced'

        # make sure 3 - no. of rotate_count keys should not be rotated from old_keys
        for i in range(rotate_count, 3):
            if old_keys[::-1][i] not in new_keys:
                return True, '%d keys should not be rotated from old_keys' % (3 - rotate_count)
    else:
        expected_key_count = 3
        if len(old_keys) + int(rotate_count) < 4:
            expected_key_count = 3 - (3 % (len(old_keys) + rotate_count))

        if expected_key_count != len(new_keys):
            return True, 'Expected new_keys count[%d] != %d' % (
                expected_key_count, len(new_keys))

        common_keys = len([key for key in new_keys if key in old_keys])
        actual_rotation_count = len(new_keys) - common_keys if common_keys \
            else len(new_keys)

        if actual_rotation_count > rotate_count:
            # do not retry if rotation happens more than expected times
            return False, 'Expected rotation count[%d] is lesser than actual rotation[%d]' % (
                rotate_count, actual_rotation_count)

        if actual_rotation_count != rotate_count:  # make sure keys rotaion count meets expected rotate_count
            return True, 'Expected rotation count[%d] != %d' % (
                rotate_count, actual_rotation_count)
    return True, None


def keys_should_not_rotate(old_keys, new_keys):
    """

    :param old_keys:
    :param new_keys:
    :return:
    """
    logger.info("Old Keys: %s\nNew Keys: %s" % (old_keys, new_keys))
    if old_keys != new_keys:
        logger_utils.fail('old_keys[%s] != new_keys[%s]' % (old_keys, new_keys))


def debug_virtualservice(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """
    logger.info('debug virtualservice %s' % vs_name)
    for vm in infra_utils.get_vm_of_type('controller'):
        cmds = list()
        cmds.append('debug virtualservice %s' % vs_name)
        for key in kwargs:
            if key == 'flag':
                logger.info("debug vs: %s: %s" % (key, kwargs[key]))
                cmds.append('flags flag %s' % kwargs[key])
        cmds.append('save')
        cli_lib.run_commands(cmds, vm)


def update_network_profile_profileunion(net_profile_name, **kwargs):
    """

    :param net_profile_name:
    :param kwargs:
    :return:
    """
    logger.info('update_network_profile %s' % net_profile_name)
    _, json_networkprofile_data = rest.get('networkprofile',
                                           name=net_profile_name)

    if json_networkprofile_data.get('profile').get('type') == \
            'PROTOCOL_TYPE_TCP_PROXY':
        logger.info(' profile type: tcp_proxy')

    elif json_networkprofile_data.get('profile').get('type') == \
            'PROTOCOL_TYPE_TCP_FAST_PATH':
        logger.info(' profile type: tcp_fast_path')

    elif json_networkprofile_data.get('profile').get('type') == \
            'PROTOCOL_TYPE_UDP_FAST_PATH':
        logger.info(' profile type: udp_fast_path')

    rest.put('networkprofile', name=net_profile_name,
             data=json_networkprofile_data)


def get_se_uuids_from_vs_name(vs_name):
    """

    :param vs_name:
    :return:
    """
    se_uuid_list = []
    _, resp_data = rest.get('virtualservice', name=vs_name, path='runtime')

    for vip_summary in resp_data.get('vip_summary'):
        ses = vip_summary.get('service_engine')
        if not ses:
            logger_utils.fail(
                'ERROR! Cannot get se_id for virtual service %s' % vs_name)

        for se in ses:
            se_uuid_list.append(se['uuid'])

    logger.debug('se_uuid_list: ' % se_uuid_list)
    return se_uuid_list


def get_vs_secondary_se_list(vs_name):
    """

    :param vs_name:
    :return:
    """
    se_sec_list = []
    _, resp_data = rest.get('virtualservice', name=vs_name, path='runtime')

    for vip_summary in resp_data['vip_summary']:
        for se in vip_summary['service_engine']:
            if not se['primary']:
                se_sec_list.append(infra_utils.get_name_from_ref(se['url']))
    se_sec_list.sort()
    return se_sec_list


@logger_utils.aretry(retry=40, delay=10)
def vs_should_be_assigned(vs_name, se_name=None, oper_down=False,
                          retry_count=0, **kwargs):
    """

    :param vs_name:
    :param se_name:
    :param oper_down:
    :param retry_count:
    :param kwargs:
    :return:
    """
    if is_vs_assigned(vs_name, se_name, oper_down=oper_down, **kwargs):
        logger.info('VS[%s] is assigned' % vs_name)
        return True
    else:
        logger_utils.fail('VS[%s] not assigned' % vs_name)


def vsmgr_wellness_check(vs_name, t_req, t_assign, t_fsmstate,
                         t_operstate, t_one_plus_one_ha, t_num_app,
                         skip_detail_check, check_se_connected, vip_id,
                         retry_interval=5, retry_timeout=30):
    """

    :param vs_name:
    :param t_req:
    :param t_assign:
    :param t_fsmstate:
    :param t_operstate:
    :param t_one_plus_one_ha:
    :param t_num_app:
    :param skip_detail_check:
    :param check_se_connected:
    :param vip_id:
    :param retry_interval:
    :param retry_timeout:
    :return:
    """
    retry_timeout = int(retry_timeout)
    retry_interval = int(retry_interval)

    @logger_utils.aretry(delay=retry_interval, period=retry_timeout)
    def retry_action():
        return vsmgr_wellness_check_once(
            vs_name,
            t_req, t_assign, t_fsmstate,
            t_operstate, t_one_plus_one_ha,
            t_num_app, skip_detail_check, check_se_connected, vip_id)

    return retry_action()


def get_vs_runtime_db(vs_name):
    """

    :param vs_name:
    :return:
    """
    api = 'scvsstateinfo'
    _, db_output = rest.get(api)
    summary_db = db_output.get('results', [])
    logger.debug(db_output)
    vs_summary_db = dict()

    vs_uuid = rest.get_uuid_by_name('virtualservice', vs_name)
    for vip_info in summary_db:
        if vs_uuid not in vip_info['vs_id']:
            continue
        vs_summary_db[vip_info['vip_id']] = vip_info['oper_status']
    return vs_summary_db


def cache_vs(vs_name):
    """

    :param vs_name:
    :return:
    """
    vs = get_vs(vs_name)  # show vs
    vs_summary = get_vs_runtime(vs_name)  # show vs summary
    vs_detail = get_vs_runtime_detail(vs_name)  # show vs detail
    vs_ctrl_internal = get_vs_controller_internal(
        vs_name)  # show vs internal (only ctrl runtime)
    vs_summary_db = get_vs_runtime_db(vs_name)
    return vs, vs_summary, vs_detail, vs_ctrl_internal, vs_summary_db


def vs_get_num_app(vs_name):
    """

    :param vs_name:
    :return:
    """
    runtime = get_vs_runtime(vs_name)
    if not runtime.get('vh_child_vs_ref'):
        return 0
    return len(runtime['vh_child_vs_ref'])


def vsmgr_wellness_check_once(vs_name, t_req, t_assign, t_fsmstate,
                              t_operstate, t_one_plus_one_ha, t_num_app=0,
                              skip_detail_check=0, check_se_connected=1,
                              vip_id='0'):
    """

    :param vs_name:
    :param t_req:
    :param t_assign:
    :param t_fsmstate:
    :param t_operstate:
    :param t_one_plus_one_ha:
    :param t_num_app:
    :param skip_detail_check:
    :param check_se_connected:
    :param vip_id:
    :return:
    """
    t_req = int(t_req)
    t_assign = int(t_assign)

    dbg_str = 'start vs wellness check' + \
              'vs=%s t_req=%d t_assign=%d,' % (vs_name, t_req, t_assign) + \
              ' t_fsm=%s, t_operstate=%s, t_one_plus_one_ha=%s, t_num_app=%d, ' \
              'vip_id=%s' % (
                  t_fsmstate, t_operstate, t_one_plus_one_ha, t_num_app,
                  vip_id)
    logger.debug(dbg_str)

    vs, vs_summary, vs_detail, vs_internal, vs_summary_db = cache_vs(vs_name)

    t_east_west_placement = False
    if 'east_west_placement' in vs.keys() and vs['east_west_placement']:
        t_east_west_placement = True

    vip_summary = None
    for vip_summary in vs_summary['vip_summary']:
        if vip_summary['vip_id'] == vip_id:
            break

    # Oper State
    try:
        oper_state = vip_summary['oper_status']['state']
        db_oper_state = vs_summary_db.get(vip_id, dict()).get(
            'state', 'OPER_NOT_FOUND')
        # Check DB entry for this vs-vip for only OPER_UP, OPER_DOWN states
        if (db_oper_state == 'OPER_NOT_FOUND' or
                    db_oper_state not in ['OPER_UP', 'OPER_DOWN']):
            logger.info("db_oper_state: %s" % db_oper_state)
            db_oper_state = oper_state
        # If the operational status is OPER_PARTITIONED, then db will have
        #  preserve the old oper status (OPER_UP/OPER_DOWN), so skip this check
        if oper_state != 'OPER_PARTITIONED' and oper_state != db_oper_state:
            dbg_str = ('## oper status cache %s != db %s' % (
                oper_state, db_oper_state))
            logger.info("dbg_str:%s" % dbg_str)
            return False, dbg_str
    except KeyError, Argument:
        dbg_str = ('## oper status not available: %s' % Argument)
        logger.trace(dbg_str)
        return False, dbg_str

    try:
        vip_detail = None
        for vip_detail in vs_detail.get('vip_detail', []):
            if vip_detail['vip_id'] == vip_id:
                break
        detail_oper_state = vip_detail['oper_status']['state']
    except KeyError, Argument:
        dbg_str = '## oper status detail not available: %s' % Argument
        logger.debug(dbg_str)
        return False, dbg_str

    if t_fsmstate in ['Disabled']:
        t_operstate = 'OPER_DISABLED'
    elif t_fsmstate in ['AwaitingSeAssignment']:
        t_operstate = 'OPER_RESOURCES'

    if not skip_detail_check:
        if detail_oper_state != t_operstate:
            if oper_state != t_operstate:
                dbg_str = "vs[%s] not in expected state %s, summary state %s, detail state %s" % \
                          (vs_name, t_operstate, oper_state, detail_oper_state)
                logger.debug(dbg_str)
                return False, dbg_str
            else:
                dbg_str = "vs[%s] Cache issue - summary state %s != detail state %s" % (
                    vs_name,
                    oper_state, detail_oper_state)
                logger.debug(dbg_str)
                return False, dbg_str

    if oper_state != t_operstate:
        dbg_str = '## vs[%s] OPER state[%s] != expected[%s]' % \
                  (vs_name, oper_state, t_operstate)
        logger.debug(dbg_str)
        return False, dbg_str

    if t_one_plus_one_ha:
        if vs_internal['one_plus_one_ha'] is not True:
            dbg_str = "1+1HA not set in vs internal"
            logger.debug(dbg_str)
            return False, dbg_str

    logger.debug(str(vs))
    logger.debug(str(vs_internal))
    vip_runtime = None
    for vip_runtime in vs_internal['vip_runtime']:
        if vip_runtime['vip_id'] == vip_id:
            break
    # Num SE requested and assigned
    logger.debug(vip_runtime)

    db_req_se = vip_runtime['requested_resource']['num_se']
    if t_one_plus_one_ha:
        db_req_se += vip_runtime['requested_resource']['num_standby_se']
    if not t_east_west_placement and db_req_se != t_req:
        dbg_str = '## vs[%s] Num Se Requested (from db)=%d t_req=%d' % \
                  (vs_name, db_req_se, t_req)
        logger.debug(dbg_str)
        return False, dbg_str

    if 'requested_resource' in vip_runtime.keys():
        req_se = vip_runtime['requested_resource']['num_se']
    if t_one_plus_one_ha:
        if 'requested_resource' in vip_runtime.keys():
            req_se += vip_runtime['requested_resource']['num_standby_se']

    if not t_east_west_placement and req_se != t_req:
        dbg_str = '## vs[%s] Num Se Requested (from internal)=%d t_req=%d' % \
                  (vs_name, req_se, t_req)
        logger.debug(dbg_str)
        return False, dbg_str

    # Check for App VS
    if 'type' in vs.keys() and vs['type'] == 'VS_TYPE_VH_CHILD':
        se_list = vs_get_se_list(vs_name, vip_id)
        # se_list = ['/'.join(se['url'].split('/')[-1:])
        #           for se in vs_summary['service_engine']]
        if t_fsmstate in ['Disabled', 'AwaitingSeAssignment']:
            if se_list:
                dbg_str = '## APP SE (Disabled/AwaitingSe) List (%s) not empty' % \
                          (str(se_list))
                logger.debug(dbg_str)
                return False, dbg_str
        else:
            vs_endpoint = webapp_lib.get_name_from_ref(vs['vh_parent_vs_ref'])
            endpoint_vs_list = vs_get_se_list(vs_endpoint, vip_id)
            if set(endpoint_vs_list) != set(se_list):
                dbg_str = '## APP SE List (%s) != ENDPOINT VS LIST (%s)' %\
                          (str(se_list), str(endpoint_vs_list))
                logger.debug(dbg_str)
                return False, dbg_str

    if 'type' in vs.keys() and vs['type'] == 'VS_TYPE_VH_PARENT':
        num_app_in_runtime = vs_get_num_app(vs_name)
        logger.debug('num_app:', num_app_in_runtime)
        if num_app_in_runtime != t_num_app:
            dbg_str = '## Num App in Runtime(%d) != Num App expected(%d)' %\
                      (num_app_in_runtime, t_num_app)
            logger.debug(dbg_str)
            return False, dbg_str

    if u'service_engine' not in vip_summary.keys():
        num_se_assigned = 0
    else:
        num_se_assigned = len(vip_summary['service_engine'])

    if t_east_west_placement:
        num_se_assigned = vip_summary['num_se_assigned']

    if not t_east_west_placement and num_se_assigned != t_assign:
        dbg_str = '## vs[%s] Num Se Assigned=%d t_assign=%d' % \
                  (vs_name, num_se_assigned, t_assign)
        logger.debug(dbg_str)
        return False, dbg_str

    if t_one_plus_one_ha:
        # VS should only have 1 active && 1 standby
        if verify_vs_se_num_active_standby(vs_name,
                                           check_se_connected) is False:
            dbg_str = '## vs[%s] Verify num-active-standby failed' % vs_name
            logger.debug(dbg_str)
            return False, dbg_str
    elif t_east_west_placement:
        pass
        # selist is removed from runtime
        # VS should only have all primary && 0 secondary
        # if verify_ew_vs_se_num_primary_secondary(vs_name) is False:
        #    print('## EW Verify num-primary-secondary failed')
        #    raise RuntimeError(
        #        'ew vs[%s] Verify num-primary-secondary failed' % (vs_name))
        #    return False

    else:
        # VS should only have 1 primary && rest secondary
        if verify_vs_se_num_primary_secondary(vs_name,
                                              check_se_connected) is False:
            dbg_str = '## vs[%s] %s Verify num-primary-secondary failed' % (
                vs_name, vip_id)
            logger.debug(dbg_str)
            return False, dbg_str
    return True, 'validation success!'


def verify_vs_se_num_primary_secondary(vs_name, check_connected=1):
    """

    :param vs_name:
    :param check_connected:
    :return:
    """
    logger.debug("check for num primary and secondary")
    selist = vs_get_se_info(vs_name)
    if not selist:
        return True
    if len(selist) == 0:
        return True
    num_primary = 0
    num_secondary = 0
    for se in selist:
        if se['is_primary'] is True:
            num_primary = num_primary + 1
        else:
            num_secondary = num_secondary + 1
        if check_connected == 1 and se['is_connected'] is False:
            logger_utils.fail('se not connected %s' % se)
            return False
    logger.debug('## Num Primary=%d' % num_primary)
    if num_primary != 1:
        logger_utils.error('Num Primary %d != 1' % num_primary)
        return False
    if num_primary + num_secondary != len(selist):
        logger.trace('## Num Primary %d + Num Secondary %d  Num Se %d' %
                     (num_primary, num_secondary, len(selist)))
        logger_utils.error('Num Primary %d + Num Secondary %d != Num Se %d' %
                     (num_primary, num_secondary, len(selist)))
        return False
    return True


def verify_vs_se_num_active_standby(vs_name, check_connected=1):
    """

    :param vs_name:
    :param check_connected:
    :return:
    """
    logger.debug("check for num active and standby")
    selist = vs_get_se_info(vs_name)
    if not selist:
        return True
    logger.debug('## Num SE=%d' % len(selist))
    if len(selist) == 0:
        return True
    num_active = 0
    num_standby = 0
    for se in selist:
        if se['is_primary'] is True:
            num_active = num_active + 1
            if se['is_standby'] is True:
                raise RuntimeError('Active is also standby %s' % se)
        elif se['is_standby'] is True:
            num_standby = num_standby + 1
        if check_connected == 1 and se['is_connected'] is False:
            logger_utils.fail('se %s not connected' % se['uuid'])
            return False
    logger.debug('## Num Active=%d' % num_active)
    if num_active != 1:
        logger_utils.fail('Num Active %d != 1' % num_active)
        return False
    if num_active + num_standby != len(selist):
        logger_utils.fail('## Num Active %d + Num Standby %d  != Num Se %d' %
                          (num_active, num_standby, len(selist)))
        logger_utils.fail('Num Active %d + Num Standby %d != Num Se %d' %
                          (num_active, num_standby, len(selist)))
        return False
    return True


def vs_get_num_se_req(vs_name, vip_index=0):
    """

    :param vs_name:
    :param vip_index:
    :return:
    """
    vs_data = get_vs(vs_name)
    return vs_data['vip_runtime'][vip_index]['requested_resource']['num_se']


def vs_get_num_se_used(vs_name, vip_index=0):
    """

    :param vs_name:
    :param vip_index:
    :return:
    """
    runtime = get_vs_runtime(vs_name)
    if not runtime['vip_summary'][vip_index].get('service_engine'):
        return 0
    return len(runtime['vip_summary'][vip_index]['service_engine'])


def vs_se_disconnected(vs_name, se_uuid, vip_id='0'):
    logger.info("check for all se connected")
    # selist = vs_get_se_info(vs_name)
    vip_summary = get_vip_summary(vs_name, vip_id)
    if u'service_engine' not in vip_summary.keys():
        logger.info("No SE assigned")
        logger_utils.fail('No SE Assigned')
    found = False
    for se in vip_summary['service_engine']:
        logger.info("slug from uri: %s" % rest.get_uuid_from_ref(se['url']))
        if rest.get_uuid_from_ref(se['url']) == se_uuid:
            found = True
            if se['connected'] is not False:
                logger_utils.fail('se %s not disconnected' % se)
    if found is False:
        logger_utils.fail('se %s not in se_list' % se_uuid)


def vs_scalein_in_progress(vs_name, primary=False, vip_index=0):
    infra_utils.asleep(delay=5)
    vip_summary = get_vs_runtime(vs_name)['vip_summary'][vip_index]
    if 'service_engine' not in vip_summary.keys():
        logger.info("No SE assigned")
        logger_utils.fail('No SE Assigned')
        return False
    num_scalein = 0
    for se in vip_summary['service_engine']:
        if 'scalein_in_progress' in se.keys():
            if se['scalein_in_progress'] is True:
                logger.info("scalein_in_progress for se:%s" % (se['url']))
                num_scalein += 1
                if se['primary'] != primary:
                    logger.info("primary se mismatch %s != %s" %
                                (se['primary'], primary))
                    logger_utils.fail(
                        "primary se mismatch %s != %s" % (
                            se['primary'], primary))
    if num_scalein == 0:
        logger_utils.fail('No SEs with scalein_in_progress')
        return False
    return True


def vs_get_primary_se_ip(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """
    try:
        primary_se = vs_get_primary_se_info(vs_name, **kwargs)
        url = primary_se['url']
        se_api = '/'.join(url.split('/')[-2:])
        logger.info(se_api)
        se_data = rest.get(se_api)
        logger.info("primary se: %s" % se_data[1]['name'])
        return se_data[1]['name']
    except KeyError as err_msg:
        logger_utils.fail(str(err_msg))


def get_vs_reason_code(vs_name, reason_code, vip_id='0'):
    """

    :param vs_name:
    :param reason_code:
    :param vip_id:
    :return:
    """
    vs_summary = get_vs_runtime(vs_name)

    if 'vip_summary' not in vs_summary:
        return False

    vip_summary = None
    for vip_summary in vs_summary['vip_summary']:
        if vip_id == vip_summary['vip_id']:
            break
    if not vip_summary:
        logger_utils.fail(
            'ERROR! get %s(%s) summary failed while fetching vs reason code' %
            (vs_name, vip_id))
    oper_reason_code = vip_summary['oper_status']['reason_code_string']
    return oper_reason_code == reason_code


def get_scaleout_status(vs_name, scale_status, vip_index=0):
    """

    :param vs_name:
    :param scale_status:
    :param vip_index:
    :return:
    """
    vip_summary = get_vs_runtime(vs_name)['vip_summary'][vip_index]
    last_scale_status = vip_summary['last_scale_status'] if u'last_scale_status' in vip_summary.keys() \
                        else vip_summary['scale_status']
    if last_scale_status['state'] == scale_status:
        return True

    return False


@logger_utils.aretry(retry=50, delay=6)
def get_scale_status_and_wait_till_rollback(vs_name, scale_status, **kwargs):
    """

    :param vs_name:
    :param scale_status:
    :param kwargs:
    :return:
    """
    if get_scaleout_status(vs_name, scale_status):
        logger.info('VS[%s] scale status is expected %s' % (vs_name, scale_status))
        return True
    else:
        logger_utils.fail('VS[%s] scale status is not expected' % vs_name)


def retry_vs_placement(vs_name, sleep=False, vip_id=0):
    """

    :param vs_name:
    :param sleep:
    :return:
    """
    _, resp_data = rest.post('virtualservice', name=vs_name, 
                                 path='retryplacement', data={'vip_id': vip_id})
    infra_utils.asleep(delay=5)
    if sleep:
        logger.info('sleeping for 15 sec')
        infra_utils.asleep(delay=15)
    return resp_data


def get_vs_se_map(**kwargs):
    """

    :param kwargs:
    :return:
    """
    vs_se_map = {}
    vs_name = kwargs.get('vs_name', None)
    vs_data = get_vs(vs_name=vs_name)
    vs_data = vs_data['results'] if vs_data.get('results', None) else vs_data

    if vs_name:
        vs_list = [vs_data['name']]
    else:
        vs_list = [vs['name'] for vs in vs_data['results']]

    for vs_name in vs_list:
        vs_se_map[vs_name] = vs_get_se_list(vs_name)
    logger.info('VS <-> SE map: %s' % vs_se_map)
    return vs_se_map


def get_vs_runtime_and_wait_till_expected_reason(vs_name, reason, **kwargs):
    """

    :param vs_name:
    :param reason:
    :param kwargs:
    :return:
    """
    retry_timeout = int(kwargs.get('retry_timeout', 20))

    @logger_utils.aretry(delay=retry_timeout)
    def retry_action():
        return is_network_placement_needed(vs_name, reason=reason)

    return retry_action()


def is_network_placement_needed(vs_name, reason=None, vip_index=0, **kwargs):
    """

    :param vs_name:
    :param reason:
    :param vip_index:
    :param kwargs:
    :return:
    """
    logger.info('is_network_placement_needed %s %s' % (vs_name, reason))
    _, runtime = rest.get('virtualservice', name=vs_name, path='runtime')
    vip_summary = runtime['vip_summary'][vip_index]
    logger.trace('VS Runtime:%s' % runtime)

    try:
        state = vip_summary['oper_status']['state']
    except KeyError:
        logger_utils.fail(
            'vs %s runtime does not have oper_status, state field' % vs_name)
        raise RuntimeError(
            'vs %s runtime does not have oper_status, state field' % vs_name)

    logger.debug('state %s, reason_code_string %s' % (
        state, vip_summary.get('oper_status').get('reason_code_string')))
    if state == "OPER_RESOURCES" and vip_summary.get('oper_status').get('reason_code_string') == reason:
        logger.debug('Placement network needs to be set for vs %s' % vs_name)
        pool = True
        res = vip_summary.get('vip_placement_resolution_info')
        if res:
            pool = res.get('pool_uuid')
        if pool:
            return pool
        return True
    return False


def vs_check_se_distribution(vs_name, se_dist_exp):
    """

    :param vs_name:
    :param se_dist_exp:
    :return:
    """
    se_types = ['primary', 'secondary', 'standby']
    logger.info('SE expected distribution %s' % se_dist_exp)
    for i, type in enumerate(se_types):
        count_exp = se_dist_exp[i]
        kwargs = dict()
        kwargs[type] = True
        count = len(vs_get_se_list(vs_name, **kwargs))
        if int(count) != int(count_exp):
            logger_utils.fail('VS %s count does not match' % type)


def vs_get_standby_se_info(vs_name, vip_index=0):
    """

    :param vs_name:
    :param vip_index:
    :return:
    """
    if is_vs_placed(vs_name) is False:
        logger_utils.fail('VS %s not assigned to SE' % vs_name)
    _, vs_runtime = rest.get('virtualservice', name=vs_name, path='runtime')
    standby_se = None
    try:
        for se in vs_runtime['vip_summary'][vip_index]['service_engine']:
            if se['standby'] is True:
                standby_se = se
                break
    except KeyError, Argument:
        logger_utils.fail('Rest result did not have required field: %s' %
                          Argument)
    return standby_se


def vs_get_standby_se_name(vs_name, index=0):
    """

    :param vs_name:
    :param index:
    :return:
    """
    try:
        se = vs_get_standby_se_info(vs_name)
        if se:
            se_uuid = rest.get_uuid_from_ref(url_ref=se['url'])
            logger.info('standby se uuid: %s' % se_uuid)
            _, se_info = rest.get('serviceengine', uuid=se_uuid)
            return se_info['name']
    except KeyError as e:
        logger_utils.fail('Failed with the error: %s' % str(e))


def vs_has_secondary_se(vs_name, count, exc=True, vip_index=0):
    """

    :param vs_name:
    :param count:
    :param exc:
    :param vip_index:
    :return:
    """

    _, vs_runtime = rest.get('virtualservice', name=vs_name, path='runtime')
    if 'service_engine' not in vs_runtime['vip_summary'][vip_index].keys():
        return False
    sec_count = 0
    for se_iter in vs_runtime['vip_summary'][vip_index]['service_engine']:
        if 'primary' in se_iter and se_iter['primary']:
            continue
        if 'standby' in se_iter and se_iter['standby']:
            continue
        sec_count = sec_count + 1
    if sec_count >= int(count):
        return True
    if not exc:
        return False
    logger_utils.fail('ERROR! Virtualservice %s does not have %d sec se' % (
        vs_name, int(count)))


def vs_should_have_secondary_se(vs_name, count=1, **kwargs):
    """

    :param vs_name:
    :param count:
    :param kwargs:
    :return:
    """
    retry_timeout = int(kwargs.get('retry_timeout', 5))

    @logger_utils.aretry(retry=retry_timeout * 10, delay=2)
    def retry_action():
        return vs_has_secondary_se(vs_name, int(count), exc=False)

    return retry_action()


def get_vs_default_pool_name(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """

    _, vs_obj = rest.get('virtualservice', name=vs_name)
    import lib.pool_lib as pool_lib
    pool_ref = pool_lib._get_pool_from_vs(vs_obj, **kwargs)
    pool_uuid = rest.get_uuid_from_ref(pool_ref)
    _, pool_obj = rest.get('pool', uuid=pool_uuid)
    pool_name = pool_obj['name']
    return pool_name


def enable_all_vs():
    _, all_vs = rest.get('virtualservice')
    if all_vs.get('results', None):
        for result in all_vs['results']:
            enable_vs(vs_name=result['name'])


def disable_all_vs():
    _, all_vs = rest.get('virtualservice')
    if all_vs.get('results', None):
        for result in all_vs['results']:
            disable_vs(vs_name=result['name'])

def delete_network_profile(net_profile_name):
    rest.delete('networkprofile', name=net_profile_name)
    common.validate_after_delete('networkprofile', net_profile_name)


def get_vs_l7_stats(vs_name, stat_fields=[], **kwargs):
    vs_runtime = get_vs_runtime_detail(vs_name, **kwargs)
    stat_count = {}
    for stat_field in stat_fields:
        stat_count[stat_field] = vs_runtime["vip_detail"][0]["fel7stats"][0][stat_field]
    return stat_count

def get_vs_l7_internal_stats(vs_name, stat_fields=[], **kwargs):
    _, vs_internal = rest.get('virtualservice', name=vs_name, path='runtime/internal')
    stat_count = {}
    for data in vs_internal:
        for stat_field in stat_fields:
            if data.has_key('proc_id') and "L7" in data['proc_id']:
                if not stat_count.has_key(stat_field):
                        stat_count[stat_field] = 0
                stat_count[stat_field] += data['ssl'][stat_field]
    return stat_count


def verify_snat_updates(vs_name):
    _, vs_data = rest.get('virtualservice', name= vs_name)
    list_of_snat = []
    for item in vs_data.get("snat_ip"):
        list_of_snat.append(item.get("addr"))
    return len(list_of_snat), list_of_snat

def get_snat_from_vs(vs_name, **kwargs):

    _, vs_data = rest.get('virtualservice', name=vs_name)
    index = kwargs.pop('index',None)
    if index:
        index = int(index)
        snat_ip = vs_data["snat_ip"][index]
        snat_ip_addr = snat_ip.get("addr")
        if not snat_ip_addr:
            return False
        else:
            return snat_ip_addr
    else:
        return vs_data.get("snat_ip")

def update_snat_ip(vs_name, action='add', **kwargs):
    """
    Method update_snat_ip : action supported are add / remove / removeall / modify
    with remove provide the snat ip to be removed.
    with modify provide the index of snat_ip to be modified along with ip.
    """

    _, vs_data = rest.get('virtualservice', name=vs_name)
    configured_snat = len(vs_data.get("snat_ip"))
    ip = kwargs.pop('snat_ip',None)
    if action == 'add':
        configured_snat = {
            'addr': ip,
            'type': 'V4'
        }
        if not vs_data.get('snat_ip'):
            vs_data['snat_ip'] = []
        vs_data['snat_ip'].append(configured_snat)
    if action == 'removeall':
        vs_data['snat_ip'] = []
    if action == 'remove':
        for idx,item in enumerate(vs_data.get('snat_ip')):
            if item.get('addr') == ip:
                vs_data['snat_ip'].pop(idx)
    if action == 'modify':
        index = kwargs.pop('index', None)
        if index:
            index = int(index)
            try:
                if vs_data.get('snat_ip')[index].get('addr'):
                    vs_data['snat_ip'][index]['addr'] = ip
            except IndexError as e:
                logger_utils.fail("Failed with Index Error: %s" % str(e))

    rest.put('virtualservice', name= vs_name, data = vs_data)


def update_app_virtual_service_del_domain(vs_name, domain, **kwargs):
    """

    :param vs_name:
    :param domain:
    :param kwargs:
    :return:
    """
    json_vs_data = rest.get('virtualservice', name=vs_name)
    logger.info('update_vs from %s' % json_vs_data)

    if json_vs_data.get('vh_domain_name'):
        json_vs_data.get('vh_domain_name').pop(domain)
    logger.info('update_vs to' % json_vs_data)
    rest.put('virtualservice', name=vs_name, data=json_vs_data)


def rotate_vs_keys(vs_name, **kwargs):
    '''Rotate keys of the virtualservice
    '''
    rest.post('virtualservice', name=vs_name, path='rotatekeys')

