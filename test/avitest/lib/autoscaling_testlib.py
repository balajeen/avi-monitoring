import copy
import json
import avi_objects.rest as rest
import lib.pool_lib as pool_lib
import lib.vs_lib as vs_lib
import avi_objects.logger_utils as logger_utils
from avi_objects.logger import logger



AS_WAIT_TIME = 75


def autoscale_vs_raise_min_size(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """

    num_servers = vs_lib.get_vs_pool_server_count(vs_name)
    pool_name = vs_lib.get_vs_default_pool_name(vs_name, **kwargs)
    min_size = autoscale_raise_min_size(pool_name, **kwargs)
    wait_for_server_count_change(vs_name, num_servers, '>')
    return min_size


def get_vs_default_pool_name(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """

    _, vs_obj = rest.get('virtualservice', name=vs_name)
    pool_ref = pool_lib._get_pool_from_vs(vs_obj, **kwargs)
    pool_uuid = rest.get_uuid_from_ref(pool_ref)
    _, pool_obj = rest.get('pool', uuid=pool_uuid)
    pool_name = pool_obj['name']
    return pool_name


def autoscale_raise_min_size(pool_name, **kwargs):
    """
    pass the autoscale policy settings into the kwargs
    :param pool_name:
    :param kwargs:
    :return:
    """

    _, pool_obj = rest.get('pool', name=pool_name)
    asp_ref = pool_obj['autoscale_policy_ref']
    as_policy_uuid = asp_ref.split('serverautoscalepolicy/')[1].split('#')[0]

    _, autoscale_policy = rest.get('serverautoscalepolicy', uuid=as_policy_uuid)
    logger.info('received asp %s type %s ' % (autoscale_policy, type(autoscale_policy)))
    as_policy_old = copy.deepcopy(autoscale_policy)
    orig_min_size = autoscale_policy['min_size']
    orig_max_size = autoscale_policy['max_size']
    num_servers = len(pool_obj['servers'])
    for k, v in kwargs.iteritems():
        logger.info('k,v %s,%s' % (k, v))
        autoscale_policy[k] = v
    autoscale_policy['min_size'] = num_servers + 1
    autoscale_policy['max_size'] = max(autoscale_policy['max_size'],
                                       autoscale_policy['min_size'])
    asp_json = json.dumps(autoscale_policy)
    logger.info(' json: %s' % asp_json)
    rc, result = rest.put('serverautoscalepolicy', uuid=as_policy_uuid, data=asp_json)
    logger.info('updating as_policy %s %s %s' % (autoscale_policy, rc, result))
    logger_utils.asleep(delay=AS_WAIT_TIME)
    get_autoscale_info(pool_name)
    _, pool_obj = rest.get('pool', name=pool_name)
    num_servers = len(pool_obj['servers'])
    if num_servers == 0:
        logger_utils.fail('Pool %s has no up servers' % pool_name)
    _, autoscale_policy = rest.get('serverautoscalepolicy', uuid=as_policy_uuid)
    autoscale_policy['min_size'] = orig_min_size
    autoscale_policy['max_size'] = orig_max_size
    asp_json = json.dumps(autoscale_policy)
    logger.info('json: %s' % asp_json)
    rc, result = rest.put('serverautoscalepolicy', uuid=as_policy_uuid, data=asp_json)
    logger.info('rc: %s result: %s' % (rc, result))
    return autoscale_policy['min_size']


def get_autoscale_info(pool_uuid):
    """

    :param pool_name: name of pool
    :return: dict of AutoScaleState for that pool
    """
    status_code, results = rest.get('autoscale_mgr', path=pool_uuid)
    return results


def assert_vs_last_scaleout_reason(vs_name, reason_code, **kwargs):
    """

    :param vs_name:
    :param reason_code:
    :param kwargs:
    :return:
    """

    pool_name = vs_lib.get_vs_default_pool_name(vs_name, **kwargs)
    as_info = get_autoscale_info(pool_name)
    if 'last_scaleout_reason' in as_info:
        if as_info[0]['last_scaleout_reason'] != reason_code:
            logger_utils.fail('scaleout reason %s not matched %s' % (reason_code, as_info[0]))


def autoscale_vs_lower_max_size(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """

    pool_name = vs_lib.get_vs_default_pool_name(vs_name, **kwargs)
    num_servers = vs_lib.get_vs_pool_server_count(vs_name)
    max_size = autoscale_lower_max_size(pool_name, **kwargs)
    wait_for_server_count_change(vs_name, num_servers, '<')
    return max_size


def autoscale_lower_max_size(pool_name, **kwargs):
    """
    pass the autoscale policy settings into the kwargs
    :param pool_name:
    :param kwargs:
    :return:
    """

    _, pool_obj = rest.get('pool', name=pool_name)
    asp_ref = pool_obj['autoscale_policy_ref']
    as_policy_uuid = asp_ref.split('serverautoscalepolicy/')[1].split('#')[0]

    _, autoscale_policy = rest.get('serverautoscalepolicy', uuid=as_policy_uuid)
    logger.info('received asp %s   type %s' % (autoscale_policy, type(autoscale_policy)))
    orig_max_size = autoscale_policy['max_size']
    orig_min_size = autoscale_policy['min_size']

    num_servers = len(pool_obj['servers'])
    for k, v in kwargs.iteritems():
        logger.info('k,v %s,%s' % (k, v))
        autoscale_policy[k] = v
    if num_servers < 2:
        logger_utils.fail('Number of servers is less than required %d' % num_servers)
    autoscale_policy['max_size'] = num_servers-1
    autoscale_policy['min_size'] = min(autoscale_policy['min_size'],
                                       autoscale_policy['max_size'])

    asp_json = json.dumps(autoscale_policy)
    logger.info('json: %s' % asp_json)
    rc, result = rest.put('serverautoscalepolicy', uuid=as_policy_uuid, data=asp_json)
    logger.info('updating as_policy %s' % autoscale_policy)
    as_info = get_autoscale_info(pool_name)
    assert as_info

    logger_utils.asleep(delay=AS_WAIT_TIME)
    for _ in xrange(12):
        logger_utils.asleep(delay=10)
        _, pool_obj = rest.get('pool', name=pool_name)
        new_num_servers = len(pool_obj['servers'])
        if new_num_servers <= num_servers:
            break
    _, autoscale_policy = rest.get('serverautoscalepolicy', uuid=as_policy_uuid)
    autoscale_policy['max_size'] = orig_max_size
    autoscale_policy['min_size'] = orig_min_size
    asp_json = json.dumps(autoscale_policy)
    rc, result = rest.put(
        'serverautoscalepolicy', uuid=as_policy_uuid, data=asp_json)
    logger.info('json: %s rc: %s results: %s' % (asp_json, rc, result))
    return autoscale_policy['max_size']


def wait_for_server_count_change(vs_name, prev_count, expected_op='>'):
    """

    :param vs_name:
    :param prev_count:
    :param expected_op:
    :return:
    """

    for _ in xrange(20):
        curr_count = vs_lib.get_vs_pool_server_count(vs_name)
        if eval('%d %s %d' % (curr_count, expected_op, prev_count)):
            return
            logger_utils.asleep(delay=15)
    logger_utils.fail('vs %s server count did not change prev %s curr %s' % (
                       vs_name, prev_count, curr_count))


def assert_vs_last_scalein_reason(vs_name, reason_code, **kwargs):
    """

    :param vs_name:
    :param reason_code:
    :param kwargs:
    :return:
    """

    pool_name = vs_lib.get_vs_default_pool_name(vs_name, **kwargs)
    as_info = get_autoscale_info(pool_name)
    if as_info[0]['last_scalein_reason'] != reason_code:
        logger_utils.fail('scalein reason %s not matched %s'
                           % (reason_code, as_info[0]))


def wait_for_intelligent_scalein(vs_name):
    """

    :param vs_name:
    :return:
    """

    _, vs_obj = rest.get('virtualservice', name=vs_name)
    pool_ref = pool_lib._get_pool_from_vs(vs_obj)
    pool_uuid = pool_ref.split('pool/')[1].split('#')[0]
    _, pool_obj = rest.get('pool', uuid=pool_uuid)

    asp_ref = pool_obj['autoscale_policy_ref']
    as_policy_uuid = asp_ref.split('serverautoscalepolicy/')[1].split('#')[0]

    _, autoscale_policy = rest.get('serverautoscalepolicy', uuid=as_policy_uuid)

    min_size = autoscale_policy['min_size']
    # now wait for time such that num_servers == min_size
    for _ in xrange(30):
        _, pool_obj = rest.get('pool', uuid=pool_uuid)
        num_servers = len(pool_obj['servers'])
        if num_servers <= min_size:
            break
        logger_utils.asleep(delay=15)

    if num_servers > min_size:
        logger_utils.fail('scalein did not succeed pool %s' % (
            str(pool_obj['servers'])))


def manual_vs_autoscale(vs_name, action):
    """

    :param vs_name: pool name for which autoscaling is requested
    :param action: SCALEOUT or SCALEIN
    :return:
    """

    _, vs_obj = rest.get('virtualservice', name=vs_name)
    pool_ref = pool_lib._get_pool_from_vs(vs_obj)
    pool_uuid = pool_ref.split('pool/')[1].split('#')[0]
    _, pool_obj = rest.get('pool', uuid=pool_uuid)
    manual_autoscale(pool_obj['name'], action)


def manual_autoscale(pool_name, action):
    """

    :param pool_name: pool name for which autoscaling is requested
    :param action: SCALEOUT or SCALEIN
    """

    obj_data = {'reason': 'test'}
    rc, rsp = rest.post('pool', name=pool_name, path=action.lower(),
                   data=obj_data)
    logger.info('%s %s returned %s' % (action, rc, rsp))


def add_vs_autoscale_alerts(vs_name, alert_name, scaleout='true',
                            tenant='admin'):
    """

    :param vs_name:
    :param alert_name:
    :param scaleout:
    :param tenant:
    :return:
    """
    _, vs_obj = rest.get('virtualservice', name=vs_name)
    path = 'virtualservice/%s?include_name=true' % vs_obj['uuid']
    _, vs_obj = rest.get(path)
    pool_ref = pool_lib._get_pool_from_vs(vs_obj)
    pool_name = pool_ref.split('pool/')[1]
    add_autoscale_alerts_v2(pool_name, alert_name, scaleout, tenant=tenant)


def add_autoscale_alerts_v2(pool_name, alert_name, scaleout='true', **kwargs):
    """

    :param pool_name:
    :param alert_name:
    :param scaleout:
    :param kwargs:
    :return:
    """

    _, pool_obj = rest.get('pool', uuid=pool_name)
    asp_ref = pool_obj['autoscale_policy_ref']
    asp_uuid = asp_ref.split('serverautoscalepolicy/')[1].split('#')[0]
    _, asp_obj = rest.get('serverautoscalepolicy', uuid=asp_uuid)

    _, acfg_obj = rest.get('alertconfig', name=alert_name)
    alert_ref = acfg_obj['url']
    if scaleout:
        if 'scaleout_alertconfig_refs' in asp_obj:
            asp_obj['scaleout_alertconfig_refs'].append(alert_ref)
        else:
            asp_obj['scaleout_alertconfig_refs'] = [alert_ref]
    else:
        if 'scalein_alertconfig_refs' in asp_obj:
            asp_obj['scalein_alertconfig_refs'].append(alert_ref)
        else:
            asp_obj['scalein_alertconfig_refs'] = [alert_ref]

    logger.info('updating as_policy %s' % asp_obj)
    rc, asp_obj = rest.put('serverautoscalepolicy', name=asp_obj['name'],
                                      data=asp_obj)
    as_info = get_autoscale_info(pool_name)
    assert as_info


def clear_autoscale_policy_alerts(asp_name, **kwargs):
    """

    :param asp_name:
    :param kwargs:
    :return:
    """

    _, asp_obj = rest.get('serverautoscalepolicy', name=asp_name, **kwargs)
    if 'scalein_alertconfig_refs' in asp_obj:
        del asp_obj['scalein_alertconfig_refs']
    if 'scaleout_alertconfig_refs' in asp_obj:
        del asp_obj['scaleout_alertconfig_refs']
    rc, asp_obj = rest.put('serverautoscalepolicy', name=asp_obj['name'], data=asp_obj)


def update_actiongroupconfig_script(actgrpname, alert_script_name=''):
    """

    :param actgrpname:
    :param alert_script_name:
    :return:
    """

    logger.info(' getting info actiongroupconfig?name%s  alert script %s' % (actgrpname, alert_script_name))
    _, actgrp_obj = rest.get('actiongroupconfig', name=actgrpname)
    if alert_script_name:
        _, alertscript_obj = rest.get('alertscriptconfig', name=alert_script_name)
        actgrp_obj['action_script_config_ref'] = alertscript_obj['url']
    elif actgrp_obj.get('action_script_config_ref'):
        del actgrp_obj['action_script_config_ref']
    logger.info(actgrp_obj)
    rest.put('actiongroupconfig', name=actgrpname, data=actgrp_obj)


def get_pool_default_server_name(vs_name, **kwargs):
    _, vs_obj = rest.get('virtualservice', name=vs_name)
    pool_ref = pool_lib._get_pool_from_vs(vs_obj, **kwargs)
    pool_uuid = pool_ref.split('pool/')[1].split('#')[0]
    _, pool_obj = rest.get('pool', uuid=pool_uuid)
    server_obj = pool_obj['servers'][0]
    return server_obj['hostname'] + ':' + str(server_obj['port'])



def set_action_group_config_with_autoscale(agc_name, enable):
    """

    :param agc_name:
    :param enable:
    :return:
    """

    _, agc_obj = rest.get('actiongroupconfig', name=agc_name)
    agc_obj['autoscale_trigger_notification'] = enable
    rest.put('actiongroupconfig', name=agc_name, data=agc_obj)
