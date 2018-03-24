import os
import json

from avi_objects.logger import logger

import lib.common as common
import avi_objects.rest as rest
import avi_objects.logger_utils as logger_utils
import avi_objects.infra_utils as infra_utils


def create_healthmonitor(template, hm_name, hm_template_name, **kwargs):
    """

    :param template:
    :param hm_name:
    :param kwargs:
    :return:
    """

    hm = load_hm_template(template, hm_template_name)
    hm['name'] = hm_name
    http_request = kwargs.get('http_request', None)
    if http_request:
        hm['http_monitor'] = {'http_request': http_request}
    rest.post('healthmonitor', name=hm_name, data=hm)
    validate_healthmonitor('healthmonitor', hm_name)


def delete_health_monitor(hm_name):
    """

    :param hm_name:
    :return:
    """

    rest.delete('healthmonitor', name=hm_name)


def load_hm_template(hm_type, hm_template_name):
    """

    :param hm_type:
    :return:
    """

    hm_template_data = common.get_template_data('hm', hm_template_name)
    if hm_type == 'http':
        return hm_template_data['HTTP_HM_TEMPLATE']
    if hm_type == 'ping':
        return hm_template_data['PING_HM_TEMPLATE']
    if hm_type == 'tcp':
        return hm_template_data['TCP_HM_TEMPLATE']


def validate_healthmonitor(obj_type, obj_name, **kwargs):
    logger.debug('Validate_after_create: %s' % str(kwargs))
    rest.get(obj_type, name=obj_name)


def update_healthmonitor(hm_name, **kwargs):
    """

    :param hm_name:
    :param kwargs:
    :return:
    """
    logger.info('update healthmonitor %s' % hm_name)
    status_code, json_hm_data = rest.get('healthmonitor', name=hm_name)

    if kwargs.get('type'):
        json_hm_data['type'] = kwargs.get('type')

    if kwargs.get('send_interval'):
        json_hm_data['send_interval'] = kwargs.get('send_interval')

    if kwargs.get('receive_timeout'):
        json_hm_data['receive_timeout'] = kwargs.get('receive_timeout')

    if kwargs.get('successful_checks'):
        json_hm_data['successful_checks'] = kwargs.get('successful_checks')

    if kwargs.get('failed_checks'):
        json_hm_data['failed_checks'] = kwargs.get('failed_checks')

    rest.put('healthmonitor', name=hm_name, data=json_hm_data)


def get_all_hmon_stats(pool_name, handle):
    resp_code, json_pool_data = rest.get('pool', name=pool_name, path='/runtime/server/hmonstat')
    common.check_response_for_errors(json_pool_data)

    # Check if server is in handle format or name
    if ':' in handle:
        name = handle
    else:
        server = infra_utils.get_server_by_handle(handle)
        name = server.ip() + ':' + str(server.port())
        logger.info('server_name: %s' % name)

    all_shm = json_pool_data[0].get('server_hm_stat')
    logger.info("type_all_shm: %s, all_shm: %s" % (type(all_shm), all_shm))
    for shm in all_shm:
        logger.info("type_shm: %s, shm: %s" % (type(shm), shm))
        if name == shm.get('server_name'):
            return shm


def get_hmon_stats(pool_name, hm_name, handle, field1='', field2=''):
    """

    :param pool_name:
    :param hm_name:
    :param handle:
    :param field1:
    :param field2:
    :return:
    """
    resp_code, resp_data = rest.get('pool', name=pool_name, path='/runtime/server/hmonstat')
    common.check_response_for_errors(resp_data)

    # Check if server is in handle format or name
    if ':' in handle:
        name = handle
    else:
        server = infra_utils.get_server_by_handle(handle)
        name = server.ip() + ':' + str(server.port())
        logger.debug('server_name', name)

    shm = resp_data[0].get('server_hm_stat')
    for server in shm:
        if name == server.get('server_name'):
            for hm in server[field1]:
                if hm_name == hm.get('health_monitor_name'):
                    if field2:
                        return hm[field2]
                    else:
                        return hm


def error_counters_should_be_under_threshold(shm_runtime, threshold=0):
    """

    :param shm_runtime:
    :param threshold:
    :return:
    """
    hm_type = shm_runtime['health_monitor_type']
    if hm_type in ['HEALTH_MONITOR_TCP', 'HEALTH_MONITOR_HTTP', 'HEALTH_MONITOR_HTTPS',
                   'HEALTH_MONITOR_EXTERNAL', 'HEALTH_MONITOR_UDP', 'HEALTH_MONITOR_DNS',
                   'HEALTH_MONITOR_PING']:
        logger.debug('shm_runtime %s' % shm_runtime)

        bad_counters = []
        if 'curr_count' in shm_runtime and \
                        len(shm_runtime['curr_count']) > 0:
            error_list = shm_runtime['curr_count']
            for error in error_list:
                if int(error['count']) > threshold:
                    bad_counters.append("%s: %s" % (error['type'],
                                                    error['count']))
            if len(bad_counters):
                logger_utils.fail('ERROR! Non zero bad connects: %s' % "".join(bad_counters))
