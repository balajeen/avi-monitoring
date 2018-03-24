from avi_objects import infra_utils
from lib.cluster_lib import get_controller_processes
from avi_objects.logger import logger

import avi_objects.rest as rest
import avi_objects.logger_utils as logger_utils


def get_application_log(vs_name, udf='False', nf='False', **kwargs):
    logger.info('udf %s' % udf)
    logger.info('nf %s' % nf)
    query = kwargs.get('query', '') # REVIEW what to do with this?
    params = {}
    params['virtualservice'] = vs_name
    params['type'] = 1
    if udf == 'True':
        if nf == 'True':
            params['udf'] = True
            params['nf'] = True
        else:
            params['adf'] = False
            params['udf'] = True
    else:
        if nf == 'True':
            params['nf'] = True
    if kwargs.get('page_size'):
        params['page_size'] = 1

    logger.info('params: %s' % params)
    resp_code, resp = rest.get('analytics', path='logs', params=params)
    #resp_code, resp = get(url)
    #resp_code = resp.status_code
    #resp = resp.json()

    #if resp_code != 200:
    #    raise RuntimeError('ERROR! Analytics server api returned %s' % resp_code)
    logger.info('resp: %s' % resp)
    return resp


def set_basic_dns_configuration(search_domain='avi.local', dns_server_addr='10.10.0.100', **kwargs):
    """
    Adds some dns settings to systemconfiguration
    :param search_domain:
    :param dns_server_addr:
    :param kwargs:
    :return:
    """

    status_code, response = rest.get('systemconfiguration')
    response['dns_configuration']['search_domain'] = search_domain
    dns_server_already_exists = False
    if not 'server_list' in response['dns_configuration']:
        response['dns_configuration']['server_list'] = []
    dns_server_list = response['dns_configuration']['server_list']      # s.dns_configuration.server_list
    for dns_server in dns_server_list:
        if dns_server['addr'] == dns_server_addr:
            dns_server_already_exists = True
    if not dns_server_already_exists:
        dns_server = {
            'addr': dns_server_addr,
            'type': 'V4'
        }
        response['dns_configuration']['server_list'].append(dns_server)
        rest.put('systemconfiguration', data=response)


def set_dns_vs_system_configuration(vs_name):
    """

    :param vs_name:
    :return:
    """

    status_code, response = rest.get('systemconfiguration')
    if 'dns_virtualservice_uuids' not in response:
        response['dns_virtualservice_uuids'] = []
    response['dns_virtualservice_uuids'].append(rest.get_uuid_by_name('virtualservice', vs_name))
    rest.put('systemconfiguration', data=response)


def delete_dns_system_configuration():
    """
    
    :return: 
    """

    status_code, response = rest.get('systemconfiguration')
    response['dns_virtualservice_uuids'] = []
    if 'dns_virtualservice_refs' in response:
        del response['dns_virtualservice_refs']
    rest.put('systemconfiguration', data=response)

    logger_utils.asleep(delay=5)
    # Log core manager is restarted after this update
    # Review: To be enabled once function gets fixed.
    #for vm in infra_utils.get_vm_of_type('controller'):
    #    vm['processes'] = get_controller_processes(vm)


def get_all_application_log(vs_name, num=0):
    url = 'analytics/logs?virtualservice=%s&type=1&nf=True' % vs_name
    if num:
        url += '&page_size=' + str(num)
    logger.info('url %s' % url)
    resp_code, resp = rest.get(url)
    if resp_code != 200:
        logger_utils.fail('ERROR! Analytics server api returned %s' % resp_code)
    return resp
