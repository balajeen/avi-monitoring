import re
import json
import avi_objects.rest as rest
import avi_objects.logger_utils as logger_utils
from avi_objects.logger import logger
import avi_objects.infra_utils as infra_utils
import avi_objects.config_manager as config_manager

def _bool_value(bool_s):
    """

    :param bool_s:
    :return:
    """

    if type(bool_s) is str or type(bool_s) is unicode:
        if str(bool_s).upper() == 'TRUE':
            return True
        else:
            return False
    else:
        return bool_s


def delete_cert_and_key_if_seen(name, **kwargs):
    """
    Delete cert&key data that was may get created during test runtime
    Failed silently if not see the created data
    :param name:
    :param kwargs:
    :return:
    """

    rest.delete('sslkeyandcertificate', name=name, check_status_code=False)


def validate_after_delete(obj_type, obj_name, **kwargs):
    """

    :param obj_type:
    :param obj_name:
    :param kwargs:
    :return:
    """
    try:
        status_code, resp = rest.get(obj_type, name=obj_name)
        logger.trace('Status: %s, Resp: %s' % (status_code, resp))
        logger_utils.fail('%s deletion failed for object - %s' % (obj_type, obj_name))
    except:
        logger.info("%s %s successfully deleted" % (obj_type, obj_name))

def parse_handles(handles):
    '''
    Input: string of the form handle#x-#y or handle
    Output: list of handles starting with handle#x ending with
    handle#y incrementing by 1 or list with the single handle in it
    '''
    # REVIEW: re-examine where this should go
    m = re.search('^(.*\D+)(\d+)-(\d+)$', handles)
    if m:
        parsed = []
        for i in range(int(m.group(2)), int(m.group(3)) + 1):
            parsed.append('%s%s' % (m.group(1), i))
        return parsed
    else:
        return [handles]


def get_network_by_handle(handle):
    '''
    Looks up network from handle
    In the case that handle is a network will return handle
    '''

    config = infra_utils.get_config()
    if handle in config.testbed[config.site_name].networks_json:
        network = config.testbed[config.site_name].networks_json[handle]
        if not network:
            raise Exception(
                'ERROR! network for handle %s does not exist' % handle)
        return network


def set_dict(**kwargs):
    """
    set the dictionary
    :param kwargs: dictionary key and value pairs
    :return: dictionary
    """

    custom_dict = kwargs.pop("custom_dict", {})
    for key, value in kwargs.iteritems():
        custom_dict[key] = value
    return custom_dict

def set_list(**kwargs):
    """
    set the list
    :param kwargs: items for list
    :return: list
    """

    custom_list = []
    for item in kwargs:
        custom_list.append(item)
    return custom_list


def get_internal(obj_type, obj_name, core=0, ret_all=False,
                 disable_aggregate=None, **kwargs):
    """

    :param obj_type:
    :param obj_name:
    :param core:
    :param ret_all:
    :param disable_aggregate:
    :param kwargs:
    :return:
    """
    # REVIEW: re-examine where this should go

    path = '/runtime/internal'
    if disable_aggregate:
        path += '?disable_aggregate=%s' % disable_aggregate

    resp_code, resp_data = rest.get(obj_type, name=obj_name, path=path, params=kwargs.get('params', {}))

    if disable_aggregate or ret_all:
        logger.debug('Requesting disable_aggregate, returning')
        return resp_data

    for json_data in resp_data:
        proc_id_from_get_data = json_data.get('proc_id')
        if not proc_id_from_get_data:
            continue
        if re.search('C' + str(core), proc_id_from_get_data):
            return json_data

        # Shared memory (not per core)
        if obj_type == 'pool':
            if re.search('so_pool', proc_id_from_get_data):
                return json_data
            else:
                logger_utils.fail('ERROR! internal data NULL for %s proc_id: so_pool' % obj_type)

    logger_utils.fail('ERROR! internal data NULL for %s core %s' % (path, str(core)))


def check_response_for_errors(response):
    if isinstance(response, dict):
        error = response.get('error')
        config_status = response.get('config_status')
        if error:
            logger_utils.fail('Error message returned by rest api: %s' % error)
        elif config_status:
            state = config_status.get('state')
            reason = config_status.get('reason', ['Reason was not given'])
            logger_utils.fail('Error message returned by rest api: state = %s, %s' % (
                state, ', '.join(str(r) for r in reason)))


def validate_after_create(obj_type, obj_name):
    url = '%s/%s' % (obj_type, obj_name)
    logger.trace('Validate_after_create: %s' % str(obj_name))
    rest.get(url)


def retry_action_detail(action, retry_count=0, retry_interval=0.1):
    """

    :param action:
    :param retry_count:
    :param retry_interval:
    :return:
    """

    if retry_interval <= 0:
        logger_utils.fail(
            'retry_interval <= 0 is not allowed, was: %s' %
            retry_interval)
    if retry_count < 0:
        logger_utils.fail(
            'retry_count < 0 is not allowed, was %s' % retry_count)
    retry_count = int(retry_count)

    tries = 1
    success, dbg_str = action()
    if success:
        return dbg_str

    for x in xrange(1, retry_count):
        tries += 1
        success, dbg_str = action()
        if success:
            return dbg_str
        else:
            logger_utils.asleep(delay=retry_interval)

    logger.trace('Last Retry result: %s' % dbg_str)
    logger_utils.fail('%s, failed after %s tries' % (dbg_str, tries))

def get_nested_internal(obj_type, obj_name, suffix):
    path = '/runtime/' + suffix

    resp_code, resp_data = rest.get(obj_type, name=obj_name, path=path)
    return resp_data['results']

def get_template_data(templ_type, tmpl_name):
    tmpl_path = config_manager.resolve_abs_relative_path_for_template("%s/%s.json" % (templ_type, tmpl_name))
    with open(tmpl_path) as data_file:
        data = json.load(data_file)
    return data

