import avi_objects.logger_utils as logger_utils
import avi_objects.rest as rest
from avi_objects.logger import logger


def placement_get_vs_se_used(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """

    consumer = placement_get_vs_by_name(vs_name, **kwargs)
    if not consumer.get('resources_consumed'):
        return 0
    return len(consumer['resources_consumed'])


def placement_get_vs_by_name(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """

    status_code, con_rsp= rest.get('placement/consumers')
    for c in con_rsp:
        if c['name'] == vs_name:
            return c
    return None


def placement_request_api(obj_type, **kwargs):
    """

    :param obj_type:
    :param kwargs:
    :return:
    """

    resp_code, resp_data = rest.get(obj_type)
    return resp_data


def placement_get_vs_primary_se_uuid(vs_name):
    """

    :param vs_name:
    :return:
    """

    con = placement_get_vs_by_name(vs_name)
    if con.get('resources_consumed'):
        for res in con['resources_consumed']:
            if res['is_primary'] is True:
                return rest.get_uuid_from_ref(res['res_ref'])
    return None


def placement_resources():
    """

    :return:
    """
    obj_type = "placement/resources"
    return placement_request_api(obj_type)


def placement_get_se_usage_distribution():
    """

    :return:
    """
    se_dist = []
    try:
        se_vms = placement_resources()
    except Exception as (FailError, ForcedFailError):
        return []
    for se in se_vms:
        if 'resources_consumed' not in se:
            continue
        if len(se['resources_consumed']) > 0:
            se_dist.append(len(se['resources_consumed']))
    return se_dist


def placement_get_se_in_use_count():
    """

    :return:
    """
    se_dist = placement_get_se_usage_distribution()
    return len(se_dist)


def placement_get_vs_vip(vs_name):
    """

    :param vs_name:
    :return:
    """
    con = placement_get_vs_by_name(vs_name)
    return con['vip']['vip']['addr']


def placement_get_vs_se_grp(vs_name):
    """

    :param vs_name:
    :return:
    """
    con = placement_get_vs_by_name(vs_name)
    return con['se_group_uuid']


def placement_get_vs_se_req(vs_name):
    """

    :param vs_name:
    :return:
    """
    consumer = placement_get_vs_by_name(vs_name)
    return consumer['num_se']


def placement_get_vs_se_list(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """
    con = placement_get_vs_by_name(vs_name)
    se_list = []
    if con.get('resources_consumed'):
        for res in con['resources_consumed']:
            if kwargs.get('primary') and not res.get('is_primary'):
                continue
            if kwargs.get('standby') and not res.get('is_stby'):
                continue
            if kwargs.get('secondary') and res.get('is_primary'):
                continue
            if kwargs.get('secondary') and res.get('is_stby'):
                continue
            se_list.append(rest.get_uuid_from_ref(res['res_ref']))
    return se_list


def placement_compare_se_usage_dist(se_dist_exp):
    """

    :param se_dist_exp:
    :return:
    """
    se_dist = placement_get_se_usage_distribution()
    logger.info('SE distribution %s' % se_dist)
    logger.info('SE expected distribution %s' % se_dist_exp)
    for se in se_dist_exp:
        se_dist.remove(int(se))
    if len(se_dist) > 0:
        logger_utils.fail('More then necessary SE in use %s' % se_dist)


def placement_get_vs_primary_se(vs_name):
    """

    :param vs_name:
    :return:
    """
    consumer = placement_get_vs_by_name(vs_name)
    if consumer.get('resources_consumed'):
        for res in consumer['resources_consumed']:
            if res['is_primary'] is True:
                return res['res_name']
    return None
