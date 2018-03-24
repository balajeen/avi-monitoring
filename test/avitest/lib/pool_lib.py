import re
import ast

import avi_objects.rest as rest
import avi_objects.logger_utils as logger_utils
import lib.common as common
from lib.vs_lib import keys_should_rotate, keys_should_not_rotate
import avi_objects.traffic_manager as traffic_manager

from lib.json_utils import json_value
from avi_objects.logger import logger
from avi_objects.pool import ServerModel

from avi_objects import infra_utils
from avi_objects.pool import PoolModel
from lib.hm_lib import get_all_hmon_stats, get_hmon_stats, error_counters_should_be_under_threshold
import lib.vs_lib as vs_lib


from . import system_lib


def get_pool_server_stats(pool_name, api):
    resp_code, resp_data = rest.get('pool', name=pool_name, path=api)
    if not resp_data:
        raise RuntimeError("ERROR! %s data NULL " % api)
    return resp_data['results']


class Stats(object):
    """Abstraction about the L7 stats for a VS which keeps state and
    return the data in an easy digestible format"""

    def __init__(self, pool_name):
        self.pool_name = pool_name
        self.reset()

    def reset(self):
        """reset the stats, changes are counted from here"""
        self._stats = self.server_stats()

    def server_stats(self):
        """raw stats for the VS"""
        return get_pool_server_stats(self.pool_name, 'runtime/server/detail/')

    def server_l7_stats_changes(self, key, delta):
        stats = self.server_stats()
        for pre in self._stats:
            for post in stats:
                post_val = int(post['server_l7stats'][key])
                pre_val = int(pre['server_l7stats'][key])
                assert ((post_val - pre_val) == delta)

    def server_l4_stats_changes(self, key, delta):
        stats = self.server_stats()
        for pre in self._stats:
            for post in stats:
                post_val = int(post['server_l4stats'][key])
                pre_val = int(pre['server_l4stats'][key])
                assert ((post_val - pre_val) >= delta)


def simulate_ingress(handle, machine_type='client', **kwargs):
    client = machine_type.lower() == 'client'
    match1 = re.search('(.+\D+)(\d+)-(\d+)', handle)
    if match1:
        prefix = match1.group(1)
        start = match1.group(2)
        end = match1.group(3)
        for i in range(int(start), int(end) + 1):
            if client:
                vm, ip = traffic_manager.get_client_by_handle(prefix + str(i))
            else:
                vm = ServerModel.get_server(prefix + str(i)).vm()
            vm.apply_net_emulation(prefix + str(i), machine_type, **kwargs)
    else:
        if client:
            vm, ip = traffic_manager.get_client_by_handle(handle)
        else:
            vm = ServerModel.get_server(handle).vm()
        vm.apply_net_emulation(handle, machine_type, **kwargs)


def get_all_servers_of_pool(pool_name):
    status_code, rsp = rest.get('pool', name=pool_name)
    ret = []
    for server in rsp['servers']:
        ret.append(server['ip']['addr'] + ':%s' % server['port'])
    logger.info('return list: %s' % ret)
    return ret


def create_server(pool_name, server_handle, **kwargs):
    """ API Helps to Create Server for given Pool"""
    how_many = kwargs.pop('how_many', None)
    upstream = kwargs.pop('upstream', None)
    restart = kwargs.pop('restart', True)
    num_ip = kwargs.pop('num_ip', None)

    #Pool Properties
    addr_type = kwargs.pop('addr_type', 'V4')
    network = kwargs.pop('network', '${net}')
    enabled = kwargs.pop('enabled', True)
    port = kwargs.pop('port', 8000)
    app_type = kwargs.pop('app_type', 'httptest')

    if upstream:
        upstream = upstream.split(':')
        kwargs['upstream_ip'] = vs_lib.get_vip(upstream[0])
        kwargs['upstream_port'] = int(upstream[1])

    handles = []
    if how_many is not None:
        for i in range(int(how_many)):
            handle = server_handle + str(i + 1)
            handles.append(handle)
    else:
        handles.append(server_handle)

    pool_dict = {'ip': {'type': addr_type, 'addr': network},
                 'enabled': enabled,
                 'port': port,
                 'handle': server_handle,
                 'app_type': app_type
                 }
    config = infra_utils.get_config()
    context_key = config.get_context_key()
    pool = config.site_objs[context_key]['pool'].get(pool_name)

    count = 0
    server_per_ip = None
    if num_ip is not None:
        server_per_ip = int(how_many)/int(num_ip)

    for handle in handles:
        pool_dict['handle'] = handle
        pool_dict['ip']['addr'] = network
        # Server Model
        server = pool.newServer(handle, pool_dict, **kwargs)
        #Backend Server config
        server.createAppServers()
        count += 1
        if server_per_ip is not None and count == server_per_ip:
            server.reset_aws_sub_ip_port()

    server.pushBackendConfigs(restart)
    if app_type in ['ixia', 'shenick']:
        server.vm().check_if_servers_up()
    else:
        logger.info("Skip Check if server is up for app_type: %s" % app_type)

    st, pool_json_ctrl = rest.get('pool', name=pool_name)
    pool_server_json = []
    pool_server_dict = pool.servers
    for pool_server in pool_server_dict.values():
        pool_server_json.append(pool_server.get_json())
    pool_json_ctrl['servers'] = pool_server_json
    rest.put('pool', name=pool_name, data=pool_json_ctrl)


def _delete_server_model(server_handle, pool):
    pool.removeServer(server_handle)


def _delete_server_backend(server_handle, pool, cleanup_backend):
    server = infra_utils.get_server_by_handle(server_handle)
    if not server:
        logger_utils.fail('Server:%s, Could not able find' % server_handle)
    server.deleteBackend(cleanup_backend)


def delete_server(pool_name, server_handle, cleanup_backend=True):
    """ API Helps to delete server from given pool """
    config = infra_utils.get_config()
    context_key = config.get_context_key()
    pool = config.site_objs[context_key]['pool'].get(pool_name)

    _delete_server_backend(server_handle, pool, cleanup_backend)
    _delete_server_model(server_handle, pool)

    st, pool_json_ctrl = rest.get('pool', name=pool_name)
    pool_server_json = []
    pool_server_dict = pool.servers
    for pool_server in pool_server_dict.values():
        pool_server_json.append(pool_server.get_json())
    pool_json_ctrl['servers'] = pool_server_json
    rest.put('pool', name=pool_name, data=pool_json_ctrl)


def pool_get_server_count(pool_name, **kwargs):
    """

    :param pool_name:
    :param kwargs:
    :return:
    """

    pool_int = get_pool_internal(pool_name, **kwargs)
    num_servers = json_value(pool_int, 'num_servers')
    return num_servers


def get_pool_internal(pool_name, core=0, **kwargs):
    """

    :param pool_name:
    :param core:
    :param kwargs:
    :return:
    """

    json_data = common.get_internal('pool', pool_name, core, **kwargs)
    logger.info('pool_internal %s' % json_data)

    return json_data


def get_server_runtime(pool_name, handle=None, field1=None, field2=None,
                       fetch_all=False, **kwargs):
    """

    :param pool_name:
    :param handle:
    :param field1:
    :param field2:
    :param fetch_all:
    :param kwargs:
    :return:
    """

    # pool_runtime = get_pool_runtime(pool_name)
    # if 'server_detail' not in pool_runtime:
    #  raise RuntimeError("pool_lib.get_server_runtime: \
    #      'server_detail' not found in GET response")

    # server_detail = pool_runtime['server_detail']
    fetch_all = ast.literal_eval(str(fetch_all))
    server_detail = get_pool_nested(pool_name, 'server/detail?page_size=500',
                                    fetch_all=fetch_all, **kwargs)
    if not handle:  # all servers
        if field1:
            if field1 in server_detail[0]:
                if field2:
                    return [s[field1][field2] for s in server_detail]
                else:
                    return [s[field1] for s in server_detail]
            else:
                logger_utils.fail("pool_lib.get_server_runtime: field " + field1 + " \
                    not found in server_detail")
        else:
            return server_detail
    else:
        server_model = infra_utils.get_server_by_handle(handle)
        # ?not sure the format of this list in json
        for server in server_detail:
            port = server_model.port()
            if isinstance(port, list):
                port = port[0]
            if server['ip_addr']['addr'] == server_model.ip() and \
                    server['port'] == port:
                if field1:
                    if field1 in server:
                        if field2:
                            return server[field1][field2]
                        else:
                            return server[field1]
                    else:
                        logger.info("SERVER:%s" % str(server))
                        logger_utils.fail(
                            "pool_lib.get_server_runtime: field "
                            + field1 + " not found in server with ip " +
                            server_model.ip())
                else:
                    return server

        logger_utils.fail('pool_lib.get_server_runtime: server ip not found \
              in list of server_details: %s' % server_model.ip())


def get_pool_nested(pool_name, suffix, core=0, fetch_all=False, **kwargs):
    """

    :param pool_name:
    :param suffix:
    :param core:
    :param fetch_all:
    :param kwargs:
    :return:
    """

    json_data = common.get_nested_internal(
        'pool', pool_name, suffix)
    return json_data


def get_nested_internal(obj_type, obj_name, suffix, core=0, fetch_all=False,
                        **kwargs):
    """

    :param obj_type:
    :param obj_name:
    :param suffix:
    :param core:
    :param fetch_all:
    :param kwargs:
    :return:
    """

    resp_code, resp_data = rest.get(
        obj_type, name=obj_name, path='runtime/%s' % suffix)
    return resp_data


def check_pool_deleted(pool_name, **kwargs):
    """

    :param pool_name:
    :param kwargs:
    :return:
    """

    common.validate_after_delete('pool', pool_name)


def get_server_ips_for_pool(pool_name, **kwargs):
    """

    :param pool_name:
    :param kwargs:
    :return:
    """
    resp_code, resp_data = rest.get("pool", name=pool_name)
    ips = []
    for server in resp_data['servers']:
        ips.append(server['ip']['addr'])
    return ips


def get_server_ip_port_for_pool(pool_name, **kwargs):
    """

    :param pool_name:
    :param kwargs:
    :return:
    """
    resp_code, resp_data = rest.get("pool", name=pool_name)

    default_port = resp_data['default_server_port']
    ip_ports = set()
    for server in resp_data['servers']:
        port = server['port'] if 'port' in server else default_port
        ip_ports.add((server['ip']['addr'], port))
    return ip_ports


def get_pool_config(pool_name, **kwargs):
    """

    :param pool_name:
    :param kwargs:
    :return:
    """

    obj_type = 'pool'
    resp_code, resp_data = rest.get(obj_type, name=pool_name)
    return resp_data


#ToDO Check this function
def get_all_health_monitors_of_pool(pool_name, tenant="admin"):
    resp_code, resp_data = rest.get('pool', name=pool_name, path='hmon')
    ret = []
    health_monitor = resp_data[0].get('health_monitor')
    if health_monitor is not None:
        for hm in health_monitor:
            ret.append(hm['name'])
    return ret


def _get_pool_from_vs(vs_obj, **kwargs):
    """
    Check if there is a poolgroup on this VS, if so get pool from the poolgroup
    For containers, poolgroup will be there by default
    :param vs_obj:
    :param kwargs:
    :return:
    """

    pool_ref = vs_obj.get('pool_ref', None)
    if pool_ref:
        return pool_ref

    pg_ref = vs_obj.get('pool_group_ref', None)
    if not pg_ref:
        logger.info("Didnot find pool or poolgroup on this VS, very strange!!")
        return None

    pg_uuid = rest.get_uuid_from_ref(pg_ref)
    _, pg_obj = rest.get('poolgroup', uuid=pg_uuid)
    # Pick first member (there will most likely be only one member)
    pg_mem = pg_obj['members'][0]
    pool_ref = pg_mem.get('pool_ref', None)
    if not pool_ref:
        logger.info("Could not find pool on the VS or on the poolgroup "
                    "associated with the VS")
        logger.info("vs %s: %s\n; poolgroup %s: %s" % (vs_obj['name'],
                                                       vs_obj, pg_uuid, pg_obj))
        return None
    return pool_ref


def get_pool_persistence(pool_name, persistence_ip=None, persistence_end_ip=None, disable_aggregate=None):
    """

    :param pool_name:
    :param persistence_ip:
    :param persistence_end_ip:
    :param disable_aggregate:
    :return:
    """
    path = 'persistence?'
    if disable_aggregate:
        path += 'disable_aggregate=%s&' % disable_aggregate
    if persistence_ip:
        path += 'persistence_ip=%s&' % persistence_ip
    if persistence_end_ip:
        path += 'persistence_end_ip=%s' % persistence_end_ip

    status_code, runtime_data = rest.get('pool', name=pool_name, path=path)
    common.check_response_for_errors(runtime_data)
    return runtime_data


def get_pool_runtime_detail(pool_name):
    _, detail = rest.get('pool', name=pool_name, path='runtime/detail')
    return detail


def get_pool_runtime_summary(pool_name):
    """

    :param pool_name:
    :return:
    """
    _, runtime = rest.get('pool', name=pool_name, path='runtime')
    return runtime


def cache_pool(pool_name):
    """

    :param pool_name:
    :return:
    """
    pool = get_pool_config(pool_name)  # show pool
    pool_summary = get_pool_runtime_summary(pool_name)  # show pool summary
    pool_detail = get_pool_runtime_detail(pool_name)  # show pool detail
    return pool, pool_summary, pool_detail


def pool_wellness_check(pool_name, t_state, t_num, t_up, t_enabled, skip_detail_check=0):
    """

    :param pool_name:
    :param t_state:
    :param t_num:
    :param t_up:
    :param t_enabled:
    :param skip_detail_check:
    :return:
    """
    logger_utils.asleep(msg='wait', delay=10)
    t_num = int(t_num)
    t_up = int(t_up)
    t_enabled = int(t_enabled)
    logger.info('## start pool wellness check pool=%s t_state=%s t_num=%d t_up=%d t_enabled=%d'
                % (pool_name, t_state, t_num, t_up, t_enabled))

    pool, pool_summary, pool_detail = cache_pool(pool_name)

    try:
        summary_oper_state = pool_summary['oper_status']['state']
        if isinstance(pool_detail, list):
            detail_oper_state = pool_detail[0]['oper_status']['state']
            pool_det = pool_detail[0]
        else:
            detail_oper_state = pool_detail['oper_status']['state']
            pool_det = pool_detail
    except KeyError as err_msg:
        logger_utils.fail('## oper status not available: %s' % err_msg)

    if not skip_detail_check:
        if summary_oper_state != detail_oper_state:
            logger_utils.error("Cache issue - summary state %s != detail state %s" %
                               (summary_oper_state, detail_oper_state))
            logger_utils.fail("Cache issue - summary state %s != detail state %s" %
                              (summary_oper_state, detail_oper_state))

    if summary_oper_state != t_state:
        logger.debug("summary state %s != expected state %s" %
                     (summary_oper_state, t_state))
        logger_utils.fail("summary state %s != expected state %s" %
                          (summary_oper_state, t_state))

    if int(pool_summary['num_servers']) != t_num:
        logger.trace("num servers mismatch (e-%d, s-%d, d-%d)" %
                     (t_num, pool_summary['num_servers'], pool_det['num_servers']))
        logger.fail("num servers mismatch (e-%d, s-%d, d-%d)" %
                    (t_num, pool_summary['num_servers'], pool_det['num_servers']))

    if int(pool_summary['num_servers_enabled']) != t_enabled:
        logger.trace("num servers enabled mismatch (e-%d, s-%d, d-%d)" %
                     (t_enabled, pool_summary['num_servers_enabled'], pool_det['num_servers_enabled']))
        logger_utils.fail("num servers enabled mismatch (e-%d, s-%d, d-%d)" %
                          (t_enabled, pool_summary['num_servers_enabled'], pool_det['num_servers_enabled']))

    if int(pool_summary['num_servers_up']) != t_up:
        logger.trace("num servers up mismatch (e-%d, s-%d, d-%d)" %
                     (t_up, pool_summary['num_servers_up'], pool_det['num_servers_up']))
        logger_utils.fail("num servers up mismatch (e-%d, s-%d, d-%d)" %
                          (t_up, pool_summary['num_servers_up'], pool_det['num_servers_up']))

    return True


def check_cache_pool_up_percent(pool_name, up_percent=0):
    """

    :param pool_name:
    :param up_percent:
    :return:
    """
    pool_summary = get_pool_runtime_summary(pool_name)
    try:
        percent = pool_summary['percent_servers_up_total']
    except KeyError, Argument:
        logger_utils.fail('## percent_servers_up_total not available : %s' % Argument)

    if int(percent) != int(up_percent):
        logger_utils.fail('## Expected %d Got %d' % (up_percent, percent))


def get_server_ip(pool_name, handle, core=0):
    """

    :param pool_name:
    :param handle:
    :param core:
    :return:
    """
    server = infra_utils.get_server_by_handle(handle)
    return server.ip()


def update_server(pool_name, handle, skip_backend_refresh=False, **kwargs):
    """

    :param pool_name:
    :param handle:
    :param skip_backend_refresh:
    :param kwargs:
    :return:
    """
    server_ip = get_server_ip(pool_name, handle)
    status_code, json_data = rest.get('pool', name=pool_name)
    for index, server in enumerate(json_data['servers']):
        if server['ip']['addr'] == server_ip:
            if kwargs.get('enabled') in [0, False]:
                json_data['servers'][index]['enabled'] = False
            elif kwargs.get('enabled'):
                json_data['servers'][index]['enabled'] = True

    rest.put('pool', name=pool_name, data=json_data)


def nginx_down(handle):
    """

    :param handle:
    :return:
    """
    server = infra_utils.get_server_by_handle(handle)
    logger.info('nginx_down : %s' %(handle))
    server.vm().bring_nginx_server_down(handle)
    server.vm().reload_server_context_nginx()


def nginx_up(handle):
    """

    :param handle:
    :return:
    """
    server = infra_utils.get_server_by_handle(handle)
    logger.info('nginx_up: %s '% server)
    server.vm().bring_nginx_server_up(handle)
    server.vm().reload_server_context_nginx()
    server.vm().check_if_servers_up()


def get_http_cookie_persistence_keys(profile_name):
    _, resp = rest.get('applicationpersistenceprofile', name=profile_name)
    return resp['http_cookie_persistence_profile']['key']


def persistence_keys_should_rotate(profile_name, old_keys, count=1):
    for index in range(3):   # retrying for max 3 times, if keys_should_rotate fails
        new_keys = get_http_cookie_persistence_keys(profile_name)
        ret, msg = keys_should_rotate(old_keys, new_keys, int(count))
        if not ret or (index == 2 and msg):
            logger_utils.fail(msg)
            raise RuntimeError(msg)


def persistence_keys_should_not_rotate(profile_name, old_keys):
    new_keys = get_http_cookie_persistence_keys(profile_name)
    keys_should_not_rotate(old_keys, new_keys)


def update_pool(pool_name, **kwargs):
    """

    :param pool_name:
    :return:
    """
    logger.info('update pool %s, fileds: %s' % (pool_name, kwargs))
    status_code, json_data = rest.get("pool", name=pool_name)

    if kwargs.get('lb_algorithm'):
        json_data['lb_algorithm'] = kwargs.get('lb_algorithm')

    if kwargs.get('lb_algorithm_hash'):
        json_data['lb_algorithm_hash'] = kwargs.get('lb_algorithm_hash')

    if kwargs.get('lb_algorithm_consistent_hash_hdr'):
        json_data['lb_algorithm_consistent_hash_hdr'] = kwargs.get(
            'lb_algorithm_consistent_hash_hdr')

    if kwargs.get('default_server_port'):
        json_data['default_server_port'] = kwargs.get('default_server_port')

    if kwargs.get('application_persistence_profile_uuid'):
        status_code, json_profile_data = \
            rest.get("applicationpersistenceprofile",
                     name=kwargs.get('application_persistence_profile_uuid'))
        json_data['application_persistence_profile_ref'] = \
            json_profile_data.get('url')

    if kwargs.get('graceful_disable_timeout'):
        json_data['graceful_disable_timeout'] = kwargs.get(
            'graceful_disable_timeout')

    if kwargs.get('connection_ramp_duration'):
        json_data['connection_ramp_duration'] = kwargs.get(
            'connection_ramp_duration')

    if kwargs.get('max_concurrent_connections_per_server'):
        json_data['max_concurrent_connections_per_server'] = kwargs.get(
            'max_concurrent_connections_per_server')

    rest.put('pool', name=pool_name, data=json_data)


def add_hm_to_pool(pool_name, healthmonitor_name, detect_dup='on'):
    """

    :param pool_name:
    :param healthmonitor_name:
    :param detect_dup:
    :return:
    """
    logger.info('add hm %s to pool %s' % (healthmonitor_name, pool_name))

    status_code, json_pool_data = rest.get('pool', name=pool_name)
    status_code, json_hm_data = rest.get('healthmonitor',
                                         name=healthmonitor_name)

    if 'health_monitor_refs' not in json_pool_data:
        json_pool_data['health_monitor_refs'] = []

    if json_hm_data.get('url') in json_pool_data.get('health_monitor_refs') \
            and detect_dup == 'on':
        logger_utils.fail('HealthMonitor "%s" already in pool %s' % (
            healthmonitor_name, pool_name))

    json_pool_data.get('health_monitor_refs').append(json_hm_data.get('url'))
    rest.put('pool', name=pool_name, data=json_pool_data)


def negative_update_pool(pool_name, expected_error=None, **kwargs):
    """

    :param pool_name:
    :param expected_error:
    :param kwargs:
    :return:
    """
    logger.info('update pool %s, fileds: %s' % (pool_name, kwargs))
    _, json_pool_data = rest.get('pool', name=pool_name)

    if kwargs.get('name') or kwargs.get('name') == '':
        json_pool_data['name'] = kwargs.get('name')

    if kwargs.get('default_server_port'):
        json_pool_data['default_server_port'] = kwargs.get('default_server_port')

    if kwargs.get('graceful_disable_timeout'):
        json_pool_data['graceful_disable_timeout'] = kwargs.get('graceful_disable_timeout')

    if kwargs.get('connection_ramp_duration'):
        json_pool_data['connection_ramp_duration'] = kwargs.get('connection_ramp_duration')

    try:
        rest.put('pool', name=pool_name, data=json_pool_data)
        logger_utils.fail('No exception was raised in negative test case')
    except Exception as e:
        if expected_error:
            if expected_error.lower() not in str(e).lower():
                logger_utils.fail('Expected error %s did not occur\n%s' % (expected_error, str(e)))
        return True


def update_persistence_profile_ip(profile_name, **kwargs):
    """

    :param profile_name:
    :param kwargs:
    :return:
    """
    logger.info('update profile %s with persistence profile ip %s' % (
        profile_name, kwargs))
    status_code, json_profile_data = rest.get('applicationpersistenceprofile',
                                              name=profile_name)

    if kwargs.get('ip_persistent_timeout'):
        json_profile_data['ip_persistence_profile']['ip_persistent_timeout'] =\
            kwargs.get('ip_persistent_timeout')

    rest.put('applicationpersistenceprofile', name=profile_name, data=json_profile_data)


def remove_hm_from_pool(pool_name, healthmonitor_name):
    """

    :param pool_name:
    :param healthmonitor_name:
    :return:
    """
    logger.info('add hm %s to pool %s' % (healthmonitor_name, pool_name))

    status_code, json_pool_data = rest.get('pool', name=pool_name)
    status_code, json_hm_data = rest.get('healthmonitor',
                                         name=healthmonitor_name)

    if json_hm_data.get('url') in json_pool_data.get('health_monitor_refs'):
        json_pool_data.get('health_monitor_refs').remove(json_hm_data.get(
            'url'))
        rest.put('pool', name=pool_name, data=json_pool_data)


def delete_servers(pool_name, how_many, prefix, cleanup_backend=True):
    """

    :param pool_name:
    :param how_many:
    :param prefix:
    :param cleanup_backend:
    :return:
    """
    logger.info('delete servers from pool %s' % pool_name)
    config = infra_utils.get_config()
    context_key = config.get_context_key()
    pool = config.site_objs[context_key]['pool'].get(pool_name)

    for count in range(int(how_many)):
        handle = '%s%s' % (prefix, count + 1)
        _delete_server_backend(handle, pool, cleanup_backend)

    for count in range(int(how_many)):
        handle = '%s%s' % (prefix, count + 1)
        _delete_server_model(handle, pool)

    st, pool_json_ctrl = rest.get('pool', name=pool_name)
    pool_server_json = []
    pool_server_dict = pool.servers
    for pool_server in pool_server_dict.values():
        pool_server_json.append(pool_server.get_json())
    pool_json_ctrl['servers'] = pool_server_json
    rest.put('pool', name=pool_name, data=pool_json_ctrl)


def parse_server_string(servers):
    """

    :param servers:
    :return:
    """
    parsed = []
    if not servers:
        return parsed

    servers = servers.split(';')
    for server in servers:
        server_model = infra_utils.get_server_by_handle(server)
        parsed.append('%s:%s' % (server_model.ip(), server_model.port()))
    return parsed


def is_pool_servers_in_state(pool_name, down_servers=None, disabled_servers=None,
                             error_string=None):
    """

    :param pool_name:
    :param down_servers:
    :param disabled_servers:
    :param error_string:
    :return:
    """
    parsed_down_servers = parse_server_string(down_servers)
    parsed_disabled_servers = parse_server_string(disabled_servers)

    servers = {}
    err_str_arr = {}
    try:
        server_detail = get_server_runtime(pool_name)
        for server in server_detail:
            server_key = '%s:%s' % (server['ip_addr']['addr'], server['port'])
            state = server['oper_status']['state']
            if server_key in servers:
                logger_utils.fail(
                    'Multiple servers with same ip:port combination: %s' %
                    server_key)
            servers[server_key] = state
            if error_string and state == 'OPER_DOWN':
                err_str_arr[server_key] = server['oper_status']['reason']
    except KeyError, Argument:
        logger_utils.fail(
            'Rest result did not have required field: %s' % Argument)

    for k, s in servers.items():
        if k in parsed_down_servers:
            if not s == 'OPER_DOWN':
                logger.info('%s is not in OPER_DOWN state' % k)
                return False
            elif error_string:
                # Check error string
                found = False
                for string in err_str_arr[k]:
                    if error_string in string:
                        found = True
                if found is False:
                    logger.info('Got Error string: %s, Expected %s' % (err_str_arr[k][0], error_string))
                    return False
        elif k in parsed_disabled_servers:
            if not s == 'OPER_DISABLED':
                logger.info('%s is not in OPER_DISABLED state' % k)
                return False
        elif not s == 'OPER_UP':
            logger.info('%s is not in OPER_UP state' % k)
            return False

    return True


def get_all_pool_stats(pool_name):
    """

    :param pool_name:
    :return:
    """
    pool_stats = []
    logger.info('get all pool stats for pool: %s' % pool_name)
    logger.info('delete servers from pool %s' % pool_name)
    status_code, json_pool_data = rest.get('pool', name=pool_name)

    # getting all the healthmonitor stats
    hm_list = json_pool_data.get('health_monitor_refs')
    hm_stat_list = list()
    for hm_ref in hm_list:
        hm_uuid = rest.get_uuid_from_ref(hm_ref)
        _, hm_stat = rest.get('healthmonitor', uuid=hm_uuid)
        hm_stat_list.append(hm_stat)

    pool_stats.append({'servers': [server for server in json_pool_data.get('servers')]})
    pool_stats.append({'healthmonitors': hm_stat_list})
    return pool_stats


def check_pool_state(pool_name, **kwargs):
    """

    :param pool_name:
    :param kwargs:
    :return:
    """
    down_servers = kwargs.get('down_servers')
    disabled_servers = kwargs.get('disabled_servers')
    error_string = kwargs.get('error_string')
    retry_timeout = int(kwargs.get('retry_timeout', 10))
    retry_interval = float(kwargs.get('retry_interval', 1))
    try:

        @logger_utils.aretry(delay=retry_interval, period=retry_timeout)
        def retry_action():
            return is_pool_servers_in_state(pool_name,
                                            down_servers,
                                            disabled_servers,
                                            error_string)

        return retry_action()

    except Exception as e:
        stats = get_all_pool_stats(pool_name)
        logger.debug("Failure case : All pool stats %s" % stats)
        logger_utils.error('Did not find pool in expected state after retry '
                          'timeout of %s, down servers: %s, failed with '
                          'error: %s' % (retry_timeout, down_servers, e))


def pool_and_servers_should_be_up(pool_name, **kwargs):
    """

    :param pool_name:
    :param kwargs:
    :return:
    """
    retry_timeout = kwargs.get('retry_timeout', str(0))
    try:
        check_pool_state(pool_name, **kwargs)
    except Exception as e:
        logger_utils.fail('Pool and servers were not up after retry timeout '
                          'of %s, failed with error: %s' % (retry_timeout, e))


def _update_server_model(handle, **kwargs):
    """

    :param handle:
    :param kwargs:
    :return:
    """
    server = infra_utils.get_server_by_handle(handle)
    server.updateServer(**kwargs)


def negative_update_server(pool_name, handle, **kwargs):
    """

    :param pool_name:
    :param handle:
    :param kwargs:
    :return:
    """
    server = infra_utils.get_server_by_handle(handle)

    response_code, json_pool_data = rest.get('pool', name=pool_name)

    if kwargs.get('port'):
        for index, rest_server in enumerate(json_pool_data.get('servers')):
            json_server_data = server.get_json()
            server_ip = json_server_data.get('ip')
            if server_ip and server_ip.get('addr') == rest_server['ip']['addr']:
                json_pool_data['servers'][index]['port'] = kwargs.get('port')
    try:
        rest.put('pool', name=pool_name, data=json_pool_data)
        logger_utils.fail('No exception was raised in negative test case')
    except Exception as e:
        logger.info('Field port must be in the range 1-65535')
        return True


def pool_and_servers_with_hm_should_be_up_with_counter_threshold(pool_name, **kwargs):
    """

    :param pool_name:
    :param kwargs:
    :return:
    """
    pool_and_servers_should_be_up(pool_name, **kwargs)
    # list of servers in ip:port format
    servers = get_all_servers_of_pool(pool_name)
    # list of all hm's
    hm_list = get_all_health_monitors_of_pool(pool_name)
    for hm in hm_list:
        for s_name in servers:
            shm = get_hmon_stats(pool_name, hm, s_name, 'shm_runtime')
            error_counters_should_be_under_threshold(shm, 1)


def update_pool_network(pool_name, network, ip=None, **kwargs):
    _, json_pool_data = rest.get('pool', name=pool_name)
    if ip:
        json_pool_data['servers'][0]['ip']['addr'] = ip
    else:
        new_ip = infra_utils.get_ip_for_network(network)
        json_pool_data['servers'][0]['ip']['addr'] = new_ip
    rest.put('pool', name=pool_name, data=json_pool_data)
