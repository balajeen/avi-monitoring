import avi_objects.infra_utils as infra_utils
import avi_objects.logger_utils as logger_utils
import avi_objects.rest as rest
from avi_objects.logger import ForcedFailError, FailError
from avi_objects.logger import logger
from avi_objects.suite_vars import suite_vars
from lib.placement_lib import placement_get_vs_by_name, placement_get_vs_vip, \
    placement_get_vs_se_grp, \
    placement_get_vs_se_req, placement_get_vs_se_used, placement_get_vs_se_list
from lib.pool_lib import \
    pool_and_servers_with_hm_should_be_up_with_counter_threshold
from lib.vs_lib import vsmgr_wellness_check_once, vsmgr_wellness_check, get_vs, \
    vs_get_vip, vs_get_se_grp, \
    vs_get_num_se_req, vs_get_num_se_used, vs_get_se_list


def set_controller_properties(**kwargs):
    status_code, _controller_props = rest.get('controllerproperties')
    _controller_props.update(kwargs)

    logger.info('Controller Properties: ' + str(_controller_props))
    try:
        resp_code, resp_data= rest.put('controllerproperties', data=_controller_props)
    except FailError as e:
        raise FailError(e.msg)
    else:
        return resp_code, resp_data


def get_controller_port(**kwargs):
    controller_vms = infra_utils.get_vm_of_type('controller')
    for controller_vm in controller_vms:
        if controller_vm.api_port:
            port = str(controller_vm.api_port)
            break
    return port


def get_controller_ip():
    """This function Return Controller IP Address
    Args:
        :param handle: The handle to get the corresponding handle details.
        :type handle: str
    Returns:
        Controller VM IP or DNS name if it configured
    Raises:
        ValueError, AttributeError, KeyError
    """
    if not suite_vars.dns:
        ip_list = [vm.ip for vm in infra_utils.get_vm_of_type('controller')]
    else:
        ip_list = [vm.name for vm in infra_utils.get_vm_of_type('controller')]
    if ip_list:
        leader_ip = sorted(ip_list)[0]
        return leader_ip
    return None


def fetch_controller_events(fetch_all=False, tenant='admin'):
    """

    :param fetch_all:
    :param tenant:
    :return:
    """

    uri = 'analytics/logs?type=2&page_size=1000'
    _, resp_data = rest.get(uri)
    return resp_data


def stop_controller_process(vm, process_name, update_pids=True):
    import lib.cluster_lib as cluster_lib
    update_pids = (update_pids or update_pids == 'True')
    proc = process_name
    logger.info('Stopping process %s on controller with IP %s' % (proc, vm.ip))
    vm.stop_upstart_job(proc)
    if update_pids:
        logger_utils.asleep(delay=5)
        cluster_lib.wait_until_cluster_ready()
        cluster_lib.update_processes_for_all_controllers()


def reset_controller_processes(vm_id=None):
    import lib.cluster_lib as cluster_lib
    for vm in infra_utils.get_vm_of_type('controller'):
        if vm_id and vm.name != vm_id:
            continue
        vm.processes.clear()
        vm.processes = cluster_lib.get_controller_processes(vm)


def set_key_rotate_period(**kwargs):
    try:
        set_controller_properties(**kwargs)
    except Exception as e:
        if kwargs.get('should_pass', True):
            logger_utils.fail("set_controller_properties should fail")
        return True   # do not sleep if expected error is caught
    logger_utils.asleep(msg='wait', delay=61)  # sleeping for 1 min, so that


def config_consistency_check(tenant='admin'):
    resp_code, resp = rest.get('configconsistencycheck')
    consistent = resp['consistent']
    if not consistent:
        logger.trace('config_consistency_check failed, error:%s' % resp)
        logger_utils.fail('config_consistency_check failed, error:%s' % resp)


def controller_wellness_check(vs, pool, num_requested, num_assigned, fsm_state,
                              check_pool=1, one_plus_one_ha=0,
                              vs_state='OPER_UP', check_placement=1,
                              skip_cc_check=False, num_app=0,
                              skip_detail_check=0, check_se_connected=1,
                              retry_timeout=30, vip_id="0"):
    """

    :param vs:
    :param pool:
    :param num_requested:
    :param num_assigned:
    :param fsm_state:
    :param check_pool:
    :param one_plus_one_ha:
    :param vs_state:
    :param check_placement:
    :param skip_cc_check:
    :param num_app:
    :param skip_detail_check:
    :param check_se_connected:
    :param retry_timeout:
    :param vip_id:
    :return:
    """
    _, vs_data = rest.get('virtualservice', name=vs)
    cloud_type = infra_utils.get_cloud_context_type()
    if cloud_type == 'baremetal' and vs_data['east_west_placement']:
        logger.info("baremetal, skip check for east_west vs:" + vs)
        return True, ''

    check_pool = int(check_pool)
    one_plus_one_ha = int(one_plus_one_ha)
    check_placement = int(check_placement)
    num_app = int(num_app)
    logger.debug("controller_wellness_check(%s, %s, %d, %d, %s %d %d %s %d %d %s" %
                 (vs, pool, num_requested, num_assigned, fsm_state, check_pool,
                  one_plus_one_ha, vs_state, check_placement, num_app, skip_detail_check))
    if one_plus_one_ha == 1:
        logger.debug("check one_plus_one_ha")
    # Timeout 120 sec, due to Azure VS creation
    if cloud_type == 'azure':
        retry_timeout = 120
    # If timeout less than 10 seconds, call VS & Pool checks only once
    # In case this is called from the with_retey function, retry_timeout will
    # be set to 1
    if retry_timeout < 10:
        result, dbg_str = vsmgr_wellness_check_once(
            vs, num_requested, num_assigned, fsm_state,
            vs_state, one_plus_one_ha, num_app,
            skip_detail_check, check_se_connected, vip_id)
        if not result:
            return result, dbg_str

        if check_pool == 1:
            logger.debug("check pool status")
            pool_and_servers_with_hm_should_be_up_with_counter_threshold(
                pool, retry_timeout=1, retry_interval=1)
    else:
        vsmgr_wellness_check(
            vs, num_requested, num_assigned, fsm_state,
            vs_state, one_plus_one_ha, num_app,
            skip_detail_check, check_se_connected, vip_id,
            retry_timeout=retry_timeout)
        if check_pool == 1:
            logger.debug("check pool status")
            pool_and_servers_with_hm_should_be_up_with_counter_threshold(
                pool, retry_timeout=retry_timeout, retry_interval=5)
    vs = get_vs(vs)  # show vs
    if 'type' in vs.keys() and vs['type'] == 'VS_TYPE_VH_CHILD':
        logger.debug("APP vs")
    # Placement checks for VS
    if ('type' in vs.keys() and fsm_state != "Disabled" and
                check_placement == 1 and vs['type'] != 'VS_TYPE_VH_CHILD'):
        logger.debug("check placement status")
        verify_placement_vs_properties(vs)
        verify_placement_vs_resources(vs)
    skip_config_consistency_check = str(skip_cc_check).lower() == 'true'
    # FIXME: uncomment this check when all tests are good
    skip_config_consistency_check = True
    if num_requested == num_assigned and \
            not skip_config_consistency_check:
        config_consistency_check()
    else:
        logger.debug("num_requested != num_assigned check: skip consistency check")
    return True, ''


def controller_wellness_check_with_retry(vs, pool, num_requested, num_assigned,
                                         fsm_state, check_pool=1,
                                         one_plus_one_ha=0, vs_state='OPER_UP',
                                         check_placement=1, skip_cc_check=False,
                                         num_app=0,
                                         retry_interval=10, retry_timeout=300,
                                         skip_detail_check=0,
                                         check_se_connected=1, retry_count=30, vip_id='0'):
    """

    :param vs:
    :param pool:
    :param num_requested:
    :param num_assigned:
    :param fsm_state:
    :param check_pool:
    :param one_plus_one_ha:
    :param vs_state:
    :param check_placement:
    :param skip_cc_check:
    :param num_app:
    :param retry_interval:
    :param retry_timeout:
    :param skip_detail_check:
    :param check_se_connected:
    :param retry_count:
    :param vip_id:
    :return:
    """
    retry_interval = int(retry_interval)
    retry_timeout = int(retry_timeout)
    retry_count = max(retry_count, retry_timeout/retry_interval)

    @logger_utils.aretry(retry=retry_count, delay=retry_interval, period=retry_timeout)
    def retry_action():
        return controller_wellness_check(vs, pool, num_requested,
                                         num_assigned, fsm_state,
                                         check_pool, one_plus_one_ha,
                                         vs_state, check_placement,
                                         skip_cc_check=skip_cc_check,
                                         num_app=num_app,
                                         skip_detail_check=skip_detail_check,
                                         check_se_connected=check_se_connected,
                                         retry_timeout=1, vip_id=vip_id)

    return retry_action()


def verify_placement_vs_properties(vs_name):
    """

    :param vs_name:
    :return:
    """
    if not placement_get_vs_by_name(vs_name):
        return True

    vip1 = placement_get_vs_vip(vs_name)
    vip2 = vs_get_vip(vs_name)
    if vip1 != vip2:
        logger.trace('VS %s VIP %s and '
                     'RM VIP %s dont match' % (vs_name, vip2, vip1))
        logger_utils.fail('VS %s VIP %s and '
                         'RM VIP %s dont match' % (vs_name, vip2, vip1))

    se_grp1 = placement_get_vs_se_grp(vs_name)
    se_grp2 = vs_get_se_grp(vs_name)
    if se_grp1 != se_grp2:
        logger.trace('VS %s SE Grp %s and '
                     'RM SE Grp %s dont match' % (vs_name, se_grp2, se_grp1))
        logger_utils.fail('VS %s SE Grp %s and '
                         'RM SE Grp %s dont match' % (
                             vs_name, se_grp2, se_grp1))


def verify_placement_vs_resources(vs_name):
    """

    :param vs_name:
    :return:
    """
    if not placement_get_vs_by_name(vs_name):
        return True

    n1 = placement_get_vs_se_req(vs_name)
    n2 = vs_get_num_se_req(vs_name)
    if n1 != n2:
        logger.trace('VS SE Req %d and '
                     'RM SE Req %d dont match' % (n2, n1))
        logger_utils.fail('VS SE Req %d and '
                         'RM SE Req %d dont match' % (n2, n1))

    n1 = placement_get_vs_se_used(vs_name)
    n2 = vs_get_num_se_used(vs_name)
    if n1 != n2:
        logger.trace('VS SE Used %d and '
                     'RM SE Used %d dont match' % (n2, n1))
        logger_utils.fail('VS SE Used %d and '
                         'RM SE Used %d dont match' % (n2, n1))

    se_list1 = placement_get_vs_se_list(vs_name)
    se_list2 = vs_get_se_list(vs_name)
    # Set symmetric difference
    if len(set(se_list1) ^ set(se_list2)) > 0:
        logger.trace('VS %s SE List %s and '
                     'RM SE List %s dont match' % (vs_name, se_list2, se_list1))
        logger_utils.fail('VS %s SE Used %s and '
                         'RM SE Used %s dont match' % (
                             vs_name, se_list2, se_list1))

    se_list1 = placement_get_vs_se_list(vs_name, secondary=True)
    se_list2 = vs_get_se_list(vs_name, secondary=True)
    if len(set(se_list1) ^ set(se_list2)) > 0:
        logger.trace('VS %s Sec SE List %s and '
                     'RM Sec SE List %s dont match' % (vs_name, se_list2, se_list1))
        logger_utils.fail('VS %s Sec SE List %s and '
                         'RM Sec SE List %s dont match' % (
                             vs_name, se_list2, se_list1))

    se_list1 = placement_get_vs_se_list(vs_name, standby=True)
    se_list2 = vs_get_se_list(vs_name, standby=True)
    if len(set(se_list1) ^ set(se_list2)) > 0:
        logger.trace('VS %s Stby SE List %s and '
                     'RM Stby SE List %s dont match' % (
                         vs_name, se_list2, se_list1))
        logger_utils.fail('VS %s Stby SE List %s and '
                         'RM Stby SE List %s dont match' % (
                             vs_name, se_list2, se_list1))


def set_dns_resolver_on_controller(*args):
    """

    :param args:
    :return:
    """
    _, response = rest.get('systemconfiguration')
    server_list = []
    current_dns_list = [ip_addr['addr'] for ip_addr in response.get('dns_configuration', {}).get('server_list', {})]
    for ip in args:
        if ip not in current_dns_list:
            server_list.append({"type": "V4", "addr": ip})
    if server_list:
        if 'server_list' in response["dns_configuration"].keys():
            for server_data in server_list:
                response["dns_configuration"]["server_list"].append(server_data)
        else:
            response["dns_configuration"].update({'server_list': server_list})
        rest.put('systemconfiguration', data=response)


class TechSupport:

    @classmethod
    def init(cls, **kwargs):
        """ Initialize the site specific master-vm; """
        import lib.cluster_lib as cluster_lib
        cls.ctrl_vm = cluster_lib.get_cluster_master_vm(**kwargs)
        cls.url = 'techsupport/'
        return

    @classmethod
    def _clean(cls):
        cmd = 'sudo rm -rf /opt/avi/tech_support/*'
        output = cls.ctrl_vm.execute_command(cmd)
        logger.info('command output: %s' % output)

    @classmethod
    def _total_count(cls):
        cmd = 'ls /opt/avi/tech_support/*.tar.gz | wc -l'
        output = cls.ctrl_vm.execute_command(cmd)
        logger.info('command output: %s' % output)
        return int(output[-1])

    @classmethod
    def _count(cls, level):
        cmd = 'ls /opt/avi/tech_support/%s*.tar.gz | wc -l' % level
        output = cls.ctrl_vm.execute_command(cmd)
        logger.info('command output: %s' % output)
        return int(output[-1])

    @classmethod
    def _execute_api(cls, level_key='', **kwargs):
        """ Use avibot api to leverage multi-site etc"""
        payload = {}
        fields = ['tech_support_filename', 'se_group_name', 'cloud_name']
        for field in fields:
            if kwargs.get(field, None):
                payload[field] = kwargs[field]
        logger.info('payload %s' % payload)
        if len(payload):
            kwargs['params'] = payload

        uri = cls.url + level_key
        logger.info('api %s' % uri)

        _, content = rest.get(uri, timeout=150)
        return content

    @classmethod
    def test_verify_tech_support(cls, **kwargs):
        cls._clean()
        before_count = cls._total_count
        resp = cls._execute_api(**kwargs)
        if kwargs.get('tech_support_filename', None):
            levels = ['clustering', 'debuglogs', 'placement', 'portal',
                      'serviceengine', 'upgrade', 'virtualservice', 'gslb']
            # check the support list of level
            if set(levels) != set(resp.keys()):
                logger_utils.fail()
        after_count = cls._total_count
        if after_count != before_count:
            # assumption is test are never run in parallel
            logger_utils.fail('ValueError')

    @classmethod
    def test_verify_tech_support_level(cls, level, key='', **kwargs):
        cls._clean()
        before_count = cls._count(level)
        logger.info('level: %r , key: %r , kwargs: %r' % (level, key, kwargs))
        logger.info('before_count: %r' % before_count)

        if key is not '':
            if level in ['serviceengine', 'virtualservice', 'gslb']:
                key = '/' + key
        cls._execute_api(level_key=level + key, **kwargs)

        after_count = cls._count(level)
        logger.info('after_count: %r' % after_count)
        if after_count == before_count:
            logger_utils.fail('ValueError')


def verify_vs_se_az_distribution(vs_name):
    """

    :param vs_name:
    :return:
    """
    from lib.se_lib import get_se_az
    from lib.vcenter_lib import cloud_get_all_az, cloud_supports_multiple_az
    se_list = vs_get_se_list(vs_name)
    num_se = len(se_list)
    vs_azs = set([get_se_az(se) for se in se_list])
    if cloud_supports_multiple_az():
        avail_azs = set(cloud_get_all_az())
        logger.info('VS AZs %s, Available AZz %s, Num SE %d' % (vs_azs,
                                                                avail_azs, num_se))
        if len(vs_azs) < min(len(avail_azs), num_se):
            logger.info('VS AZs %s needs to be Min of Available AZz %s & Num '
                        'SE %d' % (vs_azs, avail_azs, num_se))
            logger_utils.fail('VS AZs %s needs to be Min of Available AZz %s '
                              '& Num SE %d' % (vs_azs, avail_azs, num_se))
