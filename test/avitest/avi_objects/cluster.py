import json
import random
import re
import infra_utils
from avi_objects.logger import logger
from avi_objects.avi_config import AviConfig
from rest import (put,
                  get,
                  create_session,
                  update_admin_user, reset_admin_user)
from logger_utils import aretry, asleep, error, fail



DEFAULT_CLUSTER_NAME = 'cluster-0-1'
MAX_TIME_FOR_CLUSTER_READY = 600

def get_node_config(retries = 10, delay = 30, **kwargs):
    @aretry(retry=retries, delay=delay, period = 15)
    def get_node_config_retries(**kwargs):
        config = AviConfig.get_instance()
        mode = config.get_mode()
        rsp = None
        try:
            st, rsp = get('cluster', check_status_code = False)
        except Exception as ex:
            fail("get_node_config: sdk-exception %s" % str(ex))
        logger.info('get_node_config: Got cluster nodes %s' % str(rsp))
        if re.search('Authentication credentials were not provided.', str(rsp)):
            fail('Controller %s is not running basic auth!', force = True)
        if re.search('Invalid username', str(rsp)):
            logger.info('get_node_config: invalid username/password admin/%s.Try admin/admin' % config.password)
            config.switch_mode(user = 'admin', password = 'admin')
            st, rsp = get('cluster', check_status_code = False)
            if st != 200:
                fail("Non 200 status code received %s %s" %(st, rsp))
        config.switch_mode(**mode)
        return rsp['nodes']
    return get_node_config_retries(**kwargs)

def verify_cluster_mode(result, **kwargs):
    controllers = infra_utils.get_vm_of_type('controller')
    for node in result:
        ip_addr = node['ip']['addr']
        ctrl_ips = [ctrl.ip for ctrl in controllers]
        if ip_addr not in ctrl_ips:
            logger.debug('Cluster is not up in desired mode(ip). Could not find %s in controller ips %s'  %(ip_addr, ctrl_ips))
            return True
    return False

def make_follower_ready_for_cluster(ctrl_vm, **kwargs):
    """
    Resets Controller password to admin/admin
    """
    config = AviConfig.get_instance()
    mode = config.get_mode()
    logger.debug("Current Default Mode %s" %mode)
    username = mode['user']
    current_password = mode['password']
    logger.info('Reset controller password for %s' % ctrl_vm.ip)
    try:
        config.switch_mode(password=ctrl_vm.password)
        session = create_session(ctrl_vm)
        config.switch_mode(session=session)
        # REVIEW password should be original default password
        reset_admin_user(username = username, password='admin', old_password=ctrl_vm.password, **kwargs)
    except Exception as e:
        logger.debug("Trying with admin/admin")
        config.switch_mode(password='admin')
        session = create_session(ctrl_vm)
        config.switch_mode(session=session)
        # REVIEW password shoulde original default password
        reset_admin_user(username = username, password='admin', old_password='admin', **kwargs)
    config.switch_mode(session=None, password=current_password)

def wait_until_n_cluster_nodes_ready(n=0, wait_time=MAX_TIME_FOR_CLUSTER_READY, removed_vm=None, **kwargs):
    if n==0:
        n = len(infra_utils.get_vm_of_type('controller'))
    logger.info('Wait until n cluster nodes are ready [n=%s]' % str(n))
    if not isinstance(removed_vm, list):
        removed_vm = [removed_vm]
    if n > 3:
        # In case the tb file has > 3 controllers defined.
        n = 3
    prev_choice = []
    config = AviConfig.get_instance()
    @aretry(retry=40, delay=30, maxtime=wait_time)
    def wait_until_n_cluster_nodes_ready_inner():
        rsp = None
        try:
            st, rsp = get('cluster/runtime')
        except Exception as ex:
            fail('Cluster api runtime exception: %s' % ex)
        if rsp and st == 200:
            node_states = rsp.get('node_states', [])
            cluster_state = rsp.get('cluster_state', {})
            cl_state = cluster_state.get('state', 'unknown')
            up_nodes = 0
            for node in node_states:
                if node.get('state') == 'CLUSTER_ACTIVE':
                    up_nodes += 1
            if (up_nodes != n):
                logger.debug('Cluster (status:%s) expects %d active nodes '
                             'but contains %d active nodes'
                             % (cl_state, n, up_nodes))
            elif (n == 1 and cl_state == 'CLUSTER_UP_NO_HA'):
                logger.info('Cluster is ready! Cluster state is %s' %
                            cluster_state)
                return
            elif (n == 2 and cl_state == 'CLUSTER_UP_HA_COMPROMISED'):
                logger.info('Cluster is ready! Cluster state is %s' %
                            cluster_state)
                return
            elif (n == 3 and cl_state == 'CLUSTER_UP_HA_ACTIVE'):
                logger.info('Cluster is ready! Cluster state is %s' %
                            cluster_state)
                return
        fail('Cluster runtime response not as expected %s' %
                (rsp if rsp else 'None'))

    wait_until_n_cluster_nodes_ready_inner()

def configure_cluster(wait_time=600, **kwargs):
    ignore_follower_reset = kwargs.pop('ignore_follower_reset', False)
    logger.debug("::ignore_follower_reset:: %s" %ignore_follower_reset)
    nodes = []
    controllers = infra_utils.get_vm_of_type('controller')
    ip_list = [vm.ip for vm in controllers]
    leader_ip = ip_list[0]
    ctrl_vm = None
    for vm in controllers:
        if vm.ip == leader_ip:
            ctrl_vm = vm
    for vm in controllers:
        nodes.append({'ip': {'addr': vm.ip, 'type': 'V4'},
                      'name': vm.ip})
        if vm.ip != ctrl_vm.ip and not ignore_follower_reset:
            make_follower_ready_for_cluster(vm, **kwargs)
    cluster_obj = {'name': DEFAULT_CLUSTER_NAME,
                   'nodes': nodes}
    logger.info("configure_cluster with nodes %s" % (nodes))
    st, rsp = put('cluster', data=json.dumps(cluster_obj))
    wait_until_n_cluster_nodes_ready(
        len(controllers), wait_time=wait_time, **kwargs)


def setup_cluster(**kwargs):
    # To skip setup cluster if controlelr is not present
    controllers = infra_utils.get_vm_of_type('controller')
    ip_list = [vm.ip for vm in controllers]
    if '' in ip_list:
        logger.info("Got Controller ip: %s" % ip_list)
        logger.info("Controlle ip address are None, assuming controllers are not present")
        return

    # Skip resetting follower nodes if already in factory default mode
    ignore_follower_reset = kwargs.pop('ignore_follower_reset', False)
    config_cluster = False
    if len(infra_utils.get_vm_of_type('controller')) == 3:
        result = get_node_config(**kwargs)
        if len(result) != 3:
            config_cluster = True
            if not ignore_follower_reset:
                ignore_follower_reset = False
        elif verify_cluster_mode(result, **kwargs):
            config_cluster = True
            ignore_follower_reset = True
        if config_cluster:
            logger.info('Found 3 controllers, cluster them together')
            configure_cluster(wait_time=1200, ignore_follower_reset = ignore_follower_reset, **kwargs)

def configure_cluster_vip(ipaddr):
    st, rsp = get('cluster')
    virtual_ip = {"addr" : ipaddr, "type" : 1}
    rsp['virtual_ip'] = {"addr" : ipaddr, "type" : 1}
    st, rsp = put('cluster', data=json.dumps(rsp))

def remove_cluster_vip():
    st, rsp = get('cluster')
    rsp.pop('virtual_ip')
    st, rsp = put('cluster', data=json.dumps(rsp))


