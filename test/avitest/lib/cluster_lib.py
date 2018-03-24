import random
import os
import yaml
import re
import avi_objects.cluster as cluster
import avi_objects.logger_utils as logger_utils
import avi_objects.rest as rest
import avi_objects.infra_utils as infra_utils
import avi_objects.cluster as cluster

from avi_objects.infra_imports import *
from avi_objects.logger import logger
from avi_objects.suite_vars import suite_vars
from avi_objects.avi_config import AviConfig
from avi_objects.logger import FailError

RESMGR_COLDSTART_STATUS_URL = '/placement/globals'
SERVICES_CONF_PATH = '/opt/avi/python/bin/cluster_mgr/services.conf'
PROC_SUPERVISOR_PORT = 5005
MAX_TIME_FOR_CLUSTER_READY = 600


def get_cluster_master_vm(down_vm=None, **kwargs):
    controller_vms = infra_utils.get_vm_of_type('controller')
    if not len(controller_vms):
        # No controllers defined in the testbed file, just return.
        return
    for vm in controller_vms:
        if vm == down_vm:
            continue
        role = get_node_role(vm.ip, **kwargs)
        if role == 'CLUSTER_LEADER':
            return vm
    fail('ClusterError: Could not find the cluster master')

def get_node_role(ip, **kwargs):
    logger.debug('get_node_role for ip %s' % ip)

    nodes = []
    nodes = cluster.get_node_config(**kwargs)
    nodes_by_ip = {}
    # AV-18689 this workaround is for the mesos AWS testbed,
    # where the single cluster node has internal ip not matching the vm.ip
    if len(nodes) == 1:
        nodes_by_ip[ip] = nodes[0]
    else:
        for node in nodes:
            nodes_by_ip[node['ip']['addr']] = node
    @aretry(retry=10, delay=5, period = 5)
    def get_cluster_runtime():
        code, rsp = get('cluster', path='runtime')
        return rsp
    rsp = get_cluster_runtime()
    try:
        node_runtimes = rsp['node_states']
    except:
        logger.info('Error getting the cluster runtime. Got %s from the API' %
                    rsp)
        fail('Error getting the cluster runtime. Got %s from '
                           'the API' % rsp)

    if len(nodes_by_ip) != len(node_runtimes):
        logger.info('There are %d configured nodes, but %d active nodes '
                    'in the cluster runtime.' %
                    (len(nodes_by_ip), len(node_runtimes)))
        fail('There are %d configured nodes, but %d active '
                           'nodes in the cluster runtime.' %
                           (len(nodes_by_ip), len(node_runtimes)))

    for node in node_runtimes:
        if (node['name'] == nodes_by_ip[ip]['name'] or
                node['name'] == nodes_by_ip[ip]['vm_uuid']):
            logger.info('role for %s is %s' % (ip, node['role']))
            return node['role']

    fail('get_node_role: Could not find an active node with name '
                       '%s, so could not get its role' % ip)

def wait_until_res_mgr_coldstart_complete(timeout=500):#increased this timeout as it is taking longer if there are disconnected SEs
    """ Blocks until the res_mgr cold/warmstart is complete """
    sleep_time = 10
    timeout = int(timeout)
    retries = timeout / sleep_time
    @logger_utils.aretry(retry = retries, delay = sleep_time)
    def wait_until_res_mgr_coldstart_complete_inner():
        status_obj = None
        #try:
        status_code,status_obj = get(RESMGR_COLDSTART_STATUS_URL)
        #except Exception as e:
        #    logger_utils.fail("Exception Received %s" %e)
        if status_obj and status_obj['cold_start_in_progress'] is False:
            return
        else:
            logger_utils.fail('the coldstart in res_mgr is not in correct state= %s' %status_obj)
    return wait_until_res_mgr_coldstart_complete_inner()

def wait_until_cluster_ready(detailed_state="", timeout=MAX_TIME_FOR_CLUSTER_READY, *kwargs):
    """ Blocks until the controller cluster state is up or if a
    detailed_state was passed, then returns when the cluster reaches that
    state """
    rsp = None
    @aretry(retry=120, delay=5, maxtime=timeout)
    def retry_wait():
        rsp = None
        try:
            status_code, rsp = get('cluster', path='runtime')
        except Exception as ex:
            fail('Cluster api runtime exception: %s' % ex)
        if rsp:
            cluster_state = rsp.get('cluster_state', {})
            if (detailed_state and
                detailed_state in cluster_state.get('reason')):
                return True
            elif (not detailed_state and 'CLUSTER_UP' in cluster_state.get('state', '')):
                logger.info('Controller cluster is ready. It is in %s state' % cluster_state)
                return True
            elif ('CLUSTER_UP' in cluster_state.get('state', '') and
                not 'HA_NOT_READY' in cluster_state.get('state', '')):
                return True
            logger.debug('cluster state[%s]: %s' % (rsp['node_states'], cluster_state.get('state', 'unknown')))
        else:
            fail('Cluster api runtime exception: no response.')
    retry_wait()

def get_controller_process_names(role='CLUSTER_LEADER', exclude_tasks=True,
                                 controller_vm=None, **kwargs):
    """
    Returns a list of process names
    :param role:
    :param exclude_tasks:
    :param controller_vm:
    :param kwargs:
    :return:
    """


    if controller_vm:
        ctrl_vm = controller_vm
    else:
        ctrl_vm = infra_utils.get_vm_of_type('controller')[0]
    conf_string = ctrl_vm.read_file(SERVICES_CONF_PATH)
    conf = yaml.load(conf_string)
    proc_names = []
    for svc in conf['services']:
        if exclude_tasks and svc.get('task', False) is True:
            # don't check that task services are up since they run once and
            # exit
            continue
        svc_procs = [proc
                     if ':' not in proc
                     else '%s INSTANCE=%s' % (proc.split(':', 1)[0],
                                              proc.split(':', 1)[1])
                     for proc in svc['processes']]
        if role == 'CLUSTER_LEADER':
            proc_names += svc_procs
        elif role == 'CLUSTER_FOLLOWER' and 'slave' in svc['roles']:
            proc_names += svc_procs
    return sorted(proc_names)


def get_controller_processes(controller, retry=5, role=None, **kwargs):
    """
    Returns a list of pids for all controller processes
    :param controller:
    :param retry:
    :param role:
    :param kwargs:
    :return:
    """

    if role is None:
        role = get_node_role(controller.ip)

    _ignore = ['redis-server', 'setup_system', 'nginx', 'snmpd', 'aviportal']
    if role == 'CLUSTER_LEADER':
        _add = ['zookeeper', 'log_core_manager', 'vi-mgr',
                'redis-server INSTANCE=5001']
    else:
        _add = ['zookeeper', 'log_core_manager', 'redis-server INSTANCE=5001']
    proc_names = get_controller_process_names(role, controller_vm=controller, **kwargs)
    proc_names = [proc for proc in proc_names if proc not in _ignore]
    proc_names.extend(_add)
    if role != 'CLUSTER_LEADER':
        proc_names.remove('redis-server INSTANCE=5001')

    procs = {}
    command_str = []
    for proc in proc_names:
        try:
            if ':' in proc:
                service, instance = proc.split(':')
                command_str.append('sudo status %s INSTANCE=%s;' % (service, instance))
            else:
                command_str.append('sudo status %s;' % proc)
        except Exception as e:
            logger_utils.fail("Unexpected error:", e.message)

    retries = 5
    timeout = 300
    elapsed_time = 0
    resp = ''
    while retries:
        try:
            if rest.get_cloud_type() == 'baremetal':
                resp = controller.execute_on_docker_container(''.join(command_str))
                resp = resp[controller.ip].splitlines()
            elif rest.get_cloud_type() == 'gcp':
                resp = controller.execute_on_docker_container(''.join(command_str))
                resp = resp[controller.vm_public_ip].splitlines()
            else:
                resp = controller.execute_command(''.join(command_str))
        except Exception as e:
            # Controller might have rebooted and we are reporting a reboot failure
            # so just reset all the processes and core links for VM
            logger_utils.asleep(delay=60)
            controller.processes = []
            controller.latest_core = None
            logger_utils.error(
                'Failed to connect to Controller: %s, %s' % (controller.ip, e))
        except Exception as ie:
            # Not a valid job name?
            logger_utils.fail('Process not running on %s. Error: %s' %
                                       (controller.ip, ie.message))
        except Exception as e:
            logger.info('other ex, retry: %s' % e)
            retries -= 1
            logger_utils.asleep(delay=10)
            continue
        crashed_processes = [ proc for proc in resp if 'stop/waiting' in proc ]
        if len(crashed_processes)>0 and elapsed_time<timeout:
            logger_utils.asleep(delay=10)
            elapsed_time += 10
            continue
        break

    # Response array contains blank items which need to be removed
    resp = [value for value in resp if value != '']

    # Removed Process "\tpost-start process <pid>" from response\n
    # Pid values are captured by index but as post-start process gets introduced
    # in response it changes the pid index and hence it is removed
    for process_resp in resp:
        if 'post-start process' in process_resp:
            resp.remove(process_resp)

    current_proc = None
    try:
        for index, proc in enumerate(proc_names):
            current_proc = proc
            proc_pid = ''
            if proc in ['postgresql', 'postgresql_metrics']:
                if rest.get_cloud_type() == 'gcp':
                    out = controller.execute_on_docker_container("cat '/var/run/%s.pid'" % proc)
                    out = out[controller.vm_public_ip].splitlines()
                else:
                    out = (controller.execute_command_fab("cat '/var/run/%s.pid'" % proc))
                pid = str(out[0]) if len(out) > 0 else None
                if not pid or 'no such file' in pid.lower():
                    pass
                else:
                    proc_pid = pid
            procname = proc.split()[0]
            procresp = ''
            if 'instance' in proc.lower():
                instance_id = proc.split('=')[1]
                logger.info('Procname: %s   InstanceId: %s' % (procname, instance_id))
                for value in resp:
                    if procname in value and '(%s)' % instance_id in value:
                        procresp = value
                        break
            else:
                for value in resp:
                    resp_procname = value.split()[0]
                    if proc in ['postgresql', 'postgresql_metrics']:
                        procresp = proc_pid
                    elif procname == resp_procname:
                        procresp = value
                        break
            logger.info('Proc: %s  RespProc: %s' % (proc, procresp))
            match = re.search('(\d+$)', procresp)
            if match:
                procs[proc] = (int(match.group(1)))
            else:
                raise IndexError

    except Exception as e:
        # If fails to parse output, then match.group raises attribute error
        # In case of crash, sleep for 5 secs to allow process to restart
        # avoiding cascading failures.
        if controller.processes:
            logger_utils.asleep(delay=5)
            retry -= 1
            if retry < 1:
                del controller.processes[:]
            return get_controller_processes(controller, retry=retry, role=role, **kwargs)
        else:
            # The case where controller process not running at all!
            logger_utils.fail(
                'process: %s is not running on controller %s!' % (
                    current_proc, controller.ip))
    except Exception as ie:
        # Job not running or error while capturing output
        logger_utils.fail('Process %s not running on %s.' %
                                   (current_proc, controller.ip))

    logger.info('get_controller_processes: %s' % procs)
    return procs


def get_node_role(ip, **kwargs):
    """

    :param ip:
    :param kwargs:
    :return:
    """

    logger.debug('get_node_role for ip %s' % ip)
    if rest.get_cloud_type() == 'gcp':
        ctrl_vm = infra_utils.get_vm_of_type('controller')[0]
        vm_public_ip = ctrl_vm.vm_public_ip
    else:
        vm_public_ip = ip
    if not suite_vars.dns:
        vm_public_ip = ip
    else:
        ctrl_vms = infra_utils.get_vm_of_type('controller')
        for vm in ctrl_vms:
            if ip == vm.ip:
                vm_public_ip = vm.name
                ip = vm.name
                break
    nodes = []
    nodes = cluster.get_node_config(vm_public_ip, **kwargs)
    nodes_by_ip = {}
    # AV-18689 this workaround is for the mesos AWS testbed,
    # where the single cluster node has internal ip not matching the vm.ip
    if len(nodes) == 1:
        nodes_by_ip[vm_public_ip] = nodes[0]
    else:
        for x in nodes:
            nodes_by_ip[x['ip']['addr']] = x
    for _ in xrange(10):
        path = 'cluster/runtime'
        try:
            status_code, rsp = rest.get(path)
            break
        except:
            logger.info('Could not get cluster runtime')
            logger_utils.asleep(delay=5)
    try:
        node_runtimes = rsp['node_states']
    except:
        logger.info('Error getting the cluster runtime. Got %s from the API' %
                    rsp.text)
        logger_utils.fail('Error getting the cluster runtime. Got %s from '
                           'the API' % rsp.text)

    if len(nodes_by_ip) != len(node_runtimes):
        logger.info('There are %d configured nodes, but %d active nodes '
                    'in the cluster runtime.' %
                    (len(nodes_by_ip), len(node_runtimes)))
        logger.info('Waiting for 5 min to try and fix things...')
        logger_utils.asleep(delay=60 * 5)
        logger_utils.fail('There are %d configured nodes, but %d active '
                           'nodes in the cluster runtime.' %
                           (len(nodes_by_ip), len(node_runtimes)))

    for node in node_runtimes:
        try:
            if (node['name'] == nodes_by_ip[ip]['name'] or
                    node['name'] == nodes_by_ip[ip]['vm_uuid']):
                logger.info('role for %s is %s' % (ip, node['role']))
                return node['role']
        except Exception as e:
            # Sometime get_node_config on dns name will returns nodes with ip when set to default
            # And so the nodes_by_ip dict will have ip as keys instead of dns names
            # And vice versa
            if suite_vars.dns:
                ctrl_vms = infra_utils.get_vm_of_type('controller')
                for vm in ctrl_vms:
                    if ip == vm.ip:
                        ip = vm.name
                        break
                    elif ip == vm.name:
                         ip = vm.ip
                         break
            if (node['name'] == nodes_by_ip[ip]['name'] or
                    node['name'] == nodes_by_ip[ip]['vm_uuid']):
                logger.info('role for %s is %s' % (ip, node['role']))
                return node['role']

    logger_utils.fail('get_node_role: Could not find an active node with name '
                       '%s, so could not get its role' % ip)


def convert_controller_ip_to_ipport(ctlr_ip, **kwargs):
    """

    :param ctlr_ip:
    :param kwargs:
    :return:
    """
    import lib.controller_lib as controller_lib
    port = kwargs.get('port_override')
    if not port:
        port = controller_lib.get_controller_port(**kwargs)
    return ctlr_ip + ':' + str(port)


def reconnect_to_vm(vm, is_controller=True):
    vm.child = vm.connect()
    vm.execute_command('ls')
    vm.processes.clear()
    if is_controller:
        vm.processes = get_controller_processes(vm)


def update_processes_for_all_controllers():
    for vm in infra_utils.get_vm_of_type('controller'):
        reconnect_to_vm(vm)
        vm.processes.clear()
        vm.processes = get_controller_processes(vm)

def reboot_leader():
    ctrl_vm = get_cluster_master_vm()
    rsp = ctrl_vm.execute_command('reboot')

def warm_restart_cluster(wait=True):
    ctrl_vm = get_cluster_master_vm()

    path = os.path.join('http://localhost:%d' % (PROC_SUPERVISOR_PORT),
                        'service_event?status=warm-restart')
    cmd_str = 'curl %s' % path
    rsp = ctrl_vm.execute_command(cmd_str)
    if wait is True:
        logger_utils.asleep(delay=20)
        wait_until_cluster_ready()
        wait_until_res_mgr_coldstart_complete()
        #update_processes_for_all_controllers()
    return str(rsp[0])


def stop_process_supervisor(vm):
    vm.execute_command('stop process-supervisor')


def start_process_supervisor(vm):
    vm.execute_command('start process-supervisor')


def get_random_slave_vm():
    """ Returns a list of VMs with current role of slave """
    slave_vms = []
    for vm in infra_utils.get_vm_of_type('controller'):
        if suite_vars.dns == False:
            vm_ip = vm.ip
        else:
            vm_ip = vm.name
        role = get_node_role(vm_ip)
        if role == 'CLUSTER_FOLLOWER':
            slave_vms.append(vm)
        logger.debug('Role of vm %s is %s' % (vm_ip, role))
    if not slave_vms:
        return None
    return random.choice(slave_vms)


def add_delay_to_controller_upstart_job_start_on_one_node(ctrl_vm, job_name, delay,
                                              num_controllers=1):
    """ Adds a delay of delay sec. to the starting time for an upstart job on
    the controllers. """

    #ctrl_vms = random.sample(config.cloud.get_vm_of_type('controller'),
    #                         num_controllers)
    #for vm in ctrl_vms:
        #time_delay = random.randint(1, int(max_delay))
    logger.info('Adding a start delay of %s sec. to upstart job %s on '
                'controller with ip %s' % (delay, job_name, ctrl_vm.ip))
    job_name = job_name.split('INSTANCE', 1)[0].strip()
    path = os.path.join('/etc/init', '%s.conf' % job_name)
    ctrl_vm.execute_command("sed -i 's/^pre-start script$/pre-start script\\n    sleep %s  #testing"
                       "/' %s" % (delay, path), noerr=False)


def del_delay_from_controller_upstart_job_start_on_one_node(ctrl_vm, job_name, delay,
                                              num_controllers=3):
    """ Adds a delay of time sec. to the starting time for an upstart job on
    the controllers. """
    #ctrl_vms = random.sample(config.cloud.get_vm_of_type('controller'),
    #                         num_controllers)
    #for vm in ctrl_vms:
        #time_delay = random.randint(1, int(max_delay))
    logger.info('Deleting the start delay of %s sec. to upstart job %s on '
                'controller with ip %s' % (delay, job_name, ctrl_vm.ip))
    job_name = job_name.split('INSTANCE', 1)[0].strip()
    path = os.path.join('/etc/init', '%s.conf' % job_name)
    ctrl_vm.execute_command("sed -i '/#testing/d' %s" % path, noerr=False)


def update_processes_for_all_controllers_and_ses():
    update_processes_for_all_controllers()
    update_processes_for_all_ses()


def update_processes_for_all_ses():
    import lib.se_lib as se_lib
    se_vms = infra_utils.get_vm_of_type('se')
    for vm in se_vms:
        reconnect_to_vm(vm, False)
        vm.processes.clear()
        vm.processes = se_lib.get_se_processes(vm)


def disconnect_zk(vm, duration):
    """ Blocks the port used by zookeeper. Use duration = -1 to indefinitely
    block the port """
    vm.block_port_range(5000, 5097)
    duration = float(duration)
    if duration > 0:
        logger_utils.asleep(delay=duration)
        vm.clear_iptables()
        logger_utils.asleep(delay=120)
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        update_processes_for_all_controllers_and_ses()


def up_network_interface(vm, network):
    """

    :param vm:
    :param network:
    :return:
    """
    vm.execute_command('ifconfig %s up' % network)
    vm.execute_command('ifup %s' % network)


def down_network_interface(vm, network):
    """

    :param vm:
    :param network:
    :return:
    """
    vm.execute_command('ifconfig %s down' % network)
    vm.execute_command('ifdown %s' % network)


def disable_network_manager(vm):
    vm.execute_command('stop network-manager')


def add_subnet_to_network(name, **kwargs):
    status_code, json_data = rest.get('network', name=name)
    subnet_ip=kwargs.get('subnet_ip',None)
    subnet_mask=kwargs.get('subnet_mask',None)
    force = kwargs.get('force', False)
    add_configured_subnets = {'prefix': {'mask': subnet_mask, 'ip_addr': {'type': 0, 'addr': subnet_ip}}}
    if 'configured_subnets' in json_data.keys():
        json_data['configured_subnets'].append(add_configured_subnets)
    else:
        json_data['configured_subnets'] = [add_configured_subnets]
    if force:
        rest.put('network', name=json_data['name'], data=json_data, force = force)
    else:
        rest.put('network', name=json_data['name'], data=json_data)
