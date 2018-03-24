import json
import random
import logging
import collections
import traceback
import requests
from os import path
from datetime import datetime

import avi_objects.cleanup as cleanup
import avi_objects.cluster as cluster
import avi_objects.infra_utils as infra_utils
import avi_objects.logger_utils as logger_utils
import avi_objects.rest as rest
import lib.cluster_lib as cluster_lib
import lib.json_utils as json_utils
import lib.se_lib as se_lib
import lib.vs_lib as vs_lib
import tools.resource_deplete as r_dep
from avi_objects.logger import logger
from avi_objects.suite_vars import SuiteVars
from lib.object_inventory import get_inventory_config
from avi_objects.logger import FailError

CLUSTER_UPGRADE_STATUS_URL = '/cluster/upgrade/status'

def common_cleanup_upgradesuite():
    """
    Collection of subroutines that will run
    at the end of all tests. Should have non case
    specific routines.
    :return:
    """

    ctlr_vms = infra_utils.get_vm_of_type('controller')
    for each_vm in ctlr_vms:
        logger.debug('UnhogDisk done on %s' % each_vm.ip) \
            if r_dep.unhog_disk(each_vm, logger, dire='/var/lib/avi/upgrade_pkgs') \
            else logger.debug('UnhogDisk failed on %s' % each_vm.ip)
        each_vm.clear_iptables()
        logger.debug('Clear Iptables Done...')
        r_dep.quash_spike_cpu_on_vm(each_vm)
        logger.debug('Quash CPU Spike Done...')
        r_dep.quash_spike_disk_io_on_vm(each_vm)
        logger.debug('Quash Disk I/O Spike Done...')
    clear_upgrade_crumbs()
    # cluster_lib.update_processes_for_all_controllers_and_ses()
    # logger.debug('Update processes for Controllers and SEs Done...')


def clear_upgrade_crumbs():
    """
    Deletes files left around by failed upgrades
    :return: None
    """

    from avi.upgrade.upgrade_utils import (
        UPGRADE_ROLLEDBACK_FILE_PATH, UPGRADE_REBOOTED_FILE_PATH,
        SE_UPGRADE_IN_PROGRESS_FILE, DOCKER_UPGRADE_REBOOTED_FILE_PATH,
        DOCKER_UPGRADE_ROLLEDBACK_FILE_PATH)
    for vm in infra_utils.get_vm_of_type('controller'):
        vm.execute_command('rm -f %s %s %s %s %s' %
                           (UPGRADE_ROLLEDBACK_FILE_PATH,
                            UPGRADE_REBOOTED_FILE_PATH,
                            DOCKER_UPGRADE_REBOOTED_FILE_PATH,
                            DOCKER_UPGRADE_ROLLEDBACK_FILE_PATH,
                            SE_UPGRADE_IN_PROGRESS_FILE))


def check_vs_create_traffic_delete(ignore_error=False):
    try:
        infra_utils.create_config("vs_dummy.json")
    except Exception as e:
        logger.debug('error create vs: %s' % str(e))
        logger_utils.fail('error creating dummy vs')
    try:
        vs_lib.vs_should_be_assigned('vs-dummy', retry_timeout=30)
        http_traffic_lib.get_pages_in_loop('vs-dummy', 9000, '/', 10)
        http_traffic_lib.verify_traffic_can_flow('vs-dummy', 9000, 10)
    except Exception as e:
        logger.debug('error traffic: %s' % str(e))
    try:
        vs_lib.delete_vs('vs-dummy')
    except Exception as e:
        logger.debug('error delete vs: %s' % str(e))
        logger_utils.fail('error deleting dummy vs')


def get_upgrade_history():
    status_code, upgrade_history = rest.get('cluster/upgrade/history')
    if 'upgrade_events' in upgrade_history:
        logger.debug('# of upgrade events in history = %d' % len(upgrade_history['upgrade_events']))
    return upgrade_history


def clear_upgrade_status():

    vm = random.choice(infra_utils.get_vm_of_type('controller'))
    vm.execute_command('python -c "from avi.util.zk_utils import get_zk_client;'
                       'zk=get_zk_client();zk.delete(\'/upgrade\',recursive=True)"')


def copy_pkg_on_controller(pkg_path, pkg_file, controller):
    """ Copy file to controller """
    controller.scp_file(pkg_path, '/home/admin/%s' % pkg_file)
    controller.execute_command('mv /home/admin/%s '
                               '/var/lib/avi/upgrade_pkgs/%s' %
                               (pkg_file, pkg_file))


def wait_until_upgrade_starts(rollback=False):
    @logger_utils.aretry(retry=50, delay=6)
    def retry_action():
        try:
            status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL, check_status_code=True)
        except Exception as e:
            logger_utils.fail(e.message)
        if status_obj.get('controller_state', {}).get('in_progress'):
            if rollback and not status_obj.get('controller_state', {}).get('rollback'):
                logger_utils.error('Controller upgrade in_progress, but rollback not set')
            logger.info("upgrade in_progress")
            return True

    ret = retry_action()
    if not ret:
        logger_utils.fail('Upgrade did not start within 5 min')


def wait_until_upgrade_rebooted(interval=30):
    logger_utils.asleep(delay=30)
    gap = int(interval)
    for _ in xrange(100):
        try:
            if did_upgrade_reboot_controllers():
                logger.info('upgrade_reboot_controllers done')
                return True
        except Exception:
            pass
        logger_utils.asleep(delay=gap)
    logger_utils.fail('Upgrade did not reboot the controllers within %d seconds' % (100 * gap))


def did_upgrade_reboot_controllers():
    status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL)
    #status_obj = get_upgrade_status()
    for task in status_obj.get('controller_state', {}).get('tasks_completed'):
        if task['task'] == 'WAIT_FOR_ALL_CONTROLLER_NODES_ONLINE':
            return True
    logger.info('waiting for WAIT_FOR_ALL_CONTROLLER_NODES_ONLINE')
    return False


def wait_until_upgrade_aborted(interval=30):
    gap = int(interval)
    for _ in xrange(60):
        try:
            if did_upgrade_abort():
                return True
        except Exception:
            pass
        logger_utils.asleep(delay=gap)
    logger_utils.fail('Upgrade not aborted even after %d seconds' % (60 * gap))


def did_upgrade_abort():
    #status_obj = get_upgrade_status()
    status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL)
    controller_state = status_obj.get('controller_state', {})
    if controller_state.get('state') == 'UPGRADE_ABORTED':
        logger.info('upgrade aborted')
        return True
    return False


def verify_upgrade_aborted():
    # reset_session()
    #status_obj = get_upgrade_status()
    status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL)
    controller_state = status_obj.get('controller_state', {})
    if controller_state.get('state') != 'UPGRADE_ABORTED':
        logger_utils.fail('upgrade state %s != UPGRADE_ABORTED' % controller_state.get('state'))
    logger.info('UPGRADE_ABORTED')


def upgrade_system(pkg_path=None, wait=True, inject_error=None, version=None, docker=False):
    clear_upgrade_status()
    if rest.get_cloud_type() == 'baremetal' or docker:
        pkg_name = 'controller_docker.tgz'
    else:
        pkg_name = 'controller.pkg'

    if inject_error == 'use_se_pkg':
        if rest.get_cloud_type() == 'baremetal':
            pkg_name = 'se_docker.tgz'
        else:
            pkg_name = 'se.pkg'

    if not pkg_path or pkg_path == 'None':
        if version:
            # pkg_dir = '/mnt/builds/%s/last-good/' % version
            pkg_dir = version
        else:
            pkg_dir = SuiteVars.workspace + '/build'
        pkg_path = path.join(pkg_dir, pkg_name)
    else:
        pkg_path = path.join(pkg_path, pkg_name)

    pkg_file = pkg_path.split('/')[-1]

    leader_vm = cluster_lib.get_cluster_master_vm()
    follower_vm = cluster_lib.get_random_slave_vm()
    session = rest.create_session(controller=leader_vm)
    infra_utils.switch_mode(session=session) 
    copy_pkg_on_controller(pkg_path, pkg_file, leader_vm)

    ##############################################
    #  [inject error] setup before upgrade begins
    ##############################################

    #  [inject error] start IO spike with dd
    if inject_error == 'io_spike_on_leader':
        r_dep.spike_disk_io_on_vm(leader_vm)
        logger.debug('DISK IO spiked on leader')
    elif inject_error == 'io_spike_on_follower':
        r_dep.spike_disk_io_on_vm(follower_vm)
        logger.debug('DISK IO spiked on follower')
    # [inject error] start CPU spike
    elif inject_error == 'cpu_spike_on_leader':
        r_dep.spike_cpu_on_vm(leader_vm)
        logger.debug('CPU spiked on leader')
    elif inject_error == 'cpu_spike_on_follower':
        r_dep.spike_cpu_on_vm(follower_vm)
        logger.debug('CPU spiked on follower')
    # [inject error] corrupt pkg
    elif inject_error == 'corrupt_pkg':
        ''' After copy_pkg_on_controller the package is copied into /var/lib/avi/upgrade_pkgs/,
         we corrupt the .pkg file here and then check for errors '''
        cmd = 'sudo dd if=/dev/zero of=/var/lib/avi/upgrade_pkgs/%s bs=1 count=1 seek=30 obs=1M conv=notrunc' % pkg_file
        leader_vm.execute_command(cmd)
        logger.debug('corrupted pkg on controller')

    # CONTROLLER DISK FULL INITIAL SETUP
    if inject_error == 'ctrl_disk_full_error_on_leader':
        """
        EMULATE DISKFULL SCENERIO ON A FOLLOWER; HARD CODING THE DIR AS THIS PARTATION NEEDS TO BE FULL
        """
        r_dep.hog_disk(follower_vm, logger, dire='/var/lib/avi/upgrade_pkgs')

    # POWEROFF VICTIM SE
    if inject_error == 'se_off_throughout':
        victim_se = infra_utils.get_vm_of_type('se')[0]
        config.cloud.powerOffVM(victim_se.name)

    #####################################
    #  start UPGRADE
    #####################################
    logger.info("Leader: %s" % leader_vm.ip)
    if follower_vm:
        logger.info("Follower: %s" % (follower_vm.ip))
    logger.info("start upgrade")
    status_code, resp = rest.post('cluster/upgrade', data={
        'force': True, 
        'image_path': 'controller://upgrade_pkgs/%s' % pkg_name
    }, timeout=1200)
    logger_utils.asleep(delay=60)

    # errors with post failing
    if inject_error == 'use_se_pkg' or inject_error == 'corrupt_pkg':
        logger.info('upgrade resp error:%r. resp:%s' % (resp.get('error'), resp))
        if not resp.get('error', {}):
            logger_utils.fail('Expected upgrade error, but got none')
        return

    if resp.get('error', {}):
        logger.info('upgrade resp error:%r. resp:%s' % (resp.get('error'), resp))
        logger_utils.fail('upgrade post error %s' % resp)

    wait_until_upgrade_starts()

    #######################################
    #  [inject error] after upgrade starts
    #######################################
    logger.info("inject errors if needed")
    # IO spike
    if inject_error is 'io_spike_on_leader':
        wait_until_upgrade_rebooted()
        r_dep.spike_disk_io_on_vm(leader_vm)
        logger.debug('DISK IO spiked on leader after reboot')
        # vs_create_should_fail()
    elif inject_error is 'io_spike_on_follower':
        wait_until_upgrade_rebooted()
        r_dep.spike_disk_io_on_vm(follower_vm)
        logger.debug('DISK IO spiked on follower after reboot')
    # CPU spike
    elif inject_error is 'cpu_spike_on_leader':
        wait_until_upgrade_rebooted()
        r_dep.spike_cpu_on_vm(leader_vm)
        logger.debug('CPU spiked on leader after reboot')
        # vs_create_should_fail()
    elif inject_error is 'cpu_spike_on_follower':
        wait_until_upgrade_rebooted()
        r_dep.spike_cpu_on_vm(follower_vm)
        logger.debug('CPU spiked on follower after reboot')
        # vs_create_should_fail()
    elif inject_error == 'delay_process_on_leader':
        wait_until_upgrade_rebooted()
        logger.info('upgrade rebooted, add delay of 960 sec to se-mgr upstart')
        # vs_create_should_fail()
        cluster_lib.add_delay_to_controller_upstart_job_start_on_one_node(leader_vm,
                                                              'se-mgr', 960,
                                                              len(infra_utils.get_vm_of_type('controller')))
        wait_until_upgrade_aborted()
        cluster_lib.del_delay_from_controller_upstart_job_start_on_one_node(leader_vm,
                                                                'se-mgr', 960,
                                                                len(infra_utils.get_vm_of_type('controller')))
        logger.info('wait until cluster ready')

        cluster_lib.wait_until_cluster_ready()
        logger.info('cluster ready')
        cluster.wait_until_n_cluster_nodes_ready(len(infra_utils.get_vm_of_type('controller')))
        logger.info('all cluster nodes ready')
        #cluster_lib.update_processes_for_all_controllers()
        # vs_create_should_fail()
        verify_upgrade_aborted()
        return
    elif inject_error == 'delay_process_on_follower':
        wait_until_upgrade_rebooted()
        logger.info('upgrade rebooted, add delay of 1260 sec to se-mgr upstart')
        # vs_create_should_fail()
        cluster_lib.add_delay_to_controller_upstart_job_start_on_one_node(follower_vm,
                                                              'se-mgr', 1260,
                                                              len(infra_utils.get_vm_of_type('controller')))
        wait_until_upgrade_aborted()
        cluster_lib.del_delay_from_controller_upstart_job_start_on_one_node(follower_vm,
                                                                'se-mgr', 1260,
                                                                len(infra_utils.get_vm_of_type('controller')))
        logger.info('wait until cluster ready')
        cluster_lib.wait_until_cluster_ready()
        logger.info('cluster ready')
        cluster.wait_until_n_cluster_nodes_ready(len(infra_utils.get_vm_of_type('controller')))
        logger.info('all cluster nodes ready')
        #cluster_lib.update_processes_for_all_controllers()
        # vs_create_should_fail()
        verify_upgrade_aborted()
        return
    elif inject_error == 'leader_reboot_at_copy':
        wait_until_controller_upgrade_goes_to_state('COPY_AND_VERIFY_IMAGE')
        leader_vm.execute_command('sudo reboot')
        # vs_create_should_fail()
        wait_until_upgrade_aborted()
        cluster_lib.wait_until_cluster_ready()
        logger.info('cluster ready')
        cluster.wait_until_n_cluster_nodes_ready(len(infra_utils.get_vm_of_type('controller')))
        logger.info('all cluster nodes ready')
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()
        return
    elif inject_error == 'follower_reboot_at_copy':
        wait_until_controller_upgrade_goes_to_state('COPY_AND_VERIFY_IMAGE')
        follower_vm.execute_command('sudo reboot')
        # vs_create_should_fail()
        wait_until_upgrade_aborted()
        cluster_lib.wait_until_cluster_ready()
        logger.info('cluster ready')
        cluster.wait_until_n_cluster_nodes_ready(len(infra_utils.get_vm_of_type('controller')))
        logger.info('all cluster nodes ready')
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()
        return
    elif inject_error == 'leader_reboot_at_migrate':
        wait_until_upgrade_rebooted()
        wait_until_controller_upgrade_goes_to_state('MIGRATE_CONFIG')
        leader_vm.execute_command('sudo reboot')
        wait_until_upgrade_aborted()
        cluster_lib.wait_until_cluster_ready()
        logger.info('cluster ready')
        cluster.wait_until_n_cluster_nodes_ready(len(infra_utils.get_vm_of_type('controller')))
        logger.info('all cluster nodes ready')
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()
        return
    elif inject_error == 'follower_reboot_at_migrate':
        wait_until_upgrade_rebooted()
        wait_until_controller_upgrade_goes_to_state('MIGRATE_CONFIG')
        follower_vm.execute_command('sudo reboot')
        wait_until_upgrade_aborted()
        cluster_lib.wait_until_cluster_ready()
        logger.info('cluster ready')
        cluster.wait_until_n_cluster_nodes_ready(len(infra_utils.get_vm_of_type('controller')))
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()
        return
    elif inject_error == 'all_rsrc_mon_hang':
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        signal_to_process_vm(leader_vm, 'avi-resmon', sig='SIGSTOP')
        logger_utils.asleep(delay=30)
    elif inject_error == 'se_reboot_during':
        victim_se = infra_utils.get_vm_of_type('se')[random.randint(0, len(infra_utils.get_vm_of_type('se')))]
        logger.info('Victim SE chosen: %s' % victim_se.ip)
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        victim_se.execute_command('sudo reboot')
        logger_utils.asleep(delay=120)
        if did_upgrade_abort():
            logger_utils.fail('Upgrade aborted when SE reboots before Controller Rebooted')
            return
        wait_until_controller_upgrade_goes_to_state('START_PRIMARY_CONTROLLER')
        victim_se.execute_command('sudo reboot')
        logger_utils.asleep(delay=120)
        if did_upgrade_abort():
            logger_utils.fail('Upgrade aborted when SE reboots after Controller Rebooted')
            return

    elif inject_error == 'block_n_reboot_se':
        victim_se = infra_utils.get_vm_of_type('se')[0]
        victim_se2 = infra_utils.get_vm_of_type('se')[1]
        logger.info('Victim SE chosen: %s' % victim_se.ip)
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        victim_se.execute_command('sudo reboot')
        victim_se2.execute_command('sudo reboot')
        leader_vm.execute_command('sudo iptables -A INPUT -s %s -j DROP' % victim_se.ip)
        logger_utils.asleep(delay=120)
        if did_upgrade_abort() == True:
            logger_utils.fail('Upgrade aborted when SE reboots before Controller Rebooted and doesnt connect')
            return
        wait_until_controller_upgrade_goes_to_state('START_PRIMARY_CONTROLLER')
        victim_se.execute_command('sudo reboot')
        leader_vm.execute_command('sudo iptables -A INPUT -s %s -j DROP' % victim_se.ip)
        logger_utils.asleep(delay=120)
        if did_upgrade_abort() == True:
            logger_utils.fail('Upgrade aborted when SE reboots AFTER Controller Rebooted and doesnt connect')
            return

            # Now wait till the upgrade runs to completion
        logger_utils.asleep(delay=1)
        wait_until_controller_upgrade_complete(timeout=3000)
        logger.info('Controller upgrade is complete')
        cluster_lib.wait_until_cluster_ready()
        wait_until_se_upgrade_complete(timeout=3000)
        logger.info('SE upgrade is complete')
        # Aviportal restarts after upgrade. If we check instantly, we might get
        # 502 from controller.
        logger_utils.asleep(delay=60)
        # Before running update_processes... need to remove the iptables
        # rules as if it is unable to connect to SE this subroutine is
        # bound to fail
        leader_vm.clear_iptables()
        #try:
        #    cluster_lib.update_processes_for_all_controllers_and_ses()
        #except Exception as e:
        #    logger.debug('Update Controller/SE processes Exception: %s' % str(e))
        #    logger_utils.asleep(delay=120)
        #    cluster_lib.update_processes_for_all_controllers_and_ses()
        return

    elif inject_error == 'follower_no_conn':
        wait_until_upgrade_rebooted()
        victim_controller = cluster_lib.get_random_slave_vm()
        leader_vm.execute_command('sudo iptables -A INPUT -s %s -j DROP' % victim_controller.ip)
        wait_until_upgrade_aborted()
        logger_utils.asleep(delay=15)  # Wait till the abort is well into the rollback
        leader_vm.clear_iptables()
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()
        return
    elif inject_error == 'leader_no_conn':
        wait_until_upgrade_rebooted()
        logger.info('wait_until_upgrade_rebooted')
        followers_arr = [vm for vm in infra_utils.get_vm_of_type('controller')
                         if vm.ip != leader_vm.ip]
        cluster_lib.wait_until_cluster_ready()
        for each in followers_arr:
            each.execute_command('sudo iptables -A INPUT -s %s -j DROP' % leader_vm.ip)
            logger.info('Putting iptables in %s to drop leader %s' % (each.ip, leader_vm.ip))
        wait_until_upgrade_aborted()
        logger.info('wait_until_upgrade_aborted  DROP')
        logger.info('Upgrade Aborted as expected, removing iptables from followers')
        for each in followers_arr:
            each.clear_iptables()
            logger.info('each.clear_iptables %s' % each.ip)
        leader_vm.clear_iptables()
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()
        return

    elif inject_error == 'leader_change_se_inprog':
        present_leader = leader_vm
        wait_until_upgrade_rebooted()
        wait_until_controller_upgrade_goes_to_state('COMMIT_UPGRADE')
        wait_until_se_goes_to_state('SE_IMAGE_UPGRADE')
        leader_vm.execute_command('sudo reboot')
        logger_utils.asleep(delay=10)  # Wait till the controller stops responding
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        wait_until_controller_upgrade_complete(timeout=3000)
        cluster_lib.wait_until_cluster_ready()
        wait_until_se_upgrade_complete(timeout=3000)
        logger.info('SE upgrade is complete')
        # Aviportal restarts after upgrade. If we check instantly, we might get
        # 502 from controller.
        logger_utils.asleep(delay=60)
        #try:
        #    cluster_lib.update_processes_for_all_controllers_and_ses()
        #except Exception as e:
        #    logger.debug('Update Controller/SE processes Exception: %s' % str(e))
        #    logger_utils.asleep(delay=120)
        #    cluster_lib.update_processes_for_all_controllers_and_ses()
        leader_vm = cluster_lib.get_cluster_master_vm()
        if (present_leader.ip == leader_vm.ip):
            logger_utils.fail('Leader has not changed, Previous leader: %s and Present Leader: %s' % (
            present_leader.ip, leader_vm.ip))
        else:
            logger.info('Leader Then: %s and Leader Now: %s' % (present_leader.ip, leader_vm.ip))


    elif inject_error == 'del_file_upgr_inprog':
        wait_until_controller_upgrade_goes_to_state('STOP_CONTROLLER')
        logger_utils.asleep(delay=5)  # Wait untill we cross this stage and reach somewhere near
        # PREPARE_FOR_REBOOT_CONTROLLER_NODES
        follower_vm.execute_command('sudo rm -rf /run/upgrade_reboot_in_progress')
        logger_utils.asleep(delay=1)  # Just to make sure we remove this file
        follower_vm.execute_command('sudo rm -rf /run/upgrade_reboot_in_progress')
        logger_utils.asleep(delay=1)
        follower_vm.execute_command('sudo rm -rf /run/upgrade_reboot_in_progress')
        leader_vm.execute_command('sudo reboot')
        # Should reboot a diff node than the one we delete the file in

    elif inject_error == 'ctrlr_reboot_at_comit':
        wait_until_upgrade_rebooted()
        wait_until_controller_upgrade_goes_to_state('COMMIT_UPGRADE')
        logger_utils.asleep(delay=10)  # Wait to get well into this stage
        leader_vm.execute_command('sudo reboot')

    elif inject_error == 'posgres_cp_fail':
        wait_until_upgrade_rebooted()
        wait_until_controller_upgrade_goes_to_state('MIGRATE_CONFIG')
        leader_vm.block_port(5000)
        leader_vm.block_port(5049)
        # Block these specific ports
        wait_until_upgrade_aborted()
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()
        leader_vm.clear_iptables()
        return

    elif inject_error == 'restart_proc_sup':
        # COMPLETE THIS
        return

    elif inject_error == 'se_off_throughout':
        # HERE WE ASSUME THAT THE VICTIM SE HAS BEEN
        # TURNED OFF. CONTINUING WITH THE UPGRADE
        wait_until_upgrade_rebooted()
        logger.debug('wait_until_upgrade_rebooted  DONE')
        wait_until_controller_upgrade_complete(timeout=3000)
        logger.debug('wait_until_controller_upgrade_complete  DONE')
        logger.info('Controller upgrade is complete')
        cluster_lib.wait_until_cluster_ready()
        logger.debug('wait_until_cluster_ready  DONE')
        wait_until_se_upgrade_complete(timeout=3000)
        logger.debug('wait_until_se_upgrade_complete  DONE')
        logger.info('SE upgrade is complete')
        logger_utils.asleep(delay=10)  # Wait for system to stablize, we assume system
        # has upgraded
        config.cloud.powerOnVM(victim_se.name)
        se_lib.wait_for_all_se_to_connect()
        logger.info('wait_for_all_se_to_connect  DONE')
        logger_utils.asleep(delay=60)
        #try:
        #    cluster_lib.update_processes_for_all_controllers_and_ses()
        #    logger.debug('update_processes_for_all_controllers_and_ses  DONE')
        #except Exception as e:
        #    logger.debug('Update Controller/SE processes Exception: %s' % str(e))
        #    logger_utils.asleep(delay=120)
        #    cluster_lib.update_processes_for_all_controllers_and_ses()

        #########################
        # Verify Block for this
        # TC
        #########################
        #status_obj = get_upgrade_status()
        status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL)
        if type(status_obj) is not dict:
            logger_utils.fail('Incomprehensible Upgrade Status')

        if not status_obj.get('se_state', {}).get('se_upgrade_errors'):
            logger_utils.fail('No SE upgrade errors encountered but errors Expected')

        err_arr = status_obj.get('se_state', {}).get('se_upgrade_errors')
        for ele in err_arr:
            if ele.get('se_ref') != victim_se.ip:
                logger_utils.fail(
                    'Another SE encountered and unexpected error: %s on %s' % (ele.task, ele.get('se_ref')))


    elif inject_error == 'discon_se_attempt':
        prev_version = SuiteVars.api_version
        logger.debug('prev_version : %s' % prev_version)
        ctlr_vms = infra_utils.get_vm_of_type('controller')
        logger.debug('Got coltrollers')
        victim_se = infra_utils.get_vm_of_type('se')[0]
        logger.info('Victim SE selected: %s' % victim_se.ip)
        logger.info('Disconnecting the SE from the controllers')
        # PUT IPTABLES IN SE TO DISCONN FROM CONTROLLERS
        for each in ctlr_vms:
            logger.debug('putting iptables for %s in SE %s' % (each.ip, victim_se.ip))
            victim_se.execute_command('sudo iptables -A INPUT -s%s -j DROP' % each.ip)
        #####
        wait_until_upgrade_rebooted()
        logger.debug('wait_until_upgrade_rebooted  DONE')
        # api.se_lib.stop_se(victim_se)
        # logger.debug('stop_se  DONE')
        wait_until_controller_upgrade_complete(timeout=3000)
        logger.debug('wait_until_controller_upgrade_complete  DONE')
        logger.info('Controller upgrade is complete')
        cluster_lib.wait_until_cluster_ready()
        logger.debug('wait_until_cluster_ready  DONE')
        wait_until_se_upgrade_complete(timeout=3000)
        logger.debug('wait_until_se_upgrade_complete  DONE')
        logger.info('SE upgrade is complete')
        logger_utils.asleep(delay=10)  # Wait for system to stablize
        victim_se.clear_iptables()
        logger.debug('victim_se.clear_iptables  DONE')
        logger_utils.asleep(delay=10)  # Wait for system to stablize
        # api.se_lib.start_se(victim_se)
        # logger.info('api.se_lib.start_se  DONE')
        se_lib.wait_for_all_se_to_connect()
        logger.info('wait_for_all_se_to_connect  DONE')
        logger_utils.asleep(delay=60)
        #try:
        #    cluster_lib.update_processes_for_all_controllers_and_ses()
        #    logger.debug('update_processes_for_all_controllers_and_ses  DONE')
        #except Exception as e:
        #    logger.debug('Update Controller/SE processes Exception: %s' % str(e))
        #    logger_utils.asleep(delay=120)
        #    cluster_lib.update_processes_for_all_controllers_and_ses()

        #########################
        # Verify Block. Writing
        # the verify here as it
        # requires a diff verify
        #########################
        #status_obj = get_upgrade_status()
        status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL)
        if type(status_obj) is not dict:
            logger_utils.fail('Incomprehensible Upgrade Status')

        if not status_obj.get('se_state', {}).get('se_upgrade_errors'):
            logger_utils.fail('No SE upgrade errors encountered but errors Expected')

        err_arr = status_obj.get('se_state', {}).get('se_upgrade_errors')
        for ele in err_arr:
            if ele.get('se_ref') != victim_se.ip:
                logger_utils.fail(
                    'Another SE encountered and unexpected error: %s on %s' % (ele.task, ele.get('se_ref')))

    elif inject_error == 'se_image_diskfull':
        prev_version = get_version(leader_vm)
        victim_se = infra_utils.get_vm_of_type('se')[0]
        logger.info('Victim SE selected: %s' % victim_se.ip)
        r_dep.hog_disk(victim_se, logger, dire='/')
        logger.info('r_dep.hog_disk  DONE')
        wait_until_controller_upgrade_complete(timeout=3000)
        logger.info('Controller upgrade is complete')
        cluster_lib.wait_until_cluster_ready()
        logger.info('wait_until_cluster_ready  DONE')
        # Keep checking if the first upgrade attempt is made
        tries = 1
        for _ in xrange(0, 300):
            try:
                #status_obj = get_upgrade_status()
                status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL)
            except Exception:
                pass
            else:
                se_state = status_obj.get('se_state', {})
                if not se_state:
                    logger_utils.fail('SE Upgrade has not begun yet')
                else:
                    notes_sec = se_state.get('notes', [])
                    if not notes_sec and tries > 5:
                        logger_utils.fail('Notes section not available in SE upgrade status')
                    elif not notes_sec and tries < 5:
                        tries = + 1
                        logger.info('Number of tries: %d and still no Notes Section' % tries)
                        logger_utils.asleep(delay=1)
                        continue

                    if len(notes_sec) < 2:
                        continue
                    elif len(notes_sec) == 2 and 'Upgrade image on' in notes_sec[1]:
                        logger_utils.asleep(delay=15)
                        r_dep.unhog_disk(victim_se, logger, dire='/')
                        break
                        # AT this point the disk is now available in victim it should proceed
                        # with upgrade

        wait_until_se_upgrade_complete(timeout=3000)
        logger.info('wait_until_se_upgrade_complete  DONE')
        cluster_lib.wait_until_cluster_ready()
        logger.info('wait_until_cluster_ready DONE')
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        logger.info('wait_until_n_cluster_nodes_ready DONE')
        # Commenting out all update_processes_for_all_controllers because they are not implemented completely
        #try:
            #cluster_lib.update_processes_for_all_controllers_and_ses()
            #logger.info('update_processes_for_all_controllers_and_ses  DONE')
        #except Exception as e:
        #    logger.debug('Update Controller/SE processes Exception: %s' % str(e))
        #    logger_utils.asleep(delay=120)
        #    #cluster_lib.update_processes_for_all_controllers_and_ses()
        se_lib.wait_for_all_se_to_connect()
        logger.debug('Wait for SE to connect')
        logger_utils.asleep(delay=15)
        ##################################
        # Verification part. See that the
        # errors are seen and all SEs are
        # on the same version
        ##################################
        #status_obj = get_upgrade_status()
        status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL)
        if type(status_obj) is not dict:
            logger_utils.fail('Incomprehensible Upgrade Status')

        if not status_obj.get('se_state', {}).get('se_upgrade_errors'):
            logger_utils.fail('No SE upgrade errors encountered but errors Expected')

        err_arr = status_obj.get('se_state', {}).get('se_upgrade_errors')
        for ele in err_arr:
            if ele.get('se_ref') != victim_se.ip:
                logger_utils.fail(
                    'Another SE encountered and unexpected error: %s on %s' % (ele.task, ele.get('se_ref')))
        verify_upgrade_with_error(prev_version, victim_se, 'discon')

    elif inject_error == 'cyclic_se_reboot':
        se_arr = infra_utils.get_vm_of_type('se')
        wait_until_upgrade_rebooted()
        wait_until_controller_upgrade_goes_to_state('COMMIT_UPGRADE')
        logger_utils.asleep(delay=10)
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        wait_until_se_goes_to_state('SE_IMAGE_UPGRADE')
        for _ in xrange(0, 300):
            se_lib.wait_for_all_se_to_connect()
            #status_obj = get_upgrade_status()
            status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL)
            if status_obj.get('se_state', {}).get('state') == 'SE_UPGRADE_COMPLETE':
                logger.info('SE upgrade complete, No more reboots of SEs')
                break
            for each_se in se_arr:
                each_se.execute_command('sudo reboot')
            logger_utils.asleep(delay=30)
        se_lib.wait_for_all_se_to_connect()
        logger.debug('Wait for SE to connect')

    elif inject_error == 'kill_proc_supv':
        wait_until_controller_upgrade_goes_to_state('STOP_CONTROLLER')
        signal_to_process_vm(leader_vm, 'cluster_mgr', sig='SIGKILL')
        # Should not abort as the processs should be respawned

    elif inject_error == 'all_rsrc_mon_hang_post_reboot':
        wait_until_upgrade_rebooted()
        wait_until_controller_upgrade_goes_to_state('MIGRATE_CONFIG')
        signal_to_process_vm(leader_vm, 'avi-resmon', sig='SIGSTOP')
        wait_until_upgrade_aborted()
        logger_utils.asleep(delay=30)
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()
    elif inject_error == 'all_rsrc_slave_mon_hang_pre_reboot':
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        signal_to_process_vm(follower_vm, 'avi-resmon', sig='SIGSTOP')
        logger_utils.asleep(delay=30)
    elif inject_error == 'all_rsrc_slave_mon_hang_post_reboot':
        wait_until_upgrade_rebooted()
        wait_until_controller_upgrade_goes_to_state('MIGRATE_CONFIG')
        signal_to_process_vm(follower_vm, 'avi-resmon', sig='SIGSTOP')
        wait_until_upgrade_aborted()
        logger_utils.asleep(delay=30)
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        #cluster_lib.update_processes_for_all_controllers()
        verify_upgrade_aborted()
    elif inject_error == 'kill_upgrcrdn_leader_pre_rebot':
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        signal_to_process_vm(leader_vm, '/opt/avi/python/lib/avi/upgrade/upgrade_coordinator.py',
                             sig='SIGKILL')
        wait_until_upgrade_aborted()
        logger_utils.asleep(delay=30)
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        #cluster_lib.update_processes_for_all_controllers()
        verify_upgrade_aborted()
    elif inject_error == 'kill_all_resmon_lder_pre_reboot':
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        for _ in xrange(0, 30):
            signal_to_process_vm(leader_vm, 'avi-resmon', sig='SIGKILL')
            logger_utils.asleep(delay=1)
    elif inject_error == 'kill_all_resmon_lder_post_reboot':
        wait_until_upgrade_rebooted()
        wait_until_controller_upgrade_goes_to_state('MIGRATE_CONFIG')
        for _ in xrange(0, 30):
            signal_to_process_vm(leader_vm, 'avi-resmon', sig='SIGKILL')
            logger_utils.asleep(delay=1)
    elif inject_error == 'kill_all_resmon_slave_pre_reboot':
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        for _ in xrange(0, 30):
            signal_to_process_vm(follower_vm, 'avi-resmon', sig='SIGKILL')
            logger_utils.asleep(delay=1)
    elif inject_error == 'kill_all_resmon_slave_post_reboot':
        wait_until_upgrade_rebooted()
        wait_until_controller_upgrade_goes_to_state('MIGRATE_CONFIG')
        for _ in xrange(0, 30):
            signal_to_process_vm(follower_vm, 'avi-resmon', sig='SIGKILL')
            logger_utils.asleep(delay=1)

    elif inject_error == 'cfg_update_upgrd_inprog':
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        logger.info('wait_until_controller_upgrade_goes_to_state  DONE')
        try:
            vs = config.get_all('virtualservice')[0]
            logger.info('vn name  DONE :  %s' % vs.name)
            vs_lib.update_virtualservice(vs.name, application_profile_uuid='applicationprofile-2')
            logger.info('update_virtualservice  DONE')
        except Exception as e:
            logger.info('Exception caught as expected, %s' % e)
            cmnd = 'sudo reboot'
            leader_vm.execute_command(cmnd)
            wait_until_upgrade_aborted()
            cluster_lib.wait_until_cluster_ready()
            cluster.wait_until_n_cluster_nodes_ready(
                len(infra_utils.get_vm_of_type('controller')))
            #cluster_lib.update_processes_for_all_controllers()
            verify_upgrade_aborted()
            return
        else:
            logger_utils.fail('No error seen, this is not expected')
            cmnd = 'sudo reboot'
            leader_vm.execute_command(cmnd)
            wait_until_upgrade_aborted()
            cluster_lib.wait_until_cluster_ready()
            cluster.wait_until_n_cluster_nodes_ready(
                len(infra_utils.get_vm_of_type('controller')))
            #cluster_lib.update_processes_for_all_controllers()
            verify_upgrade_aborted()
            return

    elif inject_error == 'kill_upgrcrdn_slave_pre_rebot':
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        signal_to_process_vm(follower_vm, '/opt/avi/python/lib/avi/upgrade/upgrade_coordinator.py',
                             sig='SIGKILL')
        wait_until_upgrade_aborted()
        logger_utils.asleep(delay=30)
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        #cluster_lib.update_processes_for_all_controllers()
        verify_upgrade_aborted()
    elif inject_error == 'kill_upgrcrdn_leader_post_rebot':
        wait_until_upgrade_rebooted()
        logger.info('wait_until_upgrade_rebooted  DONE')
        wait_until_controller_upgrade_goes_to_state('MIGRATE_CONFIG')
        logger.info('wait_until_controller_upgrade_goes_to_state  DONE')
        signal_to_process_vm(leader_vm, '/opt/avi/python/lib/avi/upgrade/upgrade_coordinator.py',
                             sig='SIGKILL')
        logger.info('signal_to_process_vm  DONE')
        wait_until_upgrade_aborted()
        logger.info('wait_until_upgrade_aborted  DONE')
        logger_utils.asleep(delay=30)
        cluster_lib.wait_until_cluster_ready()
        logger.info('wait_until_cluster_ready  DONE')
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        logger.info('wait_until_n_cluster_nodes_ready  DONE')
        #cluster_lib.update_processes_for_all_controllers()
        logger.info('update_processes_for_all_controllers  DONE')
        verify_upgrade_aborted()
        logger.info('verify_upgrade_aborted  DONE')
        logger_utils.asleep(delay=20)
        flag_after = update_a_vs()
        logger.info('update_a_vs AFTER  DONE')
        if (flag_after != True):
            logger_utils.fail('Config after upgrade was not allowed')

    elif inject_error == 'kill_upgrcrdn_slave_post_rebot':
        wait_until_controller_upgrade_goes_to_state('MIGRATE_CONFIG')
        signal_to_process_vm(
            follower_vm,
            '/opt/avi/python/lib/avi/upgrade/upgrade_coordinator.py',
            sig='SIGKILL')
        wait_until_upgrade_aborted()
        logger_utils.asleep(delay=30)
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        #cluster_lib.update_processes_for_all_controllers()
        verify_upgrade_aborted()

    elif inject_error == 'se_reboot_stage6':
        victim_se = infra_utils.get_vm_of_type('se')[random.randint(0, len(infra_utils.get_vm_of_type('se')))]
        logger.info('Victim SE chosen: %s' % victim_se.ip)
        wait_until_controller_upgrade_goes_to_state('PREPARE_FOR_REBOOT_CONTROLLER_NODES')
        logger.info('wait_until_controller_upgrade_goes_to_state  DONE')
        victim_se.execute_command('sudo reboot')
        logger_utils.asleep(delay=15)
        try:
            se_lib.wait_for_all_se_to_connect()
        except:
            pass
    elif inject_error == 'se_reboot_stage10':
        victim_se = infra_utils.get_vm_of_type('se')[random.randint(0, len(infra_utils.get_vm_of_type('se')))]
        logger.info('Victim SE chosen: %s' % victim_se.ip)
        wait_until_upgrade_rebooted()
        logger.info('wait_until_upgrade_rebooted  DONE')
        wait_until_controller_upgrade_goes_to_state('MIGRATE_CONFIG')
        logger.info('wait_until_controller_upgrade_goes_to_state  DONE')
        victim_se.execute_command('sudo reboot')
        logger_utils.asleep(delay=15)
        try:
            se_lib.wait_for_all_se_to_connect()
        except:
            pass


    elif inject_error == 'ctrl_reboot_stage2':
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        leader_vm.execute_command('sudo reboot')
        wait_until_upgrade_aborted()
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        logger_utils.asleep(delay=30)
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()
    elif inject_error == 'ctrl_reboot_stage13':
        wait_until_upgrade_rebooted()
        wait_until_controller_upgrade_goes_to_state('POST_UPGRADE_HOOKS')
        leader_vm.execute_command('sudo reboot')
        wait_until_upgrade_aborted()
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        logger_utils.asleep(delay=30)
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()
    elif inject_error == 'ctrl_reboot_stage5':
        wait_until_controller_upgrade_goes_to_state('STOP_CONTROLLER')
        leader_vm.execute_command('sudo reboot')
        wait_until_upgrade_aborted()
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        logger_utils.asleep(delay=30)
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()

    elif inject_error == 'slave_ctrl_reboot_stage2':
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        follower_vm.execute_command('sudo reboot')
        wait_until_upgrade_aborted()
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        logger_utils.asleep(delay=30)
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()
    elif inject_error == 'slave_ctrl_reboot_stage13':
        wait_until_upgrade_rebooted()
        wait_until_controller_upgrade_goes_to_state('POST_UPGRADE_HOOKS')
        follower_vm.execute_command('sudo reboot')
        wait_until_upgrade_aborted()
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        logger_utils.asleep(delay=30)
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()
    elif inject_error == 'slave_ctrl_reboot_stage5':
        wait_until_controller_upgrade_goes_to_state('STOP_CONTROLLER')
        follower_vm.execute_command('sudo reboot')
        wait_until_upgrade_aborted()
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        logger_utils.asleep(delay=30)
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()
    elif inject_error == 'ctrl_disk_full_error_on_leader':
        logger_utils.asleep(delay=random.randint(60, 90))
        wait_until_upgrade_aborted()
        r_dep.unhog_disk(follower_vm, logging, dire='/var/lib/avi/upgrade_pkgs')
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        verify_upgrade_aborted()
        return
    elif inject_error == 'poweroff_leader_before_reboot':
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        logger.info('wait_until_controller_upgrade_goes_to_state  DONE')
        config.cloud.powerOffVM(leader_vm.name)
        logger.info('config.cloud.powerOffVM  DONE')
        logger_utils.asleep(delay=60)
        logger.info('sleep1  DONE')
        # Let the upgrde fail, now switch on VM
        config.cloud.powerOnVM(leader_vm.name)
        logger.info('config.cloud.powerOnVM  DONE')
        # SInce the leader would have changed, get the new Leader
        leader_vm = cluster_lib.get_cluster_master_vm()
        logger.info('get_cluster_master_vm  DONE')
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        logger.info('wait_until_n_cluster_nodes_ready  DONE')
        wait_until_upgrade_aborted()
        logger.info('wait_until_upgrade_aborted  DONE')
        logger_utils.asleep(delay=60)
        logger.info('sleep2  DONE')
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        logger.info('wait_until_n_cluster_nodes_ready  DONE')
        logger_utils.asleep(delay=30)
        logger.info('sleep3  DONE')
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        logger.info('update_processes_for_all_controllers_and_ses  DONE')
        verify_upgrade_aborted()
        logger.info('verify_upgrade_aborted  DONE')
        return
    elif inject_error == 'poweroff_follower_before_reboot':
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        logger.info('wait_until_controller_upgrade_goes_to_state  DONE')
        config.cloud.powerOffVM(follower_vm.name)
        logger.info('config.cloud.powerOffVM  DONE')
        logger_utils.asleep(delay=60)
        logger.info('sleep1  DONE')
        wait_until_upgrade_aborted()
        logger.info('wait_until_upgrade_aborted  DONE')
        config.cloud.powerOnVM(follower_vm.name)
        logger.info('config.cloud.powerOnVM  DONE')
        logger_utils.asleep(delay=60)
        logger.info('sleep2  DONE')
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        logger.info('wait_until_n_cluster_nodes_ready  DONE')
        logger_utils.asleep(delay=30)
        logger.info('sleep3  DONE')
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        logger.info('update_processes_for_all_controllers_and_ses  DONE')
        verify_upgrade_aborted()
        logger.info('verify_upgrade_aborted  DONE')
        return
    elif inject_error == 'poweroff_leader_after_reboot':
        wait_until_upgrade_rebooted()
        logger.info('wait_until_upgrade_rebooted  DONE')
        wait_until_controller_upgrade_goes_to_state('MIGRATE_CONFIG')
        logger.info('wait_until_controller_upgrade_goes_to_state  DONE')
        config.cloud.powerOffVM(leader_vm.name)
        logger.info('config.cloud.powerOffVM  DONE')
        logger_utils.asleep(delay=60)
        logger.info('sleep1  DONE')
        wait_until_upgrade_aborted()
        config.cloud.powerOnVM(leader_vm.name)
        logger.info('config.cloud.powerOnVM  DONE')
        logger_utils.asleep(delay=60)
        logger.info('sleep2  DONE')
        logger.info('wait_until_upgrade_aborted  DONE')
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        logger.info('wait_until_n_cluster_nodes_ready  DONE')
        logger_utils.asleep(delay=30)
        logger.info('sleep3  DONE')
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        logger.info('update_processes_for_all_controllers_and_ses  DONE')
        verify_upgrade_aborted()
        logger.info('verify_upgrade_aborted  DONE')
        return
    elif inject_error == 'poweroff_follower_after_reboot':
        wait_until_controller_upgrade_goes_to_state('MIGRATE_CONFIG')
        logger.info('wait_until_controller_upgrade_goes_to_state  DONE')
        config.cloud.powerOffVM(follower_vm.name)
        logger.info('config.cloud.powerOffVM  DONE')
        logger_utils.asleep(delay=60)
        logger.info('sleep1  DONE')
        wait_until_upgrade_aborted()
        logger.info('wait_until_upgrade_aborted  DONE')
        config.cloud.powerOnVM(follower_vm.name)
        logger.info('config.cloud.powerOnVM  DONE')
        logger_utils.asleep(delay=60)
        logger.info('sleep2  DONE')
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        logger.info('wait_until_n_cluster_nodes_ready  DONE')
        logger_utils.asleep(delay=30)
        logger.info('sleep3  DONE')
        #cluster_lib.update_processes_for_all_controllers_and_ses()
        logger.info('update_processes_for_all_controllers_and_ses  DONE')
        verify_upgrade_aborted()
        logger.info('verify_upgrade_aborted  DONE')
        return
    elif inject_error == 'blockzk_leader_before_reboot':
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        cluster_lib.disconnect_zk(leader_vm, -1)
        logger_utils.asleep(delay=30)
        wait_until_upgrade_aborted()
        leader_vm.clear_iptables()
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        #cluster_lib.update_processes_for_all_controllers()
        verify_upgrade_aborted()
        return
    elif inject_error == 'blockzk_follower_before_reboot':
        wait_until_controller_upgrade_goes_to_state('INSTALL_IMAGE')
        cluster_lib.disconnect_zk(follower_vm, -1)
        logger_utils.asleep(delay=30)
        wait_until_upgrade_aborted()
        follower_vm.clear_iptables()
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        #cluster_lib.update_processes_for_all_controllers()
        verify_upgrade_aborted()
        return
    elif inject_error == 'blockzk_leader_after_reboot':
        wait_until_upgrade_rebooted()
        wait_until_controller_upgrade_goes_to_state('MIGRATE_CONFIG')
        cluster_lib.disconnect_zk(leader_vm, -1)
        wait_until_upgrade_aborted(interval=2)
        logger_utils.asleep(delay=15)  # Wait for upgrade abort to sink in
        leader_vm.clear_iptables()
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        #cluster_lib.update_processes_for_all_controllers()
        verify_upgrade_aborted()
        return
    elif inject_error == 'blockzk_follower_after_reboot':
        wait_until_upgrade_rebooted()
        wait_until_controller_upgrade_goes_to_state('MIGRATE_CONFIG')
        cluster_lib.disconnect_zk(follower_vm, -1)
        wait_until_upgrade_aborted(interval=2)
        logger_utils.asleep(delay=15)  # Wait for upgrade abort to sink in
        follower_vm.clear_iptables()
        cluster_lib.wait_until_cluster_ready()
        cluster.wait_until_n_cluster_nodes_ready(
            len(infra_utils.get_vm_of_type('controller')))
        #cluster_lib.update_processes_for_all_controllers()
        verify_upgrade_aborted()
        return

    #######################################
    #  [NO ERROR] case
    #######################################

    infra_utils.clear_session(all_sessions=True)
    if str(wait) == 'True':
        logger_utils.asleep(delay=1)
        wait_until_controller_upgrade_complete(timeout=3000)
        logger.info('Controller upgrade is complete')
        # commenting for now because vs_dummy.json is not present currently
        #vs_create_should_fail()
        cluster_lib.wait_until_cluster_ready()
        #vs_create_should_fail()
        wait_until_se_upgrade_complete(timeout=3000)
        logger.info('SE upgrade is complete')
        # Aviportal restarts after upgrade. If we check instantly, we might get
        # 502 from controller.
        logger_utils.asleep(delay=60)
        # commenting for now because vs_dummy.json is not present currently
        #try:
        #    rest.delete('virtualservice', name='vs-dummy')
        #except FailError:
        #    logger.debug('Failed to delete virtualservice vs-dummy')
        # COmment this out for now since cluster_lib.update_processes_for_all_controllers_and_ses is not implemented
        #try:
        #    cluster_lib.update_processes_for_all_controllers_and_ses()
        #except Exception as e:
        #    logger.debug('Update Controller/SE processes Exception: %s' % str(e))
        #    logger_utils.asleep(delay=120)
        #    cluster_lib.update_processes_for_all_controllers_and_ses()


def vs_create_should_fail():
    try:
        check_vs_create_traffic_delete()
    except Exception as e:
        logger.debug('EXPECTED error vs create, err:%s' % str(e))
        pass
    else:
        logger.info('ERROR vs_create was allowed during upgrade')
        logger_utils.fail('error creating dummy vs')


def wait_until_controller_upgrade_goes_to_state(state, timeout=3000):
    """ Blocks until the controller upgrade is goes to expected state """
    logger.info('wait until controller goes to state %s' % state)
    sleep_time = 2
    for attempt in xrange(0, timeout / sleep_time):
        try:
            #status_obj = get_upgrade_status()
            status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL)
        except Exception:
            pass
        else:
            if not status_obj.get('controller_state', {}).get('tasks_completed'):
                logger.info('Tasks not ready, sleeping')
                logger_utils.asleep(delay=sleep_time)
            else:
                controller_state = status_obj.get('controller_state', {})
                tasks = [item['task']
                         for item in controller_state['tasks_completed']]
                if state in tasks:
                    logger.info('upgrade reaches state %s' % state)
                    return
        logger_utils.asleep(delay=sleep_time)
    msg = 'Timeout: the controller upgrade did not go to %s' % state
    msg += 'after %s sec' % timeout
    logger_utils.fail(msg)


def signal_to_process_vm(vm, process_name, sig='SIGSTOP'):
    '''
    Pass given signal to the given process name
    '''
    cmd = 'sudo kill -s %s `ps -ef | grep "%s" | grep -v grep | awk {\'print $2\'}`' % (sig, process_name)
    logger.info('Passed signal : %s to process: %s on machine %s' % (sig, process_name, vm.ip))
    vm.execute_command(cmd)


def wait_until_se_goes_to_state(state, timeout=3000):
    """ Blocks until the upgrade goes to state specified.
        Will raise an exception if called before the controller is up and
        responding to APIs
    """

    sleep_time = 10
    for attempt in xrange(0, timeout / sleep_time):
        try:
            status_code, status_obj = rest.get(
                '/seupgrade/statusdetail')
        except Exception:
            pass
        else:
            tasks = status_obj.get('tasks', {})
            for task in tasks:
                if state in task['state'] and \
                                task['status'] == 'TASK_COMPLETED':
                    return
        logger_utils.asleep(delay=sleep_time)
    logger_utils.fail('Timeout: the SE upgrade was not finished after %s sec' %
                       timeout)


def wait_until_controller_upgrade_complete(timeout=900,
                                           stimulus=None, verification=None):
    """ Blocks until the controller upgrade is complete """
    sleep_time = 10
    timeout = int(timeout)
    for attempt in xrange(0, timeout / sleep_time):
        try:
            #status_obj = get_upgrade_status()
            status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL)
        except Exception:
            pass
        else:
            controller_state = status_obj.get('controller_state', {})
            se_state = status_obj.get('se_state', {})
            se_group_state = status_obj.get('se_group_state[1]', {})

            if (not status_obj.get('in_progress', False) and
                    not controller_state.get('state', None)):
                logger_utils.fail('Controller upgrade not in progress')

            if controller_state.get('state') == 'UPGRADE_ABORTED':
                cluster_lib.wait_until_cluster_ready()
                #cluster_lib.update_processes_for_all_controllers()
                logger_utils.fail('Controller upgrade has been aborted')
            elif not controller_state.get('in_progress', True):
                if controller_state.get('state') == 'UPGRADE_CONTROLLER_COMPLETED' or \
                                controller_state.get('state') == 'UPGRADE_COMPLETED' or \
                                se_state.get('state') == 'SE_UPGRADE_COMPLETE' or \
                                se_group_state.get('state') == 'SEGROUP_UPGRADE_COMPLETE':
                    return
                else:
                    logger.debug('upgrade state: %s' % controller_state.get('state'))
                    logger.info(controller_state.get('state'))
                    logger_utils.fail('in_progress is False, but state != UPGRADE_CONTROLLER_COMPLETED')
        if stimulus and verification:
            if verification():
                stimulus()
        logger_utils.asleep(delay=sleep_time)
    logger_utils.fail('Timeout: the controller upgrade was not finished after %s sec' % timeout)


def wait_until_se_upgrade_complete(timeout=900,
                                   stimulus=None, verification=None):
    """ Blocks until the upgrade is complete. Will raise an exception if called
    before the controller is up and responding to APIs """
    sleep_time = 10
    timeout = int(timeout)
    for attempt in xrange(0, timeout / sleep_time):
        try:
            #status_obj = get_upgrade_status()
            status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL)
        except Exception:
            pass
        else:
            se_state = status_obj.get('se_state', {})
            if not se_state:
                logger.info('SE upgrade state not set')
                pass
                # raise TimeoutError('SE upgrade state not set')
            if str(se_state.get('state', None)) == 'SE_UPGRADE_COMPLETE':
                if not se_state.get('in_progress', True):
                    return
                else:
                    logger.debug('se upgrade state: %s' % se_state.get('state'))
                    logger.debug(se_state.get('state'))
                    logger_utils.fail('SE_UPGRADE_COMPLETE, but in_progress is set')
        if stimulus and verification:
            if verification():
                stimulus()
        logger_utils.asleep(delay=sleep_time)
    logger_utils.fail('Timeout: the SE upgrade was not finished after %s sec' %
                       timeout)


def get_version(vm):
    return (vm.get_version_tag()).strip()


def verify_upgrade_with_error(previous_version, error_vm, err_tag, upgrade_should_be_successful=True):
    """ Verifications:
        1. Check upgrade status
        2. Check upgrade state
        3. Check version on every controller and se not in error_vm
    """
    # reset_session()
    upgrade_should_be_successful = True if upgrade_should_be_successful == 'True' or upgrade_should_be_successful == True else False
    if not err_tag or not error_vm:
        # No use of using this function. Raise error
        logger_utils.fail('No upgrade error VM or tag found')

    #status_obj = get_upgrade_status()
        status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL)
    logger.debug('Upgrade status response: %s' % status_obj)
    if (status_obj['in_progress'] is True):
        logger_utils.fail('Upgrade still in progress')
    if (status_obj['controller_state']['state'] != 'UPGRADE_COMPLETED' and
                status_obj['controller_state']['state'] != 'UPGRADE_ABORTED'):
        logger_utils.fail('Controller upgrade status != COMPLETED/ABORTED')
    if (status_obj['controller_state']['state'] == 'UPGRADE_COMPLETED' and
                status_obj['se_state']['state'] != 'SE_UPGRADE_COMPLETE'):
        logger_utils.fail('SE upgrade status != SE_UPGRADE_COMPLETE')

    versions = [get_version(vm)
                for vm in (infra_utils.get_vm_of_type('controller') +
                           infra_utils.get_vm_of_type('se'))
                if vm.ip != error_vm.ip]
    current_version = versions[0]
    logger.debug("versions:%s" % versions)
    for ver in versions:
        if ver != current_version:
            logger_utils.fail('Not all EXPECTED controllers and SEs are on the'
                               'same version. Excepted version: %s, got: %s' %
                               (current_version, ver))
        if upgrade_should_be_successful is True:
            if ver == previous_version:
                logger_utils.fail('Found a VM that does not seem to be upgraded. '
                                   'Its version [%s] has not changed.' % ver)
        else:
            if ver != previous_version:
                logger_utils.fail('Found a VM that got upgraded. '
                                   'Its version [%s] has changed.' % ver)
    if (status_obj['controller_state']['state'] == 'UPGRADE_COMPLETED'
        and err_tag == 'discon'):
        expected_se_errors = ['SE_IMAGE_UPGRADE', 'SE_REBOOT']
        verify_no_errors_in_se_upgrade(expect_errors=expected_se_errors)


def verify_no_errors_in_se_upgrade(**kwargs):
    """ Checks
        1. Number of SEs upgraded = no of se connected to controller
        2. List of upgraded/not upgraded SEs don't have anything in common
        3. No errors in SE error list
        4. If expected error list is specified, no other errors than expected.
    """
    expect_errors = kwargs.get('expect_errors', [])

    #status_obj = get_upgrade_status()
    status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL)
    se_states = status_obj['se_state']
    connected_ses = cleanup.get_all_se_uuid()
    logger.info('Connected SEs: %s, upgraded SEs: %s' % (
        len(connected_ses), len(se_states.get('se_upgrade_completed', []))))

    if 'se_upgrade_not_started' in se_states:
        logger.debug('se_upgrade_not_started on some SEs: %s' % str(se_states['se_upgrade_not_started']))
        logger_utils.fail('se_upgrade_not_started on some SEs: %s' % str(se_states['se_upgrade_not_started']))

    if 'se_upgrade_in_progress' in se_states:
        logger.debug('se_upgrade_in_progress: %s' % str(se_states['se_upgrade_in_progress']))
        logger_utils.fail('se_upgrade_in_progress: %s' % str(se_states['se_upgrade_in_progress']))

    if 'se_disconnected_at_start' in se_states:
        logger.debug('se_disconnected_at_start: %s' % str(se_states['se_disconnected_at_start']))
        logger_utils.fail('se_disconnected_at_start: %s' % str(se_states['se_disconnected_at_start']))

    if 'se_poweredoff_at_start' in se_states:
        logger.debug('se_poweredoff_at_start: %s' % str(se_states['se_poweredoff_at_start']))
        logger_utils.fail('se_poweredoff_at_start: %s' % str(se_states['se_poweredoff_at_start']))

    if 'se_upgrade_errors' in se_states and not len(expect_errors):
        logger.debug('se_upgrade_errors: %s' % str(se_states['se_upgrade_errors']))
        logger_utils.fail('se_upgrade_errors: %s' % str(se_states['se_upgrade_errors']))

    if 'se_already_upgraded_at_start' in se_states:
        logger.debug('se_already_upgraded_at_start: %s' % str(se_states['se_already_upgraded_at_start']))
        logger_utils.fail('se_already_upgraded_at_start: %s' % str(se_states['se_already_upgraded_at_start']))

    if 'se_upgrade_errors' not in se_states:
        return
    actual_errors = [error['task'].lower() for error in se_states['se_upgrade_errors']]
    for error in expect_errors:
        if error.lower() not in actual_errors:
            logger_utils.fail('Expected Error: %s not found in %s' % (error, actual_errors))


def update_a_vs():
    ''' Tries to update some config on a VS,
        returns True if sucessful else False.
        [assuming an appl. prof. is configured]
    '''
    status_code, json_data = rest.get('virtualservice')
    vs = json_data['results'][0]
    logger.info('Vserver chosen to update: %s' % vs.name)
    try:
        vs_lib.update_virtualservice(vs['name'], application_profile_uuid='applicationprofile-2')
    except Exception as e:
        logger.info('Exception encountered: %s, during update of a VS' % e)
        return True
    else:
        logger.info('No Exception encountered during an update of a VS')
        return False


def verify_upgrade_history(previous_upgrade_history):
    upgrade_history = get_upgrade_history()
    # logger.debug('Upgrade history response: %s' % upgrade_history)
    status_code, upgrade_status = rest.get(CLUSTER_UPGRADE_STATUS_URL)
    # logger.debug('Upgrade status response: %s' % upgrade_status)

    num_prev_events = 0
    num_curr_events = 0
    if 'upgrade_events' in previous_upgrade_history:
        num_prev_events = int(len(previous_upgrade_history['upgrade_events']))
    num_curr_events = int(len(upgrade_history['upgrade_events']))

    if num_curr_events == 0:
        logger_utils.fail('upgrade_history: no events')

    #if num_prev_events:
    #    if upgrade_history['upgrade_events'][0]['from_version'] != upgrade_history['upgrade_events'][1]['to_version']:
    #        raise RuntimeError('upgrade_history: curr from_version %s != prev to_version %s' % (
    #            upgrade_history['upgrade_events'][0]['from_version'],upgrade_history['upgrade_events'][1]['to_version']))
    if num_curr_events != (num_prev_events + 1):
        logger.debug('num events in history not incremented by 1, prev=%d curr=%d' % (num_prev_events, num_curr_events))
        logger_utils.fail(
            'num events in history not incremented by 1, prev=%d curr=%d' % (num_prev_events, num_curr_events))

    upgrade_history = upgrade_history['upgrade_events'][0]
    json_utils.compare_json(upgrade_history, upgrade_status)


def rollback_system(wait=True):
    clear_upgrade_status()
    leader_vm = cluster_lib.get_cluster_master_vm()
    follower_vm = cluster_lib.get_random_slave_vm()
    session = rest.create_session(controller=leader_vm)
    infra_utils.switch_mode(session=session)    
    logger.info("Leader: %s, Follower: %s" % (leader_vm.ip, follower_vm.ip))
    logger.info("start upgrade")
    status_code, resp = rest.post('cluster', path='rollback', data={})
    logger_utils.asleep(delay=1)
    if resp.get('error', {}):
        logger.info('rollback resp error:%r. resp:%s' % (resp.get('error'), resp))
        logger_utils.fail('rollback post error %s' % resp)
    # do_post_request('cluster/rollback', {})
    # sleep(1)
    wait_until_upgrade_starts(rollback=True)

    if str(wait) == 'True':
        logger_utils.asleep(delay=1)
        wait_until_controller_upgrade_complete(timeout=3000)
        logger.info('Controller rollback is complete')
        wait_until_se_upgrade_complete(timeout=3000)
        logger.info('SE rollback is complete')
        # Aviportal restarts after rollback. If we check instantly, we might get
        # 502 from controller.
        logger_utils.asleep(delay=60)
        #try:
        #    cluster_lib.update_processes_for_all_controllers_and_ses()
        #except Exception as e:
        #    logger.debug('Update Controller/SE processes Exception: %s' % str(e))
        #    logger_utils.asleep(delay=120)
        #    cluster_lib.update_processes_for_all_controllers_and_ses()
    # reset_session()


def verify_controller_state(status_obj, previous_version, current_version, upgrade_should_be_successful):
    """

    :param status_obj:
    :param previous_version:
    :param current_version:
    :param upgrade_should_be_successful:
    :return:
    """
    controller_obj = status_obj.get('controller_state')

    try:
        # verify from version
        if status_obj['from_version'] != previous_version:
            logger_utils.error("from_version in status(%s) != expected(%s)" % (status_obj.get('from_version'), previous_version))
    except KeyError as e:
        logger.warning('Warning: %s' % str(e))

    # verify to version
    if upgrade_should_be_successful:
        if status_obj.get('to_version') != current_version:
            logger_utils.fail("to_version in status(%s) != expected(%s)" % (status_obj.get('to_version'), current_version))

    task_for_rollback = ['INSTALL_IMAGE', 'PREPARE_CONTROLLER_FOR_SHUTDOWN',
                 'STOP_CONTROLLER', 'PREPARE_FOR_REBOOT_CONTROLLER_NODES', 'REBOOT_CONTROLLER_NODES',
                 'WAIT_FOR_ALL_CONTROLLER_NODES_ONLINE', 'PRE_UPGRADE_HOOKS', 'START_ALL_CONTROLLERS',
                 'POST_UPGRADE_HOOKS', 'SE_UPGRADE_START', 'COMMIT_UPGRADE']

    task_for_upgrade = ['COPY_AND_VERIFY_IMAGE',
                        'INSTALL_IMAGE',
                        'PREPARE_CONTROLLER_FOR_SHUTDOWN',
                        'PREPARE_FOR_REBOOT_CONTROLLER_NODES',
                        'REBOOT_CONTROLLER_NODES',
                        'WAIT_FOR_ALL_CONTROLLER_NODES_ONLINE',
                        'PRE_UPGRADE_HOOKS',
                        'MIGRATE_CONFIG',
                        'START_PRIMARY_CONTROLLER',
                        'START_ALL_CONTROLLERS',
                        'POST_UPGRADE_HOOKS',
                        'SET_CONTROLLER_UPGRADE_COMPLETED',
                        'SE_UPGRADE_START',
                        'COMMIT_UPGRADE']

    # verify controller progress percentage
    # if (controller_obj['controller_progress'] != 100):
    #     logger_utils.fail("Upgrade controller progress is %s it is not 100"
    #                        % controller_obj['controller_progress'])

    # verify controller progress status
    if controller_obj.get('in_progress') != status_obj.get('in_progress'):
        logger_utils.fail('controller in progress is %s not match with status in progress %s' %
            (controller_obj.get('in_progress'), status_obj.get('in_progress')))


    #verify controller tasks
    tasks_completed=[]
    if controller_obj.get('tasks_completed'):
        for i in range(len(controller_obj.get('tasks_completed', []))):
            tasks_completed.append(controller_obj.get('tasks_completed')[i]['task'])

            #start_time = controller_obj['tasks_completed'][i]['start_time'].split(".")[0]
            #end_time = controller_obj['tasks_completed'][i]['end_time'].split(".")[0]
            #duration = datetime.strptime(end_time, "%Y-%m-%d %H:%M:%S") - datetime.strptime(start_time, "%Y-%m-%d %H:%M:%S")
            #if int(controller_obj['tasks_completed'][i]['duration']) != duration.seconds:
                #logger_utils.fail("Duration not match for %s" % controller_obj['tasks_completed'][i]['task'])

    if controller_obj.get('rollback'):
        if status_obj.get('rollback') != controller_obj.get('rollback'):
            logger_utils.fail("status rollback: %s not match with controller rollback:%s" %
                    (status_obj.get('rollback'), controller_obj.get('rollback')))
        if set(task_for_rollback) != set(tasks_completed):
            logger_utils.fail("Controller tasks missing from the upgrade status after rollback")
    else:
        if set(task_for_upgrade) != set(tasks_completed):
            if upgrade_should_be_successful:
                logger_utils.fail("Controller tasks missing from the upgrade status")


def get_segroup_counts(rollback, segroup_name, segroup_inventory_resp):
    """

    :param rollback:
    :param segroup_name:
    :param segroup_inventory_resp:
    :return:
    """
    logger.debug("get count of distrupted vs,scaledout vs,not scaledout vs and vs has no se")
    se_ref_list = collections.Counter()
    se_with_no_vs_count = 0
    vs_runtime = []
    disrupted_vs_count = 0
    disrupted_vs_ref = []
    east_west_vs = []
    se_not_scaledout = []
    scaledout_se = []
    for vs_ref in segroup_inventory_resp.get("virtualservices", []):
        # Get VS detail
        status_code, vs_detail = rest.get("virtualservice/%s" % vs_ref.rpartition('/')[2])
        vs_name = vs_detail.get('name')
        vs_summary = vs_lib.get_vs_runtime(vs_name)

        # Check if east west placement is enabled
        if vs_detail.get('east_west_placement'):
            east_west_vs.append(vs_name)

        # Skip VS verification if vs is disabled.
        if vs_summary.get('oper_status') and vs_summary.get('oper_status').get('state') == 'OPER_DISABLED':
            continue

        total_vip_se = 0
        disrupted = True
        for vip_id in range(len(vs_summary.get('vip_summary', []))):
            num_se = 0
            if vs_summary.get('vip_summary')[vip_id].get('service_engine'):
                num_se = len(vs_summary.get('vip_summary')[vip_id].get('service_engine'))
                total_vip_se += num_se
                for se_index in range(num_se):
                    se_ref = vs_summary['vip_summary'][vip_id]['service_engine'][se_index]['url']
                    se_ref_list[se_ref] += 1

        if not rollback:
            # Verify scaledout SE
            if total_vip_se > 1:
                disrupted = False
                scaledout_se = se_ref_list.keys()

            vs_ref = vs_ref.split('#')[0]
            vs_dict = {'vs_name': vs_name, 'vs_ref': vs_ref, 'disrupted': disrupted}
            vs_runtime.append(vs_dict)

            # verify se with no vs
            se_segroup = se_lib.get_se_in_group(segroup_name)
            for se in se_segroup:
                if se.get('config') and len(se.get('config', {}).get('virtualservice_refs', [])) == 0:
                    se_with_no_vs_count += 1

            # Get all SEs from serviceengine-group
            sg_se_list = segroup_inventory_resp.get('serviceengines')
            sg_se_url_list = []
            for se in sg_se_list:
                se = se.split('#')[0]
                sg_se_url_list.append(se)
                
            # Get not scaledout se
            se_not_scaledout = list(set(sg_se_url_list) - set(scaledout_se))

    if rollback:
        segrp_count_dict = {'se': se_ref_list.keys(), 'east_west_vs': east_west_vs}
    else:
        # Count of disrupted vs
        for vs_dict in range(len(vs_runtime)):
            if vs_runtime[vs_dict].get('disrupted'):
                disrupted_vs_ref.append(vs_runtime[vs_dict].get('vs_ref'))
                disrupted_vs_count += 1

        segrp_count_dict = {'disrupted_vs_count': disrupted_vs_count, 'se_with_no_vs': se_with_no_vs_count,
                            'disrupted_vs_ref': disrupted_vs_ref, 'se': se_ref_list.keys(),
                            'se_with_vs_not_scaledout': se_not_scaledout, 'se_with_vs_scaledout': scaledout_se,
                            'east_west_vs': east_west_vs}
    return segrp_count_dict

def verify_segroup_upgrade_status(rollback, segroup_status, total_se, upgrade_completed_on_se):
    """

    :param rollback:
    :param segroup_status:
    :param total_se:
    :param upgrade_completed_on_se:
    :return:
    """
    logger.info("###verify se status")
    se = []
    num_se = 0

    for sg_status in segroup_status:
        segroup_name = sg_status.get('se_group_name')
        segroup_uuid = sg_status.get('se_group_uuid')
        status_code, segroup = rest.get('serviceenginegroup/%s' % segroup_uuid)
        status_code, resp_cloud = rest.get('cloud/%s' % segroup['cloud_ref'].split('/')[-1])
        infra_utils.switch_mode(cloud=resp_cloud['name'])
        status_code, segroup_inventory_resp = rest.get('serviceenginegroup-inventory?uuid=%s' % segroup_uuid)
        segroup_inventory_resp = segroup_inventory_resp['results'][0]
        logger.debug("Se group inventory response: %s" % segroup_inventory_resp)

        segroup_info = get_segroup_counts(rollback, segroup_name, segroup_inventory_resp)
        logger.debug("dict of all vs %s" % segroup_info)

        se.extend(segroup_info['se'])

        # Check if VS is east_west_vs
        num_vs_in_segrp_exclude_ew = len(segroup_inventory_resp.get("virtualservices", [])) - len(segroup_info.get('east_west_vs',[]))
        logger.debug("East-West vs is %s" % segroup_info.get('east_west_vs'))

        # Verify SE state
        if sg_status.get('state') != 'SEGROUP_UPGRADE_COMPLETE':
            logger_utils.fail("segrp[%s]: status(%s) != COMPLETE" %
                               (sg_status.get('se_group_name'), sg_status.get('state')))

        if 'se_with_vs_not_scaledout' in segroup_info:
            if sg_status.get('num_se_with_vs_not_scaledout') != len(segroup_info.get('se_with_vs_not_scaledout', [])):
                logger_utils.fail("segroup [%s] From upgrade status num se with vs not scaledout (%d) "
                                   "mismatch with Expected (%d)" % (
                                   segroup_name, sg_status.get('num_se_with_vs_not_scaledout'),
                                   len(segroup_info.get('se_with_vs_not_scaledout', []))))

        # Verify if se with vs not scaledout is found in segroup status
        if 'se_with_vs_not_scaledout' in sg_status:
            if sg_status.get('num_se_with_vs_not_scaledout') != len(sg_status.get('se_with_vs_not_scaledout', [])):
                logger_utils.fail("segroup [%s] num_se_with_vs_scaledout(%d) != "
                                   "len(se_with_vs_not_scaledout)(%d)"
                                   % (segroup_name, sg_status.get('num_se_with_vs_not_scaledout'),
                                      len(sg_status.get('se_with_vs_not_scaledout', []))))

            # Verify Number of se vs not scaledout
            if sg_status.get('num_se_with_vs_not_scaledout') != len(segroup_info.get('se_with_vs_not_scaledout', [])):
                logger_utils.fail("segroup [%s] From upgrade status num se with vs not scaledout (%d) != Expected (%d)"
                                   % (segroup_name, sg_status.get('num_se_with_vs_not_scaledout'),
                                      len(segroup_info.get('se_with_vs_not_scaledout', []))))

            # verify se_with_vs_not_scaledout ref
            if not (
            all(vs in segroup_info.get('se_with_vs_not_scaledout', []) for vs in sg_status.get('se_with_vs_not_scaledout', []))):
                logger_utils.fail("segroup [%s] From upgrade status se_with_vs_not_scaledout ref [%s] != Expected [%s]"
                                   % (segroup_name, segroup_info.get('se_with_vs_not_scaledout'),
                                   sg_status.get('se_with_vs_not_scaledout')))

        if 'disrupted_vs_count' in segroup_info:
            if sg_status.get('num_vs_disrupted') != segroup_info.get('disrupted_vs_count'):
                logger_utils.fail("segroup [%s] From upgrade status num vs disrupted (%d) "
                                   "mismatch with Expected (%s)" % (segroup_name, sg_status.get('num_vs_disrupted'),
                                                                    segroup_info.get('disrupted_vs_count')))

        # Verify if disrupted vs is found in segroup status
        if 'disrupted_vs_ref' in sg_status:
            if len(sg_status.get('disrupted_vs_ref', [])) != sg_status.get('num_vs_disrupted', 0):
                logger_utils.fail("segroup [%s] Distrupted vs ref (%d) != len(num_vs_disrupted)(%d)" %
                                   (segroup_name, sg_status.get('num_vs_disrupted', 0),
                                    len(sg_status.get('disrupted_vs_ref', []))))

            # Verify number of vs disrupted
            if sg_status.get('num_vs_disrupted') != segroup_info.get('disrupted_vs_count'):
                logger_utils.fail("segroup [%s] From upgrade status num vs disrupted (%d) "
                                   "!= Expected (%s)" % (segroup_name, sg_status.get('num_vs_disrupted'),
                                                         segroup_info.get('disrupted_vs_count')))

            # Verify disrupted vs references
            if not (all(vs in segroup_info.get('disrupted_vs_ref') for vs in sg_status.get('disrupted_vs_ref', []))):
                logger_utils.fail("segroup [%s] From upgrade status disrupted vs ref [%s] != Expected [%s]"
                                   % (segroup_name, sg_status.get('disrupted_vs_ref'), segroup_info.get('disrupted_vs_ref')))

        if 'se_with_vs_scaledout' in segroup_info:
            if sg_status.get('num_se_with_vs_scaledout') != len(segroup_info.get('se_with_vs_scaledout', [])):
                logger_utils.fail("segroup [%s] From upgrade status num_se_with_vs_scaledout (%d) mismatch with "
                                   "Expected (%d)" % (segroup_name, sg_status.get('num_se_with_vs_scaledout'),
                                                      len(segroup_info.get('se_with_vs_scaledout', []))))

        # Verify if se with vs scaledout is found in segroup status
        if 'se_with_vs_scaledout' in sg_status:
            if len(sg_status.get('se_with_vs_scaledout', [])) != sg_status.get('num_se_with_vs_scaledout'):
                logger_utils.fail("segroup [%s] num se with vs scaledout(%d) != "
                                   "len(se with vs scaledout)(%d)" %
                                   (segroup_name, sg_status.get('num_se_with_vs_scaledout'),
                                    len(sg_status.get('se_with_vs_scaledout', []))))

            # Verify number of se with vs scaledout
            if sg_status.get('num_se_with_vs_scaledout') != len(segroup_info.get('se_with_vs_scaledout', [])):
                logger_utils.fail("segroup [%s] From upgrade status num_se_with_vs_scaledout (%d) != Expected (%d)"
                                   % (segroup_name, sg_status.get('num_se_with_vs_scaledout'),
                                      len(segroup_info.get('se_with_vs_scaledout', []))))

            # Verify se with vs scaledout reference
            if not (all(se in segroup_info.get('se_with_vs_scaledout') for se in sg_status.get('se_with_vs_scaledout'))):
                logger_utils.fail("segroup [%s] From upgrade status se_with_vs_scaledout [%s] != EXpected [%s]"
                                   % (segroup_name, sg_status.get('se_with_vs_scaledout'),
                                      segroup_info.get('se_with_vs_scaledout')))

        # Verify if se with no vs found in segroup status
        if 'se_with_no_vs' in sg_status:
            if len(sg_status.get('se_with_no_vs', [])) != sg_status.get('num_se_with_no_vs'):
                logger_utils.fail("segroup [%s] num se with no vs (%d) != len(se with no vs)(%d)" %
                                   (segroup_name, sg_status.get('num_se_with_no_vs'), len(sg_status.get('se_with_no_vs', []))))

        #Verify if se with no vs in expected
        if 'se_with_no_vs' in segroup_info:
            # Verify number of se with no vs
            if sg_status.get('num_se_with_no_vs') != segroup_info.get('se_with_no_vs'):
                logger_utils.fail("segroup [%s] inventory of Num of se with no vs(%s) != status of num se no vs(%d)"
                                   % (segroup_name, segroup_info.get('se_with_no_vs'), sg_status.get('num_se_with_no_vs')))

        # verify total number vs
        if num_vs_in_segrp_exclude_ew != sg_status.get('num_vs'):
            logger_utils.fail("segroup [%s] From upgrade status number of VS (%d) != Expected (%d)"
                               % (segroup_name, sg_status.get('num_vs'), num_vs_in_segrp_exclude_ew))

        # Verify HA mode
        if segroup_inventory_resp.get("config") and segroup_inventory_resp.get("config")['ha_mode'] != sg_status.get('ha_mode'):
            logger_utils.fail("segroup [%s] From upgrade status ha mode(%s) != Expected (%s)"
                               % (segroup_name, sg_status.get('ha_mode'), segroup_inventory_resp.get("config")['ha_mode']))

        # Verify Number of SE
        if len(segroup_inventory_resp.get('serviceengines', [])) != sg_status.get('num_se'):
            logger_utils.fail("segroup [%s] From upgrade status number SE(%d) != Expected (%d)" %
                               (segroup_name, sg_status.get('num_se'), len(segroup_inventory_resp.get('serviceengines', []))))

        # Verify se group uuid
        if sg_status.get("se_group_uuid") != segroup_inventory_resp["uuid"]:
            logger_utils.fail("segroup [%s] From upgrade status se group uuid[%s] != expected [%s]" %
                               (segroup_name, sg_status.get("se_group_uuid"), segroup_inventory_resp[uuid]))

        num_se += sg_status.get('num_se', 0)

    # Verify upgraded SE
    if not (all(se in se for se in upgrade_completed_on_se)):
        logger_utils.fail("From upgraded status SE upgraded completed != Expected")

    # Verify Total SE
    if num_se != total_se:
        logger_utils.fail("Status Num SE (%d) != Total SE (%d)" % (num_se, total_se))


def verify_seupgrade_status(upgrade_status, upgrade_should_be_successful):
    """

    :param upgrade_status:
    :param upgrade_should_be_successful:
    :return:
    """
    if not upgrade_should_be_successful:
        return

    logger.info("Inside verify_seupgrade_status")

    if upgrade_status.get('controller_state') and upgrade_status.get('controller_state').get('state') == 'UPGRADE_COMPLETED':
        verify_no_errors_in_se_upgrade()

    se_status = upgrade_status.get('se_state')
    total_se = se_lib.se_count_owned_by_controller()

    # Verify SE progress
    if se_status.get('in_progress') != upgrade_status.get('in_progress'):
        logger_utils.fail("SE is in progress: %s not match with status is in progress: %s" % (
        se_status('in_progress'), upgrade_status.get('in_progress')))

    se_state_date = datetime.strptime(se_status['start_time'], "%Y-%m-%d %H:%M:%S")
    status_obj_date = datetime.strptime(upgrade_status['start_time'], "%Y-%m-%d %H:%M:%S.%f")
    se_end_time = datetime.strptime(se_status['end_time'], "%Y-%m-%d %H:%M:%S")
    duration = se_end_time - se_state_date

    #if int(se_status['duration']) != duration.seconds:
    #    logger_utils.fail("Duration not match for SE state")

    # Verify date
    if se_state_date.date() != status_obj_date.date():
        logger_utils.fail("Se state date is not match with date of status")

    rollback = False
    if upgrade_status.has_key('rollback'):
        rollback = upgrade_status.get('rollback')
    # Verify all se group status
    verify_segroup_upgrade_status(rollback, se_status.get('se_group_status'), total_se, se_status.get('se_upgrade_completed'))

    # Verify upgrade SE complete
    if total_se != len(se_status.get('se_upgrade_completed', [])):
        logger_utils.fail("Total SE are %s not match with upgrade completed se %s" % (
        total_se, len(se_status.get('se_upgrade_completed', []))))


def verify_upgrade(previous_version, upgrade_should_be_successful=True, stage=None, omit_version_check=False):
    """ Verifications:
        1. Check upgrade status
        2. Check upgrade state
        3. Check version on every controller and se
    """
    infra_utils.clear_session(all_sessions=True)
    stage = None if stage == 'None' else stage
    #status_obj = get_upgrade_status()
    status_code, status_obj = rest.get(CLUSTER_UPGRADE_STATUS_URL)
    logger.debug('Upgrade status response: %s' % status_obj)
    if (status_obj['in_progress'] is True):
        logger_utils.fail('Upgrade still in progress')
    if (status_obj['controller_state']['state'] != 'UPGRADE_COMPLETED' and
                status_obj['controller_state']['state'] != 'UPGRADE_ABORTED'):
        logger_utils.fail('Controller upgrade status != COMPLETED/ABORTED')
    if (status_obj['controller_state']['state'] == 'UPGRADE_COMPLETED' and
                status_obj['se_state']['state'] != 'SE_UPGRADE_COMPLETE'):
        logger_utils.fail('SE upgrade status != SE_UPGRADE_COMPLETE')
    # if(stage != None and stage != status_obj.get('controller_state').get('tasks_completed')[-1].get('task') ):
    #    logger_utils.fail('Controller expected to complete only %s stage(s) but aborted at %s' %(stage, status_obj.get('controller_state').get('tasks_completed')[-1].get('task')))

    #duration = datetime.strptime(status_obj['end_time'], "%Y-%m-%d %H:%M:%S.%f") - datetime.strptime(status_obj['start_time'], "%Y-%m-%d %H:%M:%S.%f")
    #if status_obj['duration'] != duration.seconds:
    #    logger_utils.fail('Duration not match for Upgrade status')
    versions = [get_version(vm)
                for vm in (infra_utils.get_vm_of_type('controller') +
                           infra_utils.get_vm_of_type('se'))]
    try:
        logger.info("###Verify controller state")
        verify_controller_state(status_obj, previous_version, versions[0], upgrade_should_be_successful)
        verify_seupgrade_status(status_obj, upgrade_should_be_successful)
    except Exception as e:
        logger.debug(traceback.format_exc())
        logger_utils.fail('Failed with error: %s' % str(e))

    if omit_version_check:
        return

    current_version = versions[0]
    logger.debug("versions:%s" % versions)
    for ver in versions:
        if ver != current_version:
            logger_utils.fail('Not all controllers and SEs are on the same '
                              'version. Excepted version: %s, got: %s' %
                               (current_version, ver))
        '''
        if previous_version and ver == previous_version:
            raise UpgradeError('Found a VM that does not seem to be upgraded. '
                               'Its version has not changed.')
        '''
        if upgrade_should_be_successful is True:
            if ver == previous_version:
                logger_utils.fail('Found a VM that does not seem to be '
                                  'upgraded. Its version [%s] has not '
                                  'changed.' % ver)
        else:
            if ver != previous_version:
                logger_utils.fail('Found a VM that got upgraded. Its version '
                                  '[%s] has changed.' % ver)

