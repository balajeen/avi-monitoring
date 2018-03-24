import pytest
import random
from avi_objects.infra_utils import setup_cloud, create_config, delete_config, get_vm_of_type, get_config, get_vm_cloud_sdkconn
from avi_objects.logger import logger
from avi_objects.rest import get, ApiNode, create_session, switch_session
from lib.cluster_lib import get_cluster_master_vm, wait_until_cluster_ready, get_node_role
from avi_objects.cluster import wait_until_n_cluster_nodes_ready

@pytest.fixture(scope='module', autouse=True)
def all_sessions(request):
    controllers = get_vm_of_type('controller')
    sessions={}
    for controller in controllers:
        sessions[controller.name] = create_session(controller=controller)
    return sessions


class Test_Controller(object):

    def test_disconnect_random_controller(self, request):
        '''
        This test case explains how an user can switch their session to
        different controller after a controller goes down
        '''
        controller_vm = random.choice(get_vm_of_type('controller')) # Get random controller
        logger.info("name of the controller going down " + controller_vm.name)
        get_vm_cloud_sdkconn(controller_vm.name).poweroff()

        # This api establishes session to a new random controller which is up and running
        switch_session(down_vm=controller_vm)

        # Need to wait untill cluster comes up. Because if the controller
        # brought down is leader controller cluster takes around a minute to elect new leader
        wait_until_n_cluster_nodes_ready(n=2)

        out, resp_code = get('initial-data') # test the new session
        get_vm_cloud_sdkconn(controller_vm.name).poweron()
        wait_until_n_cluster_nodes_ready()

    def test_disconnect_master_controller(self, request):
        '''
        This test case explains how an user can bring their leader
        controller down and perform a switch session
        '''
        controller_vm = get_cluster_master_vm() # Get the master_controller vm
        logger.info("name of the controller going down " + controller_vm.name)
        get_vm_cloud_sdkconn(controller_vm.name).poweroff()
        switch_session(down_vm=controller_vm)
        wait_until_n_cluster_nodes_ready(n=2)
        out, resp_code = get('initial-data') # test the new session
        get_vm_cloud_sdkconn(controller_vm.name).poweron()
        wait_until_n_cluster_nodes_ready()

    def test_disconnect_follower_controller(self, request):
        '''
        This test case explains how an user can bring one of the follower node down
        and perform a switch session
        '''
        for controller in get_vm_of_type('controller'):
            if get_node_role(controller.ip) == "CLUSTER_FOLLOWER":
                controller_vm = controller
                break
        logger.info("name of the controller going down " + controller_vm.name)
        get_vm_cloud_sdkconn(controller_vm.name).poweroff()
        switch_session(down_vm=controller_vm)
        wait_until_n_cluster_nodes_ready(n=2)
        out, resp_code = get('initial-data') # test the new session
        get_vm_cloud_sdkconn(controller_vm.name).poweron()
        wait_until_n_cluster_nodes_ready()

    def test_disconnect_two_controller_nodes(self, request):
        controller_vm_1, controller_vm_2 = get_vm_of_type('controller')[:2]
        logger.info("name of the controllers going down " + controller_vm_1.name + " " +  controller_vm_2.name)
        get_vm_cloud_sdkconn(controller_vm_1.name).poweroff()
        get_vm_cloud_sdkconn(controller_vm_2.name).poweroff()
        switch_session(down_vm=[controller_vm_1, controller_vm_2])
        try:
            wait_until_n_cluster_nodes_ready(n=1)
            fail("Cluster is not supposed to be up")
        except:
            logger.info("Failed as expected")
        get_vm_cloud_sdkconn(controller_vm_1.name).poweron()
        wait_until_n_cluster_nodes_ready(n=2)
        out, resp_code = get('initial-data')
        get_vm_cloud_sdkconn(controller_vm_2.name).poweron()
        wait_until_n_cluster_nodes_ready()

    def test_reboot_two_controller_nodes(self, request):
        controller_vm_1, controller_vm_2 = get_vm_of_type('controller')[:2]
        logger.info("name of the controllers going down " + controller_vm_1.name + " " +  controller_vm_2.name)
        get_vm_cloud_sdkconn(controller_vm_1.name).poweroff()
        get_vm_cloud_sdkconn(controller_vm_1.name).poweron()
        get_vm_cloud_sdkconn(controller_vm_2.name).poweroff()
        get_vm_cloud_sdkconn(controller_vm_2.name).poweron()
        switch_session(down_vm=[controller_vm_1, controller_vm_2])
        wait_until_cluster_ready()
        out, resp_code = get('initial-data')
        wait_until_n_cluster_nodes_ready()

    def test_session_with_each_controller(self, all_sessions):
        '''
        This testcase shows how to maintain sessions to different clusters 
        in the controller and work with them
        '''
        config = get_config()
        controllers = get_vm_of_type('controller')
        for controller in controllers:
            config.switch_mode(session=all_sessions[controller.name])
            out, resp_code = get('initial-data')
            logger.info("switch_mode session "+str(config.get_mode(key='session')))
        config.switch_mode(session=None)

