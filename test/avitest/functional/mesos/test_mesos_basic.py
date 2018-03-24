import pytest
import urllib3

# avitest infra libraries
from avi_objects.logger import logger

import avi_objects.infra_utils as infra_utils
import avi_objects.logger_utils as logger_utils
import avi_objects.traffic_manager as traffic_manager
import lib.se_lib as se_lib
import lib.ms_lib as ms_lib
import lib.metrics_lib as metrics_lib
import lib.vs_lib as vs_lib
import lib.mesos_lib as mesos_lib
import lib.controller_metrics_testlib as controller_metrics_testlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Test_MesosBasic(object):
    config_file = 'mesos_basic.json'
    app_prefix = 'ma1'
    num_apps = 12
    northsouth = 2
    num_edges = 15
    public_port_range_start = 10000
    dns_vs = 'container-dns-vs'
    dns_vs_vip = ''

    def setup_method(self, method):
        """called before every test method invocation"""
        pass

    def teardown_method(self, method):
        """called after every test method invocation"""
        logger.report_errors()

    def get_default_pool_obj(self):
        pool_obj = {}
        pool_obj[
            'autoscale_launch_config_ref'] = '/api/autoscalelaunchconfig?name\=default-autoscalelaunchconfig'
        pool_obj['lb_algorithm'] = 'LB_ALGORITHM_FEWEST_SERVERS'
        pool_obj['capacity_estimation'] = True
        pool_obj['capacity_estimation_ttfb_thresh'] = 10
        return pool_obj

    @pytest.mark.setup
    def test_setup(self):
        infra_utils.create_config(self.config_file)
        mesos_lib.delete_all_apps()
        # Create Cloud
        mesos_lib.setup_container_cloud()

    def test_create_clients(self):
        traffic_manager.create_clients(1, 'c', 'net1', 'httperf')

    def test_se_creation(self):
        mesos_lib.check_ses_on_all_slaves()

    def test_create_dns_vs_if_appropriate(self):
        if mesos_lib._is_aws_testbed() or mesos_lib._is_openstack_testbed():
            # see AV-15393
            return
        else:
            infra_utils.create_config('container_dns_vs.json')
            self.dns_vs_vip = mesos_lib.get_dns_vs_vip_if_exists(self.dns_vs)
            logger.info('got dnsvsvip = %s' %self.dns_vs_vip)

    def test_basic_traffic_setup(self):
        start_index = self.public_port_range_start + 1000

        tenant = mesos_lib.get_tenant_for_container()
        infra_utils.switch_mode(tenant=tenant)
        mesos_lib.create_app(self.app_prefix, num_apps=self.num_apps,
                             num_instances=1, northsouth=self.northsouth,
                             ns_service_port=80,
                             ew_service_port_start_index=start_index,
                             network='net1')

    def test_dns(self):
        vs_list = [self.app_prefix + '-1', self.app_prefix + '-2',
                   self.app_prefix + '-3', self.app_prefix + '-4',
                   self.app_prefix + '-5', self.app_prefix + '-6']
        tenant = mesos_lib.get_tenant_for_container()
        infra_utils.switch_mode(tenant=tenant)        
        # REVIEW why is this commented out?
        vs_lib.check_for_vs(vs_list, verify_dns=True, dns_vs_vip=self.dns_vs_vip)

    def test_update_profiles(self):
        vs_1 = 'ma1-1'
        vs_2 = 'ma1-2'

        tenant = mesos_lib.get_tenant_for_container()
        infra_utils.switch_mode(tenant=tenant)
        # Update apps to different app and nw profiles (1 NS and 1 EW)
        mesos_lib.update_app_app_profile(vs_1, 'test-app-profile')
        mesos_lib.update_app_nw_profile(vs_1, 'test-nw-profile')
        mesos_lib.update_app_app_profile(vs_2, 'test-app-profile')
        mesos_lib.update_app_nw_profile(vs_2, 'test-nw-profile')

        # Change apps' profiles to earlier ones: System-HTTP, System-TCP-Proxy
        mesos_lib.update_app_app_profile(vs_1, 'System-HTTP')
        mesos_lib.update_app_nw_profile(vs_1, 'System-TCP-Proxy')
        mesos_lib.update_app_app_profile(vs_2, 'System-HTTP')
        mesos_lib.update_app_nw_profile(vs_2, 'System-TCP-Proxy')

    def test_traffic_1(self):
        # traffic_manager.create_clients(1, 'c', 'net1', 'httperf')
        msvc_map = mesos_lib.create_erdos_renyi_graph(self.app_prefix,
                                                      self.num_apps, None,
                                                      self.num_edges,
                                                      ip_client='c1',
                                                      northsouth=self.northsouth)

        mesos_lib.generate_microservice_traffic(msvc_map, load=1)
        start_time = mesos_lib.generate_microservice_traffic(msvc_map)
        logger_utils.asleep(delay=15)
        mesos_lib.validate_microservice_traffic(msvc_map, start_time)

    def test_license_sanity(self):
        se_list = se_lib.get_connected_se_names()
        se_len = len(se_list)
        se_count = str(se_len)
        controller_metrics_testlib.license_api_sanity(expected_num_ses=se_count)

    def test_check_realtime_traffic(self):
        # traffic_manager.create_clients(1, 'c', 'net1', 'httperf')
        mesos_lib.set_mesos_rt_collection(rt_flag=True)
        # sleep for the default collection period until the new period kicks in
        logger_utils.asleep(delay=60)
        # Generate traffic
        adj_list = []
        mesos_lib.add_edge(adj_list, 'c1', 'ma1-1', src_type='vm', load=20000)

        msvc_map = mesos_lib.create_microservice_map(adj_list)
        start_time = mesos_lib.generate_microservice_traffic(msvc_map,
                                                             load=20000)
        logger_utils.asleep(delay=5)
        ma1_1_pool = mesos_lib.get_pool_name_with_tenant('ma1-1')
        metrics_lib.metrics_check_poolvm_container(ma1_1_pool, step=5, limit=12,
                                                   mbaseline=0)
        mesos_lib.set_mesos_rt_collection(rt_flag=False)

    def test_traffic_cleanup(self):
        tenant = mesos_lib.get_tenant_for_container()
        infra_utils.switch_mode(tenant=tenant)
        mesos_lib.delete_app(self.app_prefix, num_apps=self.num_apps,
                             dns_suffix='avi-container-dns.internal',
                             verify_dns=True,
                             dns_vs_vip=self.dns_vs_vip)

    @pytest.mark.auth
    def test_token_authenticated_traffic_setup(self):
        start_index = self.public_port_range_start + 2000
        mesos_lib.create_app('auth1', num_apps=self.num_apps, num_instances=1,
                             northsouth=self.northsouth,
                             auth_type='token', ns_service_port=80,
                             ew_service_port_start_index=start_index,
                             network='net1', verify_dns=True,
                             dns_vs_vip=self.dns_vs_vip)

    @pytest.mark.auth
    def test_token_authenticated_traffic(self):
        # traffic_manager.create_clients(1, 'c', 'net1', 'httperf')
        msvc_map = mesos_lib.create_erdos_renyi_graph('auth1', self.num_apps,
                                                      None, self.num_edges,
                                                      ip_client='c1',
                                                      northsouth=self.northsouth)
        mesos_lib.generate_microservice_traffic(msvc_map, auth_type='token',
                                                load=1)
        start_time = mesos_lib.generate_microservice_traffic(msvc_map,
                                                             auth_type='token')
        logger_utils.asleep(delay=15)
        mesos_lib.validate_microservice_traffic(msvc_map, start_time)

    @pytest.mark.auth
    def test_token_authenticated_bad_pwd(self):
        mesos_lib.get_app_bad_auth('auth1-1', auth_type='token',
                                   bad_username='admin',
                                   bad_password='badpassword')

    @pytest.mark.auth
    def test_token_authenticated_bad_no_credentials(self):
        mesos_lib.get_app_bad_auth('auth1-1', auth_type='token',
                                   bad_username='', bad_password='')

    @pytest.mark.auth
    def test_token_authenticated_traffic_cleanup(self):
        mesos_lib.delete_app('auth1', num_apps=self.num_apps, auth_type='token',
                             dns_suffix='avi-container-dns.internal',
                             verify_dns=True,
                             dns_vs_vip=self.dns_vs_vip)

    @pytest.mark.auth
    def test_multiple_marathon_setup(self):
        mara1_start_index = self.public_port_range_start + 2500
        mara2_start_index = self.public_port_range_start + 2600

        mesos_lib.create_app('mara1', num_apps=3, num_instances=1, northsouth=1,
                             ns_service_port=80,
                             ew_service_port_start_index=mara1_start_index,
                             network='net1')
        mesos_lib.create_app('mara2', num_apps=3, num_instances=1, northsouth=1,
                             auth_type='token',
                             ns_service_port=80,
                             ew_service_port_start_index=mara2_start_index,
                             network='net1')

    @pytest.mark.auth
    def test_multiple_marathon_traffic(self):
        adj_list = []
        mesos_lib.add_edge(adj_list, 'mara1-1', 'mara2-1')
        mesos_lib.add_edge(adj_list, 'mara1-3', 'mara2-2')
        mesos_lib.add_edge(adj_list, 'mara1-2', 'mara2-3')
        mesos_lib.add_edge(adj_list, 'mara2-3', 'mara1-1')
        mesos_lib.add_edge(adj_list, 'mara2-2', 'mara1-2')
        mesos_lib.add_edge(adj_list, 'mara2-1', 'mara1-3')
        mesos_lib.add_edge(adj_list, 'c1', 'mara1-1', src_type='vm')
        mesos_lib.add_edge(adj_list, 'c1', 'mara2-1', src_type='vm')

        msvc_map = mesos_lib.create_microservice_map(adj_list)
        mesos_lib.generate_microservice_traffic(msvc_map, auth_type='hybrid',
                                                load=1)
        start_time = mesos_lib.generate_microservice_traffic(msvc_map,
                                                             auth_type='hybrid')
        logger_utils.asleep(delay=15)
        mesos_lib.validate_microservice_traffic(msvc_map, start_time)

    @pytest.mark.auth
    def test_multiple_marathon_cleanup(self):
        mesos_lib.delete_app('mara1', num_apps=3)
        mesos_lib.delete_app('mara2', num_apps=3, auth_type='token')

    def test_traffic_with_security_policy_setup(self):
        start_index = self.public_port_range_start + 3000

        tenant = mesos_lib.get_tenant_for_container()
        infra_utils.switch_mode(tenant=tenant)
        mesos_lib.create_app('t2', num_apps=6, num_instances=1,
                             northsouth=self.northsouth,
                             ns_service_port=80,
                             ew_service_port_start_index=start_index,
                             network='net1', verify_dns=True,
                             dns_vs_vip=self.dns_vs_vip)
        ms_lib.add_security_policy_to_vs('t2-1', ms_name=['t2-2-microservice',
                                                          't2-3-microservice'],
                                         policy_name='t2-1-networksecuritypolicy',
                                         deny=1)
        ms_lib.add_security_policy_to_vs('t2-2', ms_name=['t2-4-microservice',
                                                          't2-5-microservice'],
                                         policy_name='t2-2-networksecuritypolicy',
                                         deny=0)
        vs_lib.create_application_obj('app1')
        vs_lib.create_application_obj('app2')
        vs_lib.add_vs_to_application('app1', ['t2-1', 't2-2'])
        vs_lib.add_vs_to_application('app2', ['t2-4', 't2-5'])

    def test_traffic_with_security_policy(self):
        # traffic_manager.create_clients(1, 'c', 'net1', 'httperf')
        adj_list = []
        blocked = True
        mesos_lib.add_edge(adj_list, 't2-1', 't2-2', blocked=blocked)
        mesos_lib.add_edge(adj_list, 't2-1', 't2-3')
        mesos_lib.add_edge(adj_list, 't2-1', 't2-4')
        mesos_lib.add_edge(adj_list, 't2-2', 't2-1', blocked=blocked)
        mesos_lib.add_edge(adj_list, 't2-2', 't2-4')
        mesos_lib.add_edge(adj_list, 't2-3', 't2-1', blocked=blocked)
        mesos_lib.add_edge(adj_list, 't2-4', 't2-2')
        mesos_lib.add_edge(adj_list, 't2-5', 't2-2')

        msvc_map = mesos_lib.create_microservice_map(adj_list)
        mesos_lib.generate_microservice_traffic(msvc_map, load=1)
        start_time = mesos_lib.generate_microservice_traffic(msvc_map)
        logger_utils.asleep(delay=15)
        mesos_lib.validate_microservice_traffic(msvc_map, start_time)

    def test_traffic_with_security_policy_cleanup(self):
        tenant = mesos_lib.get_tenant_for_container()
        infra_utils.switch_mode(tenant=tenant)
        vs_lib.delete_application_obj('app1')
        vs_lib.delete_application_obj('app2')
        mesos_lib.delete_app('t2', num_apps=6,
                             dns_suffix='avi-container-dns.internal',
                             verify_dns=True,
                             dns_vs_vip=self.dns_vs_vip)
        # these msg were created as part of add_security_policy_to_vs; should be deleted now
        ms_lib.delete_microservice_group('vs-msg-t2-1')
        ms_lib.delete_microservice_group('vs-msg-t2-2')

    @pytest.mark.attribute
    def test_slave_attribute_traffic_setup(self):
        start_index1 = self.public_port_range_start + 4000
        constraint_1 = ['name', 'CLUSTER', 'slave1']
        constraint_list1 = [constraint_1]
        start_index2 = self.public_port_range_start + 4001
        constraint_2 = ['name', 'CLUSTER', 'slave2']
        constraint_list2 = [constraint_2]
        mesos_lib.create_app('attr-1', num_apps=1, num_instances=1,
                             northsouth=False,
                             ns_service_port=80,
                             ew_service_port_start_index=start_index1,
                             network='net1', constraints=constraint_list1)
        mesos_lib.create_app('attr-2', num_apps=1, num_instances=1,
                             northsouth=False,
                             ns_service_port=80,
                             ew_service_port_start_index=start_index2,
                             network='net1', constraints=constraint_list2)
        mesos_lib.verify_app_antiaffinity('attr-1', 'attr-2')
        mesos_lib.create_app('attr-3', num_apps=1, num_instances=1,
                             northsouth=True,
                             ns_service_port=80, network='net1',
                             constraints=constraint_list1)
        mesos_lib.create_app('attr-4', num_apps=1, num_instances=1,
                             northsouth=True,
                             ns_service_port=80, network='net1',
                             constraints=constraint_list2)

        mesos_lib.verify_app_antiaffinity('attr-3', 'attr-4')

    @pytest.mark.attribute
    def test_slave_attribute_traffic(self):
        # traffic_manager.create_clients(1, 'c', 'net1', 'httperf')
        adj_list = []
        mesos_lib.add_edge(adj_list, 'attr-1', 'attr-1')
        mesos_lib.add_edge(adj_list, 'attr-1', 'attr-2')
        mesos_lib.add_edge(adj_list, 'attr-1', 'attr-3')
        mesos_lib.add_edge(adj_list, 'attr-1', 'attr-4')

        mesos_lib.add_edge(adj_list, 'attr-3', 'attr-1')
        mesos_lib.add_edge(adj_list, 'attr-3', 'attr-2')
        mesos_lib.add_edge(adj_list, 'attr-3', 'attr-3')
        mesos_lib.add_edge(adj_list, 'attr-4', 'attr-4')

        # skipping attr-2 and attr-4 due to symmetry
        mesos_lib.add_edge(adj_list, 'c1', 'attr-3', src_type='vm')
        mesos_lib.add_edge(adj_list, 'c1', 'attr-4', src_type='vm')

        msvc_map = mesos_lib.create_microservice_map(adj_list)
        mesos_lib.generate_microservice_traffic(msvc_map, load=1)
        start_time = mesos_lib.generate_microservice_traffic(msvc_map)

        logger_utils.asleep(delay=15)

        mesos_lib.validate_microservice_traffic(msvc_map, start_time)

    @pytest.mark.attribute
    def test_slave_attribute_traffic_cleanup(self):
        mesos_lib.delete_app('attr', num_apps=4)

    def test_post_clean_any_lingering_apps(self):
        mesos_lib.delete_all_apps(verify_vs=True)

    def test_delete_configs(self):
        infra_utils.switch_mode(tenant='admin')
        mesos_lib.delete_dns_vs_if_needed(self.dns_vs)
        infra_utils.delete_config(self.config_file)

    @pytest.mark.teardown
    def test_delete_cloud(self):
        mesos_lib.remove_container_cloud_config()
