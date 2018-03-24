from avi_objects.infra_imports import *
import pytest
from random import randint
import time


@pytest.fixture(autouse=True)
def initialize(avi_setup,request):
   request.function.func_globals['ctrl_vm'] = get_vm_of_type('controller')[0]

@pytest.fixture(scope="module")
def setup_suite(request):
    logger.info("IN Setup")
    yield "setup_suite"
    logger.info("In Cleanup")

class TestSmoke(object):

    def test_create(self):
        """ Create Config """
        setup_cloud(wait_for_cloud_ready=True)
        create_config('test_api_config.json')
        setup_pool_server_configs()
        logger.report_errors()

    def test_traffic(self,setup_suite):
        """ Test Traffic """
        kwargs = {
            'vs_names':['vs-1'],
            'vport':8000,
            'print_body':True,
            'uri':['/echo_listen_port']
        }
        traffic_obj, output = request(**kwargs)
        logger.info("echo_listen_port URI Output: %s " % output)
        if '8000' not in output:
            error("/echo_listen_port URI Did not went through fine")
        traffic_stop(traffic_obj,clear_logs=False)

    def test_continuous_traffic(self,setup_suite):
        """
        Traffic Test with infinet number of requests i,e continuous
        """
        logger.info('Test Traffic in continuous Mode')
        kwargs = { 'vs_names':['vs-1', 'vs-2']}
        traffic_obj = traffic_start(**kwargs)
        logger.info('Waiting for 10 sec while traffic is flowing ...')
        time.sleep(10)
        traffic_expect_no_errors(traffic_obj, vs_names=['vs-1', 'vs-2'])
        traffic_get_stats(traffic_obj)
        traffic_stop()

    def test_get_all_virtualservices(self,setup_suite):
        """
        Traffic Test with finet number of requests
        """
        _, resp = get('virtualservice')
        vs_obj_list = resp['results']
        for vs_obj in vs_obj_list:
            logger.info(" >>> VS Name: %s  <<<" % vs_obj['name'])

    def test_delete_config(self):
        """ Delete Config """
        delete_config('test_api_config.json')
