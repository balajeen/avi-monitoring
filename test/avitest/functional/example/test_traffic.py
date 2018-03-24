from avi_objects.infra_imports import *
import pytest
from random import randint
import time


@pytest.fixture(autouse=True)
def initialize(avi_setup,request):
   request.function.func_globals['client'] = get_vm_of_type('client')[0]

@pytest.fixture(scope="module")
def setup_suite(request):
    logger.info("IN Setup")
    yield "setup_suite"
    logger.info("In Cleanup")

vport=8000
class TestTraffic(object):
    """ Traffic related Unit Test cases """

    def test_create(self):
        """ Create Config """
        setup_cloud(wait_for_cloud_ready=True)
        create_config('test_api_config.json')
        logger.report_errors()

    def test_requests_basic(self,setup_suite):
        """ Request with basic params """
        #Traffic parms
        kwargs = {
            'vs_names':['vs-1'],
            'vport':vport,
            'print_body':True,
            'uri':['/echo_listen_port']
        }
        traffic_obj, output = request(**kwargs)
        logger.info("echo_listen_port URI Output: %s " % output)
        if str(vport) not in output[0].values():
            error("/echo_listen_port URI Did not went through fine")

    def test_requests_with_custom(self,setup_suite):
        """ Request with basic params URLs, custom URLs and Body Print """
        kwargs = {
            'vs_names':['vs-1'],
            'vport':vport,
            'custom':'/echo_http_host 4',
            'uri':['/index.html'],
        }
        traffic_obj, output = request(**kwargs)
        traffic_stop()
        logger.report_errors()

    def test_requests_with_body_contains(self,setup_suite):
        """ Request with basic params URLs, custom URLs and Body Print """
        kwargs = {
            'vs_names':['vs-1'],
            'vport':vport,
            'print_body':True,
            'uri':['/index.html'],
            'body_contains':'Welcome'
        }
        traffic_obj, output = request(**kwargs)
        traffic_stop()
        logger.report_errors()

    def test_requests_with_prints(self, setup_suite):
        """ Request with print params """
        kwargs = {
            'vs_names':['vs-1'],
            'vport':vport,
            'print_body':True,
            'print_headers':True,
            'uri':['/echo_server'],
        }
        traffic_obj, output = request(**kwargs)
        traffic_stop()
        logger.report_errors()

    def test_continuous_traffic(self,setup_suite):
        """
        Traffic Test with infinet number of requests i,e continuous
        """
        logger.info('Test Traffic in continuous Mode')
        kwargs = { 'vs_names':['vs-1']}
        traffic_obj = traffic_start(**kwargs)
        time.sleep(5)
        traffic_expect_no_errors(traffic_obj, vs_names=['vs-1'], internal_traffic_check=False)
        traffic_get_stats(traffic_obj)
        traffic_stop()

    def test_continuous_traffic_defautl(self,setup_suite):
        """
        Traffic Test with infinet number of requests i,e continuous
        """
        logger.info('Test Traffic in continuous Mode with no VS Parmas ')
        traffic_obj = traffic_start()
        time.sleep(5)
        traffic_expect_no_errors(traffic_obj)
        traffic_get_stats(traffic_obj)
        traffic_stop()
        logger.report_errors()

    def test_continuous_traffic_with_multi_vs(self,setup_suite):
        """ Traffic Test with Diffrent type of Virtual Services """
        #vs_names = ['vs-1:0','vs-2:0', 'vs-3', 'z-foo']
        vs_names = ['vs-1:0','vs-2:0', 'vs-3', 'vs-4']
        kwargs = { 'vs_names':vs_names}
        traffic_obj = traffic_start(**kwargs)
        time.sleep(10)
        traffic_expect_no_errors(traffic_obj, vs_names=vs_names, internal_traffic_check=False)
        traffic_expect_no_errors(traffic_obj, vs_names=vs_names, skip_vs_list=['vs-5'], internal_traffic_check=False)
        traffic_get_stats(traffic_obj)
        traffic_stop()
        logger.report_errors()

    def test_traffic_with_fixture(self,setup_suite, traffic_test_case):
        """ Traffic  with fixture"""
        print_str = "\n"+"*"*40
        logger.info("\t%s\n\t* Traffic is running - api unit test case *\n\t%s" % (print_str,print_str))

    def test_curl(self, setup_suite):
        """ CURL Traffic Test case """
        start_curl(vs_name='vs-1', vport=vport, client_range='c1', uri='/echo_listen_port')
        stop_curl()
        logger.report_errors()

    def test_cmd_exec_on_client(self,setup_suite):
        """ Command execution on client """

        logger.info("*******  Command execution on client *******")
        logger.info(client)
        out = client.execute_command('ls -l')
        logger.info("Command output: \n%s" %''.join(out))

    def test_get_all_virtualservices(self,setup_suite):
        """
        Traffic Test with finet number of requests
        """
        staus_code, resp = get('virtualservice')

        vs_obj_list = resp['results']

        for vs_obj in vs_obj_list:
            logger.info(" >>> VS Name: %s  <<<" % vs_obj['name'])

    def test_delete_config(self):
         """ Delete Config """
         delete_config('test_api_config.json')

