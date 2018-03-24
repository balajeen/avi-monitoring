'''
Usage:
=====
  Infra: AviTest
  Requirements: Testbed JSON file.
                (Example: $ws/test/avitest/functional/example/pytest_tb_tmp.json)
  Settings:
    export PYTHONPATH=$workspace/python/lib:$workspace/python/bin:$workspace/test/avitest

  Command to run:
      - cd ~/$ws/test/avitest/functional/example
      - pytest test_demo.py --testbed <tb_json file> \
        --loglevel DEBUG -v -s --robot_html test_demo.html
  Example cmd: pytest test_demo.py --testbed ./../../topo_confs/jay_pytb_17.json\
               --loglevel INFO -v -s --robot_html test_demo.html

  email: test-automation@avinetworks.com
'''
import pytest
import json
from avi_objects.logger_utils import fail
from avi_objects.infra_utils import (setup_cloud, create_config, delete_config,
                                    get_vm_of_type)
from avi_objects.logger import logger
from avi_objects.traffic_manager import request
import avi_objects.rest as rest
from avi_objects.test_fixtures import (traffic_test_case,
                                  cleanup_client_server)

@pytest.fixture(scope="module")
def setup_suite(request):
    logger.info("IN Setup")
    yield "setup_suite"
    logger.info("In Cleanup")

class TestDemo(object):
    """ Demo Test case """

    @pytest.mark.mandatory
    def test_setup(self, cleanup_client_server):
        """ Create Config """
        setup_cloud(wait_for_cloud_ready=True)
        create_config('test_api_config.json')

        logger.report_errors()

    def test_crud_demo(self):
        """ Create, Read, Update and Delete SE Group  """
        sg_name = 'demo_sg_group'
        # Create
        se_group = {}
        se_group['name'] = sg_name
        rest.post('serviceenginegroup', name=sg_name, data=json.dumps(se_group))
        # Read 
        _, resp = rest.get('serviceenginegroup', name=sg_name)
        # Update
        se_group = {}
        se_group['vs_host_redundancy'] = False
        _, resp = rest.update('serviceenginegroup', name=sg_name, **se_group)
        # Delete
        rest.delete('serviceenginegroup', name=sg_name)

    def test_get_all_virtualservices(self,setup_suite):
        staus_code, resp = rest.get('virtualservice')
        for vs_obj in resp['results']:
            logger.info(" *** VS Name: %s  ***" % vs_obj['name'])

        logger.report_errors()

    def test_requests_basic(self):
        """ Request with basic params """
        # Traffic parms
        kwargs = {
            'vs_names':['vs-1'],
            'vport':8000,
            'print_body':True,
            'print_length':True,
            'uri':['/echo_listen_port']
        }
        traffic_obj, output = request(**kwargs)
        logger.info("echo_listen_port URI Output: %s " % output)
        if '8000' not in output[0].values():
            error("/echo_listen_port URI Did not went through fine")

        logger.report_errors()

    def test_requests_with_prints(self, setup_suite):
        """ Request with print params """
        kwargs = {
            'vs_names':['vs-1'],
            'vport':8000,
            'print_body':True,
            'print_headers':True,
            'uri':['/echo_server'],
        }
        traffic_obj, output = request(**kwargs)

        logger.report_errors()

    def test_traffic_with_fixture(self,setup_suite, traffic_test_case):
        """ Traffic  with fixture"""
        print_str = "\n"+"*"*40
        logger.info("\t%s\n\t* Traffic is running - api unit test case *\n\t%s" % (print_str,print_str))

        # Check there should not be any errors on all VSs
        traffic_test_case.traffic_expect_no_errors()

    def test_vm_access(self):
        """ Accessing diff vm objects """
        controller_vms = get_vm_of_type('controller')
        logger.info("Controller VMs: %s" % controller_vms)
        logger.info("Controller VM details: Name:%s , IP: %s" % (controller_vms[0].name, controller_vms[0].ip))

        client_vms = get_vm_of_type('client')
        client_vm_obj = client_vms[0]
        logger.info("Client VMs: %s" % controller_vms)
        logger.info("Client VM details: Name:%s , IP: %s" % (client_vm_obj.name, client_vm_obj.ip))

        output = client_vm_obj.execute_command('uname -a')
        logger.info("Command output: \n%s" %''.join(output))

    def test_teardown(self, cleanup_client_server):
        """ Delete Config """
        delete_config('test_api_config.json', ignore_deleted=True)
        logger.report_errors()

