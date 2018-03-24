from avi_objects.infra_imports import *
import pytest
from random import randint


@pytest.fixture(autouse=True)
def initialize(avi_setup,request):
   request.function.func_globals['ctrl_vm'] = get_vm_of_type('controller')[0]

@pytest.fixture(scope="module")
def setup_suite(request):
    logger.info("IN Setup")
    yield "setup_suite"
    logger.info("In Cleanup")

class TestL7Config(object):

    def test_create(self):
        setup_cloud(wait_for_cloud_ready=True)
        create_config('test_api_config1.json')

    def test_api(self,setup_suite):
        logger.info("In Test Case")
        logger.info(ctrl_vm)
        out = ctrl_vm.execute_command('ls -l')
        logger.info("OUT = %s" %out)
        status_code, json = get('cluster')
        logger.info("Response %s, %s" %(status_code, json))

    def test_case_example_2(self,setup_suite):
        switch_mode(tenant='admin')
        logger.info('TEST CASE 2')

    def test_ignore_deleted(self):
        delete('virtualservice', 'nonexistent_vs_uuid', check_status_code=False)

    def test_teardown(self):
        delete_config('test_api_config1.json')

