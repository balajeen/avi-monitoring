from avi_objects.infra_imports import *
import pytest


@pytest.fixture(autouse=True)
def initialize(avi_setup,request):
   request.function.func_globals['ctrl_vm'] = get_vm_of_type('controller')[0]

@pytest.fixture(scope="module")
def setup_suite(request):
    logger.info("IN Setup")
    setup_cloud()
    yield "setup_suite"
    logger.info("In Cleanup")

class TestL7Config(object):

    def test_config(self,setup_suite):
        logger.info("In Test Case")
        logger.info(ctrl_vm)
        out = ctrl_vm.execute_command('ls -l')
        logger.info("OUT = %s" %out)
        _, resp = get('virtualservice')
        logger.info("Response %s " %resp)
        logger.info(get_mode())
        switch_mode(tenant='foo')
        logger.info(get_mode())
        logger.info("OUT = %s" %out)
        _, resp = get('virtualservice', check_status_code=False)
        logger.info("Response %s " %resp)
        verify(1 == 2, 'one is not two')
        logger.report_errors()

    def test_case_2(self,setup_suite):
        switch_mode(tenant='admin')
        logger.info("In Test Case")
        logger.info(ctrl_vm)
        out = ctrl_vm.execute_command('ls -l')
        logger.info("OUT = %s" %out)
        _, resp = get('virtualservice')
        logger.info("Response %s " %resp)
        logger.info(get_mode())

    def test_case_3(self,setup_suite):
        switch_mode(tenant='admin')
        logger.info("In Test Case")
        logger.info(ctrl_vm)
        out = ctrl_vm.execute_command('ls -l')
        logger.info("OUT = %s" %out)

    def test_case_4(self,setup_suite):
        switch_mode(tenant='admin')
        logger.info("In Test Case")
        logger.info(ctrl_vm)
        out = ctrl_vm.execute_command('ls -l')
        logger.info("OUT = %s" %out)

