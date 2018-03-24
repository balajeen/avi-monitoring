from globals import *
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

    def test_example(self,setup_suite):
        logger.info("In Test Case")
        logger.info(ctrl_vm)
        out = ctrl_vm.execute_command('ls -l')
        logger.info("OUT = %s" %out)
        resp = get('cluster')
        error("I FAILED")
        asleep('Wait for 10 sec', delay=1)
        b = check_retry()
        logger.info(b)
        logger.warn('DONE')
    def test_case_example_2(self,setup_suite):
        switch_mode(tenant='admin')
        logger.info('TEST CASE 2')


@aretry(retry=3, delay=5)
def check_retry():
     b = randint(0,9)
     logger.info('b = %s' %b)
     if b > 10:
         return 'Success'
     else:
         error('b is not 5')
