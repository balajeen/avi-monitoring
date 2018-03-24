from globals import *
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

class TestLogger(object):

    def test_logger(self,setup_suite):
        """ Test log error """
        logger.info("\n %s \n #               I am INFO log look like this             #\n %s " % ( '#' * 60, '#' * 60))
        logger.warn("\n %s \n #               I am WARING log look like this             #\n %s " % ( '#' * 60, '#' * 60))
        logger.debug("\n %s \n #               I am DEBUG log look like this             #\n %s " % ( '#' * 60, '#' * 60))

    def test_error(self,setup_suite):
        """ Test log error """
        logger.info(" Test log error Started")
        self.abc_test_logger()
        logger.info(" i am after internal method still i am continoue")
        if 1!=2:
            error(" Test Error: One is not Equal to Two")

        logger.report_errors()

    def abc_test_logger(self):
        logger.info(" I am in ABC Test Logger")
        error(" Error Function: Test logger")
        logger.info(" After Error Function : Still Test contunoiuse")

    def test_fail(self,setup_suite):
        """ Test Fail in logger """
        logger.info(' Going to call Fail so i will exit from complete Test case ')
        fail("I am  Faling here ")
        logger.info(" After Fail statement -1  -Coming ")
        logger.info(" After Fail statement -2  -Coming ")
        logger.info(" After Fail statement -3  -Coming ")
        logger.info(" After Fail statement -4  -Coming ")

    def test_abort(self,setup_suite):
        """ Test Abort in logger """
        logger.info(' Going to call Abort so i will exit from complete suite ')
        abort("I am aborting here ")
        logger.info(" After Abort statemnt -1 coming")

    def test_test_after_abort(self):
        logger.info(" after the abort still tcs are exectuting ")






