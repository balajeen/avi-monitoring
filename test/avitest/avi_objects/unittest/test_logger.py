import pytest
from avi_objects.logger import logger, FailError, ForcedFailError, ErrorError, AbortError
import avi_objects.logger_utils as logger_utils

class TestLogger(object):

    def test_logger(self):
        """ Test log error """
        logger.info("\n %s \n #               I am INFO log             #\n %s " % ( '#' * 60, '#' * 60))
        logger.warning("\n %s \n #               I am WARNING log             #\n %s " % ( '#' * 60, '#' * 60))
        logger.debug("\n %s \n #               I am DEBUG             #\n %s " % ( '#' * 60, '#' * 60))
        logger.trace("\n %s \n #               I am TRACE             #\n %s " % ( '#' * 60, '#' * 60))

    def test_parameterized_logger(self):
        a = 'hello'
        b = 'world'
        logger.info('info: %s %s', a, b)
        logger.warning('warn: %s %s', a, b)
        logger.debug('debug: %s %s', a, b)
        logger.trace('trace: %s %s', a, b)

    def test_fail(self):
        logger.info('Testing %s method in logger_utils', 'fail')
        try:
            logger_utils.fail("Testing %s method in logger_utils", 'fail')
        except FailError as e:
            if e.msg != "Testing fail method in logger_utils":
                assert 0, "logger_utils.fail not working as expected"
        else:
            assert 0, "logger_utils.fail not working as expected"

        try:
            logger_utils.fail("Testing %s method in logger_utils", 'fail', force=True)
        except ForcedFailError as e:
            if e.msg != "Testing fail method in logger_utils":
                assert 0, "logger_utils.fail not working as expected"
        else:
            assert 0, "logger_utils.fail not working as expected"

    def test_error(self):
        logger.info('Testing %s method in logger_utils', 'error')
        temp = logger._log
        logger._log = False
        try:
            logger_utils.error("Testing %s method in logger_utils", 'error')
        except ErrorError as e:
            logger._log = temp
            if e.msg != "Testing error method in logger_utils":
                logger_utils.fail("logger_utils.error not working as expected")
        else:
            logger._log = temp
            logger_utils.fail("logger_utils.error not working as expected")

    def test_verify(self):
        logger.info('Testing %s method in logger_utils', 'verify')
        logger_utils.verify(1 == 1, 'verify if %s == %s', 1, 1)
        logger_utils.verify(1 == 2, 'verify if %s == %s, This should fail', 1, 2)

    def test_abort(self):
        logger.info('Testing %s method in logger_utils', 'abort')
        try:
            logger_utils.abort("Testing %s method in logger_utils", 'abort')
        except AbortError as e:
            if e.msg != "Testing abort method in logger_utils":
                logger_utils.fail("logger_utils.abort not working as expected")
        else:
            logger_utils.fail("logger_utils.abort not working as expected")
        logger_utils.abort('Testing abort - This test passed if you are seeing aborterror and no more tests run after this')

    def test_test_after_abort(self):
        logger_utils.fail("Test continuing after abort")
