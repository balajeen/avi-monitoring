import pytest

from avi_objects.logger import logger
from avi_objects.logger import FailError, ErrorError, AbortError
from avi_objects.logger_utils import fail, error, abort

class Test_Failures(object):
    """
    Test various failure mechanisms in avitest
    """

    fail_count = 0
    error_count = 0
    assert_count = 0

    def test_assert(self):
        ''' Test baseline python assert '''
        print self
        try:
            Test_Failures.assert_count = 1
            assert 1 == 2
            Test_Failures.assert_count = 2
        except AssertionError:
            logger.info('Got assertion triggered as expected')

    def test_assert_count(self):
        assert Test_Failures.assert_count == 1 # should have stopped before incrementing
        print 'assert count was 1 as expected'

    def test_fail(self):
        ''' fail() is noncontinuable exception '''
        logger.info('failing once')
        try:
            fail('failure 1')
            Test_Failures.fail_count += 1
        except FailError:
            logger.info('Caught FailError')
        logger.info('failing twice')
        try:
            fail('failure 2')
            Test_Failures.fail_count += 1
        except FailError:
            logger.info('Caught FailError')

    def test_fail_count(self):
        ''' since fail breaks out, we never increment '''
        assert Test_Failures.fail_count == 0
        logger.info('fail_count was 0 as expected')

    def test_error(self):
        ''' error() is continuable '''
        logger.info('error once')
        error('error 1')
        Test_Failures.error_count = 1
        logger.info('error twice')
        error('error 2')
        Test_Failures.error_count = 2
        logger.error_list = [] # reset to not actually fail

    def test_error_count(self):
        assert Test_Failures.error_count == 2
        logger.info('error count was 2 as expected')

    def test_abort(self):
        ''' TODO: how do we trap this yet still maintain the abort? '''
        logger.info('aborting')
        abort('aborted')

    def test_after_abort(self):
        ''' should get skipped due to the abort '''
        fail('did not abort and skip this method as expected')
