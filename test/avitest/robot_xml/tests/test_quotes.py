from avi_objects.logger import logger

import pytest

class Test_Quotes(object):
    """
    Test quotes in test case names
    """
    @pytest.mark.parametrize("input",
                             [("input1 with quote \"id:'1000'\""),
                              ('input2 with quote "id:\'1001\'"')
                             ])
    def test_quote_in_params(self, input):
        logger.info('got input %s' %input)

    def test_quote_in_log(self):
        logger.info('"hello" \'world\'')
