from avi_objects.logger import logger

class Test_Class_A(object):

    def test_method_A(self):
        logger.info('class A, test method A')

def test_method_B():
    logger.info('no class, test method B between A and C')

class Test_Class_C(object):

    def test_method_C(self):
        logger.info('class C, test method C')

def test_method_D():
    logger.info('no class, test method D after A-B-C')


