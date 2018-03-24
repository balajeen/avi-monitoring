import pytest

class ParentTest(object):

    def test_mode(self, mode):
        clsname = self.__class__.__name__
        print 'Test class %s using mode %s' %(clsname, mode)
        if clsname == 'Test_Mode_A':
            assert mode == 'A'
        elif clsname == 'Test_Mode_B':
            assert mode == 'B'
        else:
            raise RuntimeError('unknown clsname %s with mode %s' %(clsname, mode))

class Test_Mode_A(ParentTest):
    @pytest.fixture()
    def mode(self):
        return 'A'

class Test_Mode_B(ParentTest):
    @pytest.fixture()
    def mode(self):
        return 'B'

