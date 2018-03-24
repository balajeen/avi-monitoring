from avi_objects.infra_imports import *
import pytest
import avi_objects.infra_utils

@pytest.fixture(scope='module')
def create_sdkconn(request):
    clients = avi_objects.infra_utils.get_vm_of_type('client')
    client_name = clients[0].name
    c1 = avi_objects.infra_utils.get_vm_cloud_sdkconn(client_name)
    return c1

class Test_Cloud(object):

    def test_poweroff(self, create_sdkconn):
        create_sdkconn.poweroff()
        
    def test_poweron(self, create_sdkconn):
        create_sdkconn.poweron()

    def test_get_available_AZs(self, create_sdkconn):
    
        a_zones = create_sdkconn.get_available_az()
        assert sorted(a_zones.keys()) == ['nova', 'testAZ']

    def test_clone_and_delete(self, create_sdkconn):

        create_sdkconn.clone('10.10.6.37', template='unittest', 
            clone_name='jenkins-avitest-cloudsdk-unittest-clone-deleteme')

    def test_restart(self, create_sdkconn):

        create_sdkconn.restart(wait_time=10)
