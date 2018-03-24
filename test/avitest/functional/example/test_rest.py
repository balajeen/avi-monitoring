import avi_objects.rest as rest
from avi_objects.logger import logger
from avi_objects.logger import FailError
from avi_objects.logger_utils import fail

import json
import pytest

class TestRest(object):
    ''' Unit Test the rest layer '''

    @pytest.fixture(scope="module")
    def vs1(self):
        vs1 = rest.ApiNode('virtualservice', name='vs1')
        return vs1
    
    def test_create(self, vs1):
        vs1_json = {'name': 'vs1', 'uuid': 'vs1'}
        vs1_json['vip'] = [{'vip_id': 0, 'ip_address': {'type': 'V4', 'addr': '10.10.10.10'}}]
        vs1_json['services'] = [{'enable_ssl': False, 'port_range_end': 80, 'port': 80}]
        vs1.post(data=json.dumps(vs1_json))
        _, data = vs1.get()
        logger.info('Got back %s' %data)

    def test_get_before_create(self):
        vs2 = rest.ApiNode('virtualservice', name='doesnt_exist')
        try:
            status_code, data = vs2.get()
        except FailError:
            logger.info('As expected, failed to get vs that does not exist')
        status_code, data = vs2.get(check_status_code=False)
        assert status_code == 404
    
    def test_get_systemconfig(self):
        systemconfig = rest.ApiNode('systemconfiguration')
        status, resp = systemconfig.get()
        logger.info('response = %s' %resp)
    
    def test_delete(self, vs1):
        vs1.delete()
        logger.info('Successfully deleted vs1')
    
    def test_delete_nonexistent(self):
        vs1_2 = rest.ApiNode('virtualservice', name='doesnt_exist')
        try:
            status_code, data = vs1_2.delete()
        except FailError:
            logger.info('As expected, failed to delete vs that does not exist')
        status_code, resp = vs1_2.delete(check_status_code=False)
        assert status_code == 404
