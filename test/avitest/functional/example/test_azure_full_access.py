from avi_objects.infra_imports import request, logger, asleep, cleanup_client_server, setup_cloud, create_config, delete_config
import pytest
from lib.se_lib import delete_all_se_vms
import lib.vs_lib_v2 as vs_lib_v2
import avi_objects.rest as rest
import json

class TestSmoke(object):
    def test_create(self, cleanup_client_server):
        """ Create Config """
        setup_cloud(wait_for_cloud_ready=True)
        create_config('azure_smoke_full_access.json')
        logger.report_errors()

    def test_config_wellness_check(self):
        """Testcase helps to check that VSs are in OPER_UP  status or not"""
        for vs in ['vs-1', 'vs-2']:
            vs_lib_v2.vs_wellness_check(vs, ['0-1-1-OPER_UP'], timeout=600)
        logger.report_errors()
    
    @pytest.mark.parametrize("to_floating_vip", [
        True, 
        False
        ])
    def test_requests_basic(self, to_floating_vip):
        """ Request with basic params """
        for i in range(5):
            for vs in ['vs-1', 'vs-2']:
                kwargs = {
                    'vs_names':[vs],
                    'vport':8000,
                    'print_body':True,
                    'uri':['/'],
                    'client_range': 'c1',
                    'to_floating_vip': to_floating_vip
                }

                traffic_obj, output = request(**kwargs)
                logger.info("echo_listen_port URI Output: %s " % output)
        logger.report_errors()

    def test_delete_config(self,cleanup_client_server):
        """ Delete Config """
        delete_config('azure_smoke_full_access.json')
        asleep("Waiting for Config objects to get Deleted", delay=60, period = 20)
        delete_all_se_vms()
        asleep("Waiting for SEs to get Deleted", delay=60, period = 20)
        _data = {}
        _data['vtype'] = 'CLOUD_NONE'
        _data['name'] = 'Default-Cloud'
        status, result = rest.put('cloud', name='Default-Cloud', data=json.dumps(_data))
