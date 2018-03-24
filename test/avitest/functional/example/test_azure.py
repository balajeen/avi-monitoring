from avi_objects.infra_imports import request, logger, asleep, cleanup_client_server, setup_cloud, create_config, delete_config
import pytest
import lib.vs_lib_v2 as vs_lib_v2
import avi_objects.rest as rest
import json

class TestSmoke(object):
    
    def test_create(self, cleanup_client_server):
        """ Create Config """
	logger.info('Waiting for cloud to configure and ready')
	setup_cloud(wait_for_cloud_ready=True)
        create_config('test_azure_config.json')
        asleep("Waiting for Config to settle in", delay=180, period = 20)
        logger.report_errors()

    def test_config_wellness_check(self):
        """Testcase helps to check that VSs are in OPER_UP  status or not"""
        for vs in ['vs-1', 'vs-2']:
            vs_lib_v2.vs_wellness_check(vs, ['0-1-1-OPER_UP'], timeout=100)
        logger.report_errors()

    def requests_basic(self, count):
        """ Request with basic params """
        #Traffic parms
        for i in range(count):
            for vs in ['vs-1', 'vs-2']:
                kwargs = {
                    'vs_names':[vs],
                    'vport':8000,
                    'print_body':True,
                    'uri':['/'],
                    'client_range': 'c1'
                }

                traffic_obj, output = request(**kwargs)
                logger.info("echo_listen_port URI Output: %s " % output)

    def test_requests_basic(self):
        """Testcase to check if the traffic is flowing consistently"""
        self.requests_basic(10)
        logger.report_errors()

    def test_delete_config(self,cleanup_client_server):
        """ Delete Config """
        status, result = rest.get('cloud',name='Default-Cloud')
        result['linuxserver_configuration']['hosts'] = []
        status, result = rest.put('cloud', name='Default-Cloud', data=json.dumps(result))
        delete_config('test_azure_config.json')
        asleep("Waiting for SEs to get Deleted", delay=60, period = 20)
	_data = {}
        _data['vtype'] = 'CLOUD_NONE'
        _data['name'] = 'Default-Cloud'
        status, result = rest.put('cloud', name='Default-Cloud', data=json.dumps(_data))
