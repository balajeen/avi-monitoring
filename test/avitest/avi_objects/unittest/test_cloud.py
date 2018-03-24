from avi_objects.infra_imports import *
import pytest
from random import randint
import time
from avi_objects.test_fixtures import cleanup_client_server

@pytest.fixture(autouse=True)
def initialize(avi_setup,request):
   request.function.func_globals['client'] = get_vm_of_type('client')[0]

class TestMultiTenantMultiCloud(object):
    """ MultiTenantMultiCloud related Unit Test cases """

    def test_create(self, cleanup_client_server):
        """ Create Config """
        setup_cloud(config_file='test_cloud_cloudconfig.json', wait_for_cloud_ready=True)
        #switch_mode(cloud=None) # This should be removed once AV-26805 is fixed
        create_config('test_cloud_config.json')
        logger.report_errors()

    def test_verify_configs(self):
        
        switch_mode(cloud='Default-Cloud')
        st, vs_list = get('virtualservice')
        assert 6 == vs_list['count']
        switch_mode(cloud='Cloud-2')
        st, vs_list = get('virtualservice')
        assert 5 == vs_list['count']
        logger.report_errors()

    def test_tenant_cloud_create(self):
        tenant_config = {
            "description": "tenant-new",
            "name": "tenant-new"
        }
        post('tenant', data=tenant_config)
        switch_mode(tenant='tenant-new')
        #switch_mode(tenant='tenant-new',cloud=None)
        create_config('test_cloud_tenant_new.json')
        switch_mode(cloud='Default-Cloud')
        st, vs_list = get('virtualservice')
        assert 5 == vs_list['count']
        switch_mode(cloud='Cloud-2')
        st, vs_list = get('virtualservice')
        assert 5 == vs_list['count']
        #switch_mode(cloud=None)
        delete_config('test_cloud_tenant_new.json')
        delete('tenant', name='tenant-new')
        

    def test_multi_tenant_multi_objects_create(self):
        hmon_obj = {
            "failed_checks": 1,
            "tenant_ref": "/api/tenant/?name=admin",
            "cloud_ref": "/api/cloud/?tenant=admin&name=Default-Cloud",
            "name": "healthmonitor-crud",
            "receive_timeout": 2,
            "send_interval": 3,
            "successful_checks": 1,
            "tcp_monitor": {},
            "type": "HEALTH_MONITOR_TCP"
        }
        switch_mode(tenant='admin', cloud='Default-Cloud')
        resp = post('healthmonitor', data=hmon_obj)
        st, obj_details = get('healthmonitor', name='healthmonitor-crud')
        logger.info("Health monitor object = %s" %obj_details)
        tenant_ref = obj_details['tenant_ref']
        # Change X-Avi-Tenant header and not tenant_ref in data.
        switch_mode(tenant='tenant-crud')
        resp = post('healthmonitor', data=hmon_obj)
        st, obj_details = get('healthmonitor', name='healthmonitor-crud')
        logger.info("Health monitor object = %s" %obj_details)
        tenant_ref_2 = obj_details['tenant_ref']
        assert tenant_ref != tenant_ref_2
        delete('healthmonitor', name='healthmonitor-crud')
        switch_mode(tenant='admin', cloud='Default-Cloud')
        delete('healthmonitor', name='healthmonitor-crud')
        
        poolgrp_pbj = {
            "name": "pool-group-crud",
            "tenant_ref": "/api/tenant/?name=admin",
            "cloud_ref": "/api/cloud/?tenant=admin&name=Default-Cloud"
        }
        logger.info("Creating Pool Group in Tenant admin and Cloud Default-Cloud")
        resp = post('poolgroup', data=poolgrp_pbj)
        st, obj_details = get('poolgroup', name='pool-group-crud')
        logger.info("Pool Group Created = %s" %obj_details)
        tenant_ref = obj_details['tenant_ref']
        cloud_ref = obj_details['cloud_ref']
        logger.info("Creating Pool Group in Tenant tenant-crud and Cloud Cloud-2")
        switch_mode(tenant='tenant-crud', cloud='Cloud-2')
        resp = post('poolgroup', data=poolgrp_pbj)
        st, obj_details = get('poolgroup', name='pool-group-crud')
        logger.info("Pool Group Created = %s" %obj_details)
        tenant_ref_2 = obj_details['tenant_ref']
        cloud_ref_2 = obj_details['cloud_ref']
        assert tenant_ref != tenant_ref_2
        assert cloud_ref != cloud_ref_2
        delete('poolgroup', name='pool-group-crud')
        switch_mode(tenant='admin', cloud='Default-Cloud')
        delete('poolgroup', name='pool-group-crud')

    def test_delete_config(self, cleanup_client_server):
         """ Delete Config """
         #switch_mode(tenant='admin',cloud=None) # cloud=None should be removed once AV-26805 is fixed
         switch_mode(tenant='admin')
         delete_config('test_cloud_config.json')
         switch_mode(cloud='Default-Cloud')
         delete_config('test_cloud_cloudconfig.json')
         logger.report_errors()


