import pytest
from random import randint
import time
import traceback
from avi_objects.infra_imports import *
from avi_objects.cluster import *
from avi_objects.infra_utils import get_config
from avi_objects.test_fixtures import cleanup_client_server
from cluster_lib import reboot_leader, wait_until_cluster_ready


class TestSmoke(object):
    
    def test_create(self, cleanup_client_server):
        """ Create Config """
        setup_cloud(wait_for_cloud_ready=False)
        create_config('azure_cluster_vip.json')
        logger.report_errors()

    def test_setup_cluster_vip(self):
        """Initial setup of cluster vip"""
        cluster_vip = '10.152.139.105'
        configure_cluster_vip(cluster_vip)
        time.sleep(60)
        for i in range(10):
            try:
                session = create_session(ip=cluster_vip)
                rsp = session.get('cluster')
                logger.info('Response received : %s', rsp.__dict__)
                break
            except Exception as e:
                if i == 9:
                    fail('failed to connect to cluster vip after 10 tries: %s'% traceback.format_exc())
                    raise e
                time.sleep(5)

    def test_cluster_vip_failover(self):
        reboot_leader()
        time.sleep(60)
        wait_until_cluster_ready()
        count = 60
        for i in range(count):
            try:
                session = create_session(ip='10.152.139.105')
                rsp = session.get('cluster')
                logger.info('Response received : %s', rsp.__dict__)
                break
            except Exception as e:
                if i == count-1:
                    fail('failed to connect to cluster vip after 10 tries: %s'% traceback.format_exc())
                    raise e
                time.sleep(5)

    def test_setup_cluster_vip_delete(self):
        """Initial setup of cluster vip"""
        cluster_vip = '10.152.139.105'
        session = create_session(ip=cluster_vip)
        get_config().switch_mode(session=session)
        remove_cluster_vip()
        get_config().switch_mode(session=None)
        for i in range(20):
            try:
                session = create_session(ip=cluster_vip)
                rsp = session.get('cluster')
                logger.info('cluster vip still active, retrying')
                time.sleep(5)
                if i==19:
                    fail('cluster vip not removed after 10 tries')
                continue
            except Exception as e:
                print 
                break
        
    def test_delete_config(self,cleanup_client_server):
        """ Delete Config """
        delete_config('azure_cluster_vip.json')
