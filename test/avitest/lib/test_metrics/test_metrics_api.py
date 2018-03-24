
############################################################################
 # 
 # AVI CONFIDENTIAL
 # __________________
 # 
 # [2013] - [2017] Avi Networks Incorporated
 # All Rights Reserved.
 # 
 # NOTICE: All information contained herein is, and remains the property
 # of Avi Networks Incorporated and its suppliers, if any. The intellectual
 # and technical concepts contained herein are proprietary to Avi Networks
 # Incorporated, and its suppliers and are covered by U.S. and Foreign
 # Patents, patents in process, and are protected by trade secret or
 # copyright law, and other laws. Dissemination of this information or
 # reproduction of this material is strictly forbidden unless prior written
 # permission is obtained from Avi Networks Incorporated.
 ###

'''
Created on Jun 10, 2015

@author: grastogi
'''
import logging
from string import Template
import time
import unittest

from avi.protobuf.analytics_policy_pb2 import MetricsMgrPorts
from lib.test_metrics.api_interface import AviAPIInterface, \
    AviSDKApi, ApiError
import string
#from avi.visibility.metrics_pb import MetricsPbUtils
from requests.packages import urllib3
import requests
if hasattr(requests, 'packages') and hasattr(requests.packages, 'urllib3') and hasattr(requests.packages.urllib3, 'disable_warnings'):
    requests.packages.urllib3.disable_warnings()

log = logging.getLogger('/opt/avi/log/test_metrics_api.log')
g_avi_api_lib = None


avi_settings = {'controller_ip': '10.10.25.42',
                'user': 'admin', 'passwd': 'avi123', 'tenant': 'admin'}


class InvalidAviAPIInterface(Exception):
    pass


class MetricsMapNotFound(Exception):
    def __init__(self, se_uuid, vs_uuid, *args, **kwargs):
        super(MetricsMapNotFound, self).__init__(*args, **kwargs)
        self.message = \
            'SE %s did not have metrics map for vs %s' % (se_uuid, vs_uuid)

    def __str__(self, *args, **kwargs):
        return self.message


class MetricsLCMMapNotFound(Exception):
    pass


def setUpModule():
    global g_avi_api_lib
    if g_avi_api_lib:
        return
    g_avi_api_lib = AviSDKApi(controller_ip=avi_settings['controller_ip'],
                              user=avi_settings['user'],
                              passwd=avi_settings['passwd'],
                              tenant=avi_settings['tenant'])


def tearDownModule():
    global g_avi_api_lib
    # g_avi_api_lib.sess.close()
    g_avi_api_lib = None


class MetricsApiTest(unittest.TestCase):
    hs_entity_uri = Template('analytics/healthscore/${entity_type}/'
                             '${entity_uuid}?${options}')

    insights_uri = \
        Template('analytics/insights/${entity_type}/'
                 '${entity_uuid}?${options}')

    hs_collection_uri = \
        Template('analytics/healthscore/${entity_type}/?${options}')

    metrics_entity_uri = Template('analytics/metrics/${entity_type}/'
                                  '${entity_uuid}?${options}')

    metrics_collection_uri = 'analytics/metrics/collection?'

    lcm_uri = \
        Template('logcontroller?vs_uuid=${vs_uuid}')

    se_metrics_uri = \
        Template('serviceengine/${se_uuid}/metrics?')

    msvc_uri = Template('analytics/microservicemap/virtualservice/'
                        '${entity_uuid}?${options}')

    msvc_app_uri = Template('analytics/microservicemap/application/'
                        '${entity_uuid}?${options}')

    hs_entity_types_list = ['virtualservice', 'serviceengine', 'pool']
    api_lib = None
    num_collection_consistency_check_rounds = 2

    #mp_utils = MetricsPbUtils()

    def setUp(self):
        global g_avi_api_lib
        self.api_lib = g_avi_api_lib

    def tearDown(self):
        self.api_lib = None

    def setAviApi(self, api_lib=None):
        if api_lib is None:
            self.api_lib = g_avi_api_lib
            return
        if not isinstance(api_lib, AviAPIInterface):
            raise InvalidAviAPIInterface
        self.api_lib = api_lib

    def getEntityMQApi(self, entity_type, entity_uuid, **kwargs):
        log.info(' query options %s', kwargs)
        path = self.metrics_entity_uri.substitute(entity_type=entity_type,
                                                  entity_uuid=entity_uuid,
                                                  options='')
        return self.api_lib.get(path, params=kwargs)

    def getMetricsSeMapping(self, se_uuid, vs_uuid, **kwargs):
        path = self.se_metrics_uri.substitute(se_uuid=se_uuid)
        rsp = self.api_lib.get(path, params=kwargs)
        assert rsp.status == 200
        for result in rsp.results_dict:
            assert result.get('metrics_objs')
            metrics_objs = result['metrics_objs']
            for metricsmap in metrics_objs:
                if metricsmap['uuid'] == vs_uuid:
                    return metricsmap
            # should not get here
            log.error("path %s rsp %s", path, rsp)
            raise MetricsMapNotFound(se_uuid, vs_uuid)
        return None

    def getLCMMapping(self, vs_uuid, **kwargs):
        path = self.lcm_uri.substitute(vs_uuid=vs_uuid)
        rsp = self.api_lib.get(path, params=kwargs)
        assert rsp.status == 200
        assert rsp.results_dict.get('results')
        for result in rsp.results_dict.get('results'):
            if result['vs_uuid'] == vs_uuid:
                return result
        raise MetricsLCMMapNotFound('VS %s LCM map not found' % vs_uuid)

    def getVsSeList(self, vs_uuid):
        rsp = self.api_lib.get('virtualservice-inventory/%s' % vs_uuid,
                               params='page_size=1000')
        return rsp.results_dict['runtime']['service_engine']

    def dosCheckAttacksNoDimensions(self, entity_type, entity_list,
                                    **kwargs):
        kwargs['metric_id'] = 'dos.avg_attack_count'
        kwargs['dimension_aggregation'] = 'all'
        kwargs['limit'] = 72
        kwargs['step'] = 300
        for entity_uuid in entity_list:
            rsp = self.getEntityMQApi(entity_type, entity_uuid, **kwargs)
            results = rsp.results_dict
            if not results.get('series'):
                continue
            mseries = results['series'][0]
            header = mseries['header']
            assert header.get('statistics')
            assert 'mean' in header['statistics']
            assert 'min' in header['statistics']
            assert 'max' in header['statistics']
            assert len(mseries['data']) == 1
            kwargs['metric_id'] = 'dos.avg_attack_count,l4_client.avg_bandwidth'
            rsp = self.getEntityMQApi(entity_type, entity_uuid, **kwargs)
            assert rsp.status < 300
            results = rsp.results_dict
            ml = set(kwargs['metric_id'].split(','))
            for mseries in results['series']:
                metric_id = mseries['header']['name']
                ml.remove(metric_id)
                assert len(mseries['data']) == 1
            print ml

    def dosCheckSumAttackDurationNoDimensions(self, entity_type,
                                                    entity_list, **kwargs):
        for entity_uuid in entity_list:
            kwargs['metric_id'] = 'dos.sum_attack_duration'
            kwargs['dimension_aggregation'] = 'all'
            kwargs['limit'] = 72
            kwargs['step'] = 300
            try:
                rsp = self.getEntityMQApi(entity_type, entity_uuid, **kwargs)
                assert False
            except:
                pass
            kwargs['dimension_aggregation'] = 'sum'
            rsp = self.getEntityMQApi(entity_type, entity_uuid, **kwargs)
            assert rsp.status < 300
            results = rsp.results_dict
            if not results.get('series'):
                continue
            mseries = results['series'][0]
            header = mseries['header']
            assert header.get('statistics')
            if not header['statistics'].get('num_samples', 0):
                continue
            print header['statistics']
            # assert 'sum' in header['statistics']
            assert len(mseries['data']) == 1
            kwargs['metric_id'] = 'dos.sum_attack_duration,l4_client.avg_bandwidth'
            rsp = self.getEntityMQApi(entity_type, entity_uuid, **kwargs)
            assert rsp.status < 300
            results = rsp.results_dict
            ml = set(kwargs['metric_id'].split(','))
            for mseries in results['series']:
                metric_id = mseries['header']['name']
                ml.remove(metric_id)
                assert len(mseries['data']) == 1
            print ml

    def dosCheckAttacksWithDimensions(self, entity_type, entity_list,
                                          dimension, **kwargs):
        for entity_uuid in entity_list:
            kwargs['metric_id'] = 'dos.avg_attack_count'
            kwargs['dimension_aggregation'] = 'all'
            rsp = self.getEntityMQApi(entity_type, entity_uuid, **kwargs)
            results = rsp.results_dict
            if not results.get('series'):
                continue
            agg_all_mseries = results['series'][0]
            agg_rate = agg_all_mseries['data'][0]['value']
            kwargs['dimensions'] = dimension
            rsp = self.getEntityMQApi(entity_type, entity_uuid, **kwargs)
            results = rsp.results_dict
            assert results.get('series')
            for mseries in results['series']:
                header = mseries['header']
                assert header.get('statistics')
                assert 'mean' in header['statistics']
                assert 'min' in header['statistics']
                assert 'max' in header['statistics']
                assert mseries['data'][0]['value'] <= agg_rate

    def checkMetricsMap(self, vs_uuid, se_uuid):
        lcm = self.getLCMMapping(vs_uuid)
        se_metrics = self.getMetricsSeMapping(se_uuid, vs_uuid)
        assert se_metrics['uuid'] == vs_uuid
        assert se_metrics['connected'] == True
        se_mmgr_port = int(se_metrics['metrics_mgr_port'])
        se_mmgr_port_str = \
            MetricsMgrPorts.DESCRIPTOR.values_by_number[se_mmgr_port].name
        assert se_mmgr_port_str == lcm['metrics_mgr_port']
        assert se_metrics['type'] == 'VSERVER_METRICS_ENTITY'
        assert se_metrics['controller_ip'] == lcm['controller_ip']

    def validateCollectionAPIConsistencyResponse(self, data, rsp):
        '''
        validates the response to make sure there are same number of
        points in every metric series.
        '''
        limit = None
        last_data_ts = None
        first_data_ts = None
        if ('limit' in data['metric_requests'][0] and
                'start' not in data['metric_requests'][0]):
            limit = data['metric_requests'][0]['limit']
        for mid, mseries_dict in rsp.results_dict['series'].iteritems():
            print mid, ' num series ', len(mseries_dict)
            for eid, mseries_list in mseries_dict.iteritems():
                print 'processing metrics for', eid
                for mseries in mseries_list:
                    if limit is None:
                        limit = len(mseries['data'])
                    assert limit == len(mseries['data'])
                    if not last_data_ts:
                        last_data_ts = mseries['data'][-1]['timestamp']
                    first_series_data_ts = mseries['data'][0]['timestamp']
                    first_series_data_ts = first_series_data_ts.split('+')[0]
                    if not first_data_ts:
                        first_data_ts = first_series_data_ts
                    assert first_series_data_ts == first_data_ts

        return last_data_ts

    def checkMetricsCollectionApiConsistencyRound(self, vs_uuid, **kwargs):
        '''
        single round of consistency check. It expects metrics query
        params in the kwargs.
        '''
        data = {}
        data['metric_requests'] = []
        metric_id = (
            'l7_client.avg_complete_responses,l7_server.avg_complete_responses'
            )
        mqdata = {'metric_id': metric_id,
                  'step': 5,
                  'limit': 360,
                  'entity_uuid': vs_uuid,
                  'id': 'l7_client.avg_complete_responses'}
        for k, v in kwargs.iteritems():
            mqdata[k] = v
        data['metric_requests'].append(mqdata)
        metric_id = (
            'l4_client.avg_complete_conns,l4_server.avg_complete_conns')
        mqdata = {'metric_id': metric_id,
                  'step': 5, 'limit': 360,
                  'entity_uuid': vs_uuid,
                  'id': 'l4_client.avg_complete_conns'}
        data['metric_requests'].append(mqdata)
        for k, v in kwargs.iteritems():
            mqdata[k] = v
        rsp = self.api_lib.post(self.metrics_collection_uri,
                                params={}, headers=None, data=data)
        last_ts = self.validateCollectionAPIConsistencyResponse(data, rsp)
        print 'validataion successful for ', data
        return last_ts

    def checkMetricsCollectionAPIConsistency(self, vs_uuid):
        '''
        This test simulates the browser behavior with the collection api
        call where it would request all the metrics and then do
        incremental loads. this would make AV-864 easy to reproduce
        '''
        last_ts = None
        for _ in range(self.num_collection_consistency_check_rounds):
            kwargs = {}
            if last_ts:
                kwargs['start'] = last_ts
            last_ts = self.checkMetricsCollectionApiConsistencyRound(
                        vs_uuid, **kwargs)
            time.sleep(10)
        return

    def testAllDosAttacksNoDimensions(self):
        rsp = self.api_lib.get('virtualservice-inventory',
                               params='page_size=1000')
        assert rsp.status == 200
        vs_list = []
        for vs_data in rsp.results_dict['results']:
            if vs_data['runtime']['oper_status']['state'] != 'OPER_UP':
                print 'skipping the vs ', vs_data['config']['uuid']
                continue
            vs_list.append(vs_data['config']['uuid'])
        self.dosCheckAttacksNoDimensions('virtualservice', vs_list)

    def testAllDosAttacksWithDimensions(self):
        rsp = self.api_lib.get('virtualservice-inventory',
                               params='page_size=1000')
        assert rsp.status == 200
        vs_list = []
        for vs_data in rsp.results_dict['results']:
            if vs_data['runtime']['oper_status']['state'] != 'OPER_UP':
                print 'skipping the vs ', vs_data['config']['uuid']
                continue
            vs_list.append(vs_data['config']['uuid'])
        self.dosCheckAttacksWithDimensions('virtualservice', vs_list,
                                           'attack')
        self.dosCheckAttacksWithDimensions('virtualservice', vs_list,
                                           'ipgroup')

    def testAllSumAttackDurationWithNoDimensions(self):
        rsp = self.api_lib.get('virtualservice-inventory',
                               params='page_size=1000')
        assert rsp.status == 200
        vs_list = []
        for vs_data in rsp.results_dict['results']:
            if vs_data['runtime']['oper_status']['state'] != 'OPER_UP':
                print 'skipping the vs ', vs_data['config']['uuid']
                continue
            vs_list.append(vs_data['config']['uuid'])
        self.dosCheckSumAttackDurationNoDimensions('virtualservice',
                                                   vs_list)

    def disabledtestMetricsMap(self):
        rsp = self.api_lib.get('virtualservice-inventory',
                               params='page_size=1000')
        assert rsp.status == 200
        for vs_data in rsp.results_dict['results']:
            if vs_data['runtime']['oper_status']['state'] != 'OPER_UP':
                print 'skipping the vs ', vs_data['config']['uuid']
                continue
            vs_uuid = vs_data['config']['uuid']
            assert vs_uuid
            for se_info in self.getVsSeList(vs_uuid):
                self.checkMetricsMap(vs_uuid, se_info['uuid'])

    def predictionCheck(self, entity_type, entity_list, **kwargs):
        for entity_uuid in entity_list:
            kwargs['metric_id'] = 'l4_client.avg_bandwidth'
            kwargs['prediction'] = 'true'
            kwargs['step'] = '300'
            kwargs['limit'] = 2
            try:
                rsp = self.getEntityMQApi(entity_type, entity_uuid, **kwargs)
                assert False
            except ApiError:
                pass
            kwargs['metric_id'] = ('l4_client.avg_error_connections,'
                                   'l4_client.avg_bandwidth')
            try:
                rsp = self.getEntityMQApi(entity_type, entity_uuid, **kwargs)
                assert False
            except ApiError:
                pass
            kwargs['metric_id'] = 'l4_client.avg_bandwidth'
            # assert rsp.status > 299
            kwargs['limit'] = 1
            rsp = self.getEntityMQApi(entity_type, entity_uuid, **kwargs)
            results = rsp.results_dict
            assert results.get('series')
            for mseries in results['series']:
                assert mseries.get('data')
                for data in mseries['data']:
                    assert 'value' in data
                    assert data.get('timestamp')
                    assert 'prediction_interval_high' in data
                    assert 'prediction_interval_low' in data

    def get_all_vs_oper_up(self):
        rsp = self.api_lib.get('virtualservice-inventory',
                               params='page_size=1000')
        assert rsp.status == 200
        vs_list = []
        for vs_data in rsp.results_dict['results']:
            if vs_data['runtime']['oper_status']['state'] != 'OPER_UP':
                print 'skipping the vs ', vs_data['config']['uuid']
                continue
            vs_list.append(vs_data['config']['uuid'])
        return vs_list

    def get_all_applications(self):
        rsp = self.api_lib.get('application',
                               params='page_size=1000')
        assert rsp.status == 200
        app_list = []
        for data in rsp.results_dict['results']:
            app_list.append(data['uuid'])
        return app_list

    def testMetricsPrediction(self):
        vs_list = self.get_all_vs_oper_up()
        self.predictionCheck('virtualservice', vs_list)

    def validateMicroserviceMap(self, msvc_id, root_msvc, msvc_map):
        assert 'nodes' in msvc_map
        assert 'edges' in msvc_map
        assert 'id' in msvc_map
        assert msvc_map['id'] == msvc_id
        nodes = msvc_map.get('nodes', [])
        for node in nodes:
            assert 'healthscore' in node
            assert 'index' in node
            assert 'name' in node
            if node['uuid'].find('microservice') == -1:
                assert 'num_servers' in node
            if node['index'] == 0:
                assert node['uuid'] == root_msvc

        for edge in msvc_map['edges']:
            assert 'policy_drops' in edge
            assert 'source' in edge
            assert 'target' in edge
            assert 'metrics' in edge

    def microserviceApiCheck(self, vs, *args, **kwargs):
        path = self.msvc_uri.substitute(entity_uuid=vs, options='')
        kwargs['metric_id'] = 'source_insights.avg_bandwidth'
        kwargs['pool'] = '*'
        log.info(' query options %s', kwargs)
        rsp = self.api_lib.get(path, params=kwargs)
        assert rsp.status == 200
        print rsp.results_dict
        assert len(rsp.results_dict) == 1
        for msvc_id, msvc_map in rsp.results_dict.iteritems():
            self.validateMicroserviceMap(msvc_id, vs, msvc_map)

        path = self.msvc_uri.substitute(entity_uuid=vs, options='')
        kwargs['metric_id'] = 'source_insights.avg_bandwidth,source_insights.avg_complete_conns,source_insights.avg_policy_drops'
        rsp = self.api_lib.get(path, params=kwargs)
        assert rsp.status == 200
        assert len(rsp.results_dict) == 1
        for msvc_id, msvc_map in rsp.results_dict.iteritems():
            self.validateMicroserviceMap(msvc_id, vs, msvc_map)
        return rsp

    def appMicroserviceApiCheck(self, app, *args, **kwargs):
        path = self.msvc_app_uri.substitute(entity_uuid=app, options='')
        kwargs['metric_id'] = 'source_insights.avg_bandwidth'
        kwargs['pool'] = '*'
        log.info(' query options %s', kwargs)
        rsp = self.api_lib.get(path, params=kwargs)
        assert rsp.status == 200
        print rsp.results_dict
        assert len(rsp.results_dict) == 1
        #for msvc_id, msvc_map in rsp.results_dict.iteritems():
        #    self.validateMicroserviceMap(msvc_id, vs, msvc_map)

        path = self.msvc_app_uri.substitute(entity_uuid=app, options='')
        kwargs['metric_id'] = 'source_insights.avg_bandwidth,source_insights.avg_complete_conns,source_insights.avg_policy_drops'
        rsp = self.api_lib.get(path, params=kwargs)
        assert rsp.status == 200
        assert len(rsp.results_dict) == 1
        #for msvc_id, msvc_map in rsp.results_dict.iteritems():
        #    self.validateMicroserviceMap(msvc_id, vs, msvc_map)
        return rsp


    def microserviceEdgeTrafficCheck(
            self, src_vs, dst_vs, metric_id='', **kwargs):
        # self.microserviceApiCheck(src_vs)
        metric_id = 'source_insights.avg_bandwidth'
        #metric_id = 'source_insights.avg_client_end2end_latency'

            # need to do validation on the destination vs
        path = self.msvc_uri.substitute(entity_uuid=dst_vs, options='')
        kwargs['metric_id'] = metric_id
        print 'microservicemap api ', path, kwargs
        log.debug('path %s kwargs %s', path, str(kwargs))
        rsp = self.api_lib.get(path, params=kwargs)
        assert rsp.status == 200
        print rsp.results_dict
        log.debug(' result %s', rsp.results_dict)
        msvc_map = rsp.results_dict.values()[0]
        src_vs_index = None
        dst_vs_index = None
        print 'checking map for edge for ', src_vs, ' - ', dst_vs
        for node in msvc_map['nodes']:
            if dst_vs == node['uuid']:
                dst_vs_index = node['index']
            if src_vs == node['uuid']:
                src_vs_index = node['index']
            if src_vs_index and dst_vs_index:
                break
        print 'found src %s index %s dst %s index %s' % (
                src_vs, src_vs_index, dst_vs, dst_vs_index)
        log.debug('found src %s index %s dst %s index %s',
                  src_vs, src_vs_index, dst_vs, dst_vs_index)
        assert src_vs_index is not None
        assert dst_vs_index is not None
        found = False
        for edge in msvc_map['edges']:
            if (edge['source'] == src_vs_index and
                edge['target'] == dst_vs_index):
                print 'checking edge ', edge
                found = True
                assert metric_id in edge['metrics']
                log.debug('checking edge %s blocked %s', edge, 
                          kwargs.get('blocked', False))
                if kwargs.get('blocked', False):
                    assert edge['policy_drops'] > 0
                else:
                    assert edge['metrics'][metric_id]['value'] >= 0
                # REVIEW @yzhang can we break here? is there any point to checking more edges?
                break;
        assert found

    def testMicroserviceApi(self):
        vs_list = self.get_all_vs_oper_up()
        for vs in vs_list:
            kwargs = {}
            kwargs['step'] = 300
            kwargs['limit'] = 72
            kwargs['dimension_aggregation'] = 'avg'
            self.microserviceApiCheck(vs, **kwargs)
            kwargs['step'] = 5
            kwargs['limit'] = 360
            kwargs['dimension_aggregation'] = 'avg'
            self.microserviceApiCheck(vs, **kwargs)

    def testCollectionConsistency(self):
        vs_list = self.get_all_vs_oper_up()
        for vs_uuid in vs_list:
            self.checkMetricsCollectionAPIConsistency(vs_uuid)

    def testMetricsPagination(self):
        kwargs = {}
        kwargs['metric_id'] = 'l4_client.avg_bandwidth'
        kwargs['limit'] = 72
        kwargs['step'] = 300
        kwargs['page'] = 1
        kwargs['page_size'] = 10
        rsp = self.getEntityMQApi('virtualservice', '', **kwargs)
        vs_list = self.get_all_vs_oper_up()
        assert len(vs_list) <= rsp.results_dict['count']

    def testMicroserviceApplicationApi(self):
        app_list = self.get_all_applications()
        for app in app_list:
            kwargs = {}
            kwargs['step'] = 300
            kwargs['limit'] = 72
            kwargs['dimension_aggregation'] = 'avg'
            self.appMicroserviceApiCheck(app, **kwargs)
            kwargs['step'] = 300
            kwargs['limit'] = 72
            self.appMicroserviceApiCheck(app, **kwargs)

    def metricsInventoryInfoCheck(self, vs_info, metric_ids, dimension_aggregation=''):
        assert vs_info['metrics']
        log.debug('metrics info %s', vs_info['metrics'])
        for metric in metric_ids:
            assert metric in vs_info['metrics']
            rmetric = vs_info['metrics'][metric]
            log.debug('rmetric %s: %s', metric, rmetric)
            if not dimension_aggregation:
                assert rmetric['timestamp']
            # REVIEW disabling to reduce dependencies
            #if (dimension_aggregation == 'sum' and
            #    self.mp_utils.is_metric_sum_agg_invalid(metric)):
            #    assert rmetric['is_null']
            #else:
            #    if not rmetric.get('is_null'):
            #        assert rmetric['value'] is not None

    def testMetricsInventory(self):
        metric_ids = ['l4_client.avg_bandwidth','l4_client.avg_total_rtt',
                      'l7_client.avg_complete_responses']
        rsp = self.api_lib.get(
                'virtualservice-inventory',
                params='metric_id=%s&step=300'%(string.join(metric_ids, 
                                                            sep=',')))
        assert rsp.status == 200
        for vs_info in rsp.results_dict['results']:
            self.metricsInventoryInfoCheck(vs_info, metric_ids)
        rsp = self.api_lib.get(
                'virtualservice-inventory',
                params='metric_id=%s&step=300&dimension_aggregation=avg'%(string.join(metric_ids, 
                                                            sep=',')))
        assert rsp.status == 200
        for vs_info in rsp.results_dict['results']:
            self.metricsInventoryInfoCheck(vs_info, metric_ids, 
                                           dimension_aggregation='avg')
        rsp = self.api_lib.get(
                'virtualservice-inventory',
                params='metric_id=%s&step=300&dimension_aggregation=sum'%(string.join(metric_ids, 
                                                            sep=',')))
        assert rsp.status == 200
        for vs_info in rsp.results_dict['results']:
            self.metricsInventoryInfoCheck(vs_info, metric_ids, 
                                           dimension_aggregation='sum')

    def runTest(self):
        pass

if __name__ == "__main__":
    # import sys;sys.argv = ['', 'Test.testName']
    setUpModule()
    tests = MetricsApiTest()
    tests.setAviApi(g_avi_api_lib)
    tests.test_dummy()
    tearDownModule()
    print 'All tests success'
