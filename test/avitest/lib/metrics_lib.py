from datetime import datetime
import json
import math
import copy
import time
from collections import namedtuple
from copy import deepcopy
from iso8601.iso8601 import parse_date
from avi_objects.logger import logger
import avi_objects.logger_utils as logger_utils
import avi_objects.common_utils as common_utils
import avi_objects.infra_utils as infra_utils

from avi_objects.pool import ServerModel

from lib.test_metrics import test_metrics_api
import lib.controller_lib as controller_lib
import lib.se_lib as se_lib
import lib.performance_lib as perf
import lib.webapp_lib as webapp_lib
import lib.vs_lib as vs_lib
import lib.pool_lib as pool_lib
import lib.metrics_thresholds as metrics_thresholds
import avi_objects.rest as rest



metrics_skip_list = set(
    ['l4_client.avg_rx_bytes', 'l4_client.avg_rx_pkts',
     'l4_client.avg_tx_pkts', 'l4_client.avg_rx_pkts_dropped',
     'vm_stats.avg_disk3_usage', 'vm_stats.avg_disk4_usage',
     'vm_stats.avg_virtual_disk_commands_aborted',
     'vm_stats.avg_disk2_usage', 'vm_stats.avg_uptime'])

METRICS_ALERT_CONFIG = {
    'uuid': "",
    'name': "",
    'alert_rule': {
        'metrics_rule': []
    },
    'enabled': True,
    'threshold': 1,
    'throttle': 10,
    'expiry_time': 86400,
    'source': 'METRICS',
    'category': 'REALTIME',
    #'level': 'ALERT_HIGH',
    'summary': "scaleout when max open conns is over 50",
    'action_group_ref': 'System-Alert-Level-High',
    'tenant_uuid': "admin",
    'autoscale_alert': True
}

DEF_METRIC_RULE = {
    'metric_id': 'l4_server.max_open_conns',
    'metric_threshold': {
        'threshold': 75,
        'comparator': 'ALERT_OP_GT'
        }
}

metrics_api_tests = None


def get_metrics_api_tests(tenant='admin'):
    global metrics_api_tests
    if metrics_api_tests:
        return metrics_api_tests
    controller_ip = controller_lib.get_controller_ip()
    port = controller_lib.get_controller_port()
    if port:
        controller_ip = controller_ip + ":" + port
    mode = infra_utils.get_mode()
    avi_settings = {'controller_ip': controller_ip,
                    'user': mode['user'], 'passwd': mode['password'], 'tenant': mode['tenant']}
    test_metrics_api.avi_settings = avi_settings
    test_metrics_api.setUpModule()
    metrics_api_tests = test_metrics_api.MetricsApiTest()
    metrics_api_tests.setAviApi()
    return metrics_api_tests


class Metrics_Error (Exception):
    pass


class MetricsValidationError(Exception):
    pass

debug_skip_traffic = False


MetricsTestContext = namedtuple('MetricsTestContext',
                                ['start_time', 'test_duration',
                                 'after_test_wait', 'vs_metrics_1',
                                 'vs_metrics_2',
                                 'pool_metrics', 'server_metrics',
                                 'se_metrics_1', 'se_metrics_2'])

# XXX TODO: Pb?
#mp_utils = MetricsPbUtils()


def metrics_options():
    jsondata = get_all_metrics_options()
    missing_description = []
    missing_unit = []

    for i in jsondata['metrics_data']:
        for k, v in i.items():
            if v.get('description', '') == 'Deprecated':
                continue
            if 'metric_units' not in v:
                missing_unit.append(k)
            if 'description' not in v:
                missing_description.append(k)

    if len(missing_unit) or len(missing_description):
        logger_utils.error('Missing unit or description, unit: <%s>, '
                           'description: <%s>'
                           % (missing_unit, missing_description))


def get_all_metrics_options():
    path = 'metrics-options'
    status_code, results = rest.get('analytics', path=path)
    return results

def metrics_se_eth(vs_name, vs_port):
    pass


def metrics_controller_mem_usage_test(vs_name):
    """

    :param vs_name:
    :return:
    """

    max_total_memory = 'controller_stats.max_total_memory'
    avg_mem_usage = 'controller_stats.avg_mem_usage'
    metric_ids = '%s,%s' % (max_total_memory, avg_mem_usage)
    controller_vm = infra_utils.get_vm_of_type('controller')[0]

    controller_vm.use_memory(30)

    logger_utils.asleep(delay=15)

    start_time = get_start_time(vs_name)

    memory_info = controller_vm.get_memory_info()

    logger.info('memory_info: %s' % str(memory_info))

    controller_series = get_vs_series(vs_name, start_time, 1,
                                      metric_id=metric_ids, step=5)

    logger.info('controller_series: %s' % controller_series)

    # Make sure to use the rest of the use_memory method
    logger_utils.asleep(delay=15)

    controller_total_memory = float(controller_series[max_total_memory][0])
    reported_total = float(memory_info['total'])

    controller_percent_used = float(controller_series[avg_mem_usage][0])
    reported_percent_used = float(memory_info['percent_used'])

    if controller_total_memory < reported_total - 2 or \
            controller_total_memory > reported_total + 2:
        logger_utils.error('Contoller total memory <%s> was not within range' \
                           'of <%s>'
                           % (controller_total_memory, reported_total))

    if controller_percent_used < reported_percent_used - 2 or \
            controller_percent_used > reported_percent_used + 2:
        logger_utils.fail('Controller memory usage <%s> was not within range of <%s>' % (
            controller_percent_used, reported_percent_used))


def get_start_time(vs_name, **kwargs):
    """

    :param vs_name:
    :param kwargs:
    :return:
    """

    start_time = get_metrics_vs(vs_name, step=5, limit=1)['start']
    start_time = start_time.split('+')[0]
    return start_time


def get_metrics_vs(vs_name, **kwargs):
    uuid = rest.get_uuid_by_name('virtualservice', vs_name)
    path = 'metrics/virtualservice/' + uuid + '/?'
    path += generate_query_string(kwargs)
    logger.info('getting metrics analytics/%s' % path)
    status_code, results = rest.get('analytics', path=path)
    return results


def generate_query_string(qdict):
    """

    :param qdict:
    :return:
    """

    query = ''
    for k, v in qdict.items():
        query += '%s=%s&' % (k, v)
    # strip the last &
    query = query[:-1]

    return query


def get_vs_series(vs_name, start_time, how_many, **kwargs):
    """

    :param vs_name:
    :param start_time:
    :param how_many:
    :param kwargs:
    :return:
    """

    kwargs['start'] = start_time
    kwargs['limit'] = how_many

    series = get_metrics_vs(vs_name, **kwargs)['series']

    series_with_load = parse_series(series, how_many, **kwargs)

    return series_with_load


def fixup_series(element, step, how_many):
    """

    :param element:
    :param step:
    :param how_many:
    :return:
    """

    header = element.get('header')
    metric_id = header['name']
    data = element.get('data')
    if header is None or data is None:
        logger_utils.error('Header or data was not present<%s>' % element)
    # print 'fixing up series ', metric_id
    maxv = header['statistics']['max']
    num_samples = 0
    mean_exc_max = 0
    max_index = None
    for i, mdata in enumerate(data):
        if max_index is None and mdata['value'] == maxv:
            max_index = i
            continue
        num_samples += 1
        mean_exc_max += mdata['value']
    mean_exc_max = mean_exc_max / num_samples if num_samples else 0

    prev_ts = None
    prev_val = None
    fix_up_done = False
    for mdata in data:
        ts = mdata['timestamp']
        ts_obj = parse_date(ts)
        if prev_ts:
            if ((ts_obj - prev_ts).total_seconds() > step):
                # need to patch
                logger.info('changing metric' + str(metric_id) + ' data ' +
                            str(mdata) + ' to value ' + str(prev_val))
                mdata['value'] = prev_val
                fix_up_done = True
        else:
            if mdata['value'] == maxv and mean_exc_max > 0:
                err = abs(maxv - mean_exc_max) / mean_exc_max
                if err > 1.75 or err < 1.85:
                    mdata['value'] = mean_exc_max
        prev_ts = ts_obj
        prev_val = mdata['value']
    if fix_up_done and len(data) < how_many:
        for _ in range(how_many - len(data)):
            data.append(data[-1]['value'])

    if fix_up_done:
        logger.info('fixed up series' + str(element))
    return element


def parse_series(series, how_many, **kwargs):
    """

    :param series:
    :param how_many:
    :param kwargs:
    :return:
    """

    step = int(kwargs.get('step', 5))
    pad_missing_data = kwargs.get('pad_missing_data', True)
    if not pad_missing_data or pad_missing_data == 'false':
        pad_missing_data = False
    else:
        pad_missing_data = True
    series_with_load = {}
    logger.debug(' pad_missing_data %s' % str(pad_missing_data))
    for element in series:
        if not pad_missing_data:
            element = fixup_series(element, step, how_many)
        header = element.get('header')
        data = element.get('data')
        is_prev_data_null = False
        prev_val = None
        if header is None or data is None:
            logger_utils.error('Header or data was not present<%s>' % (element))
        for _, val in enumerate(data):
            if not series_with_load.get(header['name']):
                series_with_load[header['name']] = []
            if prev_val and is_prev_data_null:
                series_with_load[header['name']].append(prev_val)
                logger.info('detected a missing interval so using previous '
                            'value as current value may not be correct as '
                            'metrics mgr may do aggregation across two '
                            'intervals')
            else:
                series_with_load[header['name']].append(val['value'])
            is_prev_data_null = val.get('is_null', False)
            prev_val = val['value']

    for k, v in series_with_load.items():
        if len(v) != how_many:
            logger_utils.error('For key <%s> expected %s entries, got %s' % (
                k, how_many, len(v)))
    logger.info(series_with_load)
    return series_with_load


def get_metrics_se(se_uuid, **kwargs):
    """

    :param se_uuid:
    :param kwargs:
    :return:
    """

    path = 'analytics/metrics/serviceengine/' + se_uuid + '?'
    path += generate_query_string(kwargs)
    status_code, results = rest.get(path)
    # XXX TODO is this no longer needed?
    return results


def get_metrics_vm(vm_uuid, **kwargs):
    path = 'analytics/metrics/virtualmachine/' + vm_uuid + '?'
    path += generate_query_string(kwargs)
    status_code, results = rest.get(path)
    #rest.check_response_for_errors(results)
    return results


def get_se_series(se_uuids, start_time, how_many, **kwargs):
    """

    :param se_uuids:
    :param start_time:
    :param how_many:
    :param kwargs:
    :return:
    """

    kwargs['start'] = start_time
    kwargs['limit'] = how_many
    # step = int(kwargs.get('step', 5))

    parsed = {}

    for se_uuid in se_uuids:
        series = get_metrics_se(se_uuid, **kwargs)['series']

        parsed[se_uuid] = parse_series(series, how_many, **kwargs)

    return parsed

def get_vms_series(vm_uuids, start_time, how_many, **kwargs):
    how_many = int(how_many)
    kwargs['start'] = start_time
    kwargs['limit'] = how_many

    parsed = {}
    for vm_uuid in vm_uuids:
        series = get_metrics_vm(vm_uuid, **kwargs)['series']
        parsed[vm_uuid] = parse_series(series, how_many, **kwargs)
    return parsed

def metrics_mem_usage_test(vs_name):
    """

    :param vs_name:
    :return:
    """

    logger.info(' doing memory usage test for vs %s' % vs_name)
    se_vm = infra_utils.get_vm_of_type('se')[0]

    start_time = get_start_time(vs_name)

    se_uuids = se_lib.get_se_uuids_from_vs_name(vs_name)

    se_series1 = get_se_series(se_uuids, start_time, 1,
                               metric_id='se_stats.avg_mem_usage', step=5)

    logger.info(se_series1)
    mem_usage1 = se_vm.get_memory_info()['percent_used']
    logger.info('mem_usage1:' + str(mem_usage1))

    for v in se_series1.values():
        se_mem_use = float(v['se_stats.avg_mem_usage'][0])
        reported_mem = float(mem_usage1)
        if se_mem_use < reported_mem - 2 or se_mem_use > reported_mem + 2:
            logger_utils.error('SE cpu usage <%s> did not match expected range'
                               ' <%s>'
                               % (se_mem_use, reported_mem))

    se_vm.use_memory(25)
    mem_usage2 = se_vm.get_memory_info()['percent_used']

    logger_utils.asleep(delay=25)

    start_time = get_start_time(vs_name)

    logger.info('mem_usage2:' + str(mem_usage2))

    se_series2 = get_se_series(se_uuids, start_time, 1,
                               metric_id='se_stats.avg_mem_usage', step=5)

    logger.info(se_series2)

    for v in se_series2.values():
        se_mem_use = float(v['se_stats.avg_mem_usage'][0])
        reported_mem = float(mem_usage2)
        if se_mem_use < reported_mem - 2 or se_mem_use > reported_mem + 2:
            logger_utils.error('SE mem usage <%s> did not match expected range'
                               ' <%s>'
                               % (se_mem_use, reported_mem))


def metrics_cpu_usage_test(vs_name):
    """

    :param vs_name:
    :return:
    """

    logger.info('doing cpu usage test for vs' + str(vs_name))
    se_vm = infra_utils.get_vm_of_type('se')[0]

    start_time = get_start_time(vs_name)

    se_uuids = se_lib.get_se_uuids_from_vs_name(vs_name)

    se_series1 = get_se_series(se_uuids, start_time, 1,
                               metric_id='se_stats.avg_cpu_usage', step=5)

    logger.info(se_series1)
    cpu_usage1 = se_vm.get_cpu_use()

    logger.info('cpu_usage1:' + str(cpu_usage1))

    for v in se_series1.values():
        se_cpu_use = float(v['se_stats.avg_cpu_usage'][0])
        reported_cpu = float(cpu_usage1)
        if se_cpu_use < reported_cpu - 2 or se_cpu_use > reported_cpu + 2:
            logger_utils.fail('SE cpu usage <%s> did not match expected range <%s>' % (
                se_cpu_use, reported_cpu))

    se_vm.start_cpu_use()

    logger_utils.asleep(delay=25)

    start_time = get_start_time(vs_name)

    cpu_usage2 = se_vm.get_cpu_use()

    logger.info('cpu_usage2:' + str(cpu_usage2))

    se_series2 = get_se_series(se_uuids, start_time, 1,
                               metric_id='se_stats.avg_cpu_usage', step=5)

    logger.info(se_series2)

    se_vm.stop_cpu_use()

    for v in se_series2.values():
        se_cpu_use = float(v['se_stats.avg_cpu_usage'][0])
        reported_cpu = float(cpu_usage2)
        if se_cpu_use < reported_cpu - 2 or se_cpu_use > reported_cpu + 2:
            logger_utils.error('SE cpu usage <%s> did not match expected range'
                               ' <%s>'
                               % (se_cpu_use, reported_cpu))


# XXX This does not seem to be present in the original file
def metrics_se_disk_usage_start(vs_name):
    """

    :param vs_name:
    :return:
    """

    se_vm = infra_utils.get_vm_of_type('se')[0]
    se_vm.create_file_of_size('metrics-test', (4*1024*1024*1024))


def metrics_se_disk_usage_stop(vs_name):
    """

    :param vs_name:
    :return:
    """

    se_vm = infra_utils.get_vm_of_type('se')[0]
    se_vm.remove_tmp_file('metrics-test')


def metrics_vm_cpu_usage_start(vs_name, server_name):
    """

    :param vs_name: name of the virtual service
    :param server_name: server name as in topo conf file.
    :return:
    """

    # TODO: get the nginx vm corresponding to the pool server.
    # Since functional tests have only one nginx, this would work now.
    server_vm = infra_utils.get_vm_of_type('server')[0]
    logger.info('cpu_usage:'+ str(server_name)+str( server_vm.get_cpu_use()))
    server_vm.start_cpu_use()
    logger_utils.asleep(delay=5)
    logger.info('cpu_usage:'+ str(server_name)+str(server_vm.get_cpu_use()))
    return


def metrics_vm_cpu_usage_stop(vs_name, server_name):
    """

    :param vs_name:
    :param server_name:
    :return:
    """

    server_vm = infra_utils.get_vm_of_type('server')[0]
    server_vm.stop_cpu_use()
    logger_utils.asleep(delay=5)
    logger.info('cpu_usage: %s' % (str(server_name) + str(server_vm.get_cpu_use())))
    return


def metrics_vm_disk_usage_start(vs_name, server_name, size=(4*1024*1024*1024)):
    """

    :param vs_name: name of the virtual service
    :param server_name: server name as in topo conf file.
    :param size:
    :return:
    """

    server_vm = infra_utils.get_vm_of_type('server')[0]
    server_vm.create_file_of_size('metrics-test', size)


def metrics_vm_disk_usage_stop(vs_name, server_name):
    """

    :param vs_name:
    :param server_name:
    :return:
    """

    server_vm = infra_utils.get_vm_of_type('server')[0]
    server_vm.remove_tmp_file('metrics-test')


def metrics_disk_usage_test(vs_name, file_size):
    """

    :param vs_name:
    :param file_size:
    :return:
    """

    se_vm = infra_utils.get_vm_of_type('se')[0]
    file_name = 'large_tmp_file'

    should_sleep = False
    try:
        se_vm.remove_tmp_file(file_name)
    except:
        should_sleep = True

    if should_sleep:
        logger.info('Did not clean up, sleeping')
        logger_utils.asleep(delay=15)

    start_time = get_start_time(vs_name)

    se_uuids = se_lib.get_se_uuids_from_vs_name(vs_name)

    se_series1 = get_se_series(se_uuids, start_time, 1,
                               metric_id='se_stats.avg_disk1_usage', step=5)

    logger.info(se_series1)

    disk_space1 = se_vm.used_disk_space()

    logger.info('disk_space1 %s' % disk_space1)

    se_vm.create_file_of_size(file_name, file_size)

    disk_space2 = se_vm.used_disk_space()

    logger_utils.asleep(delay=15)

    start_time = get_start_time(vs_name)

    se_series2 = get_se_series(se_uuids, start_time, 1,
                               metric_id='se_stats.avg_disk1_usage', step=5)

    logger.info(se_series2)

    logger.info('disk_space2 %s' % disk_space2)

    se_vm.remove_tmp_file(file_name)

    for v in se_series2.values():
        se_disk_space = int(v['se_stats.avg_disk1_usage'][0])
        reported_disk_space = int(disk_space2)
        if se_disk_space != reported_disk_space:
            logger_utils.error('SE disk space <%s> did not match expected <%s>'
                               % (se_disk_space, reported_disk_space))


def get_pool_series(vs_name, start_time, how_many, **kwargs):
    """

    :param vs_name:
    :param start_time:
    :param how_many:
    :param kwargs:
    :return:
    """

    kwargs['start'] = start_time
    kwargs['limit'] = how_many
    # step = int(kwargs.get('step', 5))

    series = get_metrics_vs(vs_name, **kwargs)['series']

    parsed = parse_series(series, how_many, **kwargs)

    return parsed

def get_server_series(vs_name, pool_model, start_time, how_many, **kwargs):

    kwargs['start'] = start_time
    kwargs['limit'] = how_many

    all_servers = {}
    for name, server in pool_model.servers.items():
        kwargs['obj_id'] = '%s:%s' % (server.ip(), server.port())
        series = get_metrics_vs(vs_name, **kwargs)['series']

        all_servers['name'] = parse_series(series, how_many, **kwargs)

    return all_servers


def check_series_stdev(series_data):
    """

    :param series_data:
    :return:
    """

    if not series_data or len(series_data) < 2:
        return True
    num_data = len(series_data)
    meanv = sum(series_data) / num_data
    standard_dev = (sum(pow((x - meanv), 2) for x in series_data)) / num_data
    standard_dev = math.sqrt(standard_dev)
    if meanv == 0 or standard_dev / meanv < 2:
        return True
    logger.info('standard_dev' + str(standard_dev))
    return False


def metrics_test_validation(vs_name, vs_port, client_handles, file_size,
                            test_ctx, **kwargs):
    """

    :param vs_name:
    :param vs_port:
    :param client_handles:
    :param file_size:
    :param test_ctx:
    :param kwargs:
    :return:
    """

    step = int(kwargs.get('step', 5))
    samples = int(kwargs.get('samples', 5))
    se_uuids = se_lib.get_se_uuids_from_vs_name(vs_name)
    vs = vs_lib.get_vs(vs_name)
    pool_uuid = webapp_lib.get_uuid_from_ref(vs['pool_ref'])
    pool_name = webapp_lib.get_name_from_ref(vs['pool_ref'])
    pad_missing_data = kwargs.get('pad_missing_data', 'true')

    from avi_objects.avi_config import AviConfig
    config = AviConfig.get_instance()
    context_key = config.get_context_key()
    pool = config.site_objs[context_key]['pool'][pool_name]
    vs_series_1 = get_vs_series(vs_name, test_ctx.start_time, samples,
                                metric_id=test_ctx.vs_metrics_1, step=step,
                                pad_missing_data=pad_missing_data)

    vs_series_2 = get_vs_series(vs_name, test_ctx.start_time, samples,
                                metric_id=test_ctx.vs_metrics_2, step=step,
                                pad_missing_data=pad_missing_data)

    pool_series = get_pool_series(vs_name, test_ctx.start_time, samples,
                                  pool=pool_uuid,
                                  metric_id=test_ctx.pool_metrics, step=step,
                                  pad_missing_data=pad_missing_data)

    server_series = get_server_series(vs_name, pool, test_ctx.start_time,
                                      samples,
                                      pool=pool_uuid,
                                      metric_id=test_ctx.server_metrics,
                                      step=step,
                                      pad_missing_data=pad_missing_data)

    se_series_1 = get_se_series(se_uuids, test_ctx.start_time, samples,
                                metric_id=test_ctx.se_metrics_1, step=step,
                                pad_missing_data=pad_missing_data)

    se_series_2 = get_se_series(se_uuids, test_ctx.start_time, samples,
                                metric_id=test_ctx.se_metrics_2, step=step,
                                pad_missing_data=pad_missing_data)

    check_series(vs_series_1, metrics_thresholds.metrics, 'vs',
                 pad_missing_data)
    check_series(vs_series_2, metrics_thresholds.metrics, 'vs',
                 pad_missing_data)
    check_series(pool_series, metrics_thresholds.metrics, 'pool',
                 pad_missing_data)

    for v in server_series.values():
        check_series(v, metrics_thresholds.metrics, 'server')

    for se_uuid, series in se_series_1.items():
        # TODO(joec): catch and add the se_uuid before rethrowing
        check_series(series, metrics_thresholds.metrics, 'se')
    for se_uuid, series in se_series_2.items():
        check_series(series, metrics_thresholds.metrics, 'se')
    return

def check_series_stdev(series_data):
    if not series_data or len(series_data) < 2:
        return True
    num_data = len(series_data)
    meanv = sum(series_data) / num_data
    standard_dev = (sum(pow((x - meanv), 2) for x in series_data)) / num_data
    standard_dev = math.sqrt(standard_dev)
    if meanv == 0 or standard_dev / meanv < 2:
        return True
    logger.info('standard_dev %s' % str(standard_dev))
    return False

def check_series(series, metrics_thresholds, type_of_series,
                 pad_missing_data='true'):
    outliers = {}
    full_series = {}
    logger.info(series)

    for k, v in metrics_thresholds[type_of_series].items():
        found = []
        min_val = v.get('min_val')
        max_val = v.get('max_val')
        if k not in series.keys() or k.find('absolute') != -1:
            continue

        if min_val is not None or max_val is not None:
            logger.info('Expected range(%s):%s-%s,\n values: %s' % (k, min_val,
                                                              max_val,
                                                              series.get(k)))
            continue

        if k.find('pkts') != -1:
            continue

        for i in series[k]:
            if k.find('pkts') != -1 or k in metrics_skip_list:
                continue
            if min_val is not None and i < min_val:
                found.append(i)
            if max_val is not None and i > max_val:
                found.append(i)

        if (k in metrics_skip_list
                and not check_series_stdev(series[k]) and
                k.find('se_stats') == -1):
            found.append('Expected range(%s):%s-%s' % (k,
                                                       min_val, max_val))
            outliers[k] = series[k][0]
            full_series[k] = series[k]

        if found:
            found.append('Expected range(%s):%s-%s' % (k,
                                                       min_val, max_val))
            outliers[k] = found
            full_series[k] = series[k]

    for k, v in outliers.items():
        if len(v) > 0:
            logger_utils.error(
                'Metrics error: --%s-- series had values out of expected range: %s\n\nFull '
                'series:%s'
                % (type_of_series, outliers, full_series)
            )

def metrics_check_vs_collection(vs_req, use_ids=False, ret_last_val=False, **kwargs):
    #default_mq = MetricsQuery()
    vs_uuids = ''
    if vs_req and 'vs' in vs_req:
        resp_code, vs_obj = rest.get('virtualservice', name=vs_req.get('vs'))
        vs_list = [vs_obj]
    else:
        resp_code, vs_list = rest.get('virtualservice')
        vs_list = vs_list['results']
        ret_last_val = False
        # print "got n vs ", len(vs_list)
    test_vs_list = []
    num_non_rt_vs = 0
    for vs_obj in vs_list:
        logger.info('adding vs %s %s' %(vs_obj['uuid'], vs_obj['name']))
        if webapp_lib.get_name_from_ref(vs_obj['tenant_ref']) != kwargs.get('tenant', 'admin'):
            continue
        #if not vs_obj.analytics_policy.metrics_realtime_update.enabled:
        vs_analytics_policy = vs_obj.get('analytics_policy')
        if vs_analytics_policy:
            logger.debug("Found analytics_policy %s" % vs_analytics_policy)
            metrics_realtime_update = vs_analytics_policy.get('metrics_realtime_update')
            logger.debug("metrics_realtime_update %s" % metrics_realtime_update)
            if not metrics_realtime_update.get('enabled'):
                num_non_rt_vs += 1
        else:
           logger.debug("vs %s no analytics policy" % vs_obj['name'])
           num_non_rt_vs += 1
        test_vs_list.append(vs_obj)
    logger.debug("\n metrics_check_vs_collection: num_non_rt_vs %s \n" % num_non_rt_vs)
    # one vs is not realtime.
    vs_list = test_vs_list
    vs_uuids = ','.join([vs['name'] for vs in test_vs_list])
    req_list = []
    reqid = 0
    non_rt_adjust = 0
    for vs_obj in vs_list:
        mq_req = {}
        if vs_req:
            mq_req = vs_req.copy()
        mq_req['vs'] = vs_obj['name']
        mq_req['metric_entity'] = "VSERVER_METRICS_ENTITY"
        if mq_req.get('limit'):
            mq_req['limit'] = int(mq_req['limit'])
        if mq_req.get('step'):
            mq_req['step'] = int(mq_req['step'])
        if use_ids or kwargs.get('id'):
            mq_req['id'] = str(reqid)
            reqid += 1
        req_list.append(mq_req)
        logger.info(str(mq_req)+str(vs_req))

    if 'step' in req_list[-1]:
        step = int(req_list[-1].get('step'))
    elif 'step' in kwargs:
        step = int(kwargs['step'])
    else:
        step = 5

    pad_missing_data = True
    if 'pad_missing_data' in req_list[-1]:
        pad_missing_data = \
            str(req_list[-1].get('pad_missing_data', 'true')).lower() == 'true'
    elif 'pad_missing_data' in kwargs:
        pad_missing_data = \
            str(kwargs.get('pad_missing_data', 'true')).lower() == 'true'
    if step == 5 and not pad_missing_data:
        non_rt_adjust = num_non_rt_vs
    logger.debug('non_rt_adjust %s' % non_rt_adjust)

    # mq_req['limit'] = int(kwargs['limit'])
    # mq_req['step'] = int(kwargs['step'])
    results = metrics_collection_get(req_list, **kwargs)
    is_using_ids, ids = metrics_query_is_using_ids(req_list)
    mrsps = {}
    if not is_using_ids:
        series_dict = results['series']
        mrsps[''] = series_dict
    else:
        for rspid in ids:
            for k in results['series'].keys():
                if k.find(rspid) != -1:
                    mrsps[rspid] = results['series'][k]
                    break

    limit = int(mq_req.get('limit') if mq_req.get('limit') else
                kwargs.get('limit') if kwargs.get('limit') else
                60) # default_mq.limit
    if (mq_req.get('page') and mq_req.get('page_size') and
        mq_req.get('dimension_aggregation') and
        (not mq_req.get('dimensions') or
         (mq_req.get('dimensions') and
          'METRIC_DIMENSION_METRIC_TIMESTAMP' not in mq_req['dimensions']))):
        limit = int(mq_req.get('page_size'))
    num_data_expected = limit

    if (mq_req.get('dimension_aggregation') and
        (not mq_req.get('dimensions') or
         (mq_req.get('dimensions') and
          'METRIC_DIMENSION_METRIC_TIMESTAMP' not in mq_req['dimensions']))):
        num_data_expected = None
    for series_dict in mrsps.values():
        metric_ids = (mq_req.get('metric_id') if mq_req.get('metric_id') else
                      kwargs.get('metric_id') if kwargs.get('metric_id') else
                      '')

        num_series_expected = len(metric_ids.split(','))
        if (num_series_expected != 1):
            ret_last_val = False
        if len(series_dict.keys()) != (len(vs_list) - non_rt_adjust):
            logger_utils.error(
                'step %s limit %s Number of vs %d %s is not same as expected %d non rt %s %s' %
                (step, limit, len(series_dict.keys()), series_dict.keys(),
                 len(vs_list), non_rt_adjust, vs_uuids))
        for k, v, in series_dict.iteritems():
            #logger.info('m key'+ str(k)+ ' num_series '+ len(v))
            if len(v) != num_series_expected:
                logger_utils.error('vs %s has %d but expected num %d' %
                                   (k, len(v), num_series_expected))
            for mseries in v:
                logger.info('checking series for key' + str(k) + ' metric '+str(
                       mseries['header']['name']))
                if (num_data_expected and
                        len(mseries['data']) > num_data_expected):
                    logger_utils.error(
                        'num data %d is not same as expected %d' %
                        (len(mseries['data']), num_data_expected))
                if (ret_last_val):
                    return (mseries['data'])

def metrics_collection_get(req_list, path='metrics/collection/?',
                           **kwargs):
    httpreq = {'metric_requests': []}
    logger.debug('req_list %s' % req_list)
    for mqreq in req_list:
        if 'vs' in mqreq:
            vs_list = mqreq['vs'].split(',')
            vs_uuids = ''
            for vs_name in vs_list:
                # Talk to Gaurav
                #vs_obj = vs_lib.get_vs(vs_name,**kwargs)
                vs_obj = vs_lib.get_vs(vs_name)
                vs_uuid = vs_obj['uuid']
                vs_uuids = \
                    vs_uuids + ',' + vs_obj['uuid'] if vs_uuids else vs_uuid
                logger.debug('vs_obj %s' % vs_obj)
            mqreq['entity_uuid'] = vs_uuids
            del(mqreq['vs'])
        if 'se' in mqreq:
            se_list = se_lib.get_se_uuids_from_vs_name(mqreq['se'])
            logger.info('se in mreq se_list %s' % se_list)
            se_uuids = ''
            for se in se_list:
                logger.info('se %s' % se)
                se_uuids = se_uuids + ',' + se if se_uuids else se
            mqreq['entity_uuid'] = se_uuids
            del(mqreq['se'])

        if 'pool' in mqreq:
            pool_list = mqreq['pool'].split(',')
            pool_uuids = ''
            for pool in pool_list:
                logger.info('pool %s' % pool)
                plid = rest.get_uuid_by_name('pool', pool)
                pool_uuids = pool_uuids + ',' + plid if pool_uuids else plid
            mqreq['pool_uuid'] = pool_uuids
            del(mqreq['pool'])
        if 'serviceengine_uuid'in mqreq:
            se_list = \
                se_lib.get_se_uuids_from_vs_name(mqreq['serviceengine_uuid'])
            mqreq['serviceengine_uuid'] = se_list[0]
        if 'serviceengine'in mqreq:
            se_list = \
                se_lib.get_se_uuids_from_vs_name(mqreq['serviceengine'])
            mqreq['serviceengine'] = se_list[0]
            logger.info(' setting se filter %s' % str(mqreq['serviceengine']))
        if 'server' in mqreq and mqreq['server'] != '*':
            svr = ServerModel.get_server(mqreq['server'])
            if svr:
                server_ip_port = svr.ip() + ':' + str(svr.port())
                mqreq['server'] = server_ip_port

        httpreq['metric_requests'].append(mqreq)
    #print 'sending request', httpreq
    logger.debug('httpreq %s' % httpreq)
    logger.debug('httpreq kwargs %s' % kwargs)
    results = metrics_post_collection(httpreq, path, **kwargs)
    return results

def metrics_post_collection(collection_req, path, **kwargs):
    '''
    Args:
    @param req_list: list of MetricsQuery converted into dictionary
    @param additional query params
    '''
    path += generate_query_string(kwargs)
    logger.info(' posting request for metrics %s request: %s' % (path, str(json.dumps(collection_req))))
    status_code, results = rest.post('analytics', path=path, data=json.dumps(collection_req))
    # XXX do we no longer need the line?
    logger.info(results)
    return results

def metrics_query_is_using_ids(req_list):
    ids = []
    if not req_list:
        return False, ids
    is_using_ids = False
    for mqreq in req_list:
        if 'id' in mqreq:
            is_using_ids = True
            ids.append(mqreq['id'])
    return is_using_ids, ids

def metrics_check_pool_collection_api(pool_req, **kwargs):
    # default_mq = MetricsQuery()
    req_list = []
    logger.info('pool_req %s' % str(pool_req))

    if pool_req and pool_req.get('pool'):
        pool_list = pool_req['pool'].split(',')
    else:
        #pool_list = [pool_obj.name for pool_obj in config.get_all('pool')]
        pool_list = []
        status_code, _data = rest.get('pool')
        for _pool in _data['results']:
            pool_list.append(_pool.get('name'))

    logger.info('Using pool list %s' % str(pool_list))
    # XXX This seem different
    if pool_req:
        metric_ids = pool_req.get(
            'metric_id', 'l4_server.avg_bandwidth,l4_server.avg_complete_conns')
    else:
        metric_ids = 'l4_server.avg_bandwidth,l4_server.avg_complete_conns'
    for index, pool in enumerate(pool_list):
        for metric_id in metric_ids.split(','):
            mq_req = deepcopy(pool_req)
            mq_req['entity_uuid'] = '*'
            # mq_req['metric_entity'] = "VSERVER_METRICS_ENTITY"
            if mq_req.get('limit', ''):
                mq_req['limit'] = int(mq_req['limit'])
            if mq_req.get('step', ''):
                mq_req['step'] = int(mq_req['step'])
            mq_req['limit'] = int(kwargs.get('limit', 12))
            mq_req['step'] = int(kwargs.get('step', 5))
            mq_req['metric_id'] = metric_id
            mq_req['pool'] = pool
            mq_req['id'] = str(index) + '-' + metric_id
            req_list.append(mq_req)
    results = metrics_collection_get(req_list, **kwargs)
    collection_series = results['series']
    num_metrics = len(metric_ids.split(','))
    num_pools = len(pool_list)
    if len(collection_series) != 1:
        logger_utils.error(
            'expected 1 got %s ids %s' % (
            len(collection_series), collection_series.keys()))
    for req_id, req_id_series in collection_series.items():
        # one series per pool
        if 'server' not in pool_req:
            assert len(req_id_series) == num_pools
        for etuple, ms_results in req_id_series.items():
            if len(ms_results) != num_metrics:
                logger_utils.error(
                    'expected %s got %s ids %s' % (
                    num_metrics, len(ms_results), etuple))
            assert len(ms_results) == num_metrics

def match_metric_values(series1, series2):
    if len(series1) == 0 :
        logger_utils.error("No values returned")
    if len(series1) != len(series2) :
        logger_utils.error("number of values not same")
    if series1[len(series1)-1]['timestamp'] != series2[len(series1)-1]['timestamp']:
        if len(series2) < 2:
            logger_utils.error("metric time stamps dont match")
        if series1[len(series1)-1]['timestamp'] != series2[len(series1)-2]['timestamp']:
            logger_utils.error("metric time stamps dont match")
        else:
            if series1[len(series1)-1]['value'] != series2[len(series1)-2]['value']:
                logger_utils.error("metric values dont match")
    else:
        if series1[len(series1)-1]['value'] != series2[len(series1)-1]['value']:
            logger_utils.error("metric values dont match")
    logger.info('metric values match')

def run_traffic(client_handles, client_type, vs_name, vs_port, file_name,
                rate, num_conns, requests_per_session, request_method):
    if client_type == 'apache_bench':
        perf.run_ab_on_client(client_handles, vs_name, vs_port, file_name,
                              rate, num_conns)
    elif client_type == 'httperf':
        perf.start_httperf_on_client(client_handles, vs_name, vs_port,
                                     file_name, rate, num_conns,
                                     requests_per_session,
                                     method=request_method)
    else:
        logger_utils.error('Unsupported client type: %s for client handles: %s' % (
            client_type, client_handles))

def stop_traffic(client_handles, client_type='httperf'):
    if client_type == 'apache_bench':
        perf.stop_ab_on_client(client_handles)
    elif client_type == 'httperf':
        # only works for client handle...
        perf.stop_httperf_on_client(client_handles)
    else:
        logger_utils.error('Unsupported client type: %s for client handles: %s' %
                         (client_type, client_handles))

def metrics_test_setup(vs_name, vs_port, client_handles, file_size, **kwargs):
    logger_utils.asleep("waiting for vs to be up", delay=10)
    if not vs_lib.is_vs_assigned(vs_name):
        logger_utils.error('VS %s is not up' % vs_name)
    step = kwargs.get('step', 5)
    client_type = kwargs.get('client_type', 'httperf')
    request_method = kwargs.get('request_method', 'GET')
    app_delay = int(kwargs.get('app_delay', 0))
    response_status = int(kwargs.get('response_status', 0))
    client_direction = kwargs.get('client_direction', 'egress')
    server_direction = kwargs.get('server_direction', 'ingress')
    client_delay = kwargs.get('client_delay', '0ms')
    server_delay = kwargs.get('server_delay', '0ms')
    client_loss = kwargs.get('client_loss', '0%')
    server_loss = kwargs.get('server_loss', '0%')
    rate = int(kwargs.get('rate', 100))
    requests_per_session = int(kwargs.get('requests_per_session', 1))
    num_conns = int(kwargs.get('num_conns', 0))
    samples = int(kwargs.get('samples', 5))
    error_percent = float(kwargs.get('error_percent', 0))
    error_file = kwargs.get('error_file', '404')
    traffic_startup_buffer = int(kwargs.get('traffic_startup_buffer', 6))
    after_test_buffer = int(kwargs.get('after_test_buffer', 0))

    stop_traffic(client_handles, client_type)

    # Make sure it starts with a /
    error_file = '/' + error_file.strip('/')

    if not num_conns:
        # If num_conns is supplied, assume apache bench or user supplied
        # num_conns
        # If not, calculate num_conns from total samples + buffer
        num_conns = rate * (samples + traffic_startup_buffer) * step

    file_name = kwargs.get('uri_path', '')
    if not file_name:
        file_name = str(file_size) + '.txt'
        file_name += '?delay=%s&responseStatus=%s' % (app_delay,
                                                      response_status)
    if file_name[0] != '/':
        file_name = '/' + file_name

    vs = vs_lib.get_vs(vs_name)

    logger.info('vs %s obj %s' % (vs_name, str(vs)))
    pool_name = webapp_lib.get_name_from_ref(vs['pool_ref'])
    status_code, pool_obj = rest.get('pool', name=pool_name)
    config = infra_utils.get_config()
    context_key = config.get_context_key()
    pool = config.site_objs[context_key]['pool'][pool_name]
    error_rate = int(rate * error_percent)
    error_connections = int(num_conns * error_percent)

    rate = int(rate * (1 - error_percent))
    num_conns = int(num_conns * (1 - error_percent))

    se_uuids = se_lib.get_se_uuids_from_vs_name(vs_name)

    # Ugly hard code to 1 SE, will revisit when needed
    try:
        se_vm = infra_utils.get_vm_of_type('se')[0]
        interfaces = get_se_interfaces(se_uuids[0], se_vm)
    except IndexError:
        interfaces = {}

    # config.vs_info {u'vs1': ['10.10.116.61', u'net1', 'dvPGTest116']}
    vip = vs_lib.get_vs_network_by_name(vs_name)
    vs_net = infra_utils.get_network_name(vip)

    if len(metrics_thresholds.metrics['vs']) == 0:
        metrics_thresholds.run_generate_thresholds()
    # vs_metrics = ','.join(metrics_thresholds.metrics['vs'])
    # We hit the limit of Django request URIs. Splitting them into half to
    # reduce length.
    vs_metrics_1 = dict(metrics_thresholds.metrics['vs'].items()[
                        len(metrics_thresholds.metrics['vs']) / 2:])
    vs_metrics_2 = dict(metrics_thresholds.metrics['vs'].items()[
                        :len(metrics_thresholds.metrics['vs']) / 2])
    vs_metrics_1 = ','.join(vs_metrics_1)
    vs_metrics_2 = ','.join(vs_metrics_2)
    pool_metrics = ','.join(metrics_thresholds.metrics['pool'])
    server_metrics = ','.join(metrics_thresholds.metrics['server'])
    # se_metrics = ','.join(metrics_thresholds.metrics['se'])
    se_metrics_1 = dict(metrics_thresholds.metrics['se'].items()[
                        len(metrics_thresholds.metrics['se']) / 2:])
    se_metrics_2 = dict(metrics_thresholds.metrics['se'].items()[
                        :len(metrics_thresholds.metrics['se']) / 2])
    se_metrics_1 = ','.join(se_metrics_1)
    se_metrics_2 = ','.join(se_metrics_2)

    metrics_thresholds.calculate_metrics_thresholds(
        step, app_delay, client_delay, server_delay, rate,
        file_size, requests_per_session, pool.servers,
        error_rate, error_file, response_status, request_method,
        interfaces, vs_net
    )

    if 'check_metric_id' in kwargs:
        check_metric_id = kwargs.get('check_metric_id')
        min_val = int(kwargs.get('min_val'))
        max_val = int(kwargs.get('max_val'))

        divide_by_servers = metrics_thresholds.create_divide_by_servers()

        for metric_key, metric_values in metrics_thresholds.metrics.items():
            # print 'metric_values:', metric_values
            for k in metric_values.keys():
                if k == check_metric_id:
                    if metric_key == 'server' and k in divide_by_servers:
                        metric_values[k]['min_val'] = \
                            float(min_val) / len(pool.servers)
                        metric_values[k]['max_val'] = \
                            float(max_val) / len(pool.servers)
                    else:
                        metric_values[k]['min_val'] = min_val
                        metric_values[k]['max_val'] = max_val
                else:
                    if 'min_val' in metric_values[k]:
                        del metric_values[k]['min_val']
                    if 'max_val' in metric_values[k]:
                        del metric_values[k]['max_val']

    if not debug_skip_traffic:
        remove_net_emulation(client_handles, pool)

        add_net_emulation(client_handles, pool, client_delay, server_delay,
                          client_loss, server_loss, client_direction,
                          server_direction)

        time_initial = time.time()

        if error_percent < 1:
            run_traffic(client_handles, client_type, vs_name, vs_port,
                        file_name, rate, num_conns, requests_per_session,
                        request_method)

        if error_percent > 0:
            run_traffic(client_handles, client_type, vs_name, vs_port,
                        error_file, error_rate, error_connections,
                        requests_per_session, request_method)

        logger.info('Time passed after run traffic before first sleep:' +
            str(time.time() - time_initial))

        logger_utils.asleep(get_initial_sleep(step, traffic_startup_buffer))

        logger.info('Time passed after sleep' + str(time.time() - time_initial))

        start_time = get_start_time(vs_name)
        duration = get_collection_sleep(step, samples)
        test_wait = get_after_test_sleep(step, after_test_buffer)
        test_ctx = MetricsTestContext(start_time=start_time,
                                      test_duration=duration,
                                      after_test_wait=test_wait,
                                      vs_metrics_1=vs_metrics_1,
                                      vs_metrics_2=vs_metrics_2,
                                      pool_metrics=pool_metrics,
                                      server_metrics=server_metrics,
                                      se_metrics_1=se_metrics_1,
                                      se_metrics_2=se_metrics_2)
    else:
        start_time = get_start_time(vs_name)
        test_ctx = MetricsTestContext(start_time=start_time,
                                      test_duration=0,
                                      after_test_wait=0,
                                      vs_metrics_1=vs_metrics_1,
                                      vs_metrics_2=vs_metrics_2,
                                      pool_metrics=pool_metrics,
                                      server_metrics=server_metrics,
                                      se_metrics_1=se_metrics_1,
                                      se_metrics_2=se_metrics_2)
    return test_ctx


def get_initial_sleep(step, traffic_startup_buffer):
    """

    :param step:
    :param traffic_startup_buffer:
    :return:
    """

    return step * traffic_startup_buffer - 1


def get_collection_sleep(step, samples):
    return step * (samples + 2)

def get_after_test_sleep(step, after_test_buffer):
    """

    :param step:
    :param after_test_buffer:
    :return:
    """

    return step * after_test_buffer

def add_net_emulation(client_handles, pool, client_delay, server_delay,
                      client_loss, server_loss, client_direction,
                      server_direction):
    for server_handle in pool.servers:
        pool_lib.simulate_ingress(server_handle, 'server', delay=server_delay,
                                  loss=server_loss, direction=server_direction)
    pool_lib.simulate_ingress(client_handles, 'client', delay=client_delay,
                              loss=client_loss, direction=client_direction)

def remove_net_emulation(client_handles, pool):
    for server_handle in pool.servers:
        pool_lib.simulate_ingress(server_handle, 'server', delay='0ms',
                                  direction='both')
    pool_lib.simulate_ingress(client_handles, 'client', delay='0ms',
                              direction='both')

def get_se_interfaces(se_uuid, se_vm):
    jsondata = se_lib.get_se_stats(se_uuid, 'interface', 'all')
    #   {
    # 'dvPGTest134': [('avi_eth7', '00:50:56:ac:4b:db', '10.10.134.10')],
    # 'dvPGTest135': [('avi_eth9', '00:50:56:ac:5e:69', '10.10.135.10')],
    eth_to_net = {}

    for core in jsondata:
        for obj in core['vnics']:
            net = infra_utils.get_network_name(obj['ip_info'][0]['ip_addr'])
            eth_to_net[obj['vnic_name']] = net

    return eth_to_net


def metrics_check_vm_stats(vm_uuid, vm_type='virtualmachine', **kwargs):
    logger.debug('checking stats for vm %s' % vm_uuid)
    cloud_type = rest.get_cloud_type()
    logger.debug('cloud_type %s' % cloud_type)

    kwargs['pad_missing_data'] = 'false'
    if not kwargs.get('limit'):
        kwargs['limit'] = 1
    if not kwargs.get('step'):
        kwargs['step'] = 300
    metric_ids = kwargs.get('metric_id', '')
    if not metric_ids:
        # metrics = mp_utils.obj_fields('vm_stats')
        # metric_ids = mp_utils.metrics_list_to_str(metrics)
        metrics = ['vm_stats.avg_cpu_usage', 'vm_stats.avg_mem_usage']
        metric_ids = ','.join(metrics)
        kwargs['metric_id'] = metric_ids
    else:
        metrics = metric_ids.split(',')

    if vm_type == 'serviceengine':
        qrsp = get_metrics_se(vm_uuid, **kwargs)
    elif vm_type == 'host':
        qrsp = get_metrics_host(vm_uuid, **kwargs)
    else:
        qrsp = get_metrics_vm(vm_uuid, **kwargs)
    vmseries = qrsp.get('series', None)
    if not vmseries:
        logger_utils.error('Metrics for vm %s not found' % vm_uuid)
    qmetrics_list = []
    for mseries in vmseries:
        metric_id = mseries['header']['name']
        if metric_id in metrics_skip_list:
            continue
        if not mseries.get('data'):
            if cloud_type == 'vmware':
                # TODO: Disabled till AV-24789 is fixed
                logger.debug('ignoring this check for vmware till ESX Mapping is'
                    'stable. cloud %s metrics %s' %
                    (cloud_type, metrics))
                continue
            if (metric_id in ('vm_stats.avg_cpus_user_time_secs',
                              'vm_stats.avg_port_usage',
                              'vm_stats.avg_cpus_system_time_secs')):
                if cloud_type == 'mesos':
                    logger_utils.error(
                        'No metric data for cloud %s vm %s metric %s' %
                        (cloud_type, vm_uuid, metric_id))

                else:
                    continue
            else:
                logger_utils.error('No metric data for vm %s metric %s' %
                                   (vm_uuid, metric_id))
        if len(mseries.get('data')) < kwargs['limit']:
            print ('metrics %s has only %d data rather than %d' %
                   (metric_id, len(mseries['data']), kwargs['limit']))
        qmetrics_list.append(metric_id)
    qmetrics_list.sort()
    missing_metrics = set(metrics) - set(qmetrics_list) - metrics_skip_list
    if missing_metrics:
        logger.debug(str(metrics))
        logger.debug((qmetrics_list))
        if cloud_type != 'vmware':
            # TODO: Disabled till AV-24789 is fixed
            logger_utils.error('Metrics series missing for vm %s metrics %s' %
                                (vm_uuid, str(missing_metrics)))
    return


def get_metrics_host(host_uuid, **kwargs):
    path = 'analytics/metrics/host/' + host_uuid + '?'
    path += generate_query_string(kwargs)
    status_code, results = rest.get(path)
    # XXX TODO is this no longer needed?
    #rest.check_response_for_errors(results)
    return results


def get_metrics_vm(vm_uuid, **kwargs):
    path = 'analytics/metrics/virtualmachine/' + vm_uuid + '?'
    path += generate_query_string(kwargs)
    status_code, results = rest.get(path)
    # XXX TODO is this no longer needed?
    #rest.check_response_for_errors(results)
    return results


def metrics_check_all_se_vm_stats(**kwargs):
    se_list = se_lib.get_se_uuid()
    for se_uuid in se_list:
        metrics_check_vm_stats(se_uuid, 'serviceengine', **kwargs)


def get_pool_server_vm_host_uuids():
    host_list = set([])
    #pool_list = config.get_all('pool')
    status_code, pool_list = rest.get('pool')
    for pool_obj in pool_list['results']:
        for server in pool_obj.get('servers', []):
            if not server.get('vm_ref', ''):
                continue
            vm_ref = server['vm_ref']
            vm_uuid = vm_ref.split('vimgrvmruntime/')[1].strip()
            host = se_lib.get_host_uuid_from_vm_uuid(vm_uuid)
            logger.debug('Adding host %s for vm %s' %(host,vm_uuid))
            host_list = host_list | set([host])
    logger.debug('Hosts with vm refs for this test %s' %str(host_list))
    return list(host_list)


def metrics_check_all_pool_server_vm_stats(**kwargs):
    status_code, pool_list = rest.get('pool')
    logger.debug('pool_list %s' %pool_list)
    for pool in pool_list['results']:
        logger.debug('metrics_check_all_pool_server_vm_stats %s' %pool['name'])
        metrics_check_pool_server_vm_stats(pool['name'])
    return


def metrics_check_pool_server_vm_stats(pool_name, **kwargs):
    # print str(pool_obj)';/f
    vms = metrics_get_all_pool_vms(pool_name)
    for vm_uuid in vms:
        if not vm_uuid:
            continue
        metrics_check_vm_stats(vm_uuid, 'virtualmachine', **kwargs)
    return


def metrics_check_vs_invalid_req_id(vs_req, **kwargs):
    """

    :param vs_req:
    :param kwargs:
    :return:
    """
    # This code is just copy paste, Need to convert as per new format
    vs_uuids = ''
    if vs_req and 'vs' in vs_req:
        vs_obj = config.get('virtualservice', vs_req.get('vs'))
        vs_list = [vs_obj]
    else:
        vs_list = config.get_all('virtualservice')
        # print "got n vs ", len(vs_list)
    for vs_obj in vs_list:
        # print 'adding vs', vs_obj.uuid, vs_obj.name
        vs_uuids = vs_uuids + ',' + vs_obj.name if vs_uuids else vs_obj.name
    req_list = []
    for vs_obj in vs_list:
        mq_req = {}
        if vs_req:
            mq_req = vs_req.copy()
        mq_req['vs'] = vs_obj.name
        mq_req['metric_entity'] = "VSERVER_METRICS_ENTITY"
        if mq_req.get('limit'):
            mq_req['limit'] = int(mq_req['limit'])
        if mq_req.get('step'):
            mq_req['step'] = int(mq_req['step'])
        if kwargs.get('id'):
            mq_req['id'] = 0
        req_list.append(mq_req)
        print mq_req, vs_req
    # mq_req['limit'] = int(kwargs['limit'])
    # mq_req['step'] = int(kwargs['step'])
    try:
        metrics_collection_get(req_list, **kwargs)
        assert False
    except:
        pass
    reqid = 'x'
    req_list = []
    for vs_obj in vs_list:
        mq_req = {}
        if vs_req:
            mq_req = vs_req.copy()
        mq_req['vs'] = vs_obj.name
        mq_req['metric_entity'] = "VSERVER_METRICS_ENTITY"
        if mq_req.get('limit'):
            mq_req['limit'] = int(mq_req['limit'])
        if mq_req.get('step'):
            mq_req['step'] = int(mq_req['step'])
        if kwargs.get('id'):
            reqid = reqid + ',' + 'x'
            mq_req['id'] = reqid
        req_list.append(mq_req)
     # mq_req['limit'] = int(kwargs['limit'])
     # mq_req['step'] = int(kwargs['step'])
    try:
        metrics_collection_get(req_list, **kwargs)
        assert False
    except Exception as e:
        logger.info(e)


def metrics_check_poolvm_container(pool_name, **kwargs):
    """

    :param pool_name:
    :param kwargs:
    :return:
    """

    if not kwargs.get('metric_id'):
        kwargs['metric_id'] = 'vm_stats.avg_cpu_usage'
    if not kwargs.get('step'):
        kwargs['step'] = 300
    if not kwargs.get('limit'):
        kwargs['limit'] = 2
    metric_id = kwargs['metric_id']
    vms = metrics_get_all_pool_vms(pool_name)
    vms = set(vms)
    if not vms:
        logger.warn('No VMs found for pool %s' % pool_name)
        logger_utils.fail('No VMs found for pool %s' % pool_name)
    result = get_poolvm_series(pool_name, **kwargs)
    logger.info('num_vms: %s num_metrics %s' % (len(vms), len(metric_id.split(','))))
    logger.info('metrics response %s baseline %s' % (result, kwargs['mbaseline']))
    max_val = result['series'][0]['header']['statistics']['max']
    assert max_val > int(kwargs['mbaseline'])


def metrics_get_all_pool_vms(pool_name, hostname=''):
    """

    :param pool_name:
    :param hostname:
    :return:
    """

    vms = []
    pool_obj = metrics_get_pool_obj(pool_name)
    for server in pool_obj.get('servers', []):
        vm_uuid = ''
        if hostname and server['hostname'] != hostname:
            continue
        if 'vm_ref' in server:
            vm_ref = server['vm_ref']
            vm_uuid = vm_ref.split('vimgrvmruntime/')[1].strip()
        elif 'external_uuid' in server and server['external_uuid']:
            vm_uuid = server['external_uuid']
        elif 'vm_ref' in server and (not server.get('nw_ref', '')):
            logger.info('NW ref not set for server %s' %
                   server['hostname'])
            continue
        if not vm_uuid:
            logger_utils.fail('Invalid pool %s server %s vm not found' % (pool_name, server))
        vms.append(vm_uuid)
        if hostname and server['hostname'] == hostname:
            break
    if not vms:
        logger.debug('pool with no vms %s ', pool_obj)
    return vms


def metrics_get_pool_obj(pool_name):
    """

    :param pool_name:
    :return:
    """

    status_code, results = rest.get('pool', name=pool_name)
    return results


def get_poolvm_series(pool_name, **kwargs):
    """

    :param pool_name:
    :param kwargs:
    :return:
    """

    pool_uuid = rest.get_uuid_by_name('pool', pool_name)
    logger.info('get pool_vm metrics for %s' % pool_uuid)
    path = 'analytics/metrics/poolvm/' + pool_uuid + '?'
    path += generate_query_string(kwargs)
    logger.info('getting metrics %s' % path)
    status_code, results = rest.get(path)
    return results


def metrics_check_poolvm(pool_name, **kwargs):
    if not kwargs.get('metric_id'):
        kwargs['metric_id'] = 'vm_stats.avg_cpu_usage,vm_stats.avg_mem_usage'
    if not kwargs.get('step'):
        kwargs['step'] = 300
    metric_id = kwargs['metric_id']
    vms = metrics_get_all_pool_vms(pool_name)
    vms = set(vms)
    if not vms:
        logger.info('No VMs found for pool: %s' % pool_name)
        return
    result = get_poolvm_series(pool_name, **kwargs)
    logger.info('num_vms:%s, num_metrics:%s' %(len(vms),len(metric_id.split(','))))
    assert len(result['series'])
    assert len(result['series']) == len(vms) * len(metric_id.split(','))


def metrics_get_all_pool_server_ip(pool_name, server_handle=''):
    import lib.pool_lib as  pool_lib
    server_ip_port_list = []
    # if server_handle:
    #     svr = ServerModel.get_server(server_handle)
    #     server_ip_port = svr.ip() + ':' + str(svr.port())
    #     server_ip_port_list.append(server_ip_port)
    #     return server_ip_port_list
    server_ip_port_list = pool_lib.get_all_servers_of_pool(pool_name)
    return server_ip_port_list


def metrics_check_pool_metrics(pool_name, metric_id, server_name='',
                               **kwargs):
    config = infra_utils.get_config()
    pool_uuid = rest.get_uuid_by_name('pool', pool_name)
    pool_vms = metrics_get_all_pool_vms(pool_name)
    kwargs['metric_id'] = metric_id
    server_ip_port_list = []
    if server_name and server_name != '*':
        if config.testbed[config.site_name].cloud[0]['vtype'] == 'mesos':
            kwargs['server'] = server_name
            server_ip_port_list.append(server_name)
        # else:
        #     svr = infra_utils.get
        #     logger.info(' vm for server ', server_name, svr.pb.hostname)
        #     pool_vms = metrics_get_all_pool_vms(pool_name, svr.pb.hostname)
        #     print ' server vm', pool_vms
        #     server_ip_port = svr.ip() + ':' + str(svr.port())
        #     kwargs['server'] = server_ip_port
        #     server_ip_port_list.append(server_ip_port)
    if server_name == '*':
        kwargs['server'] = '*'
        server_ip_port_list = metrics_get_all_pool_server_ip(pool_name)
    if not server_name and kwargs.get('server'):
        del kwargs['server']
    '''
    1. get metrics for pool and pool vms
    2. check if the pool vm metrics were returned.
    '''
    vm_metrics = set([])
    p_metrics = set([])
    server_metrics = {}
    for m in metric_id.split(','):
        if m.find('vm_stats') != -1:
            vm_metrics.add(m)
        elif server_name:
            for server_ip_port in server_ip_port_list:
                if server_ip_port not in server_metrics:
                    server_metrics[server_ip_port] = set([])
                server_metrics[server_ip_port].add(m)
        else:
            p_metrics.add(m)
    logger.info(server_name)
    logger.info('vm metrics: %s' % vm_metrics)
    logger.info('p_metrics: %s' % p_metrics)
    logger.info('server_metrics: %s' % server_metrics)
    path = 'analytics/metrics/pool/%s/?' % pool_uuid
    path += generate_query_string(kwargs)
    logger.info('getting metrics %s server name %s' % (path, server_name))
    status_code, results = rest.get(path)
    if server_name:
        for vm in pool_vms:
            per_vm_metrics = p_metrics.copy()
            for mseries in results['series']:
                m = mseries['header']['name']
                print 'metrics ', m, ' vm ', vm
                if m.find('vm_stats') == -1:
                    continue
                if m in per_vm_metrics:
                    per_vm_metrics.remove(mseries['header']['name'])
                # it should become empty
            assert not per_vm_metrics

    for mseries in results['series']:
        metric_id = mseries['header']['name']
        if not server_name:
            if metric_id in vm_metrics:
                vm_metrics.remove(metric_id)
                logger.info('Hawa')
        elif mseries['header'].get('server', ''):
            server = mseries['header']['server']
            if metric_id in server_metrics[server]:
                server_metrics[server].remove(metric_id)
            if not server_metrics[server]:
                del server_metrics[server]
        if pool_vms and metric_id in p_metrics:
            p_metrics.remove(mseries['header']['name'])
    if pool_vms:
        metric_ids = results['metric_id'].split(',')
        for metric_id in metric_ids:
            if metric_id in vm_metrics:
                vm_metrics.remove(metric_id)
        assert not vm_metrics
    assert not p_metrics
    assert not server_metrics
    logger.info('server metrics: %s' % server_metrics)


def metrics_check_pool_anomalies(pool_name, server_name='',
                                 **kwargs):
    pool_uuid = rest.get_uuid_by_name('pool', pool_name)
    pool_vms = metrics_get_all_pool_vms(pool_name)
    # if server_name and server_name != '*':
    #     svr = ServerModel.get_server(server_name)
    #     print ' vm for server ', server_name, svr.pb.hostname
    #     pool_vms = metrics_get_all_pool_vms(pool_name, svr.pb.hostname)
    #     print ' server vm', pool_vms
    #     server_ip_port = svr.ip() + ':' + str(svr.port())
    #     kwargs['server'] = server_ip_port
    if server_name == '*':
        kwargs['server'] = '*'
    if not server_name and kwargs.get('server'):
        del kwargs['server']
    '''
    1. get metrics for pool and pool vms
    2. check if the pool vm metrics were returned.
    '''
    path = 'analytics/anomaly/pool/%s/?' % pool_uuid
    path += generate_query_string(kwargs)
    logger.info(' getting metrics %s' % path)
    status_code, results = rest.get(path)


def create_alert_config(vs_name, acfg_name, metric_rules,
                        alert_rule_operator='OPERATOR_AND', **kwargs):
    """

    :param vs_name:
    :param acfg_name:
    :param metric_rules:
    :param alert_rule_operator:
    :param kwargs:
    :return:
    """

    acfg = copy.deepcopy(METRICS_ALERT_CONFIG)
    if metric_rules:
        acfg['alert_rule']['metrics_rule'].extend(metric_rules)
    else:
        acfg['alert_rule']['metrics_rule'] = [DEF_METRIC_RULE]

    logger.debug('metric rules %s, alert_rules %s'% (metric_rules, acfg['alert_rule']['metrics_rule']))

    acfg['name'] = acfg_name
    acfg['summary'] = (acfg_name + '-' +
                       acfg['alert_rule']['metrics_rule'][0]['metric_id'])
    acfg['alert_rule']['operator'] = alert_rule_operator
    if vs_name:
        vs_obj = rest.get('virtualservice', name=vs_name)
        #vs_uuid = vs_obj['uuid']
        pool_ref = vs_obj[1]['pool_ref']
        pool_uuid = rest.get_uuid_from_ref(pool_ref)
        acfg['obj_uuid'] = pool_uuid
    _, rsp = rest.get('actiongroupconfig', name=acfg['action_group_ref'])
    # log.debug('group_ref %s', rsp)
    acfg['action_group_ref'] = rsp['url']
    # log.debug('creating alert config %s', acfg)
    rc, rsp = rest.post('alertconfig', data=acfg)
    # rsp = webapp_lib.post_object('alertconfig', acfg, tenant)
    logger.debug('created alert config rc %d, rsp %s' % (rc, rsp))


def get_alerts(alert_config_uuid, obj_name, tenant='admin'):
    """
    Fetch list of alerts that match alet config uuid or obj_uuid
    :param alert_config_uuid:
    :param obj_name:
    :param tenant:
    :return:
    """

    path = 'alert/'
    qparams = {}
    if alert_config_uuid:
        qparams['alert_config_ref'] = alert_config_uuid
    if obj_name:
        qparams['obj_name'] = obj_name
    query_params = rest.get_query_params(qparams)
    if query_params:
        path = path + '?' + query_params
    logger.info(path)
    return rest.get(path)


def dismiss_all_alerts(**kwargs):
    """

    :param kwargs:
    :return:
    """

    num_alerts = 1
    num_retries = int(kwargs.get('num_retries', 100))
    tenant = kwargs.get('tenant', 'admin')
    while num_alerts and num_retries:
        num_retries = num_retries-1
        status_ocde, resp = get_alerts('', '', tenant=tenant)
        num_alerts = resp['count']
        if not num_alerts:
            logger.warning('no alerts present')
            return
        for alert_obj in resp['results']:
            logger.info(str(alert_obj['name']))
            dismiss_alert(alert_obj['name'])


def dismiss_alert(alert_id):
    """

    :param alert_id:
    :param tenant:
    :return:
    """

    logger.info('dismissing alert %s' % alert_id)
    rest.delete('alert', name=alert_id)


def metrics_check_vs_stats(vs_name, mbaseline, **kwargs):
    metric_ids = ''
    for metric_id in mbaseline.keys():
        if metric_ids:
            metric_ids = metric_ids + metric_id
        else:
            metric_ids = metric_id
    kwargs['metric_id'] = metric_ids
    logger.info(str(kwargs['metric_id']))
    logger.info('baseline metrics db %s' % mbaseline)
    vs_metrics = get_metrics_vs(vs_name, **kwargs)
    logger.info(str(vs_metrics))
    margin = kwargs.get('margin', 50)
    margin = margin / 200.0
    for m_id in mbaseline.keys():
        metrics_check_vs_metric_stats(vs_name, m_id, mbaseline[m_id],
                                      vs_metrics, margin, **kwargs)
    return

_STATS_FIELDS = ['mean', 'min', 'max', 'num_samples', 'sum']

def metrics_check_vs_metric_stats(vs_name, m_id, mbaseline, vs_metrics,
                                  margin, **kwargs):

    if not vs_lib.is_vs_assigned(vs_name):
        raise RuntimeError('VS %s is not up' % vs_name)
    for series in vs_metrics['series']:
        hdr = series['header']
        if m_id != hdr['name']:
            logger.info('ignoring series as metric not match %s' % hdr['name'])
            continue
        stats = hdr['statistics']
        for field in _STATS_FIELDS:
            mfield = field
            if field == 'sum':
                mfield = 'mean'
            if not mbaseline.get(mfield, ''):
                logger.info('did not find the stats %s %s' % (str(mbaseline), field))
                continue
            mstat = float(mbaseline.get(mfield))
            stat = stats[mfield]
            if field != 'sum':
                expected_hi = mstat * (1 + margin)
                expected_lo = mstat * (1 - margin)
            else:
                num_samples = stats['num_samples']
                stat = stat * num_samples
                expected_hi = mstat * (1 + margin) * num_samples
                expected_lo = mstat * (1 - margin) * num_samples
            if (stat > expected_hi or stat < expected_lo):
                msg = \
                    ('VS %s metric %s value %s outside expected [%s-%s]' %
                     (vs_name, m_id, stat, expected_lo, expected_hi))
                logger.info(msg)
                raise MetricsValidationError(msg)
            msg = ('VS %s metric %s value %s is inside expected [%s-%s]' %
                   (vs_name, m_id, stat, expected_lo, expected_hi))
            logger.info(msg)
            break
    return
