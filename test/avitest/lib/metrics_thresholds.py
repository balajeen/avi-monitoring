import copy
import math
import avi_objects.rest as rest
import avi_objects.common_utils as common_utils
from avi_objects.logger import logger

def get_all_metric_ids():
    path = 'analytics/metrics-options/'
    status_code, results = rest.get(path)
    ids = []
    for k, v in results.items():
        if k == 'metrics_data':
            for i in v:
                ids.append(i.keys()[0])
    return ids

metrics = {
    'vs': {},
    'pool': {},
    'server': {},
    'se': {},
}

get_post_other = ['get', 'post', 'other']

not_for_pool_or_server = [
    'collection.avg_client_latency',
    'collection.avg_l4_client_latency',
    'collection.avg_total_bandwidth',
    'collection.avg_total_finished_connections',
    'collection.sum_total_errors',
    'collection.virtualservice_total_tolerated_responses',
    'collection.virtualservice_total_satisfactory_responses',
    'collection.virtualservice_total_frustrated_responses',
    'collection.server_total_frustrated_responses',
    'collection.server_total_tolerated_responses',
    'collection.server_total_satisfactory_responses',
    'collection.avg_max_concurrent_connections',
    'collection.avg_resp_4xx_errors_excluded',
    'collection.avg_resp_5xx_errors_excluded',
]

estimated_backend_time = 10
connection_overhead = 410
request_header = 216
client_request = 125

file_size_string_to_bits = {
    # added number is overhead like header, ip, tcp, mac etc
    # doing sizes smaller than 1kb is not reliable
    '1kb': 1024,
    '100kb': 102400,
    '200kb': 204800,
    '500kb': 500000,
    '1mb': 1000000,
    '2mb': 2048000,
    '5mb': 5120000,
    '10mb': 10000000,
    '50mb': 51200000,
    '100mb': 100000000,
    '500mb': 512000000,
    '1gb': 1002400000,
    '/404': 1242,
}

rx_100kb = {
    'packets': 50,
    'bytes': 3500,
}

def run_generate_thresholds():

    all_metric_ids = get_all_metric_ids()

    collection_list = [
        x for x in all_metric_ids if x.startswith('collection.')]
    # controller_list = [x for x in all_metric_ids if x.startswith('controller_')]
    l4_list = [x for x in all_metric_ids if x.startswith('l4_')]
    l7_list = [x for x in all_metric_ids if x.startswith('l7_')]
    se_list = [x for x in all_metric_ids if x.startswith('se_')]
    # vm_list = [x for x in all_metric_ids if x.startswith('vm_')]

    # set defaults to x%
    for i in l4_list + l7_list + collection_list:
        # TODO(joec): look into removing the need for excessive padding on
        # sums after bug #715
        percent = 25
        metrics['vs'][i] = {
            'min_percent': percent,
            'max_percent': percent,
        }

    # override defaults
    metrics['vs']['l7_client.avg_total_requests'] = {
        'min_percent': 5,
        'max_percent': 5,
    }
    metrics['vs']['l4_client.avg_new_established_conns'] = {
        'min_percent': 5,
        'max_percent': 5,
    }
    metrics['vs']['l4_server.avg_total_rtt'] = {
        'min_percent': 0,
        'max_percent': 50,
        'min_value_must_be_at_least': 0,
        'max_percent_must_add_at_least': 40,
    }
    metrics['vs']['l4_client.avg_total_rtt'] = {
        'min_percent': 0,
        'max_percent': 25,
        # Should this ever be 0? Usually 1, sometimes 0
        'min_value_must_be_at_least': 0,
        # Seems high, when no delay this value is 1
        # with simulated 100ms delay the metric reports 115ms delay
        'max_percent_must_add_at_least': 20,
    }

    metrics['vs']['l7_server.avg_resp_latency'] = {
        'min_percent': 0,
        'max_percent': 25,
        'max_percent_must_add_at_least': 30,
    }

    metrics['vs']['collection.avg_application_latency'] = {
        'min_percent': 0,
        'max_percent': 25,
        'max_percent_must_add_at_least': 30,
    }

    metrics['vs']['l7_client.avg_client_txn_latency'] = {
        'min_percent': 0,
        'max_percent': 25,
        'max_percent_must_add_at_least': 30,
    }

    metrics['vs']['collection.avg_client_latency'] = {
        'min_percent': 0,
        'max_percent': 25,
        'max_percent_must_add_at_least': 30,
    }

    metrics['vs']['l4_client.sum_end_to_end_rtt'] = {
        'min_percent': 50,
        'max_percent': 50
    }

    for i in get_post_other:
        metrics['vs']['l7_server.sum_%s_resp_latency' % (i)] = {
            'min_percent': 25,
            'max_percent': 30,
            # TODO(joec): check this only when latency is under test
            'max_percent_must_add_at_least': 10000,
        }
        metrics['vs']['l7_server.sum_%s_resp_latency_bucket2' % (i)] = {
            'min_percent': 25,
            'max_percent': 25,
            'max_percent_must_add_at_least': 5,
        }
        metrics['vs']['l7_server.sum_%s_resp_latency' % (i)] = {
            'min_percent': 25,
            'max_percent': 50,
        }
        metrics['vs']['l7_client.sum_%s_client_txn_latency_bucket2' % (i)] = {
            'min_percent': 25,
            'max_percent': 25,
            'max_percent_must_add_at_least': 5,
        }

    # Is a SE metric
    del metrics['vs']['collection.min_se_disk_usage']

    # Remove rum metrics for now
    rum_list = []
    for k in metrics['vs']:
        if 'rum_' in k:
            rum_list.append(k)
    logger.info('rum_list:'+str(rum_list))
    for k in rum_list:
        del metrics['vs'][k]

    metrics['pool'] = copy.deepcopy(metrics['vs'])

    metrics['server'] = copy.deepcopy(metrics['vs'])

    global not_for_pool_or_server

    not_for_pool_or_server += [x for x in all_metric_ids
                               if x.startswith('l4_client')
                               or x.startswith('l7_client')]

    for k in rum_list:
        if k in not_for_pool_or_server:
            not_for_pool_or_server.remove(k)

    for i in not_for_pool_or_server:
        del metrics['pool'][i]
        del metrics['server'][i]

    # set defaults to x%
    for i in se_list:
        metrics['se'][i] = {
            'min_percent': 25,
            'max_percent': 25,
        }

    # override defaults
    metrics['se']['se_stats.avg_cpu_usage'] = {
        'max_value_must_be_at_least': 100,
    }

    # Find End to End Timing api and verify

def calculate_avg_bandwidth(file_size, rate, requests_per_session):
    ''' Calculates avg bandwidth of the file size requested.
        Arguments:
        file_size:      One of the key defined in file_size_string_to_bits
        rate            Rate of new connections (number)
        requests_per_session    Number of requests per session (number)
    '''
    file_size_in_bytes = file_size_string_to_bits[file_size.lower()]
    request_size = (request_header + file_size_in_bytes)
    # MTU = 1500, 1500 - 66 = 1434
    request_chunks = math.ceil(request_size / float(1434))

    actual_request_size = (request_chunks * 66 +
                           request_size +
                           client_request) * 8

    connection_size = connection_overhead * 8 + \
        actual_request_size * requests_per_session
    return rate * connection_size

def calculate_tx_bytes_and_packets(file_size, rate, requests_per_session):
    file_size_in_bytes = file_size_string_to_bits[file_size.lower()]
    request_size = (request_header + file_size_in_bytes)
    # MTU = 1500, 1500 - 66 = 1434
    request_chunks = math.ceil(request_size / float(1434))

    actual_request_size = (request_chunks * 66 +
                           request_size) * 8

    connection_size = connection_overhead / 2 * 8 + \
        actual_request_size * requests_per_session
    return rate * connection_size / 8, request_chunks * rate * requests_per_session

def calculate_rx_bytes_and_packets(file_size, rate, requests_per_session):
    return rx_100kb['bytes'] * rate, rx_100kb['packets'] * rate

def calculate_apdexr(error_rate, total_rate):
    apdexr = 100
    if error_rate != 0:
        apdexr = int(100 - 100 * (error_rate / float(total_rate)))
    return apdexr

def calculate_sum_reqs(request_method, sum_total_requests):
    sum_reqs = {}
    sum_reqs['get'] = 0
    sum_reqs['post'] = 0
    sum_reqs['other'] = 0
    if request_method == 'PUT':
        request_method = 'other'
    sum_reqs[request_method.lower()] = sum_total_requests
    return sum_reqs, request_method

def handle_app_delay(vs_baselines, app_delay, sum_reqs, rate, step):
    app_delay_rate_ratio = app_delay / rate / 10
    if app_delay_rate_ratio > 20:
        vs_baselines['l4_server.max_open_conns'] = app_delay_rate_ratio
        vs_baselines['l4_client.max_open_conns'] = app_delay_rate_ratio

    if app_delay >= 50:
        vs_baselines['l4_server.sum_conn_duration'] = app_delay * \
            rate * step * 1.2
        vs_baselines['l4_client.sum_conn_duration'] = app_delay * \
            rate * step * 1.2

        for i in get_post_other:
            vs_baselines['l7_server.sum_%s_resp_latency' %
                         (i)] = sum_reqs[i] * app_delay
            vs_baselines['l7_server.sum_%s_resp_latency_bucket1' % (i)] = 0
            vs_baselines['l7_server.sum_%s_resp_latency_bucket2' % (i)] = 0
            if app_delay < 500:
                vs_baselines[
                    'l7_server.sum_%s_resp_latency_bucket1' % (i)] = sum_reqs[i]
            elif app_delay > 500 and app_delay < 500 * 4:
                vs_baselines['l7_client.apdexr'] = 50
                vs_baselines['l7_server.apdexr'] = 50
                vs_baselines[
                    'l7_server.sum_%s_resp_latency_bucket2' % (i)] = sum_reqs[i]
            else:
                vs_baselines['l7_client.apdexr'] = 0
                vs_baselines['l7_server.apdexr'] = 0
    else:
        if 'collection.avg_application_latency' in vs_baselines:
            # This is to variable when app_delay is not intentionally set
            del vs_baselines['collection.avg_application_latency']
        for i in get_post_other:
            if 'l7_server.sum_%s_resp_latency' % (i) in vs_baselines:
                # This is too variable when app_delay is not intentionally set
                del vs_baselines['l7_server.sum_%s_resp_latency' % (i)]
            vs_baselines['l7_server.sum_%s_resp_latency_bucket1' %
                         (i)] = sum_reqs[i]
            vs_baselines['l7_server.sum_%s_resp_latency_bucket2' % (i)] = 0

def handle_response_status(vs_baselines, response_status, total_requests,
                           sum_total_requests, error_rate, step):
        # zero out all response statuses
    for i in [1, 2, 3, 4, 5]:
        vs_baselines['l7_client.sum_resp_%sxx' % (i)] = 0
        vs_baselines['l7_server.sum_resp_%sxx' % (i)] = 0

    # 100% one response type case
    if response_status:
        # set the correct response
        prefix = int(str(response_status)[:1])
        vs_baselines['l7_client.sum_resp_%sxx' %
                     (prefix)] = total_requests * (1 - error_rate) * step
        vs_baselines['l7_server.sum_resp_%sxx' %
                     (prefix)] = total_requests * (1 - error_rate) * step
        if prefix in [4, 5]:
            vs_baselines['l7_server.apdexr'] = 0
            vs_baselines['l7_client.apdexr'] = 0
            vs_baselines['l7_client.sum_errors'] = sum_total_requests
            vs_baselines['collection.sum_total_errors'] = sum_total_requests
            for j in get_post_other:
                vs_baselines['l7_server.sum_%s_resp_latency_bucket1' % (j)] = 0
    else:
        # Error percent case
        vs_baselines['l7_client.sum_resp_2xx'] = total_requests * \
            (1 - error_rate) * step
        vs_baselines['l7_client.sum_resp_4xx'] = total_requests * \
            error_rate * step
        vs_baselines['l7_server.sum_resp_2xx'] = total_requests * \
            (1 - error_rate) * step
        vs_baselines['l7_server.sum_resp_4xx'] = total_requests * \
            error_rate * step

def handle_server_delay(vs_baselines, server_delay):
    if server_delay:
        # This is hard/impossible to calculate in server_delay case
        del vs_baselines['l7_server.avg_resp_latency']
        # This is wrong is server_delay case
        del vs_baselines['l7_client.avg_client_txn_latency']
        if server_delay >= 100:
            # No way to tell what it will be, but will be less than 100
            del vs_baselines['l7_server.apdexr']
            del vs_baselines['l7_client.apdexr']
            for i in get_post_other:
                # Bucket 1 will go to bucket 2
                vs_baselines['l7_server.sum_%s_resp_latency_bucket2' % (i)] = vs_baselines[
                    'l7_server.sum_%s_resp_latency_bucket2' % (i)] + vs_baselines['l7_server.sum_%s_resp_latency_bucket1' % (i)]
                vs_baselines['l7_server.sum_%s_resp_latency_bucket1' % (i)] = 0

def handle_client_delay(vs_baselines, client_delay, request_method, sum_reqs):
    if client_delay:
        # This is hard/impossible to calculate
        del vs_baselines['l7_server.avg_resp_latency']
        del vs_baselines['l7_client.avg_client_txn_latency']
     # if client_delay >= 20:
    #   for i in get_post_other:
    #          TODO: Move this to more reliable app_delay section
    #         vs_baselines['l7_client.sum_%s_client_txn_latency' % (i)] = (client_delay + estimated_backend_time) * sum_reqs[i]
    #         vs_baselines['l7_client.sum_%s_client_txn_latency_bucket1' % (i)] = 0
    #         vs_baselines['l7_client.sum_%s_client_txn_latency_bucket2' % (i)] = 0
    #         if client_delay < 500:
    #           vs_baselines['l7_client.sum_%s_client_txn_latency_bucket1' % (i)] = sum_reqs[i]
    #         elif client_delay > 500 and client_delay < 500 * 4:
    #           vs_baselines['l7_client.sum_%s_client_txn_latency_bucket2' % (i)] = sum_reqs[i]
    #           vs_baselines['l7_client.apdexr'] = 50
    #         else:
    #           vs_baselines['l7_client.apdexr'] = 0

def create_divide_by_servers():
    divide_by_servers = [
        'l4_server.avg_bandwidth',
        # Bug# 826
        # 'l4_server.avg_tx_realized_bandwidth',
        'l7_server.avg_total_requests',
        'l4_server.avg_new_established_conns',
        'l7_server.sum_total_responses',
        'l4_server.avg_rx_bytes',
        'l4_server.avg_rx_pkts',
        'l4_server.avg_tx_bytes',
        'l4_server.avg_tx_pkts',
        'l4_server.sum_connections_dropped',
        'l4_server.sum_conn_duration',
    ]
    for i in get_post_other:
        divide_by_servers.append('l7_server.sum_%s_reqs' % (i))
        divide_by_servers.append('l7_server.sum_%s_resp_latency' % (i))
        divide_by_servers.append('l7_server.sum_%s_resp_latency_bucket1' % (i))
        divide_by_servers.append('l7_server.sum_%s_resp_latency_bucket2' % (i))

    for i in [1, 2, 3, 4, 5]:
        divide_by_servers.append('l7_server.sum_resp_%sxx' % (i))

    return divide_by_servers

def calculate_metrics_thresholds(step, app_delay, client_delay, server_delay, rate, file_size, requests_per_session, servers, error_rate, error_file, response_status, request_method, interfaces, vs_net):
    num_servers = len(servers)
    avg_bandwidth_normal = calculate_avg_bandwidth(
        file_size, rate, requests_per_session)
    avg_bandwidth_errors = calculate_avg_bandwidth(
        error_file, error_rate, requests_per_session)

    avg_tx_bytes, avg_tx_pkts = calculate_tx_bytes_and_packets(
        file_size, rate, requests_per_session)
    avg_rx_bytes, avg_rx_pkts = calculate_rx_bytes_and_packets(
        file_size, rate, requests_per_session)

    avg_bandwidth = avg_bandwidth_normal + avg_bandwidth_errors
    total_requests = rate * requests_per_session + \
        error_rate * requests_per_session
    sum_total_requests = total_requests * step
    total_rate = rate + error_rate
    sum_total_rate = total_rate * step
    apdexr = calculate_apdexr(error_rate, total_rate)
    sum_reqs, request_method = calculate_sum_reqs(
        request_method, sum_total_requests)

    server_delay = common_utils.get_value_verify_unit(server_delay, ['ms', 's'])
    client_delay = common_utils.get_value_verify_unit(client_delay, ['ms', 's'])

    vs_baselines = {
        # l4_client
        'l4_client.avg_bandwidth': avg_bandwidth,
        # Bug# 826
        # 'l4_server.avg_tx_realized_bandwidth': avg_bandwidth,
        'l4_client.avg_new_established_conns': total_rate,
        'l4_client.avg_total_rtt': client_delay,
        'l4_client.sum_finished_conns': sum_total_rate,
        'l4_client.avg_complete_conns': total_rate,
        'l4_client.avg_tx_bytes': avg_tx_bytes,
        'l4_client.avg_tx_pkts': avg_tx_pkts,

        # l4_server
        'l4_server.avg_bandwidth': avg_bandwidth,
        'l4_server.avg_total_rtt': server_delay,
        'l4_server.avg_new_established_conns': total_rate,
        'l4_server.avg_rx_pkts': avg_tx_pkts,
        'l4_server.avg_rx_pkts': avg_tx_pkts,

        # l7_client
        'l7_client.apdexr': apdexr,
        'l7_client.avg_client_txn_latency': app_delay,
        'l7_client.avg_total_requests': total_requests,
        'l7_client.sum_errors': error_rate * requests_per_session * step,
        'l7_client.sum_get_reqs': sum_reqs['get'],
        'l7_client.sum_post_reqs': sum_reqs['post'],
        'l7_client.sum_other_reqs': sum_reqs['other'],
        'l7_client.sum_total_responses': sum_total_requests,

        # l7_server
        'l7_server.avg_resp_latency': app_delay,
        'l7_server.avg_total_requests': total_requests,
        'l7_server.apdexr': apdexr,
        'l7_server.sum_get_reqs': sum_reqs['get'],
        'l7_server.sum_post_reqs': sum_reqs['post'],
        'l7_server.sum_other_reqs': sum_reqs['other'],
        'l7_server.sum_total_responses': sum_total_requests,


        # Bug #
        # 'collection.avg_l4_client_latency': client_delay + estimated_backend_time,

        # collection
        # Affected by too many things
        #    'collection.avg_application_latency': app_delay,
        # TODO: find a good way to calculate this, seems to be too reliable on bandwidth and file size
        #    'collection.avg_client_latency': client_delay,
        'collection.avg_total_bandwidth': avg_bandwidth * 2,
    }

    # Just use the one file size for now
    if file_size == '100kb' and requests_per_session == 1:
        vs_baselines['l4_client.avg_rx_bytes'] = avg_rx_bytes
        vs_baselines['l4_client.avg_rx_pkts'] = avg_rx_pkts
        vs_baselines['l4_server.avg_rx_bytes'] = avg_tx_bytes
        vs_baselines['l4_server.avg_rx_pkts'] = avg_tx_pkts

    handle_app_delay(vs_baselines, app_delay, sum_reqs, rate, step)
    handle_response_status(vs_baselines, response_status,
                           total_requests, sum_total_requests, error_rate, step)
    handle_server_delay(vs_baselines, server_delay)
    handle_client_delay(vs_baselines, client_delay, request_method, sum_reqs)

    # if client_delay == 0 and server_delay == 0:
    #     vs_baselines['l4_client.sum_end_to_end_rtt_bucket1'] = sum_total_rate
    #     vs_baselines['l4_client.sum_end_to_end_rtt_bucket2'] = 0
    #     vs_baselines['l4_client.sum_end_to_end_rtt'] = sum_total_rate

    pool_baselines = copy.deepcopy(vs_baselines)
    server_baselines = copy.deepcopy(vs_baselines)

    divide_by_servers = create_divide_by_servers()

    # Remove keys that don't belong in pool/server metrics as defined
    # in not_for_pool_or_server
    # Also divides metrics by the number of servers for specific metrics
    for key, metric in server_baselines.items():
        if key in not_for_pool_or_server:
            del pool_baselines[key]
            del server_baselines[key]
        if key in divide_by_servers:
            server_baselines[key] = metric / num_servers

    se_baselines = {
        'se_stats.avg_cpu_usage': 0,  # min is 0, max is 100
        # has issues when you are looking at the UI
        'se_stats.avg_bandwidth': avg_bandwidth * 2,
    }

    net_to_server_count = {}

    logger.debug('interfaces: '+str(interfaces))
    for handle, server in servers.items():
        if server.net not in net_to_server_count:
            net_to_server_count[server.net] = 0
        net_to_server_count[server.net] += 1

    per_server_bandwidth = avg_bandwidth / float(num_servers)
    per_server_rx_bytes = avg_rx_bytes / float(num_servers)
    per_server_tx_bytes = avg_tx_bytes / float(num_servers)
    for k, v in interfaces.items():
        if v == vs_net:
            se_baselines['se_stats.avg_%s_bandwidth' % (k)] = avg_bandwidth
        if v in net_to_server_count:
            if not 'se_stats.avg_%s_bandwidth' % (k) in se_baselines:
                se_baselines['se_stats.avg_%s_bandwidth' % (k)] = 0
            se_baselines['se_stats.avg_%s_bandwidth' %
                         (k)] += net_to_server_count[v] * per_server_bandwidth

        if file_size == '100kb' and requests_per_session == 1:
            if v == vs_net:
                # rx and tx switch for vs
                se_baselines['se_stats.avg_%s_rx_bytes' % (k)] = avg_tx_bytes
                se_baselines['se_stats.avg_%s_tx_bytes' % (k)] = avg_rx_bytes
            if v in net_to_server_count:
                if not 'se_stats.avg_%s_rx_bytes' % (k) in se_baselines:
                    se_baselines['se_stats.avg_%s_rx_bytes' % (k)] = 0
                    se_baselines['se_stats.avg_%s_tx_bytes' % (k)] = 0
                se_baselines['se_stats.avg_%s_rx_bytes' %
                             (k)] += net_to_server_count[v] * per_server_rx_bytes
                se_baselines['se_stats.avg_%s_tx_bytes' %
                             (k)] += net_to_server_count[v] * per_server_tx_bytes

    populate_threshold_dict(metrics['vs'], vs_baselines)
    populate_threshold_dict(metrics['pool'], pool_baselines)
    populate_threshold_dict(metrics['server'], server_baselines)
    populate_threshold_dict(metrics['se'], se_baselines)

def populate_threshold_dict(threshold_dict, baseline_dict):
    # clear old min/max vals
    for k, v in threshold_dict.items():
        if 'min_val' in v:
            del v['min_val']
        if 'max_val' in v:
            del v['max_val']

    # add new min/max
    for k, v in baseline_dict.items():
        entry = threshold_dict[k]
        entry['min_val'] = v
        entry['max_val'] = v
        if 'min_percent' in entry:
            entry['min_val'] = v - math.ceil(v * entry['min_percent'] / 100.0)
        if 'max_percent' in entry:
            entry['max_val'] = v + math.ceil(v * entry['max_percent'] / 100.0)

        # Make sure min/max must be at least is honored
        if 'min_value_must_be_at_least' in entry and entry['min_val'] < entry['min_value_must_be_at_least']:
            entry['min_val'] = entry['min_value_must_be_at_least']

        if 'max_value_must_be_at_least' in entry and entry['max_val'] < entry['max_value_must_be_at_least']:
            entry['max_val'] = entry['max_value_must_be_at_least']

        if 'min_percent_must_add_at_least' in entry:
            if v + entry['min_percent_must_add_at_least'] < entry['min_val']:
                entry['min_val'] = v - entry['min_percent_must_add_at_least']

        # Add to max_val if max_percent did not increase v by at least the desired amount
        # Useful when you want to increase 0 or 1 by a fixed size but larger
        # numbers by a percent
        if 'max_percent_must_add_at_least' in entry:
            if v + entry['max_percent_must_add_at_least'] > entry['max_val']:
                entry['max_val'] = v + entry['max_percent_must_add_at_least']
