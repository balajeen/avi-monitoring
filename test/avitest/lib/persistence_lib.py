import lib.pool_lib as pool_lib
from avi_objects.logger import logger
import avi_objects.logger_utils as logger_utils
from lib.network_lib import get_test_subnet_networkprefix


def generate_client_server_map_persistence(pool_name, step=None,
                                           subnet=None,
                                           disable_aggregate=None):
    persistence_ip = None
    persistence_end_ip = None
    if step:
        subnet = get_test_subnet_networkprefix(subnet)
        persistence_ip = subnet + '.' + str(step * 1) + '.2'
        persistence_end_ip = subnet + '.' + str((step + 1) * 1) + '.254'

    se_list = pool_lib.get_pool_persistence(
        pool_name, persistence_ip, persistence_end_ip, disable_aggregate=disable_aggregate)

    _client_server_map = {}
    if se_list is None:
        raise RuntimeError("No SE returned")
    for se in se_list:
        se_uuid = se['uuid']
        if se_uuid not in _client_server_map.keys():
            _client_server_map[se_uuid] = {}
        if u'persistence_entry' not in se.keys():
            raise RuntimeError(
                "[%s] peristence_entry not set from se:%s" % (pool_name, se_uuid))
        if se['persistence_entry'] is None:
            raise RuntimeError(
                "[%s] no persistence_entry from se:%s" % (pool_name, se_uuid))
        for entry in se['persistence_entry']:
            _client_ip = entry['client_ip']['addr']
            _server_ip = entry['server_ip']['addr']
            _server_port = entry['port']
            _client_server_map[se_uuid][_client_ip] = ":".join([
                _server_ip, str(_server_port)])
    logger.info('Client server map: %s' % _client_server_map)
    return _client_server_map


def verify_persistence_entries(map):
    if not map:
        raise RuntimeError('Empty persistence map')
    for key in map.keys():
        for se, val in map.iteritems():
            if key == se:
                continue
            if map[key] != val:
                logger.info('Entries preset in %s and not in %s::' % (key, se))
                logger.info('%s' % str(set(val.keys()) - set(map[key].keys())))

                logger.info('Entries preset in %s and not in %s::' % (se, key))
                logger.info('%s' % str(set(map[key].keys()) - set(val.keys())))

                diff = [(k, val[k], v)
                        for k, v in map[key].iteritems() if k in val and val[k] != v]
                logger.info('Client IPs having different server Ips::')
                logger.info(diff)
                logger.debug('Comparing: %s\nAND\n%s' % (map[key], val))
                logger_utils.fail('Persistence entries do not match for %s and %s' % (key, se))
