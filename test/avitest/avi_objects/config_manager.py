import os
import simplejson as json
import re
import ipaddress
import copy
from avi_config import AviConfig
from suite_vars import suite_vars
from avi_objects.rest import get_cloud_type
from logger import logger
from logger_utils import fail, calc_exc_time
from pool import PoolModel

from cli.avi_cli.common import pb_ordered

def get_parsed_json(config_file, config_vars={}, config_vars_file=None):
    
    if config_vars_file:
        config_vars_file = get_config_abs_path(config_vars_file)
        try:
            json_data = json.load(config_vars_file)
        except Exception as e:
            fail('Json load failed for config file %s with Exception %s' %(config_file, e))
        json_data.update(config_vars)
        config_vars=json_data

    abs_path = get_config_abs_path(config_file)
    logger.info("Parsing Config %s" %abs_path)

    json_data = resolve_sourced_config_files(abs_path)
    return json_data, config_vars
    
def get_parsed_json_cloud(config_file):
    abs_path = get_config_abs_path(config_file)
    logger.info("Parsing Config for Cloud%s" %abs_path)
    json_data = resolve_sourced_config_files(abs_path)
    return __parse_config_json_cloud(json_data)

def resolve_abs_relative_path(config_file):
    workspace = suite_vars.workspace
    abs_path = os.path.join(workspace, 'test','avitest','functional',config_file)
    if os.path.isfile(abs_path):
        logger.info("Found config file with relative path provided")
        return abs_path
    else:
        return

def resolve_abs_relative_path_for_template(tmpl_file):
    workspace = suite_vars.workspace
    abs_path = os.path.join(workspace, 'test','avitest','templates',tmpl_file)
    if os.path.isfile(abs_path):
        logger.info("Found config file with relative path provided")
        return abs_path
    else:
        return

def get_config_abs_path(config_file):

    abs_path = resolve_abs_relative_path(config_file)
    if abs_path:
        return abs_path
    module_path = os.path.split(suite_vars.module_path)[0]
    cloud_type = get_cloud_type()
    logger.debug('get_config_abs_path: cloud_type %s' %cloud_type)
    if cloud_type:
        abs_path = os.path.join(module_path, 'configs', cloud_type, config_file)
        if os.path.isfile(abs_path):
            logger.info("Found %s specific config file" %cloud_type)
            return abs_path
    abs_path = os.path.join(module_path, 'configs',  config_file)
    if os.path.isfile(abs_path):
        logger.info("Found config file under configs directory")
        return abs_path
    else:
        fail('Cannot find the config file %s' %config_file)
    

def resolve_sourced_config_files(config_file):

    ret_json_data = {}
    lines = ''
    with open(config_file) as f:
        for line in f.readlines(): 
            match = re.search('^source\s*:\s*"(\S+)"', line)
            if match:
                logger.debug('Found another source json path: %s' %match.group(1))
                abs_path = get_config_abs_path(match.group(1))
                json_data = resolve_sourced_config_files(abs_path)
                ret_json_data = data_merge(ret_json_data, json_data)
            else:
                lines += line
    try:
        if lines.strip():
            json_data = json.loads(lines)
    except Exception as e:
        fail('Json load failed for config file %s with Exception %s' %(config_file, e))
    data_merge(ret_json_data, json_data)
    return ret_json_data

def data_merge(a, b):
    """merges b into a and return merged result

    NOTE: tuples and arbitrary objects are not handled as it is totally ambiguous what should happen"""
    key = None
    try:
        if a is None or any(isinstance(a, tp) for tp in [str, unicode, int, long, float]):
            a = b
        elif isinstance(a, list):
            # lists can be only appended
            if isinstance(b, list):
                # merge lists
                a.extend(b)
            else:
                # append to list
                a.append(b)
        elif isinstance(a, dict):
            # dicts must be merged
            if isinstance(b, dict):
                for key in b:
                    if key in a:
                        a[key] = data_merge(a[key], b[key])
                    else:
                        a[key] = b[key]
            else:
                raise fail('Cannot merge non-dict "%s" into dict "%s"' % (b, a))
        else:
            raise fail('NOT IMPLEMENTED "%s" into "%s"' % (b, a))
    except TypeError, e:
        raise fail('TypeError "%s" in key "%s" when merging "%s" into "%s"' % (e, key, b, a))
    return a


def __parse_config_json_cloud(json_data):
        # TODO parse the cloud to resolve secret keys with avitest_rc.json file.
        return json_data['Cloud']


def get_import_objs(json_data, config_vars={}):
    ret_json_data = {}
    objects_imported = {}
    parse_net_obj_list = ['VirtualService', 'VsVip', 'NetworkSecurityPolicy', 'HTTPPolicySet',
                          'VSDataScriptSet', 'AuthProfile', 'IpAddrGroup', 'GslbService', 
                          'TrafficCloneProfile']
    for obj in json_data:
        logger.info("Parsing obj %s" %obj)
        if obj == 'Pool':
            pool_json, configured_pools = __set_pool_json(json_data[obj], config_vars=config_vars)
            ret_json_data[obj] = pool_json
            if obj  in objects_imported:
                objects_imported[obj].extend(configured_pools)
            else:
                objects_imported[obj] = configured_pools
        else:
            configured_objs = []
            rep_json = __replace_net_with_ip(json_data[obj], obj, configured_objs, config_vars=config_vars)
            ret_json_data[obj] = rep_json
            objects_imported[obj] = configured_objs

    return ret_json_data, objects_imported

def __set_pool_json(json_data, **kwargs):

    config = AviConfig.get_instance()
    context_key = config.get_context_key()
    configured_pools = []
    if 'pool' not in config.site_objs.setdefault(context_key,{}):
        config.site_objs[context_key]['pool'] = {}
    pool_json_data = []
    for pool_obj in json_data:
        pool_model = PoolModel(json_data=pool_obj, **kwargs)
        config.site_objs[context_key]['pool'][pool_obj['name']] = pool_model
        poolmodel_json = pool_model.get_json()
        logger.trace('__set_pool_json: PoolModel.get_json returns:\n%s' % poolmodel_json)
        pool_json_data.append(poolmodel_json)
        configured_pools.append(pool_obj['name'])
    return pool_json_data, configured_pools
     
def __replace_net_with_ip(json_data, obj_name, configured_objs, config_vars={}):
      ret_json_data = get_json_networks_to_ip(json_data, configured_objs, config_vars=config_vars)
      logger.debug('__replace_net_with_ip:%s: returns:\n%s' % (obj_name, ret_json_data))
      return ret_json_data

def get_json_networks_to_ip(json_data, configured_objs, config_vars={}):
    if isinstance(json_data, dict):
        ret_data = {}
        for key, value in json_data.iteritems():
            ret_val = get_json_networks_to_ip(value, configured_objs, config_vars=config_vars)
            if key == 'name':
                configured_objs.append(ret_val)
            if key in ['addr']:
                try:
                    if type(ipaddress.ip_address(unicode(ret_val))) == ipaddress.IPv6Address:
                        json_data['type'] = ret_data['type'] = 'V6'
                    else:
                        json_data['type'] = ret_data['type'] = 'V4'
                except (ValueError, KeyError) as e:
                    logger.debug("Got Exception for addr field %s" %e)
            ret_data[key] = ret_val

    elif isinstance(json_data, list):
        ret_data = []
        for value in json_data:
            ret_data.append(get_json_networks_to_ip(value, configured_objs, config_vars=config_vars))
    else:
        ret_data = json_data
        if not any(isinstance(ret_data, tp) for tp in [str, unicode]):
            return ret_data
        config = AviConfig.get_instance()
        mode = config.get_mode()
        site_name = mode['site_name']
        ret_data = json_data
        testbed_vars = copy.deepcopy(config.get_testbed().testbed_vars)
        testbed_vars.update(config_vars)
        m = re.search('^([\s\S]*)\${(([a-zA-Z0-9]+)_(.+))}([\s\S]*)', ret_data)
        if m:
            if m.group(2) in testbed_vars:
                ret_data = testbed_vars[m.group(2)]
                return m.group(1) + ret_data + m.group(5)
            net_in_json = m.group(3)
            keyword = m.group(4)
            foundIp = config.testbed[site_name].ip_dict.get(m.group(2))
            if foundIp:
                ret_data = foundIp
            else:
                ip_host = keyword if keyword.isdigit() else None
                m_sub = re.search('([a-zA-Z]+)(\d+)', net_in_json)
                if m_sub:
                    ret_data = \
                      config.testbed[site_name].networks[net_in_json].get_ip_for_network(ip_host=ip_host)
                else:
                    ip, net = \
                        config.testbed[site_name].networks_queue.get_ip_for_network(ip_host=ip_host)
                    ret_data = ip
                    net_in_json = net
                config.testbed[site_name].ip_dict[m.group(2)] = ret_data
            return str(m.group(1)) + str(ret_data) + str(m.group(5))
        m = re.search('^([\s\S]*)\$\{([a-zA-Z]+\w+)}([\s\S]*)', ret_data)
        if m:
            if m.group(2) in testbed_vars:
                ret_data = testbed_vars[m.group(2)]
                return str(m.group(1)) + str(ret_data) + str(m.group(3))
            net_in_json = m.group(2)
            m_sub = re.search('([a-zA-Z]+)(\d+)', net_in_json)
            if m_sub:
                ret_data = config.testbed[site_name].networks[net_in_json].get_ip_for_network()
            else:
                ip, net = config.testbed[site_name].networks_queue.get_ip_for_network()
                ret_data = ip
                net_in_json = net
            return str(m.group(1)) + str(ret_data) + str(m.group(3))

    return ret_data


def get_delete_objs(json_data):
    order = pb_ordered.pb_ordered[:]
    order.append('User')
    order.append('SSLKeyAndCertificateImport') # is this needed?
    """
    order = [
            "SSLKeyAndCertificateImport",
            "ControllerLicense",
            "SeProperties",
            "UserActivity",
            "SecureChannelToken",
            "UserAccountProfile",
            "SecureChannelMapping",
            "VIMgrIPSubnetRuntime",
            "Tenant",
            "ControllerProperties",
            "CloudProperties",
            "SecureChannelAvailableLocalIPs",
            "Role",
            "User",
            "AuthProfile",
            "CloudConnectorUser",
            "CloudRuntime",
            "VIPGNameInfo",
            "SnmpTrapProfile",
            "HardwareSecurityModuleGroup",
            "VIDCInfo",
            "Gslb",
            "SCVsStateInfo",
            "GslbGeoDbProfile",
            "SCPoolServerStateInfo",
            "ApplicationPersistenceProfile",
            "GslbApplicationPersistenceProfile",
            "NetworkRuntime",
            "DebugController",
            "AutoScaleLaunchConfig",
            "CertificateManagementProfile",
            "LogControllerMapping",
            "Webhook",
            "AnalyticsProfile",
            "VIMgrControllerRuntime",
            "WafPolicy",
            "StringGroup",
            "Cluster",
            "DebugServiceEngine",
            "PKIProfile",
            "JobEntry",
            "MicroService",
            "APICLifsRuntime",
            "AlertSyslogConfig",
            "SSLProfile",
            "CustomIpamDnsProfile",
            "AlertObjectList",
            "AlertScriptConfig",
            "NetworkProfile",
            "IpAddrGroup",
            "BackupConfiguration",
            "SSLKeyAndCertificate",
            "MicroServiceGroup",
            "IpamDnsProviderProfile",
            "DnsPolicy",
            "ApplicationProfile",
            "Scheduler",
            "SystemConfiguration",
            "GslbHealthMonitor",
            "HealthMonitor",
            "NetworkSecurityPolicy",
            "Cloud",
            "Backup",
            "AlertEmailConfig",
            "GslbService",
            "VrfContext",
            "PriorityLabels",
            "PoolGroupDeploymentPolicy",
            "VIMgrVMRuntime",
            "DebugVirtualService",
            "ActionGroupConfig",
            "VIMgrHostRuntime",
            "AlertConfig",
            "VIMgrNWRuntime",
            "VIMgrClusterRuntime",
            "VIMgrSEVMRuntime",
            "ServerAutoScalePolicy",
            "Network",
            "VIMgrDCRuntime",
            "VsVip",
            "TrafficCloneProfile",
            "ServiceEngineGroup",
            "Pool",
            "VIMgrVcenterRuntime",
            "ServiceEngine",
            "PoolGroup",
            "HTTPPolicySet",
            "VSDataScriptSet",
            "VirtualService",
            "Application",
            "Alert",
            "ClusterCloudDetails"]
    """
    obj_type_name_list = []
    order.reverse()
    for obj_type in order: 
        if obj_type in json_data:
            if isinstance(json_data[obj_type], list):
                tmp_list = []
                for obj in json_data[obj_type]:
                    obj_name = obj['name']
                    tmp_list.append((obj_type, obj_name))
                tmp_list.sort(key= lambda x:x[1])
                tmp_list.reverse()
                obj_type_name_list.extend(tmp_list)
            else:
                obj_name = obj['name']
                obj_type_name_list.append((obj_type, obj_name))
                  
    return obj_type_name_list
                
