import ipaddress
import json
import re
import telnetlib

import avi_objects.infra_utils as infra_utils
import avi_objects.logger_utils as logger_utils
import avi_objects.rest as rest
import lib.common as common
import lib.controller_lib as controller_lib
import lib.vs_lib as vs_lib
import lib.webapp_lib as webapp_lib
from netaddr import IPNetwork, IPAddress
from avi_objects.logger import logger


def get_se_uuid(se_name=None, **kwargs):
    params = {'se_connected': True}
    if se_name:
        params['name'] = se_name
    status_code, se_list = rest.get('serviceengine', params=params)
    uuids = []
    if 'results' in se_list:
        for se in se_list['results']:
            if se['name'] == se_name:
                return se['uuid']
            uuids.append(se['uuid'])
    return uuids


def set_se_debug(se=None, vcpu_shares=None, flags=None):
    """Sets SE debugs

       Arguments:
       SE          Service engine name (Optional). If not specified, debug
                   options will be applied across all service engines.
       vcpu_shares vcpu shares for all CPUs (Assigns same number to each core
                   on service engine).
       flags       List of flags to set. Need exact ENUM matching protobug
                   name (case sensetive)
       tenant      Global by default.
    """

    se_uuids = []
    if se:
        se_uuids.append(get_se_uuid(se_name=se))
    else:
        se_uuids.extend(get_se_uuid())

    for se_uuid in se_uuids:
        _, se_info = rest.get('serviceengine', uuid=se_uuid)
        data = {'name': se_info['name']}
        if vcpu_shares:
            num_vcpus = int(se_info['resources']['num_vcpus'])
            data['cpu_shares'] = [{'cpu': vcpu, 'shares': vcpu_shares}
                                  for vcpu in range(num_vcpus)]
        if flags:
            data['flags'] = [{'flag': flag} for flag in flags.split(',')]

        status, data = rest.put('debugserviceengine', uuid=se_uuid, data=json.dumps(data))


def set_se_runtime_properties(**kwargs):
    status_code, data = rest.get('seproperties')
    _se_runtime_props = {}
    logger.info('Initial SE Runtime Props: ' + str(data))
    if 'se_runtime_properties' in data:
        _se_runtime_props = data['se_runtime_properties']
    _se_runtime_props.update(kwargs)

    data['se_runtime_properties'] = _se_runtime_props
    rest.put('seproperties',  data)


def create_se_group(name, **kwargs):
    """This function does start the web replay traffic on client.
    Args:
        :param vs_name: The vs_name to use pass virtual services name.
        :type vs_name: str
        :param vport: The vport to use pass virtual services port.
        :type vport: str
    Kwargs:
        :param client_range: Current client_range to be in, default value is 'w1'.
        :type client_range: str
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    logger.info('SE Group parms [kwargs] : %s ' % kwargs)
    data = {}
    se_name_prefix = kwargs.get('se_name_prefix', 'Avi')

    data['name'] = name
    data['ha_mode'] = kwargs.get('ha_mode', 'HA_MODE_SHARED')
    data['se_name_prefix'] = kwargs.get('se_name_prefix', 'Avi')

    realtime_se_metrics = {}
    realtime_se_metrics['duration'] = 0
    realtime_se_metrics['enabled'] = True
    data['realtime_se_metrics'] = realtime_se_metrics

    data['buffer_se'] = 0

    if kwargs.get('cloud_uuid', None):
        data['cloud_uuid'] = kwargs.get('cloud_uuid')
    if kwargs.get('service_ip_subnets', None):
        subnet = {}
        service_ip_subnets = kwargs.get('service_ip_subnets')
        subnet['mask'] = service_ip_subnets['prefixlen']

        subnet_ip_addr = {}
        subnet_ip_addr['addr'] = str(service_ip_subnets['ip'])
        subnet_ip_addr['type'] = 0
        subnet['ip_addr'] = subnet_ip_addr

        data['subnet'] = subnet
    if kwargs.get('mgmt_network_uuid', None):
        data['mgmt_network_uuid'] = kwargs.get('mgmt_network_uuid')

    status_code, resp = rest.post('serviceenginegroup', data=data)

    return resp['uuid']


def delete_se_group(name, **kwargs):
    """This function does Delete SE Group.
    Args:
        :param name: Service Engine Group name to delete
        :type name: str
    Kwargs:
        :param kwargs: kwargs to delete Service Engine Group
        :type kwargs: dict
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    logger.info('Delete SE Group parms [kwargs] : %s ' % kwargs)
    status_code, resp = rest.delete('serviceenginegroup', name=name)


def set_se_group_best_effort(sg_name):
    """This function does convert se group to best effort.
    Args:
        :param sg_name: Service Engine Group name to convert best effort.
        :type name: str
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    status_code, json_data = rest.get('serviceenginegroup', name=sg_name)
    if not json_data:
        logger_utils.fail('No Service Engine Group found with the name : %s ' % sg_name)

    json_data['ha_mode'] = 'HA_MODE_SHARED'
    json_data['max_vs_per_se'] = 4
    json_data['min_scaleout_per_vs'] = 1
    json_data['buffer_se'] = 0
    json_data['active_standby'] = False

    rest.put('serviceenginegroup', uuid=json_data['uuid'], data=json_data)


def set_se_group_host(sg_name, host_names=None):
    """This function does Set SE Group hosts.
    Args:
        :param name: Service Engine Group name to convert best effort.
        :type name: str
        :param host_names: Host names to add.
        :type host_names: list
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    mode = infra_utils.get_mode()
    site_name = mode['site_name']
    #TODO: Need to Discuss on this
#    cloud = mode['cloud']
#    cloud_obj = config.testbed[site_name].cloud_obj[cloud]
#    if cloud_obj.type ==  'aws':
    if 'vcenter' == 'aws':
        logger.info('Cloud type: %s, no SE group host to be set' %
                    infra_utils.get_cloud_context_type())
        return
    status_code, resp = rest.get('serviceenginegroup', name=sg_name)

    if not resp:
        logger_utils.fail('No Service Engine Group found with the name : %s ' % sg_name)

    sg_data = resp
    if not sg_data.get('vcenter_hosts', None):
        vcenter_hosts = {}
        vcenter_hosts['host_refs'] = []
        vcenter_hosts['include'] = True
        for host in host_names:
            status_code, hostdata = rest.get("vimgrhostruntime", name=host)
            vcenter_hosts['host_refs'].append(hostdata.get('url', None))
        sg_data['vcenter_hosts'] = vcenter_hosts
    else:
        if sg_data['vcenter_hosts'].get('host_uuids'):
            sg_data['vcenter_hosts']['host_uuids'] = \
                        sg_data['vcenter_hosts']['host_uuids'].extend(list(host_names))
        else:
            hostuuids = list(host_names)
            sg_data['vcenter_hosts']['host_uuids'] = hostuuids
        sg_data['vcenter_hosts']['include'] = True

    rest.put('serviceenginegroup', uuid=sg_data['uuid'], data=sg_data)


def set_se_group_max_vs_per_se(sg_name, number):
    """This function does Set SE Group Maximum VS per SE
    Args:
        :param sg_name: Service Engine Group name
        :type sg_name: str
        :param number: Maximum Number of VS per SE
        :type number: int
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    logger.info('Setting Service Engine Group [name]: %s, \
                Max no. of VS per SE : %s ' % (sg_name, number))
    set_se_group_properties(sg_name, number=number, max_vs_per_se='max_vs_per_se')


def set_se_group_max_se_per_vs(sg_name, number, **kwargs):
    """This function does Set SE Group Maximum SE scaleout per VS
    Args:
        :param sg_name: Service Engine Group name
        :type sg_name: str
        :param number: Maximum Number of scaleout per VS
        :type number: int
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    logger.info('Setting Service Engine Group [name]: %s, \
                Max/Min no. scaleout per VS : %s ' % (sg_name, number))
    set_se_group_properties(sg_name, number=number, max_scaleout_per_vs='max_scaleout_per_vs', **kwargs)


def set_se_group_min_se_per_vs(sg_name, number):
    """This function does Set SE Group Minimum SE Scaleout per VS
    Args:
        :param sg_name: Service Engine Group name
        :type sg_name: str
        :param number: Minimum Number of scaleout per VS
        :type number: int
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    logger.info('Setting Service Engine Group [name]: %s, \
                Min no. scaleout per VS : %s ' % (sg_name, number))
    set_se_group_properties(sg_name, number=number, min_scaleout_per_vs='min_scaleout_per_vs')


def set_se_group_min_number(sg_name, number):
    """This function does Set SE Group Minimum of SEs
    Args:
        :param sg_name: Service Engine Group name
        :type sg_name: str
        :param number: Minimum Number of SEs
        :type number: int
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    logger.info('Setting Service Engine Group [name]: %s, \
                Min no. of SEs : %s ' % (sg_name, number))
    set_se_group_properties(sg_name, number=number, max_se='min_se')


def set_se_group_max_number(sg_name, number):
    """This function does Set SE Group Maximum of SEs
    Args:
        :param sg_name: Service Engine Group name
        :type sg_name: str
        :param number: Maximum Number of SEs
        :type number: int
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    logger.info('Setting Service Engine Group [name]: %s, \
                Max no. of SEs : %s ' % (sg_name, number))
    set_se_group_properties(sg_name, number=number, max_se='max_se')


def set_se_group_aggressive_failover(sg_name, enable=False):
    """This function does Set SE Group Aggressive Failover
    Args:
        :param sg_name: Service Engine Group name
        :type sg_name: str
        :param enable: Enable/Disable
        :type enable: boolean
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    logger.info('Setting Service Engine Group [name]: %s, \
                Aggressive Failover : %s ' % (sg_name, enable))
    set_se_group_properties(sg_name, enable=False, aggressive_failover='aggressive_failover')


def set_se_group_sename_prefix(sg_name, se_name_prefix):
    """This function does Set SE Group SE Name Prefix
    Args:
        :param sg_name: Service Engine Group name
        :type sg_name: str
        :param se_name_prefix: SE Name prefix to set
        :type se_name_prefix: str
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    logger.info('Setting Service Engine Group [name]: %s, \
                SEName prefix : %s ' % (sg_name, se_name_prefix))
    set_se_group_properties(sg_name, name_prefix=se_name_prefix)


def set_se_group_name_prefix(sg_name, controller_name):
    """This function does Set SE Group SE Name Prefix
    Args:
        :param sg_name: Service Engine Group name
        :type sg_name: str
        :param controller_name: Controller Name to set SE Name prefix
        :type controller_name: str
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    se_name_prefix = 'Avi_' + controller_name
    logger.info('Setting Service Engine Group [name]: %s, \
                Name prefix : %s ' % (sg_name, se_name_prefix))
    set_se_group_properties(sg_name, name_prefix=se_name_prefix)


def set_se_group_purge_delay(sg_name, delay):
    """This function does Set SE Group SE Deprovision Delay
    Args:
        :param sg_name: Service Engine Group name
        :type sg_name: str
        :param delay: SE Deprovision Delay
        :type delay: int
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    se_name_prefix = 'Avi_' + sg_name
    logger.info('Setting Service Engine Group [name]: %s, \
                Purge Delay to : %s ' % (sg_name, delay))
    set_se_group_properties(sg_name, purge_delay=delay)

def set_se_group_se_tunnel_mode(sg_name='Default-Group', **kwargs):
    """This function does Set SE Group SE Tunnel Mode settings
    Args:
        :param sg_name: Service Engine Group name
        :type sg_name: str
        :param delay: SE Deprovision Delay
        :type delay: int
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    se_tunnel_mode = kwargs.get('se_tunnel_mode', 0)
    logger.info('Setting Service Engine Group [name]: %s, \
                se_tunnel_mode to : %s ' % (sg_name, se_tunnel_mode))
    set_se_group_properties(sg_name, se_tunnel_mode=se_tunnel_mode)

def set_se_group_properties(sg_name, **kwargs):
    """ Setting SE Group SEs Min/Max Scaleout per VS
    Associated Functions:
        set_se_group_max_vs_per_se
        set_se_group_max_se_per_vs
        set_se_group_min_se_per_vs
        set_se_group_min_number
        set_se_group_max_number
        set_se_group_aggressive_failover
        set_se_group_sename_prefix
        set_se_group_name_prefix
        set_se_group_purge_delay
        set_se_group_se_tunnel_mode
    """

    status_code, json_sg_data = rest.get('serviceenginegroup', name=sg_name)

    if kwargs.get('min_scaleout_per_vs', None):
        json_sg_data['min_scaleout_per_vs'] = kwargs.get('number')

    if kwargs.get('max_scaleout_per_vs', None):
        json_sg_data['max_scaleout_per_vs'] = kwargs.get('number')

    if kwargs.get('max_vs_per_se', None):
        json_sg_data['max_vs_per_se'] = kwargs.get('number')

    if kwargs.get('min_se', None):
        json_sg_data['min_se'] = kwargs.get('number')

    if kwargs.get('max_se', None):
        json_sg_data['max_se'] = kwargs.get('number')

    if kwargs.get('aggressive_failover', None):
        json_sg_data['aggressive_failure_detection'] = kwargs.get('enable')

    if kwargs.get('name_prefix', None):
        json_sg_data['se_name_prefix'] = kwargs.get('name_prefix')

    if kwargs.get('purge_delay', None):
        json_sg_data['se_deprovision_delay'] = kwargs.get('purge_delay')

    if kwargs.get('vs_scalein_timeout', None):
        json_sg_data['vs_scalein_timeout'] = kwargs.get('number')

    if kwargs.get('vs_scaleout_timeout', None):
        json_sg_data['vs_scaleout_timeout'] = kwargs.get('number')

    if kwargs.get('license_type') is not None:
        json_sg_data['license_type'] = kwargs.get('license_type')

    if kwargs.get('se_bandwidth_type') is not None:
        json_sg_data['se_bandwidth_type'] = kwargs.get('se_bandwidth_type')

    if kwargs.get('per_app') is not None:
        json_sg_data['per_app'] = kwargs.get('per_app')

    if kwargs.get('allow_burst') is not None:
        json_sg_data['allow_burst'] = kwargs.get('allow_burst')

    if kwargs.get('license_tier') is not None:
        json_sg_data['license_tier'] = kwargs.get('license_tier')

    if kwargs.get('se_tunnel_mode') is not None:
        json_sg_data['se_tunnel_mode'] = kwargs.get('se_tunnel_mode')

    rest.put('serviceenginegroup', uuid=json_sg_data.get('uuid'),
             data=json_sg_data)


def set_se_group_ha_mode(sg_name, mode=None, active_standby=False):
    """This function does Set HA mode of se group and active standby is False by default
    Args:
        :param sg_name: Service Engine Group name
        :type sg_name: str
        :param delay: SE Deprovision Delay
        :type delay: int
    Kwargs:
        :param mode: SE Group HA Mode
        :type mode: str, default None
        :param mode: SE Group Active Standby
        :type mode: boolean default False
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    status_code, resp = rest.get('serviceenginegroup', name=sg_name)
    json_data = resp

    if mode == "HA_MODE_SHARED_PAIR":
        json_data['ha_mode'] = 'HA_MODE_SHARED_PAIR'
    if mode == "HA_MODE_SHARED":
        json_data['ha_mode'] = 'HA_MODE_SHARED'
    if mode == "HA_MODE_LEGACY_ACTIVE_STANDBY":
        json_data['ha_mode'] = 'HA_MODE_LEGACY_ACTIVE_STANDBY'
    json_data['active_standby'] = active_standby
    rest.put('serviceenginegroup', uuid=json_data['uuid'], data=json_data)


def get_se_info(se_name=None, se_uuid=None, connected=True, **kwargs):
    """This function does get SE information
    Args:
        :param se_name: Service Engine name
        :type se_name: str
        :param se_uuid: Service Engine UUID
        :type se_uuid: str
    Kwargs:
        :param connected: state of the SE Connected/not
        :type connected: boolean, default True
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    if not se_name and not se_uuid:
        logger_utils.fail("Need SE Name or UUID to get SE info.")

    params = {}
    if connected:
        params = {'se_connected': True}
    status_code, resp = rest.get('serviceengine', name=se_name, uuid=se_uuid,
                                 params=params, check_status_code=False, **kwargs)
    if status_code != 200:
        logger.info('GET: status code: %s for object: %s' % (status_code, se_name))
        status_code, resp = rest.get('serviceengine', name=se_name, uuid=se_uuid, params=params, **kwargs)

        if resp:
            return resp
        else:
            return False
    elif resp:
        return resp
    else:
        return False


def get_se_ip_from_name(se_name, connected=True):
    """This function does get SE ip from name
    Args:
        :param se_name: Service Engine name
        :type se_name: str
    Kwargs:
        :param connected: Connected Service Engine
        :type connected: boolean
    Returns:
        Service Engine ID
    Raises:
        ValueError, AttributeError, KeyError
    """
    se_data = get_se_info(se_name=se_name, connected=connected)
    return se_data['mgmt_vnic']['vnic_networks'][0]['ip']['ip_addr']['addr']


def get_se_uuid_from_name(se_name, **kwargs):
    """This function does get SE ID from name
    Args:
        :param se_name: Service Engine name
        :type se_name: str
    Returns:
        Service Engine UUID
    Raises:
        ValueError, AttributeError, KeyError
    """
    se_data = get_se_info(se_name=se_name, **kwargs)
    return se_data['uuid']


def is_se_connected(se_name):
    """This function does Check SE is Connected or note
    Args:
        :param se_name: Service Engine name
        :type se_name: str
    Returns:
        Service Engine state if its up else False
    Raises:
        ValueError, AttributeError, KeyError
    """
    se_data = get_se_info(se_name=se_name)
    if se_data:
        return se_data['se_connected']
    return False


def set_se_group_one_plus_one_ha(sg_name="Default-Group", value=True):
    """This function does Set se group one plus one HA
    Kwargs:
        :param sg_name: Service Engine Group name
        :type sg_name: str default as Default-Group
        :param value: ha on value
        :type value: boolean
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    status_code, resp = rest.get('serviceenginegroup', name=sg_name)
    json_data = resp

    json_data['ha_mode'] = 'HA_MODE_SHARED'
    json_data['active_standby'] = False
    json_data['max_vs_per_se'] = 4
    json_data['min_scaleout_per_vs'] = 1
    json_data['buffer_se'] = 0
    if value is True:
        json_data['ha_mode'] = 'HA_MODE_LEGACY_ACTIVE_STANDBY'
        json_data['max_vs_per_se'] = 1
        json_data['min_scaleout_per_vs'] = 2
        json_data['active_standby'] = True

    rest.put('serviceenginegroup', uuid=json_data['uuid'], data=json_data)


def set_se_group_shared_pair(sg_name):
    """This function does set se group shared pair.
    Args:
        :param sg_name: Service Engine Group name
        :type sg_name: str
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    status_code, resp = rest.get('serviceenginegroup', name=sg_name)
    json_data = resp

    json_data['ha_mode'] = 'HA_MODE_SHARED_PAIR'
    json_data['max_vs_per_se'] = 4
    json_data['min_scaleout_per_vs'] = 2
    json_data['buffer_se'] = 0
    json_data['active_standby'] = False
    rest.put('serviceenginegroup', uuid=json_data['uuid'], data=json_data)


def set_se_group_shared(sg_name, buffer_se=1):
    """This function does set se group shared.
    Args:
        :param sg_name: Service Engine Group name
        :type sg_name: str
    kwargs:
        :param buffer_se: no of buffer SEs
        :type buffer_se: int
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    status_code, resp = rest.get('serviceenginegroup', name=sg_name)
    json_data = resp

    json_data['ha_mode'] = 'HA_MODE_SHARED'
    json_data['max_vs_per_se'] = 4
    json_data['min_scaleout_per_vs'] = 1
    json_data['buffer_se'] = buffer_se
    json_data['active_standby'] = False
    rest.put('serviceenginegroup', uuid=json_data['uuid'], data=json_data)


def set_se_group_dedicated_pair(sg_name):
    """This function does set SE Group Dedicated pair
    Args:
        :param sg_name: Service Engine Group name
        :type sg_name: str
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    status_code, resp = rest.get('serviceenginegroup', name=sg_name)
    json_data = resp

    json_data['ha_mode'] = 'HA_MODE_SHARED_PAIR'
    json_data['max_vs_per_se'] = 1
    json_data['min_scaleout_per_vs'] = 2
    json_data['buffer_se'] = 0
    json_data['active_standby'] = False
    rest.put('serviceenginegroup', uuid=json_data['uuid'], data=json_data)


def get_connected_se_names():
    """This function does Get All Connected SE Names
    Returns:
        List of Connected Service Engine names
    Raises:
        ValueError, AttributeError, KeyError
    """
    return get_se_names(connected=True)


def get_se_names(connected=False):
    """This function does Get all SE names
    Returns:
        List of Service Engine names
    Raises:
        ValueError, AttributeError, KeyError
    """
    uri = 'serviceengine'
    params = {}
    if connected:
        params = {'se_connected': True}
    status_code, resp = rest.get('serviceengine', params=params)
    se_names = [se_info['name'] for se_info in resp['results']]
    logger.debug("Service Engine Names : %s " % ' '.join(se_names))
    return se_names


def delete_all_se_vms():
    """This function does Delete All Service Engine VMs
    Args:
        :param expect_se: Expect Service Engine
        :type expect_se: int
    Returns:
        Service Engine UUIDs as list
    Raises:
        ValueError, AttributeError, KeyError
    """
    se_uuids = get_all_se_uuid()
    for se_uuid in se_uuids:
        rest.delete('serviceengine', uuid=se_uuid)


def all_se_deleted():
    """This function checks if all SE VMs are deleted
    Returns:
        True : All Service Engine Deleted
        False: All Service Engine Not Deleted
    """
    if len(get_all_se_uuid()) > 0:
        return False
    _, resp = rest.get('vimgrsevmruntime')
    logger.info("response from vimgrse %s " %resp)
    if resp["count"] != 0:
        return False
    return True


@logger_utils.aretry(retry=20, delay=30, period=10)
def wait_for_all_se_to_be_deleted():
    """This function does Wait for All Service Engine VMs """
    if not all_se_deleted():
        logger_utils.error("All SE\'s not deleted after retry timeout of 600 sec")


@logger_utils.aretry(retry=9, delay=20, period=10)
def wait_for_se_to_connect(se_name):
    """
    This function does Wait for Service Engine to Connect.
    """
    logger.info(" Wait for SE to connect : %s" % se_name)
    if not is_se_connected(se_name):
        logger_utils.error('SE was not connected after retry timeout of 180s')


@logger_utils.aretry(retry=2, delay=90, period=10)
def wait_for_se_to_disconnect(se_name):
    """
    This function does Wait for Service Engine to Connect.
    """
    if is_se_connected(se_name):
        logger_utils.error('SE was not disconnected after retry timeout of 180s')


def forcedelete_all_se_vms():
    """This function does Force Delete All Service Engine VMs """
    se_uuids = get_all_se_uuid()
    for se_uuid in se_uuids:
        logger.debug('Force Delete Service Engine UUID/Name: %s' % se_uuid)
        rest.post('serviceengine', uuid=se_uuid, path='forcedelete')


def set_se_agent_properties(**kwargs):
    """This function does Set SE agent Properties
    Kwargs:
        :param uuid:
        :type uuid: dict
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    status_code, resp = rest.get('seproperties')

    se_agent_props = {}
    se_agent_props = resp['se_agent_properties']
    logger.info('Before SeAgent Properties:\n %s ' % se_agent_props)

    se_agent_props.update(kwargs)
    resp['se_agent_properties'] = se_agent_props
    logger.info('After SeAgent Properties:\n %s ' % se_agent_props)
    rest.put('seproperties', data=resp)


def se_reconnect_vm(se_vm):
    """This function Returns SE VM Object by using name / uuid.
    Args:
        :param name: Name of Service Engine to return VM Object
        :type name: str
        :param uuid: UUID of Service Engine to return VM Object
        :type uuid: str
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    controller_ip = controller_lib.get_controller_ip()

    se_vm.connect()

    cmd = 'iptables -D OUTPUT -p tcp -j DROP -d ' + controller_ip
    logger.info('Executing cmd: %s \n \
                  on SE : %s \n User Name: %s \n Password: %s' % (cmd, se_vm.ip, se_vm.user, se_vm.password))
    out = se_vm.execute_command(cmd, log_error=False)
    logger.info('Command Output: %s ' % ''.join(out))
    #    if cloud_obj.type ==  'baremetal':
    #        logger_utils.asleep(" SE Reconnect ...", delay=60, period=15)
    logger_utils.asleep(" SE Reconnect ...", delay=10, period=5)


def disconnect_se_from_controller(se_name, sg_name):
    """This function Disconnect SE From Controller
    Args:
        :param se_name: Name of Service Engine to return VM Object
        :type se_name: str
        :param sg_name: Service Engine Group Name
        :type sg_name: str
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    controller_ip = controller_lib.get_controller_ip()
    logger.info('Disconnect se %s from ctrl %s' % (se_name, controller_ip))

    se_vm = infra_utils.get_se_vm(se_name)[0]
    se_vm.connect()
    cmd = 'iptables -A OUTPUT -p tcp -j DROP -d ' + controller_ip
    logger.info('Executing cmd: %s \n \
                  on SE : %s \n User Name: %s \n Password: %s' % (cmd, se_vm.ip, se_vm.user, se_vm.password))
    out = se_vm.execute_command(cmd, log_error=False)
    logger.info('Command Output: %s ' % ''.join(out))


def get_se_list_in_group(se_group='Default-Group', **kwargs):
    """This functio Get SE list in a SE Group
    Kwargs:
        :param se_group: Name of Service Engine Groupt
        :type se_group: str
    Returns:
        List of Service Engine are in the SE Group
    Raises:
        ValueError, AttributeError, KeyError
    """
    status_code, resp = rest.get('serviceenginegroup', name=se_group)
    se_group_uuid = resp['uuid']

    params = {'refers_to': 'serviceenginegroup:%s' % se_group_uuid}

    status_code, resp = rest.get('serviceengine', params=params)

    se_list = []
    if not len(resp.get('results')):
        return se_list
    for se in resp.get('results'):
        se_list.append(se['uuid'])

    return se_list


def reboot_se(vm, wait_and_verify=True):
    """This function Reboot SE VM.
    Args:
        :param vm: Service Engine vm Object
        :type vm: object
    Raises:
        ValueError, AttributeError, KeyError
    """
    vm.execute_command('/opt/avi/scripts/stop_se.sh robot_reboot_se', log_error=False)
    # reconnect to avoid broken SSH connections
    vm.connect()
    reboot_time = vm.execute_command("last -x reboot | head -3", host=True)
    logger.info("Before Reboot: \n%s " % ''.join(reboot_time))
    # Reboot SE and sleep for sometime
    try:
        vm.execute_command('reboot', host=True)
    except Exception as ex:
        logger.info('reboot ex: %s, wait for reboot' % ex)

    if wait_and_verify:
        logger_utils.asleep(" Rebooting SE ...", delay=60, period=10)

        # Now try to reconnect
        vm.child = vm.connect()
        reboot_time = vm.execute_command("last -x reboot | head -3", host=True)
        logger.info("After Reboot: \n%s " % ''.join(reboot_time))
        vm.execute_command('ls')

        #TODO: Need to port
        #vm.processes.clear()

        @logger_utils.aretry(retry=20, delay=5, period=5)
        def retry_check():
            pass
            #TODO: Need to port
            #vm.processes = get_se_processes(vm)


def get_se_name_from_uuid(se_uuid):
    """This function Get SE Name from UUID..
    Args:
        :param se_uuid: Service Engine UUID
        :type se_uuid: str
    Returns:
        Service Engine Name
    Raises:
        ValueError, AttributeError, KeyError
    """
    se_data = get_se_info(se_uuid=se_uuid)
    return se_data['name']


def get_se_name_from_se_url(se_url):
    if'/serviceengine/' not in se_url:
        logger_utils.fail('ERROR! Cannot get se name from '
                          'virtualservice runtime, se url: %s' % se_url)
    api_path, se_slug = se_url.split('/serviceengine/')
    return se_slug


def get_se_names_from_vs_name(vs_name):
    se_name_list = []
    resp_code, resp_data = rest.get('virtualservice', name=vs_name, path='runtime')

    for vip_summary in resp_data.get('vip_summary'):
        ses = vip_summary.get('service_engine')
        if not ses:
            logger_utils.fail('ERROR! Cannot get se_id for virtual service %s' % vs_name)

        for se in ses:
            se_name = get_se_name_from_se_url(se['url'])
            se_name_list.append(se_name)

    logger.debug('se_name_list: %s' % str(se_name_list))
    return se_name_list


def get_all_se_uuid(expect_se=0, **kwargs):
    """This function does get all SE UUID
    Args:
        :param expect_se: Expect Service Engine
        :type expect_se: int
    Returns:
        Service Engine UUIDs as list
    Raises:
        ValueError, AttributeError, KeyError
    """
    params={'page_size': 200}
    status_code, resp = rest.get('serviceengine', params=params)
    se_uuids = [res['uuid'] for res in resp['results']]
    if expect_se != 0 and expect_se != len(se_uuids):
        #Validate the SEs returned matches the expected numberl
        logger_utils.fail('Expected num of SEs: %s, Actual: %s' % (expect_se, len(se_uuids)))

    return se_uuids


def get_se_stats(se_uuid, stats_key, core=0):
    resp_code, resp_data = rest.get('serviceengine', uuid=se_uuid, path=stats_key)

    if core == 'all':
        return resp_data

    for json_data in resp_data:
        proc_id_from_get_data = ''
        proc_id_from_get_data = json_data.get('proc_id')

        if not proc_id_from_get_data:
            continue
        if (re.search('C' + str(core), proc_id_from_get_data) or
                re.search('PROC_Aggregate', proc_id_from_get_data)):
            return json_data

    logger_utils.fail('ERROR! internal data NULL for %s core %s' % (
        resp_data, str(core)))


def make_segroup_have_n_se(segroup_name, num_target_se, force=False):
    """
    Make segroup have num_target_se by moving se to and from sg-parking
    :param segroup_name: name of segroup
    :param num_target_se: num se targetted in this group
    :return: None
    """
    num_target_se = int(num_target_se)
    se_in_group = get_se_in_group(segroup_name)
    num_se_in_group = len(se_in_group)
    logger.debug("[%s] num_se=%s, target_se=%s" % (segroup_name, num_se_in_group, num_target_se))

    if num_se_in_group == num_target_se:
        logger.debug("segroup already at target, nothing to move")
        set_se_group_max_number(segroup_name, num_target_se)
        return

    se_in_sgparking = get_se_in_group('sg-parking')
    num_se_in_sgparking = len(se_in_sgparking)
    logger.debug("[sg-parking] num_se=%d" % num_se_in_sgparking)

    if num_se_in_group == 0 and num_se_in_sgparking == 0:
        logger.debug("no se in the system")
        set_se_group_max_number(segroup_name, num_target_se)
        return

    # More SE requested, none to move
    if num_target_se > num_se_in_group and num_se_in_sgparking == 0:
        logger.debug("no se in sg-parking, nothing to move out of parking")
        set_se_group_max_number(segroup_name, num_target_se)
        return

    # More SE requested, move from sg-parking
    if num_target_se > num_se_in_group:
        num_se_to_move = num_target_se - num_se_in_group
        logger.debug("move %d se from sg-parking to group" % num_se_to_move)
        set_se_group_max_number(segroup_name, num_target_se)
        num_se_available_to_move = min(num_se_to_move, num_se_in_sgparking)
        logger.debug("from sg-parking::num_se_available_to_move=%d" % num_se_available_to_move)
        for i in range(num_se_available_to_move):
            update_se_segroup(se_in_sgparking[i]['uuid'], segroup_name)

    # Less SE requested, move into sg-parking
    else:
        num_se_to_move = num_se_in_group - num_target_se
        logger.debug("move %d se from group into sg-parking" % num_se_to_move)
        se_in_group_with_zero_vs, se_vs_count_list = list(), list()
        for se in se_in_group:
            if len(se['config']['virtualservice_refs']) == 0:
                se_in_group_with_zero_vs.append(se)
                logger.debug("se %s has zero vs" % se['uuid'])
            else:
                logger.debug("se %s has %d vs: %s" % (
                    se['uuid'], len(se['config']['virtualservice_refs']), se['config']['virtualservice_refs']))
            se_vs_count_list.append((se['uuid'], len(se['config']['virtualservice_refs'])))
        num_se_in_group_with_zero_vs = len(se_in_group_with_zero_vs)
        logger.info("num_se_in_group_with_zero_vs=%d" % num_se_in_group_with_zero_vs)
        num_se_available_to_move = num_se_to_move if force else min(num_se_to_move, num_se_in_group_with_zero_vs)
        logger.info("into sg-parking::num_se_available_to_move=%d" % num_se_available_to_move)

        if force and num_se_to_move:
            se_vs_count_list = sorted(se_vs_count_list, key=lambda x: x[1])  # sorting SE as per least no. of vs
            for i in range(num_se_to_move):
                update_se_segroup(se_vs_count_list[i][0], 'sg-parking', force=True)
        else:
            for i in range(num_se_available_to_move):
                update_se_segroup(se_in_group_with_zero_vs[i]['uuid'], 'sg-parking')
        set_se_group_max_number(segroup_name, num_target_se)


def get_se_in_group(segroup_name):
    """
    :param segroup_name: segroup_name
    :return: segroup pb
    """

    segroup_uuid = rest.get_uuid_by_name('serviceenginegroup', segroup_name)
    api = ('serviceengine-inventory?refers_to=serviceenginegroup:' + segroup_uuid)
    #api = ('serviceengine/?owned_by_controller=true&refers_to=serviceenginegroup:' + segroup_uuid)
    params = {}
    params['refers_to'] = 'serviceenginegroup:' + segroup_uuid
    status_code, json_data = rest.get('serviceengine-inventory', params=params)
    return json_data.get('results')


def update_se_segroup(se_uuid, sg_name, **kwargs):
    """ Update ServiceEngine Group for Service Engine

    Args:
        :param se_uuid: ServiceEngine Grou UUID
        :type se_uuid: str
        :param sg_name: ServiceEngine Group Name
        :type sg_name: str

    Returns:
        None
    """
    logger.info('update segroup for se:%s to sg:%s' % (se_uuid, sg_name))

    status_code, json_data = rest.get("serviceengine", uuid=se_uuid)

    sg = json_data.get('se_group_ref', None)
    if not sg:
        logger_utils.fail('ERROR! Cannot get se_group from api')
    json_data['se_group_ref'] = '/api/serviceenginegroup?name=%s' % sg_name

    rest.put('serviceengine', uuid=se_uuid, data=json_data, **kwargs)


def get_cidr(netmask):
    """ Returns a cidr from netmask. For eg. If argument is 255.255.255.255,
        the function returns 32.

    Args:
        :param netmask: Netmask needs to be converted to cidr
        :type netmask: str

    Returns:
        Netmask value

    Raises:
        ipaddress.AddressValueError, ipaddress.NetmaskValueError

    """
    try:
        if type(ipaddress.ip_address(unicode(netmask))) == ipaddress.IPv6Address:
            netmask = netmask.replace('::', ':')
            if netmask[-1] == ':':
                netmask = netmask[:-1]
            return str(sum([bin(int('0x' + x, 16)).count('1') for x in netmask.split(':')]))
        else:
            return str(sum([bin(int(x)).count('1') for x in netmask.split('.')]))
    except Exception as verr:
        logger.debug("From get_cidr: %s" % str(verr))


def get_se_interfaces(se_name=None, se_uuid=None):
    """ API to get SE Interface details

    Args:
        :param se_name: SE Name to get interface details
        :type se_name: str
        :param se_uuid: SE UUID to get interface details
        :type se_uuid: str
    Returns:
        Service Engine interface details
    """
    if not se_name and not se_uuid:
        logger_utils.fail("Need se_name or se_uuid to get SE interfaces")
    status_code, se_inf_data = rest.get('serviceengine', uuid=se_uuid, path='interface')
    return se_inf_data


def verify_vip_in_se_interfaces(vs_name, ip_addr=None, addr_type=None, vip_id='0', addr_should_be_in=True):
    """ API to Check VIP IP address in SE interfaces

    Args:
        :param vs_name: Virtual Service Name to check the same
        :type vs_name: str
        :param ip_addr: Virtual Service IP address to check
        :type ip_addr: str
        :param addr_type: Virtual Service IP address Type
        :type addr_type: str
        :param vip_id: Virtual Service VIP IP
        :type vip_id: str
        :param addr_should_be_in: IP address should be present or not.
        :type addr_should_be_in: boolean
    Returns:
        - True : Success
        - False : Fail
    """

    from lib.vs_lib import get_vs_vip, vs_get_se_list
    if not ip_addr:
        ip_addr = get_vs_vip(vs_name=vs_name, addr_type=addr_type, vip_id=vip_id)

    se_list = vs_get_se_list(vs_name=vs_name, vip_id='0')

    ip_present = False
    se_inf_vnics = None
    for se_uuid in se_list:
        se_inf_data = get_se_interfaces(se_uuid=se_uuid)
        se_inf_data = se_inf_data[0]
        se_inf_vnics = se_inf_data.get('vnics', [])
        for vnic in se_inf_vnics:
            if 'ip_info' in vnic:
                for ip_info in vnic['ip_info']:
                    if ip_info['ip_addr'] == ip_addr:
                        ip_present = True
                        break
    if addr_should_be_in and ip_present:
        logger.info("IP Address: %s present as expected. in SE Interface VNIC info" % ip_addr)
        return True
    elif not addr_should_be_in and not ip_present:
        logger.info("IP Address: %s not there as expected. in SE Interface VNIC info" % ip_addr)
        return True
    else:
        logger.warning("IP Address check failed in SE Interface VNIC info. \
                        Expected to be addr_should_be_in: %s\n Given IP address:%s\n \
                        SE Interface VNIC info:%s" % (addr_should_be_in, ip_addr, se_inf_vnics))
        return False


def verify_vip_on_controller_se_interface(vs_name, ip_addr=None, addr_type=None,
                                          vip_id='0', addr_should_be_in=True):
    """ API to Check VIP IP address in Controller SE interfaces

    Args:
        :param vs_name: Virtual Service Name to check the same
        :type vs_name: str
        :param ip_addr: Virtual Service IP address to check
        :type ip_addr: str
        :param addr_type: Virtual Service IP address Type
        :type addr_type: str
        :param vip_id: Virtual Service VIP IP
        :type vip_id: str
        :param addr_should_be_in: IP address should be present or not.
        :type addr_should_be_in: boolean
    Returns:
        - True : Success
        - False : Fail
    """

    from lib.vs_lib import get_vs_vip, vs_get_se_list
    if not ip_addr:
        ip_addr = get_vs_vip(vs_name=vs_name, addr_type=addr_type, vip_id=vip_id)

    se_list = vs_get_se_list(vs_name=vs_name, vip_id='0')

    ip_present = False
    vnic_networks = []
    for se_uuid in se_list:
        se_inf_data = get_se_info(se_uuid=se_uuid)
        if 'mgmt_vnic' in se_inf_data:
            if 'vnic_networks' in se_inf_data['mgmt_vnic']:
                vnic_networks.extend(se_inf_data['mgmt_vnic']['vnic_networks'])
        if 'data_vnics' in se_inf_data:
            for data_vnic in se_inf_data['data_vnics']:
                if 'vnic_networks' in data_vnic:
                    vnic_networks.extend(data_vnic['vnic_networks'])

    # Got the all the vnic_networks details from (mgmt+data) now check for vip address
    # combining mgmt+data_vnic helps to check in inband mgmt case too
    for vnic_network in vnic_networks:
        if vnic_network['ip']['ip_addr']['addr'] == ip_addr:
            ip_present = True

    if addr_should_be_in and ip_present:
        logger.info("VIP Address: %s present as expected. in Controller SE Interface VNIC info" % ip_addr)
        return True
    elif not addr_should_be_in and not ip_present:
        logger.info("VIP Address: %s not there as expected. in Controller SE Interface VNIC info" % ip_addr)
        return True
    else:
        logger.warning("VIP Address check failed in Controller SE Interface VNIC info.\n \
                        Expected state addr_should_be_in: %s\n\
                        Given IP address:%s\n Controller SE Interface VNIC info:\n%s" %
                       (addr_should_be_in, ip_addr, vnic_networks))
        return False


def get_se_tcp_flows(se_name=None, se_uuid=None):
    """
    This function does get SE information
    Args:
        :param se_name: Service Engine name
        :type se_name: str
        :param se_uuid: Service Engine UUID
        :type se_uuid: str
    Returns:
        tcp-flow data
    Raises:
        ValueError, AttributeError, KeyError
    """
    if not se_name and not se_uuid:
        logger_utils.fail("Need SE Name or UUID to get SE info.")

    status_code, data = rest.get('serviceengine', uuid=se_uuid, path='tcp-flows')
    return data['results']


def verify_vip_on_tcp_flows(vs_name, ip_addr=None, addr_type=None,
                            vip_id='0', addr_should_be_in=True):
    """ API to Check VIP IP address for Listenerin usinf TCP-Flows
    Args:
        :param vs_name: Virtual Service Name to check the same
        :type vs_name: str
        :param ip_addr: Virtual Service IP address to check
        :type ip_addr: str
        :param addr_type: Virtual Service IP address Type
        :type addr_type: str
        :param vip_id: Virtual Service VIP IP
        :type vip_id: str
        :param addr_should_be_in: IP address should be present or not.
        :type addr_should_be_in: boolean
    Returns:
        - True : Success
        - False : Fail
    """

    from lib.vs_lib import get_vs_vip, vs_get_se_list
    if not ip_addr:
        ip_addr = get_vs_vip(vs_name=vs_name, addr_type=addr_type, vip_id=vip_id)

    se_list = vs_get_se_list(vs_name=vs_name, vip_id='0')

    ip_present = False
    connections = []
    for se_uuid in se_list:
        se_tcp_flows_data = get_se_tcp_flows(se_uuid=se_uuid)
        for each_flow in se_tcp_flows_data:
            if 'connection' in each_flow:
                connections.extend(each_flow['connection'])

    for connection in connections:
        if 'l_ip' in connection and connection['l_ip'] == ip_addr:
            ip_present = True

    if addr_should_be_in and ip_present:
        logger.info("VIP Address: %s present as expected. in SE Listener TCP-FLows" % ip_addr)
        return True
    elif not addr_should_be_in and not ip_present:
        logger.info("VIP Address: %s not there as expected. in SE Listener TCP-FLows" % ip_addr)
        return True
    else:
        logger.warning("Verify VIP Address check failed in SE Listener TCP-FLows\n \
                        Expected state addr_should_be_in: %s\n\
                        Given IP address:%s\n SE Listener TCP-FLows connections:\n%s" %
                       (addr_should_be_in, ip_addr, connections))
        return False


def get_se_dispatcher_details(se_name=None, se_uuid=None):
    """
    This function does get SE Dispatcher details
    Args:
        :param se_name: Service Engine name
        :type se_name: str
        :param se_uuid: Service Engine UUID
        :type se_uuid: str
    Returns:
        tcp-flow data
    Raises:
        ValueError, AttributeError, KeyError
    """
    if not se_name and not se_uuid:
        logger_utils.fail("Need SE Name or UUID to get SE info.")

    status_code, data = rest.get('serviceengine', uuid=se_uuid, path='vshash')
    return data


def verify_vip_on_se_dispatcher_details(vs_name, ip_addr=None, addr_type=None,
                                        vip_id='0', addr_should_be_in=True):
    """ API to Check VIP IP on SE Dispatcher details
    Args:
        :param vs_name: Virtual Service Name to check the same
        :type vs_name: str
        :param ip_addr: Virtual Service IP address to check
        :type ip_addr: str
        :param addr_type: Virtual Service IP address Type
        :type addr_type: str
        :param vip_id: Virtual Service VIP IP
        :type vip_id: str
        :param addr_should_be_in: IP address should be present or not.
        :type addr_should_be_in: boolean
    Returns:
        - True : Success
        - False : Fail
    """
    from lib.vs_lib import get_vs_vip, vs_get_se_list
    if not ip_addr:
        ip_addr = get_vs_vip(vs_name=vs_name, addr_type=addr_type, vip_id=vip_id)

    se_list = vs_get_se_list(vs_name=vs_name, vip_id='0')

    ip_present = False
    vshashs = []
    for se_uuid in se_list:
        se_dp_details = get_se_dispatcher_details(se_uuid=se_uuid)
        for each_vshash in se_dp_details:
            if 'vshashone' in each_vshash:
                vshashs.extend(each_vshash['vshashone'])
    for vshash in vshashs:
        if 'ip' in vshash and ip_addr == vshash['ip']:
            ip_present = True

    if addr_should_be_in and ip_present:
        logger.info("VIP Address: %s present as expected. in SE Dispatcher details" % ip_addr)
        return True
    elif not addr_should_be_in and not ip_present:
        logger.info("VIP Address: %s not there as expected. in SE SE Dispatcher details" % ip_addr)
        return True
    else:
        logger.warning("Verify VIP Address check failed in SE Dispatcher details\n \
                        Expected state addr_should_be_in: %s\n\
                        Given IP address:%s\n SE Dispatcher details:\n%s" %
                       (addr_should_be_in, ip_addr, vshashs))
        return False


def map_se_uuid_to_ip(se_uuid, **kwargs):
    resp_code, resp_data = rest.get('serviceengine', uuid=se_uuid)
    try:
        ses = [resp_data]
    except:
        logger_utils.fail('ERROR! Cannot get se_name for se_uuid %s' % se_uuid)

    try:
        for se in ses:
            uuid = se.get('uuid')
            if uuid == se_uuid:
                mgmt_vnic = se.get('mgmt_vnic')
                vnic = mgmt_vnic['vnic_networks'][0]
                se_ip = vnic['ip']['ip_addr']['addr']
                logger.info('map_se_uuid_to_name: uuid %s name %s' % (se_uuid, se_ip))
                return se_ip
    except:
        logger_utils.fail('ERROR! Cannot get se_ip for se_uuid %s' % se_uuid)
        logger_utils.fail('ERROR! Cannot get se_ip for se_uuid %s' % se_uuid)


def map_se_uuid_to_name(se_uuid):
    """

    :param se_uuid:
    :param kwargs:
    :return:
    """
    resp_code, resp_data = rest.get('serviceengine', uuid=se_uuid)
    resp_data = resp_data['results'][0] if resp_data.get('results') else resp_data
    return resp_data['name']


# deprecated in favor of the mesos_lib.check_se_on_all_slaves version
def check_all_slaves_connected():
    """

    :return:
    """
    import lib.mesos_lib as mesos_lib

    c_count = 0
    slist = mesos_lib.get_all_mesos_slaves()
    for vm in slist:
        se_name = vm['ip'] + '-avitag-1'
        if not is_se_connected(se_name):
            print se_name + " Not Connected"
        else:
            c_count += 1
            print se_name + " Connected"

    if c_count != len(slist):
        return 0
    else:
        return 1


def se_count_owned_by_controller():
    """

    :return:
    """
    cloud = rest.get_cloud_context()
    infra_utils.switch_mode(cloud=None)
    status_code, json_se_group_data = rest.get('serviceengine')
    infra_utils.switch_mode(cloud=cloud)
    return json_se_group_data.get('count')

def get_se_group_uuid(sg_name, tenant='admin'):
    """

    :param sg_name:
    :param tenant:
    :return:
    """

    resp_code, json_data = rest.get('serviceenginegroup', name=sg_name)
    logger.info('sg uuid:%s' % json_data['uuid'])
    return json_data['uuid']


def set_se_enable_state(se_name, enable_state):
    """

    :param se_name:
    :param enable_state:
    :return:
    """

    resp_code, json_data = rest.get('serviceengine', name=se_name)
    if enable_state in ('SE_STATE_ENABLED',
                        'SE_STATE_DISABLED_FOR_PLACEMENT',
                        'SE_STATE_DISABLED',
                        'SE_STATE_DISABLED_FORCE'):
        json_data['enable_state'] = enable_state
    else:
        logger_utils.fail("Invalid value for enable_state: %s" % str(
            enable_state))

    rest.put('serviceengine', name=se_name, data=json_data)


def get_se_enable_state(se_name):
    """

    :param se_name:
    :return:
    """

    se_data = get_se_info(se_name=se_name, connected=False)
    return se_data['enable_state']


def se_wellness_check(se_name, t_state, t_connected=True,
                      retry_count=1, retry_interval=1):
    json_se_data = get_se_config(se_name)
    if json_se_data.get('results'):
        json_se_data = json_se_data['results'][0]
    se_uuid = json_se_data.get('uuid')
    logger.info(se_uuid)
    try:
        common.retry_action_detail(lambda: se_wellness_check_once(
            se_name, se_uuid, t_state, t_connected), retry_count=retry_count,
                                   retry_interval=float(retry_interval))
    except Exception as e:
        logger_utils.fail("%s" % str(e))
        return False
    return True


def se_wellness_check_once(se_name, se_uuid, t_state, t_connected=True):
    """

    :param se_name:
    :param se_uuid:
    :param t_state:
    :param t_connected:
    :return:
    """

    t_connected = common._bool_value(t_connected)
    dbg_str = '## start se wellness check se=%s/%s t_state=%s t_connected=%s' % (
        se_name, se_uuid, t_state, t_connected)
    logger.info(dbg_str)

    #se, se_summary, se_detail = cache_se(se_name)

    se_summary = get_se_runtime_summary(se_uuid)    # show se summary
    # Oper State
    try:
        summary_oper_state = se_summary['oper_status']['state']
    except KeyError, Argument:
        dbg_str = '## oper status not available: %s' % Argument
        logger.warn(dbg_str)
        return False, dbg_str
        #logger_utils.error(
        #    '## oper status not available: %s' % Argument)

    if summary_oper_state != t_state:
        logger.info("se[%s] summary[%s] != expected[%s]" % (se_name, summary_oper_state, t_state))
        dbg_str = 'se[%s] summary[%s] != expected[%s]' % (se_name, summary_oper_state, t_state)
        logger.info(dbg_str)
        return False, dbg_str
        #logger_utils.error(
        #    "se[%s] summary[%s] != expected[%s]" % (se_name, summary_oper_state,
        #                                            t_state))

    if t_connected != se_summary['se_connected']:
        dbg_str = 'se connected %s != t_connected %s mismatch'\
               % (se_summary['se_connected'], bool(t_connected))
        logger.info(dbg_str)
        return False, dbg_str
        #logger_utils.error("se connected mismatch")

    return True, dbg_str


def get_se_runtime_summary(se_uuid):
    """

    :param se_uuid:
    :return:
    """

    api = 'serviceengine/' + se_uuid + '/runtime'
    status_code, runtime = rest.get(api)
    return runtime


def get_se_config(se_name):
    """

    :param se_name:
    :return:
    """

    resp_code, resp_data = rest.get('serviceengine', name=se_name)
    return resp_data


def get_all_se_name_list():
    """
    Create a list of all SE names present on current cluster
    @return: SE name list
    """
    status, response = rest.get("serviceengine")
    se_name_list = []
    for se in response["results"]:
        se_name_list.append(se["name"])
    return se_name_list


def se_should_be_connected(se_name, **kwargs):
    """

    :param se_name:
    :param kwargs:
    :return:
    """

    logger.info('se %s' % se_name)
    retry_timeout = int(kwargs.get('retry_timeout', 20))
    retry_interval = float(kwargs.get('retry_interval', 6))
    try:
        check_se_state(se_name, retry_timeout=retry_timeout,
                       retry_interval=retry_interval)
    except Exception as e:
        logger_utils.fail('SE not up after retry timeout of %s:%s' % (retry_timeout, e))


def check_se_state(se_name, **kwargs):
    """

    :param se_name:
    :param kwargs:
    :return:
    """
    retry_timeout = int(kwargs.get('retry_timeout', 0))
    retry_interval = float(kwargs.get('retry_interval', 0.1))

    @logger_utils.aretry(retry=retry_timeout, period=retry_interval)
    def retry_action():
        is_se_connected(se_name)
    retry_action()


def is_se_connected_by_uuid(se_uuid):
    se_data = get_se_info(se_uuid=se_uuid)
    return se_data['se_connected']


def is_se_disconnected_by_uuid(se_uuid):
    se_data = get_se_info(se_uuid=se_uuid)
    return not se_data['se_connected']


def se_should_be_connected_by_uuid(se_uuid):
    @logger_utils.aretry(retry=30, delay=3, period=1)
    def retry_action():
            if not is_se_connected_by_uuid(se_uuid):
                logger_utils.error('SE[%s] is not connected after retrying for 15 '
                             'seconds' % se_uuid)
                logger_utils.fail('SE[%s] is not connected after retrying for '
                                  '15 seconds' % se_uuid)
    retry_action()


def se_should_be_disconnected(se_uuid):
    @logger_utils.aretry(retry=15, delay=3, period=1)
    def retry_action():
            if not is_se_disconnected_by_uuid(se_uuid):
                logger_utils.error('SE[%s] is not disconnected after retrying for '
                             '15 seconds' % se_uuid)
                logger_utils.fail('SE[%s] is not disconnected '
                                               'after retrying for 15 '
                                               'seconds' % se_uuid)
    retry_action()


def se_start_by_uuid(se_uuid, wait=1):
    logger.info('start_se vm %s' % se_uuid)
    se_vm = infra_utils.get_se_vm(se_uuid=se_uuid)
    for each_vm in se_vm:
        each_vm.connect()
        cmd = '/opt/avi/scripts/start_se.sh robot_se_start'
        logger.info('Executing cmd %s username %s pwd %s' % (cmd, each_vm.user,
                                                             each_vm.password))
        out = each_vm.execute_command(cmd, noerr=False)
        logger.info('Cmd %s Output: %s' % (cmd, out))
        if not int(wait):
            return
        se_should_be_connected_by_uuid(se_uuid)
        each_vm.processes.clear()
        se_summary = get_se_runtime_summary(se_uuid)

        try:
            summary_oper_state = se_summary['oper_status']['state']
        except KeyError, Argument:
            logger_utils.fail("## Oper status not available: %s" % Argument)

        if summary_oper_state != 'OPER_UP':
            logger_utils.fail("summary_oper_state(%s) doe not matches expected_oper_state(OPER_UP)"
                           % se_summary['oper_status']['state'])
        return True


def se_stop_by_uuid(se_uuid, wait=1):
    logger.info('stop_se uuid %s' % se_uuid)
    se_vm = infra_utils.get_se_vm(se_uuid=se_uuid)
    for each_vm in se_vm:
        each_vm.connect()
        cmd = '/opt/avi/scripts/stop_se.sh robot_se_stop'
        logger.info('Executing cmd %s username %s pwd %s' % (cmd, each_vm.user,
                                                             each_vm.password))
        out = each_vm.execute_command(cmd, noerr=False)
        logger.info('Cmd %s Output: %s' % (cmd, out))
        if not int(wait):
            return
        se_should_be_disconnected(se_uuid)
        each_vm.processes.clear()

        se_summary = get_se_runtime_summary(se_uuid)

        try:
            summary_oper_state = se_summary['oper_status']['state']
        except KeyError, Argument:
            logger_utils.fail("## Oper status not available: %s" % Argument)

        if summary_oper_state != 'OPER_DOWN':
            logger_utils.fail("summary_oper_state(%s) doe not matches expected_oper_state(OPER_DOWN)"
                           % se_summary['oper_status']['state'])
        return True


def switchover_se_manual(se_name):
    rest.post('serviceengine', name=se_name, path='switchover')


def switchover_se_manual_uuid(se_uuid):
    rest.post('serviceengine', uuid=se_uuid, path='switchover')


def get_se_migrate_state(se_name):
    se_data = get_se_info(se_name=se_name, connected=False)
    se_summary = get_se_runtime_summary(se_data['uuid'])
    return se_summary['migrate_state']


def is_se_migrate_finished(se_name):
    """This function does Check SE is Migrated or note
        Args:
            :param se_name: Service Engine name
            :type se_name: str
        Returns:
            Service Engine state if its migrated else False
        Raises:
            ValueError, AttributeError, KeyError
    """
    migrate_state = get_se_migrate_state(se_name)
    if migrate_state in ['SE_MIGRATE_STATE_FINISHED_WITH_FAILURE', 'SE_MIGRATE_STATE_FINISHED']:
        return True
    return False


@logger_utils.aretry(retry=20, delay=30, period=10)
def verify_se_migrate_and_wait_till_finished(se_name, **kwargs):
    if not is_se_migrate_finished(se_name):
        logger_utils.error('SE %s not migrated after retry timeout of 600 '
                           'sec' % se_name)


def get_disconnected_se_uuids():
    """
    function return list of all SE uuids which are disconnected from controller
    """
    params = {'se_connected': False}
    status_code, se_list = rest.get('serviceengine', params=params)
    se_uuids = list()
    if se_list.get('results', None):
        se_uuids = [se_data['uuid'] for se_data in se_list['results']]

    return se_uuids


def start_all_ses_v2():
    """
    function starts all SE's which are not connected in system
    """
    se_uuids = get_disconnected_se_uuids()
    if se_uuids:
        for se_uuid in se_uuids:
            se_start_by_uuid(se_uuid, wait=0)
    else:
        logger.info('All SE"s are already connected')


def get_scaledout_vs_with_se_list():
    """
    function to return scaled out vs along with se list which are non-child vs
    """
    vs_se_dict = dict()
    resp_data = vs_lib.get_vs(vs_name=None)
    if not resp_data.get('results', None):
        logger.info('No VS found in system')
        return vs_se_dict

    for vs_info in resp_data['results']:
        se_list = vs_info['vip_runtime'][0].get('se_list', None)
        # getting all vs which are scaled out and not child VS
        if (vs_info['type'] != 'VS_TYPE_VH_CHILD') and se_list and len(se_list) > 1:
            se_uuid_list = [rest.get_uuid_from_ref(se_info['se_ref']) for se_info in se_list]
            vs_se_dict[vs_info['name']] = se_uuid_list

    return vs_se_dict


def scale_vs_to_1_se(from_sg_group='Default-Group', to_sg_group='sg-parking'):
    """
    scalein given list of vs to have single SE attached.
    Move all SE to given sg_group and keep single in Default-Group
    :param from_sg_group: serviceengine group name to move remaining SE's
    :param from_sg_group: sg group name from which SE is to move
    :param to_sg_group: sg group name to which SE will be moved
    """
    vs_se_dict = get_scaledout_vs_with_se_list()
    for retry_count in range(10):
        try:
            # forcefully moving SE's into sg-parking group
            make_segroup_have_n_se(from_sg_group, 1, force=True)
            break
        except Exception as e:
            if retry_count == 9:
                logger_utils.fail(str(e))
            logger.debug('Exception: %s' % str(e))
    # setting scalein_timeout to 1 sec for faster operation
    set_se_group_scalein_timeout(sg_name=from_sg_group, timeout=1)
    for vs_name, se_list in vs_se_dict.items():
        for num in range(len(se_list)-1):
            vs_lib.scale_in_vs(vs_name, sleep=False)
            logger_utils.asleep(delay=60)  #FIXME: Increased delay for now due to dummy scalein event delayed generation issue
    # resetting scalein_timeout to default 30 sec.
    set_se_group_scalein_timeout(sg_name=from_sg_group)
    return True


def set_se_group_scalein_timeout(sg_name='Default-Group', timeout=30):
    """
    This function sets the vs_scalein_timeout attribute
    :param sg_name: Service Engine Group Name
    :param timeout: timeout to set in seconds
    :return:
    Raises:
        ValueError, AttributeError, KeyError
    """
    logger.info('Setting Service Engine Group [name]: %s, \
                    vs_scalein_timeout : %d ' % (sg_name, timeout))
    set_se_group_properties(sg_name, number=timeout,
                            vs_scalein_timeout='vs_scalein_timeout')


def se_get_ip_for_mac(se_name, mac):
    """

    :param se_name:
    :param mac:
    :return:
    """
    se_info = get_se_info(se_name=se_name)
    if se_info.get('data_vnics'):
        for vnic in se_info['data_vnics']:
            if vnic['mac_address'].lower() == mac.lower():
                if vnic.get('vnic_networks'):
                    # if len(vnic['vnic_networks']):
                    return vnic['vnic_networks'][0]['ip']['ip_addr']['addr']
                else:
                    return 'UNKNOWN'
    if se_info.get('mgmt_vnic'):
        if se_info['mgmt_vnic']['mac_address'].lower() == mac.lower():
            if len(se_info['mgmt_vnic']['vnic_networks']):
                return se_info['mgmt_vnic']['vnic_networks'][0]['ip'][
                    'ip_addr']['addr']
            else:
                return 'UNKNOWN'


def get_mac_addr_from_vNic(se_name, vNic):
    """
    Returns MAC address corresponding to vNic on given service engine.
    :param se_name: Name of the service engine
    :param vNic: Name of the eth interface
    :return:
    """
    _, interfaces = rest.get('serviceengine', name=se_name, path='interface')
    for entry in interfaces:
        if 'vnics' in entry:
            for vnic in entry['vnics']:
                if vnic['vnic_name'] == vNic:
                    return vnic['mac_address']
    logger_utils.fail('No MAC address found for vnic: %s' % vNic)


def get_vnic_matching_ip_nw(server_ip, se_name):
    """
    Finds vNic assigned to VS or backend server using
       /serviceengine/NAME/route api. Returns vnic name.
    :param server_ip: IP of VS or backend server
    :param se_name: Corresponding service engine serving requests
    :return:
    """
    interface = None
    resp_code, resp = rest.get('serviceengine', name=se_name, path='route')
    for entry in resp:
        if 'route_entry' in entry:
            for route in entry['route_entry']:
                dest = route['destination']
                netmask = route['netmask']
                server = IPAddress(server_ip)
                network = IPNetwork(dest + '/' + get_cidr(netmask))
                if server in network:
                    print server, network, route['interface']
                    if get_cidr(netmask) == '32':
                        return route['interface']
                    else:
                        interface = route['interface']

    if interface:
        return interface
    raise logger_utils.fail('Route not found in SE route table')


def get_mac_addr_for_ip(se_name, server_ip):
    """

    :param se_name:
    :param server_ip:
    :return:
    """
    vNic = get_vnic_matching_ip_nw(server_ip, se_name)
    mac_addr = get_mac_addr_from_vNic(se_name, vNic)
    return mac_addr


def se_get_ip_for_server(se_name, server_ip):
    """

    :param se_name:
    :param server_ip:
    :return:
    """
    mac_addr = get_mac_addr_for_ip(se_name, server_ip)
    return se_get_ip_for_mac(se_name, mac_addr)


def stop_all_ses():
    """

    :return:
    """
    se_uuids = get_se_uuid()
    for se_uuid in se_uuids:
        se_stop_by_uuid(se_uuid, wait=0)


def start_all_ses():
    """

    :return:
    """
    se_uuids = get_se_uuid()
    for se_uuid in se_uuids:
        se_start_by_uuid(se_uuid, wait=0)


def se_disconnect_vm(se_vm):
    """

    :param se_vm:
    :return:
    """
    controller_ip = controller_lib.get_controller_ip()
    se_vm.connect()
    cmd = 'iptables -A OUTPUT -p tcp -j DROP -d ' + controller_ip
    logger.debug('Executing cmd %s ip %s username %s pwd %s' %
                 (cmd, se_vm.ip, se_vm.user, se_vm.password))
    out = se_vm.execute_command(cmd, noerr=False)
    logger.debug('Cmd %s Output: %s' % (cmd, out))


def get_se_num_hb_unit(aggressive=False):
    """

    :param aggressive:
    :return:
    """
    status_code, data = rest.get('seproperties')
    logger.debug('Aggressive: %s' % str(aggressive))
    if data and 'se_runtime_properties' in data.keys():
        if aggressive:
            s = 'dp_aggressive_hb_frequency'
        else:
            s = 'dp_hb_frequency'
        f = float(data['se_runtime_properties'][s])
        logger.info('Frequency: %s' % str(f))
        c = int(1000/f) if f else 0
        return c
    return 1


def set_se_group_per_app(sg_name, per_app=False):
    """

    :param sg_name:
    :param per_app:
    :return:
    """
    resp_code, json_data = rest.get('serviceenginegroup', name=sg_name)
    json_data['per_app'] = per_app
    status_code, resp = rest.put('serviceenginegroup', name=sg_name,
                                 data=json_data)


def get_se_uuid_from_vm_id(vm_id, **kwargs):
    """

    :param vm_id:
    :param kwargs:
    :return:
    """
    logger.info('get vm for vm_id: %s' % vm_id)
    vm = infra_utils.get_vm_by_id(vm_id)

    # TODO: right now removed cloud_access type from logger.
    # logger.info('client vm %s, name %s ip: %s cloud %s' % (vm, vm.name, vm.ip, config.cloud_access_pb.type))
    logger.info('client vm %s, name %s, ip: %s' % (vm, vm.name, vm.ip))

    # TODO: right now se_name is vm.name but should be either of vm.ip or vm.name depanding on cloud_access type is no_access
    # config = parse_kwargs.get_config_from_kwargs(kwargs) # uses site_name or # config
    # se_name = vm.name if config.cloud_access_pb.type != 'no_access' else vm.ip
    se_name = vm.name

    se_uuid = None
    se_uuid = get_se_uuid_from_name(se_name, **kwargs)
    logger.info('se_uuid : %s' % se_uuid)
    return se_uuid


@logger_utils.aretry(retry=4, delay=2, period=10)
def update_se_segroup_retry(se_uuid, sg_name, count=4, **kwargs):
    """

    :param se_uuid:
    :param sg_name:
    :param count:
    :param kwargs:
    :return:
    """
    update_se_segroup(se_uuid, sg_name, **kwargs)


def move_se_to_segroup(vm_id, sg_name):
    """

    :param vm_id:
    :param sg_name:
    :return:
    """
    try:
        logger.info('move se/vm:%s to segroup:%s' % (vm_id, sg_name))
        se_uuid = get_se_uuid_from_vm_id(vm_id)
        update_se_segroup_retry(se_uuid, sg_name)
    except Exception as e:
        logger.trace("Raised exception: %s" % str(e))
        logger_utils.fail("Raised exception: %s" % str(e))


def verify_se_with_no_vs_attached(segroup_name):
    """

    :param segroup_name:
    :return:
    """
    se_in_group_with_zero_vs = list()
    se_in_group = get_se_in_group(segroup_name)
    for se in se_in_group:
        if len(se['config']['virtualservice_refs']) == 0:
            se_in_group_with_zero_vs.append(se)
            print "se %s has zero vs" % se['uuid']

    num_se_in_group_with_zero_vs = len(se_in_group_with_zero_vs)

    if not num_se_in_group_with_zero_vs:
        logger.debug('SE group[%s]: No se has been found with zero vs' % segroup_name)
        return False
    else:
        return True


def set_se_group_auto_rebalance(sg_name, auto_rebalance=False):
    """

    :param sg_name:
    :param auto_rebalance:
    :return:
    """
    resp_code, json_data = rest.get('serviceenginegroup', name=sg_name)
    json_data['auto_rebalance'] = auto_rebalance
    rest.put('serviceenginegroup', name=sg_name, data=json_data)


def set_se_group_auto_rebalance_interval(sg_name, auto_rebalance_interval):
    """

    :param sg_name:
    :param auto_rebalance_interval:
    :return:
    """
    resp_code, json_data = rest.get('serviceenginegroup', name=sg_name)
    auto_rebalance_interval = int(auto_rebalance_interval)
    json_data['auto_rebalance_interval'] = auto_rebalance_interval
    rest.put('serviceenginegroup', name=sg_name, data=json_data)


def setup_bgp_arista(ip, asnum, peeras, md5=None):
    """

    :param ip:
    :param asnum:
    :param peeras:
    :param md5:
    :return:
    """
    print ("Config of bgp on arista")
    tn = telnetlib.Telnet(ip)
    tn.read_until("Username: ")
    tn.write('admin' + "\n")
    tn.read_until("Password: ")
    tn.write('admin' + "\n")
    tn.write('enable' + "\n")
    tn.read_until('#')
    tn.write('config t' + "\n")
    tn.read_until('#')

    cfg = 'router bgp %d \n' % int(asnum)
    logger.debug(cfg)
    tn.write(cfg)
    tn.read_until('#')

    cfg = "bgp listen range 10.0.0.0/8 peer-group avise remote-as %d\n" % int(peeras)
    logger.debug(cfg)
    tn.write(cfg)
    tn.read_until('#')

    cfg = "neighbor avise peer-group\n"
    logger.debug(cfg)
    tn.write(cfg)
    tn.read_until('#')

    cfg = "neighbor avise fall-over bfd\n"
    logger.debug(cfg)
    tn.write(cfg)
    tn.read_until('#')

    cfg = 'neighbor avise password %s\n' % md5.encode('utf-8')
    logger.debug(cfg)
    tn.write(cfg)
    tn.read_until('#')
    logger_utils.asleep(delay=5)

    cfg = 'maximum-paths 4 ecmp 4 \n'
    logger.debug(cfg)
    tn.write(cfg)
    tn.read_until('#')

    cfg = 'maximum-paths 4 ecmp 4 \n'
    logger.debug(cfg)
    tn.write(cfg)
    tn.read_until('#')
    tn.write('exit' + "\n")
    tn.read_until('#')
    tn.close()


def set_se_vcenter_cluster(sg_name, *cluster_name):
    """

    :param sg_name:
    :param cluster_name:
    :return:
    """
    _, json_data = rest.get('serviceenginegroup', name=sg_name)
    if not json_data.has_key('vcenter_clusters'):
        json_data['vcenter_clusters'] = {
            'include': False,
            'cluster_refs': []
        }
    _, cluster_ref_obj = rest.get('vimgrclusterruntime', name=cluster_name)
    if cluster_ref_obj.get('url') not in json_data['vcenter_clusters'][
        'cluster_refs']:
        json_data['vcenter_clusters']['cluster_refs'].append(
            cluster_ref_obj.get('url'))
        json_data['vcenter_clusters']['include'] = True
    rest.put('serviceenginegroup', name=sg_name, data=json_data)


def set_se_group_key_value(sg_name, key, value):
    """

    :param sg_name:
    :param key:
    :param value:
    :return:
    """
    _, json_se_group_data = rest.get('serviceenginegroup', name=sg_name)
    if json_se_group_data.get('results'):
        json_se_group_data = json_se_group_data['results'][0]
    json_se_group_data[key] = value
    rest.put('serviceenginegroup', name=sg_name, data=json_se_group_data)


def get_se_stats_for_all_cores(se_name, stats_key, **kwargs):
    """

    :param se_name:
    :param stats_key:
    :param kwargs:
    :return:
    """
    _, resp_data = rest.get('serviceengine', name=se_name, path=stats_key,
                            **kwargs)
    return resp_data


def get_interface_mim_stats_for_se(se_name):
    """

    :param se_name:
    :return:
    """
    rsp = get_se_stats_for_all_cores(se_name, 'interface')
    c = 0
    for obj in rsp:
        if 'vnics' in obj:
            d_stats = obj['vnics'][0]
        s = d_stats['interface_stats']
        c += s['rx_mim_etype_p2s']
        c += s['rx_mim_etype_s2p']
        c += s['tx_mim_etype_p2s']
        c += s['tx_mim_etype_s2p']

    return c


def check_bgp_route_arista(ip, vip, ecmp=None):
    """

    :param ip:
    :param vip:
    :param ecmp:
    :return:
    """
    tn = telnetlib.Telnet(ip)
    tn.read_until("Username: ")
    tn.write('admin' + "\n")
    tn.read_until("Password: ")
    tn.write('admin' + "\n")
    tn.write('enable' + "\n")
    tn.read_until('#')
    # Get the correct count of the bgp route - Metric is common for all the bgp route paths
    tn.write('show ip bgp %s | grep metric | wc -l \n' % vip.encode('utf-8'))
    a = tn.read_until('#')
    tn.write('exit' + "\n")
    tn.read_until('#')
    tn.close()
    if ecmp:
        return a.split('\n')[1]
    else:
        return a.split('\n')[1]


def delete_bgp_arista(ip, asnum):
    """

    :param ip:
    :param asnum:
    :return:
    """
    tn = telnetlib.Telnet(ip)
    tn.read_until("Username: ")
    tn.write('admin' + "\n")
    tn.read_until("Password: ")
    tn.write('admin' + "\n")
    tn.write('enable' + "\n")
    tn.read_until('#')
    tn.write('config t' + "\n")
    tn.read_until('#')
    tn.write('no router bgp ' + str(int(asnum)) + '\n')
    tn.read_until('#')
    tn.write('exit' + "\n")
    tn.read_until('#')
    tn.close()


def get_se_processes(vm, **kwargs):
    """
    Get a snapshot of the processes that are running in the Service Engine
    :param vm:
    :param kwargs:
    :return:
    """
    config = infra_utils.get_config()  # uses site_name or config

    _ignore = []
    _add = ['log_core_manager', 'se_dp', 'se_agent', 'se_log_agent',
            'se_supervisor']
    proc_names = [proc for proc in _add if proc not in _ignore]

    procs = {}
    command_str = []
    for proc in proc_names:
        try:
            if infra_utils.get_cloud_context_type() == 'baremetal':
                command_str.append('status %s;' % proc)
            else:
                command_str.append('sudo status %s;' % proc)
        except Exception as e:
            logger_utils.fail("Unexpected error:", e.message)

    try:
        if infra_utils.get_cloud_context_type() == 'baremetal':
            out = vm.execute_on_docker_container(''.join(command_str), upstart_session=True)
            resp = out[vm.ip].splitlines()
        elif infra_utils.get_cloud_context_type() == 'gcp':
            out = vm.execute_on_docker_container(''.join(command_str), upstart_session=True)
            resp = out[vm.vm_public_ip].splitlines()
        else:
            resp = vm.execute_command(''.join(command_str))
        if 'pre-start' in str(resp):
            logger_utils.error('Process is in pre-start: %s' % str(resp))
        logger.info(str(resp))
    except Exception as e:
        # SE might have rebooted and we are reporting a reboot failure
        # so just reset all the processes and core links for VM
        logger_utils.asleep(delay=60)
        vm.processes = {}
        vm.latest_core = None
        logger_utils.fail(
            'Failed to connect to SE: %s, %s' % (vm.ip, e))
    except IndexError as ie:
        # Not a valid job name?
        logger_utils.fail('Process not running on %s. Error: %s' % (vm.ip, ie.message))

    current_proc = None
    try:
        for line in resp:
            for index, proc in enumerate(proc_names):
                current_proc = proc
                if not re.search(proc, line):
                    continue
                pattern = proc + u'[\S\s]+?process\s+(\d+)'
                match = re.search(pattern, line)
                procs[proc] = (int(match.group(1)))
    except AttributeError:
        # If fails to parse output, then match.group raises attribute error
        # In case of crash, sleep for 30 secs to allow process to restart
        # avoiding cascading failures.
        if vm.processes:
            logger_utils.asleep(delay=60)
            return get_se_processes(vm, **kwargs)
        else:
            # The case where SE process not running at all!
            logger_utils.fail(
                'process: %s is not running on SE (%s)!' % (current_proc, vm.ip))
    except IndexError as ie:
        # Job not running or error while capturing output
        logger_utils.fail('Process %s not running on %s. Error: %s' %
                                   (current_proc, vm.ip, str(ie)))
    return procs


def wait_for_all_se_to_connect(**kwargs):
    """

    :param kwargs:
    :return:
    """
    retry_timeout = int(kwargs.get('retry_timeout', 180))
    retry_interval = float(kwargs.get('retry_interval', 2))
    cloud_access = kwargs.get('get_cloud_access', None)

    if retry_timeout == 0:
        calculated_retry_timout = 0
    else:
        calculated_retry_timout = retry_timeout / retry_interval

    for se in infra_utils.get_vm_of_type('se'):
        # Remove call to controller from here. The information is already there
        # in topo_conf. Call to controller hangs when upgrade is in progress.
        if config.cloud_access_pb.type in ['read', 'write']:
            se_name = se.name
        else:
            se_name = se.ip

        # Incase we remove vcenter access and call this function,
        # we must get cloud_access from api
        if cloud_access:
            privilege = get_vcenter_privilege()
            se_name = se.name if privilege != 'NONE' else se.ip

        try:
            common.retry_action_detail(lambda: is_se_connected(se_name),
                                       calculated_retry_timout, retry_interval)
        except Exception as e:
            logger_utils.fail(
                'SE was not connected after retry timeout of %s\nException: %s' %
                (retry_timeout, e))


def get_vcenter_privilege():
    """

    :return:
    """
    status, results = rest.get('systemconfiguration')
    vcenter_configuration = results.get(
        'vcenter_configuration', {'privilege': 'NONE'})
    return vcenter_configuration['privilege']


def start_se(vm):
    """

    :param vm:
    :return:
    """
    retry = 20
    logger.info('execute /opt/avi/scripts/start_se.sh')
    vm.execute_command('/opt/avi/scripts/start_se.sh robot_start_se')
    logger_utils.asleep(delay=30)
    vm.processes.clear()
    while retry > 0:
        try:
            vm.processes = get_se_processes(vm)
        except Exception as e:
            logger.warning(e)
            logger_utils.asleep(delay=5)
            retry -= 1
            continue
        break


def stop_se_no_wait(vm):
    """

    :param vm:
    :return:
    """
    logger.info('execute /opt/avi/scripts/stop_se.sh')
    vm.execute_command('/opt/avi/scripts/stop_se.sh robot_stop_no_wait')
    vm.processes.clear()


def reboot_se_without_stop(se_vm):
    """

    :param se_vm:
    :return:
    """
    se_vm.reboot()


def reconnect_se(vm):
    """

    :param vm:
    :return:
    """
    vm.connect()


def refresh_se_process(vm):
    """

    :param vm:
    :return:
    """
    vm.execute_command('ls')
    vm.processes.clear()
    vm.processes = get_se_processes(vm)


def get_vs_primary_se(vs_name):
    """

    :param vs_name:
    :return:
    """
    _, resp_data = rest.get('virtualservice', name=vs_name, path='runtime')
    logger.info('res data: %s' % resp_data)
    for vip_summary in resp_data['vip_summary']:
        for se in vip_summary['service_engine']:
            if str(se['primary']).lower() == 'true':
                se_url = se['url']
                return get_se_name_from_se_url(se_url)


def vs_get_secondary_se_ip(vs_name, index=0):
    """

    :param vs_name:
    :param index:
    :return:
    """
    try:
        sec_se = vs_lib.vs_get_secondary_se_info(vs_name)
        se = sec_se[int(index)]
        url = se['url']
        se_api = '/'.join(url.split('/')[-2:])
        logger.info(se_api)
        se_data = rest.get(se_api)
        logger.info("secondary se: %s" % se_data[1]['name'])
        return se_data[1]['name']
    except Exception as e:
        logger.info(str(e))


def se_disconnect_cntr(se_vm, cntr_vm):
    """

    :param se_vm:
    :param cntr_vm:
    :return:
    """
    cmd = 'iptables -A OUTPUT -p tcp -j DROP -d ' + se_vm.ip
    logger.info('Executing cmd %s ip %s username %s pwd %s' % (
        cmd, cntr_vm.ip, cntr_vm.user, cntr_vm.password))
    cntr_vm.execute_command(cmd, noerr=False)


def se_reconnect_cntr(se_vm, cntr_vm):
    """

    :param se_vm:
    :param cntr_vm:
    :return:
    """
    if infra_utils.get_cloud_context_type() == 'baremetal':
        logger.info('Trying to reset IP tables in baremetal setup')
    cmd = 'iptables -D OUTPUT -p tcp -j DROP -d ' + se_vm.ip
    logger.info('Executing cmd %s ip %s username %s pwd %s' % (
        cmd, cntr_vm.ip, cntr_vm.user, cntr_vm.password))
    cntr_vm.execute_command(cmd, noerr=False)


def set_se_group_management_network(sg_name, mgmt_network=None):
    """

    :param sg_name:
    :param mgmt_network:
    :return:
    """
    _, json_se_group_data = rest.get('serviceenginegroup', name=sg_name)
    json_se_group_data['mgmt_network_name'] = mgmt_network
    rest.put('serviceenginegroup', name=sg_name, data=json_se_group_data)


def reset_se_process(vm_id=None):
    """

    :param vm_id:
    :return:
    """
    for vm in infra_utils.get_vm_of_type('se'):
        logger.info('vm_id: %s' % vm_id)
        logger.info('vm.name: %s' % vm.name)
        if vm_id:
            if vm.name != vm_id:
                continue
        vm.processes.clear()
        vm.processes = get_se_processes(vm)


def set_se_group_openstack_availability_zones(sg_name):
    """

    :param sg_name:
    :return:
    """
    from lib.vcenter_lib import cloud_get_all_az
    azs = cloud_get_all_az()
    if not azs:
        return

    _, json_se_group_data = rest.get('serviceenginegroup', name=sg_name)
    json_se_group_data['openstack_availability_zones'] = azs
    rest.put('serviceenginegroup', name=sg_name, data=json_se_group_data)


def set_se_group_instance_flavour(sg_name, instance_flavor=None):
    """
    Set instace flavor of se group
    :param sg_name:
    :param instance_flavor:
    :return:
    """
    _, json_se_group_data = rest.get('serviceenginegroup', name=sg_name)
    if instance_flavor:
        json_se_group_data['instance_flavor'] = instance_flavor
    rest.put('serviceenginegroup', name=sg_name, data=json_se_group_data)


def set_se_group_aws_instance_flavour(sg_name, instance_flavor=None):
    """
    Set instace flavor of se group only if aws cloud
    :param sg_name:
    :param instance_flavor:
    :return:
    """
    if infra_utils.get_cloud_context_type() != 'aws':
        logger.debug('Cannot configure instance flavour for non-AWS cloud SG:%s' % sg_name)
        return
    set_se_group_instance_flavour(sg_name, instance_flavor=instance_flavor)
    logger.debug('Instance flavour:%s set for AWS cloud SG:%s' % (instance_flavor, sg_name))


def set_se_group_algo_distributed(sg_name):
    """

    :param sg_name:
    :return:
    """
    _, json_se_group_data = rest.get('serviceenginegroup', name=sg_name)
    if json_se_group_data.get('results'):
        json_se_group_data = json_se_group_data['results'][0]
    json_se_group_data['algo'] = 'PLACEMENT_ALGO_DISTRIBUTED'
    rest.put('serviceenginegroup', name=sg_name, data=json_se_group_data)


def get_se_az(se_uuid):
    """

    :param se_uuid:
    :return:
    """
    _, se_info = rest.get('serviceengine', uuid=se_uuid)
    return se_info.get('availability_zone', '')


def is_se_vnic_disconnected(se_name):
    """

    :param se_name:
    :return:
    """
    se_data = get_se_info(se_name=se_name)
    for data_vnics in se_data.get('data_vnics', []):
        if not (data_vnics['connected'] == False or data_vnics['network_name'] == 'Avi Internal'):
            logger_utils.fail("SE[%s] vnic is not disconnected" % se_name)
    return True


def wait_for_se_vnic_to_disconnect(se_name, **kwargs):
    """

    :param se_name:
    :param kwargs:
    :return:
    """
    retry_timeout = int(kwargs.get('retry_timeout', 480))

    @logger_utils.aretry(retry=retry_timeout/20, delay=20)
    def retry_action():
        return is_se_vnic_disconnected(se_name)
    return retry_action()


def set_se_group_algo_packed(sg_name):
    """

    :param sg_name:
    :return:
    """
    _, json_se_group_data = rest.get('serviceenginegroup', name=sg_name)
    if json_se_group_data.get('results'):
        json_se_group_data = json_se_group_data['results'][0]
    json_se_group_data['algo'] = 'PLACEMENT_ALGO_PACKED'
    rest.put('serviceenginegroup', name=sg_name, data=json_se_group_data)


def set_se_group_legacy_as(sg_name):
    """

    :param sg_name:
    :return:
        """
    _, json_se_group_data = rest.get('serviceenginegroup', name=sg_name)
    if json_se_group_data.get('results'):
        json_se_group_data = json_se_group_data['results'][0]
    json_se_group_data['ha_mode'] = 'HA_MODE_LEGACY_ACTIVE_STANDBY'
    json_se_group_data['max_vs_per_se'] = 10
    json_se_group_data['active_standby'] = True
    rest.put('serviceenginegroup', name=sg_name, data=json_se_group_data)


def move_se_to_segroup_by_uuid(se_uuid, sg_name, **kwargs):
    """

    :param se_uuid:
    :param sg_name:
    :param kwargs:
    :return:
    """
    update_se_segroup_retry(se_uuid, sg_name, **kwargs)


def limit_se_group_count(se_group, se_count, dummy_grp):
    """

    :param se_group:
    :param se_count:
    :param dummy_grp:
    :return:
    """
    se_list = get_se_list_in_group(se_group)
    if len(se_list) <= int(se_count):
        logger.info('SE list count %d Expected SE count %d' % (len(se_list),
                                                               int(se_count)))
        return

    for se_uuid in se_list[int(se_count):]:
        move_se_to_segroup_by_uuid(se_uuid, dummy_grp)


def set_se_group_distribute_active_standby_load(sg_name, distribute_load=False):
    """
    Set distribute active-standby load of se group and it is False by default
    :param sg_name:
    :param distribute_load:
    :return:
    """
    _, json_se_group_data = rest.get('serviceenginegroup', name=sg_name)
    if json_se_group_data.get('results'):
        json_se_group_data = json_se_group_data['results'][0]
    json_se_group_data['distribute_load_active_standby'] = distribute_load
    rest.put('serviceenginegroup', name=sg_name, data=json_se_group_data)


def get_se_runtime_detail(se_uuid):
    """

    :param se_uuid:
    :return:
    """
    _, se_runtime = rest.get('serviceengine', uuid=se_uuid,
                                             path='runtime/detail')
    if not se_runtime:
        logger.info('ERROR! data NULL for API serviceengine/uuid=%s',
                          se_uuid)
        logger_utils.fail('ERROR! data NULL for API  serviceengine/uuid=%s',
                          se_uuid)
    return se_runtime


def validate_se_tags(se_name, tags=[]):
    """
    Validate SE Active Standby tags
    :param se_name:
    :param tags:
    :return:
    """
    se_uuid = get_se_uuid_from_name(se_name)
    data = get_se_runtime_detail(se_uuid)
    tags_found = []
    if 'active_tags' in data:
        for tag in data['active_tags']:
            tags_found.append(tag)
    if set(tags) != set(tags_found):
        logger_utils.fail('Expected Tags %s Found Tags %s on SE %s' % (tags,
                                                                       tags_found, data['name']))


def validate_se_tags_count(se_name, tags=[]):
    """
    Validate # of SE tags
    :param se_name:
    :param tags:
    :return:
    """
    se_uuid = get_se_uuid_from_name(se_name)
    data = get_se_runtime_detail(se_uuid)
    tags_found = []
    if 'active_tags' in data:
        for tag in data['active_tags']:
            tags_found.append(tag)
    if len(tags) != len(tags_found):
        logger_utils.fail('Expected #Tags %d Found #Tags %d on SE %s' % (len(
            tags), len(tags_found), data['name']))


def set_se_group_auto_redistribute_active_standby_load(sg_name, auto_redistribute=False):
    """
    Set auto redistribute of se group and it is False by default
    :param sg_name:
    :param auto_redistribute:
    :return:
    """
    _, json_se_group_data = rest.get('serviceenginegroup', name=sg_name)
    if json_se_group_data.get('results'):
        json_se_group_data = json_se_group_data['results'][0]
    if auto_redistribute:
        json_se_group_data['auto_redistribute_active_standby_load'] = auto_redistribute
    rest.put('serviceenginegroup', name=sg_name, data=json_se_group_data)


def se_group_redistribute_action(se_grp_name):
    """

    :param se_grp_name:
    :return:
    """
    resp_code, resp_data = rest.post('serviceenginegroup', name=se_grp_name,
                                      path='redistribute')
    logger_utils.asleep(delay=20)
    return resp_code


def set_se_group_cpu(sg_name="Default-Group", value=2):
    """

    :param sg_name:
    :param value:
    :return:
    """
    _, json_se_group_data = rest.get('serviceenginegroup', name=sg_name)
    if json_se_group_data.get('results'):
        json_se_group_data = json_se_group_data['results'][0]
    json_se_group_data['vcpus_per_se'] = value
    rest.put('serviceenginegroup', name=sg_name, data=json_se_group_data)


def set_se_group_disk(sg_name="Default-Group", value=10):
    """

    :param sg_name:
    :param value:
    :return:
    """

    _, json_se_group_data = rest.get('serviceenginegroup', name=sg_name)
    if json_se_group_data.get('results'):
        json_se_group_data = json_se_group_data['results'][0]
    json_se_group_data['disk_per_se'] = value
    rest.put('serviceenginegroup', name=sg_name, data=json_se_group_data)


def set_se_group_memory(sg_name="Default-Group", value=2048):
    """

    :param sg_name:
    :param value:
    :return:
    """
    _, json_se_group_data = rest.get('serviceenginegroup', name=sg_name)
    if json_se_group_data.get('results'):
        json_se_group_data = json_se_group_data['results'][0]
    json_se_group_data['memory_per_se'] = value
    rest.put('serviceenginegroup', name=sg_name, data=json_se_group_data)


def verify_se_disk(se_name, disk):
    """

    :param se_name:
    :param disk:
    :return:
    """
    disk = int(disk)
    se_info = get_se_info(se_name=se_name)
    se_disk = se_info['resources']['disk']
    # Allow 10% tolerance
    if 0.9 * disk < se_disk < 1.1 * disk:
        pass
    else:
        logger_utils.fail('SE disk size expected %d got %d' % (disk, se_disk))


def get_se_httpstats(se_name=None, se_uuid=None):
    """
    This function does get SE HTTP Stats
    Args:
        :param se_name: Service Engine name
        :type se_name: str
        :param se_uuid: Service Engine UUID
        :type se_uuid: str
    Returns:
        httpstats data
    Raises:
        ValueError, AttributeError, KeyError
    """
    if not se_name and not se_uuid:
        logger_utils.fail("Need SE Name or UUID to get SE info.")

    status_code, data = rest.get('serviceengine', name=se_name, uuid=se_uuid, path='httpstats')
    return data[0]


def set_se_rate_limit_properties(**kwargs):
    """
    This function does get SE Rate Limit Properties
    Args:
        :param se_name: Service Engine name
        :type se_name: str
        :param se_uuid: Service Engine UUID
        :type se_uuid: str
    Returns:
        httpstats data
    Raises:
        ValueError, AttributeError, KeyError
    """
    se_rate_limiters = dict()
    if kwargs.get('icmp_rl', None):
        se_rate_limiters['icmp_rl'] = kwargs.pop('icmp_rl')
    if kwargs.get('icmp_rsp_rl', None):
        se_rate_limiters['icmp_rsp_rl'] = kwargs.pop('icmp_rsp_rl')
    if kwargs.get('arp_rl', None):
        se_rate_limiters['arp_rl'] = kwargs.pop('arp_rl')
    if kwargs.get('rst_rl', None):
        se_rate_limiters['rst_rl'] = kwargs.pop('rst_rl')
    if kwargs.get('flow_probe_rl', None):
        se_rate_limiters['flow_probe_rl'] = kwargs.pop('flow_probe_rl')
    if kwargs.get('default_rl', None):
        se_rate_limiters['default_rl'] = kwargs.pop('default_rl')

    seproperties = dict()
    seproperties['se_runtime_properties'] = dict()
    seproperties['se_runtime_properties']['se_rate_limiters'] = se_rate_limiters

    rest.put('seproperties', data=seproperties)


def get_se_group_info(sg_name):
    """
    This function does get the se group data

    Args:
        : segroup name

    Returns:
        : se group get data
    """
    resp_code, json_data = rest.get('serviceenginegroup', name=sg_name)
    logger.info('sg uuid:%s' % json_data['uuid'])
    return json_data


def get_se_scaleout_hb_stats(se_uuid):
    status_code, json_data = rest.get('serviceengine', uuid=se_uuid, path='sevshbstats')
    hb_count = 0
    for core_data in json_data:
        for hb_stat in core_data.get('se_vs_hb_stat_entry', []):
            hb_count += int(hb_stat.get('se_num_hb_v1_rqs_sent', 0)) +\
                        int(hb_stat.get('se_num_hb_v1_rsps_sent', 0))
    return hb_count

def set_se_group_scaleout_timeout(sg_name='Default-Group', timeout=30):
    """
    This function sets the vs_scaleout_timeout attribute
    :param sg_name: Service Engine Group Name
    :param timeout: timeout to set in seconds
    :return:
    Raises:
        ValueError, AttributeError, KeyError
    """
    logger.info('Setting Service Engine Group [name]: %s, \
                    vs_scaleout_timeout : %d ' % (sg_name, timeout))
    set_se_group_properties(sg_name, number=int(timeout),
                            vs_scaleout_timeout='vs_scaleout_timeout')


def reboot_se_vm_by_name(se_name, **kwargs):
    """ Reboot SE for given se name"""
    se_vms = infra_utils.get_vm_of_type('se')
    for se in se_vms:
        if se_name == se.name:
            reboot_se(se, **kwargs)

def move_all_se_to_group(se_group, **kwargs):
    """
    This function does Move all ses to se group

    Args:
        : segroup name
    Returns:
        None
    """
    se_list = get_all_se_uuid(**kwargs)
    for se_uuid in se_list:
        update_se_segroup(se_uuid, se_group, **kwargs)

def se_get_data_vnic_nw_uuid(se_name):
    se_info = get_se_info(se_name)
    nw_list = []
    if se_info.get('data_vnics'):
        for vnic in se_info['data_vnics']:
            ref = vnic['network_ref'].split('/')
            uuid = ref[len(ref) - 1]
            if str(vnic['connected']).lower() == 'false':
                logger.debug('%s: not connected' % uuid)
                continue
            nw_list.append(uuid)
    return nw_list


def set_se_group_async_ssl(sg_name, async_ssl=True, **kwargs):
    status_code, resp = rest.get('serviceenginegroup?name=%s' % sg_name)
    json_data = resp['results'][0]

    json_data["async_ssl"] = async_ssl
    status_code, resp = rest.put('serviceenginegroup/%s' % json_data['uuid'], data=json.dumps(json_data))

def get_se_ips_from_se_grp(segrp_name):
    api = 'serviceengine?se_group_ref.name=%s' % segrp_name
    status_code, json_data = rest.get(api)
    se_ips = [se_data['mgmt_vnic']['vnic_networks'][0]['ip']['ip_addr']['addr'] for se_data in json_data['results']]
    return se_ips

def get_data_vnic_se_ip(se_name, network_name):
    params = {'se_connected': True}
    if se_name:
        params['name'] = se_name
    status_code, se_list = rest.get('serviceengine', params=params)
    for data_vnic in se_list['results'][0]['data_vnics']:
        if data_vnic['network_name'] == network_name:
            return data_vnic['vnic_networks'][0]['ip']['ip_addr']['addr']

def set_se_bootup_properties(**kwargs):
    """This function does Set SE bootup Properties
    Kwargs:
        :param uuid:
        :type uuid: dict
    Returns:
        None
    Raises:
        ValueError, AttributeError, KeyError
    """
    status_code, resp = rest.get('seproperties')

    se_bootup_props = dict()
    se_bootup_props = resp['se_bootup_properties']
    logger.info('Before SE Bootup Properties:\n %s ' % se_bootup_props)

    se_bootup_props.update(kwargs)
    resp['se_bootup_properties'] = se_bootup_props
    logger.info('After SE Bootup Properties:\n %s ' % se_bootup_props)
    status_code, resp = rest.put('seproperties', data=json.dumps(resp))


def get_latest_core_link(vm):
    cmd = "ls -l /var/lib/avi/archive/last.bundle.tar.gz | awk '{print $11}'"
    resp = vm.execute_command(cmd)
    if len(resp) > 0 and not re.search('No such file or directory', resp[0]):
        return resp[0].strip('\n')
    return None
