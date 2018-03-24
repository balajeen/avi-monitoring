import json
from urlparse import urlparse

from avi_objects.avi_config import (AviConfig, get_vm_cloud_sdk, read_version,
                                    get_vm_and_cloud_json)
from netaddr import IPNetwork, IPAddress

from config_manager import (get_parsed_json, get_import_objs,
                            get_delete_objs, get_parsed_json_cloud)
from logger import logger
from avi_objects.logger_utils import aretry, asleep, error, fail
from rest import (put, post, get, delete, import_config,
                  get_cloud_context, get_cloud_type,
                  update_admin_user, get_name_from_ref)
from config_manager import (get_parsed_json, get_import_objs,
                            get_delete_objs, get_parsed_json_cloud)
from avi_objects.cluster import setup_cluster
from suite_vars import suite_vars
from vm import Se

objs = {}

def switch_mode(**kwargs):

    config = get_config()
    config.switch_mode(**kwargs)

def switch_mode_default(**kwargs):
    """" Set the default values to the switch mode variables"""
    config = get_config()
    kwargs = {'tenant': 'admin',
              'user': 'admin',
              'version': read_version(),
              'vrfcontext': 'global',
              'site_name': 'default',
              'cloud': 'Default-Cloud',
              'password': 'avi123',
              'session': None}
    config.switch_mode( **kwargs)

def get_vm_of_type(vm_type, site_name=None, network=None, state=None):

    config = get_config()
    if vm_type.lower() == 'se':
        return get_se_vm(state=state)
    else:
        return config.get_vm_of_type(vm_type, site_name=site_name, network=network)

def match_subnet(vip, network_ip, subnet):
    logger.debug("subnet check "+str(vip)+str(network_ip)+'/'+str(subnet))
    if IPAddress(str(vip)) in IPNetwork(str(network_ip)+'/'+str(subnet)):
        return True
    else:
        return False

def get_network_name(vip):
    config = get_config()
    logger.debug(config.testbed[config.site_name].networks)
    for net_name, network in config.testbed[config.site_name].networks.items():
        if match_subnet(vip, network.ip_addr, network.mask) == True:
            return net_name
    return None

def get_testbed_variable(variable=None):
    '''
    params: takes variable name which is in testbed
    return: Returns variable value which is mentioned in 'Variables' section in testbed
    '''
    config = get_config()
    if variable:
        return config.testbed[config.site_name].testbed_vars.get(variable)
    else:
        return config.testbed[config.site_name].testbed_vars

def get_vm_by_id(vm_id=None):
    config = get_config()
    return config.get_vm_by_id(vm_id=vm_id)

def get_vm_by_ip(vm_ip=None):
    config = get_config()
    return config.get_vm_by_ip(vm_ip=vm_ip)

def get_client_vm(vm_id=None, **kwargs):
    ''' Returns VM object for client vm'''
    try:
        if vm_id:
            return get_vm_by_id(vm_id)
        return get_vm_of_type('client')[0]
    except Exception:
        fail("ERROR! Did not find a client vm")

def get_se_vm(se_name=None, se_uuid=None, state=None, **kwargs):
    """ Helps to the SE VM Object """

    mgmt_addr_type = kwargs.get('mgmt_addr_type', 'V4')
    if se_name or se_uuid:
        status_code, resp = get('serviceengine', name=se_name, uuid=se_uuid)
        resp = [resp]
    else:
        status_code, resp = get('serviceengine')
        if not resp:
            logger.debug('No SEs found')
            return []
        resp = resp['results']
    vms = []
    for each_se in resp:
        stc, res = get('serviceengine', uuid=each_se['uuid'], path='runtime')
        if state and state != res["oper_status"]["state"]:
            logger.debug("SE found but not in expected state")
            continue
        se_kwargs = {}
        #Get IP
        ip = ""
        if 'vnic_networks' not in each_se['mgmt_vnic']:
            name = each_se['name']
            oper_state = res['oper_status']['state']
            logger.warning('Cannot retrieve mgmt details for SE name=%s oper_state=%s', name, oper_state)
            continue
        for vnic in each_se['mgmt_vnic']['vnic_networks']:
            if vnic['mode'] in ['DHCP', "STATIC"]:
                if mgmt_addr_type == vnic['ip']['ip_addr']['type']:
                    ip = vnic['ip']['ip_addr']['addr']
        if not ip:
            fail("Could not retrieve Management IP of Se")
        name = each_se['name']
        #Get Deployment
        if each_se['container_mode']:
            deployment = 'docker'
            se_kwargs['user'] = 'root'
        else:
            deployment = 'vm'
        #Get Platform
        cloud_ref = each_se['cloud_ref']
        url_parsed = urlparse(cloud_ref)
        cloud_uuid = url_parsed.path.split('/')[-1]
        status_code, cloud_details = get('cloud', uuid=cloud_uuid)
        vtype = cloud_details['vtype']
        if vtype == 'CLOUD_VCENTER':
            platform = 'vcenter'
        elif vtype == 'CLOUD_OPENSTACK':
            platform = 'openstack'
        elif vtype == 'CLOUD_AWS':
            platform = 'aws'
        elif vtype == 'CLOUD_MESOS':
            platform = 'mesos'
        elif vtype == 'CLOUD_LINUXSERVER':
            if 'ipam_provider_ref' in cloud_details:
                ipam_ref = cloud_details['ipam_provider_ref']
                url_parsed = urlparse(ipam_ref)
                ipam_uuid = url_parsed.path.split('/')[-1]
                status_code, ipam_details = get('ipamdnsproviderprofile', uuid=ipam_uuid)
                if ipam_details['type'] == 'IPAMDNS_TYPE_AZURE':
                    platform = 'azure'
                elif ipam_details['type'] == 'IPAMDNS_TYPE_GCP':
                    platform = 'gcp'
            else:
                platform = 'baremetal'
        else:
            platform = None
        vms.append(Se(ip=ip, name=name, deployment=deployment, platform=platform, **se_kwargs))
    return vms


def get_mode():

    config = get_config()
    return config.get_mode()

def initialize_testbed():
    config = get_config()
    mode = config.get_mode()
    logger.debug("Current Default Mode %s" %mode)
    for testbed in config.testbed:
        logger.info("Updating password for site %s" %testbed)
        username = mode['user']
        password = mode['password']
        switch_mode(site_name=testbed)
        update_admin_user(username = username, password = password)
    switch_mode(**mode)
    setup_cluster()

# TODO/Enhancements:
# We should be able to create cloud if there is no cloud present by that name.
# Basically, we should be able to use the try/except block below.
# Tried this with by passing check_status_code=False which seems to fix the issue
# But the later check_cloud_status seems to fail to get the data.
def setup_cloud(wait_for_cloud_ready=True, config_file=None):

    if suite_vars.skip_cloud_config:
        logger.info("Skipping cloud config as skip_cloud_config is set to True")
        return
    setup_tb_configuration(pre=True)
    config = get_config()
    ctrl_clouds =  config.testbed[config.site_name].cloud
    if config_file:
        config_clouds = get_parsed_json_cloud(config_file)
        if ctrl_clouds:
            ctrl_clouds.append(config_clouds)
        else:
            ctrl_clouds = config_clouds
    if ctrl_clouds:
        for cloud in ctrl_clouds:
            logger.debug('cloud data %s' %cloud)
            name = cloud['name']
            logger.info("Setting Cloud: %s" %name)
            logger.debug("Setting Cloud with %s" %cloud)
            vtype = cloud['vtype']
            if vtype == 'CLOUD_AWS':
                config = get_config()
                tb_name = config.testbed[config.get_mode(key='site_name')].name
                cloud['custom_tags'] = [{'tag_key': 'avitest_tb_tag', 'tag_val' : tb_name}]
            try:
                status_code, data = put('cloud', name=name, data=json.dumps(cloud), check_status_code=False)
            except:
                status_code, data = post('cloud', data=json.dumps(cloud))
            logger.debug("Received for cloud create: %s" %status_code)

            if cloud['vtype'] == "CLOUD_VCENTER":
                setup_vcenter_cloud_mgmt_network(cloud)

    if wait_for_cloud_ready and ctrl_clouds:
        check_cloud_state(clouds = ctrl_clouds)
    setup_tb_configuration()

def setup_vcenter_cloud_mgmt_network(cloud):
    states = ['VCENTER_DISCOVERY_COMPLETE_NO_MGMT_NW',
              'VCENTER_DISCOVERY_COMPLETE',
              'VCENTER_DISCOVERY_WAITING_DC',
              'VCENTER_DISCOVERY_ONGOING']
    wait_for_vcenter_state(cloud['name'], states)
    logger.debug('Configure cloud management network: %s' %cloud)
    mgmt_name = cloud['vcenter_configuration']['management_network']
    cloud['vcenter_configuration']['management_network'] = \
                        'vimgrruntime?name=%s' %mgmt_name
    status_code, data = put('cloud', name=cloud['name'], data=json.dumps(cloud))

@aretry(retry=20, delay=60, period=10)
def wait_for_vcenter_state(cloud_name, exp_states):
    status_code, data = get('vimgrvcenterruntime')
    logger.debug('wait_for_vcenter_state data: %s' %data)
    if data['count'] == 0:
        error('Inventory is not complete')
    state = data['results'][0]['inventory_state']

    if state in exp_states:
        return True
    else:
        error('Check for state %s one more time got %s' %(exp_states, state))

@aretry(retry=20, delay=60, period=10)
def check_cloud_state(expected_status='CLOUD_STATE_PLACEMENT_READY', **kwargs):
    cloud_name = kwargs.get('cloud_name', None)
    # config = get_config()
    # ctrl_clouds =  kwargs.get('clouds', config.testbed[config.site_name].cloud)
    asleep(msg='waiting for cloud state', delay=10)
    status_code, resp_json = get('cloud-inventory')
    #resp_json = resp.json()
    #if len(ctrl_clouds) != int(resp_json['count']):
    #    error("Number of Configured Clouds not as Received. Configured=%s Received=%s" %(len(ctrl_clouds), resp_json['count']))
    for cloud_obj in resp_json['results']:
        if cloud_name and cloud_name != cloud_obj['config']['name']:
            continue
        if 'error' in cloud_obj['status']:
            error('Received Error in cloud status %s' %cloud_obj['status']['error'])
        cloud_status = cloud_obj['status']['state']
        last_reason = cloud_obj['status'].get('reason', '')
        # To handle special? case where cloud is up but about to be reconfigured
        # REVIEW any other reasons that we need to account for?
        if cloud_status != expected_status or 'Pending re-config' in last_reason:
            if cloud_obj['config']['vtype']=='CLOUD_AWS':
                asleep("additional delay for AWS cloud", delay=30)
            error('Cloud Status is not as expected or reason not null.  Expected=%s Received=%s, reason = %s',
                  expected_status, cloud_status, last_reason)
    return True

def setup_tb_configuration(pre=False):
    config = get_config()
    if pre:
        config_type = "pre"
        ctrl_config = config.testbed[config.site_name].pre_configuration
    else:
        ctrl_config = config.testbed[config.site_name].configuration
        config_type = "post"
    if ctrl_config:
        logger.info("Setting %s Configuration" %config_type)
        logger.debug("Setting Configuration with data %s" %ctrl_config)
        status_code, resp = import_config(configuration=ctrl_config)
        logger.debug("Received for Controller Config: %s" %status_code)

def setup_pool_server(pools = []):
    config = get_config()
    context_key = config.get_context_key()
    for pool, pool_obj in config.site_objs[context_key]['pool'].items():
        if pool in pools:
            for key, server in pool_obj.servers.items():
                server.createAppServers()

def process_cloud_specific_data(json_data, operation):
    cloud_type, configuration = get_cloud_type(get_configuration=True)

    # Extracts users and tenants from Openstack
    if cloud_type == 'openstack':
        tenant_data = json_data.pop('Tenant', {})
        user_data = json_data.pop('User', {})

        # REVIEW is there a more elegant way to populate this? from the tb perhaps?
        cloud_json = {}
        cloud_json['vtype'] = 'CLOUD_OPENSTACK'
        cloud_json['name'] = get_cloud_context()
        cloud_json['openstack_configuration'] = configuration
        os_sdk = get_vm_cloud_sdk(cloud_json=cloud_json, vm_json=None)
        os_sdk.process_openstack_data(tenant_data, user_data, operation=operation)
    else:
        logger.debug('Cloud type is %s, nothing to be done' %cloud_type)


def create_config(config_file, timeout=120, config_vars={}, config_vars_file=None, config_backend_servers=True):
    if suite_vars.skip_create_config:
        logger.info("Skipping create config as skip_create_config is set to True")
        return

    config = get_config()
    cloud = config.get_mode(key='cloud')
    json_data, config_vars = get_parsed_json(config_file, config_vars=config_vars, config_vars_file=config_vars_file)
    process_cloud_specific_data(json_data, operation='create')
    import_data, objects_imported = get_import_objs(json_data, config_vars)
    logger.debug('json_data=%s, objects_imported=%s' % (import_data, objects_imported))

    #switch_mode(cloud=None)
    status_code, resp = import_config(configuration=import_data, timeout=timeout)
    logger.info("Received Response %s" %status_code)
    switch_mode(cloud=cloud)
    if config_backend_servers and 'Pool' in objects_imported:
        setup_pool_server_configs(objects_imported['Pool'])

    return objects_imported

def delete_config(config_file, ignore_deleted=False):
    """
    Delete the objects in the given json config file.
    :param ignore_deleted: if true, do not raise an error if already deleted;
        e.g. objects may have already been deleted when running delete twice
    """
    if suite_vars.skip_delete_config:
        logger.info("Skipping delete config as skip_delete_config is set to True")
        return
    logger.info('Deleting from config %s' % config_file)
    json_data, _ = get_parsed_json(config_file)
    process_cloud_specific_data(json_data, operation='delete')
    obj_type_name_list = get_delete_objs(json_data)
    config = get_config()
    cloud = config.get_mode(key='cloud')
    for obj_type_name in obj_type_name_list:
        obj_type = obj_type_name[0].lower()
        obj_name = obj_type_name[1]
        switch_mode(cloud=None)
        if obj_type in ['vsvip']:
            check_status_code = False
        else:
            check_status_code = not ignore_deleted
        cloud_name = get_cloud_name_from_obj(obj_type, name=obj_name, check_status_code=check_status_code)
        logger.info('Deleting %s name=%s in cloud %s' %(obj_type, obj_name, cloud_name))
        switch_mode(cloud=cloud_name)
        delete(obj_type, name=obj_name, check_status_code=check_status_code)
    switch_mode(cloud=cloud)

def setup_pool_server_configs(pools=[]):

    config = get_config()
    mode = get_mode()
    context_key = config.get_context_key()
    site_name = mode['site_name']
    logger.info('setup_pool_server_configs %s' %site_name)
    setup_pool_server(pools)
    httptest_vm = []
    proxyprototest_vm = []
    fwd_proxy_vm = []
    siptest_vm = []
    servers = {}
    for pool in pools:
        pool_obj = config.site_objs[context_key]['pool'][pool]
        servers.update(pool_obj.get_all_servers())
    for handle, server in servers.items():
        if server.app_type() in ['httptest', 'policytest']:
            if not server.vm() in httptest_vm:
                httptest_vm.append(server.vm())
        elif server.app_type() in ['proxy_proto_test']:
            if not server.vm() in proxyprototest_vm:
                proxyprototest_vm.append(server.vm())
        elif server.app_type() in ['fwd_proxy']:
             if not server.vm() in fwd_proxy_vm:
                 fwd_proxy_vm.append(server.vm())
        elif server.app_type() in ['sip']:
            if not server.vm() in siptest_vm:
                siptest_vm.append(server.vm())
        else:
            server.pushBackendConfigs()

    for vm in httptest_vm:
        vm.create_server_context_ip_addrs()
        vm.reload_server_context_nginx(restart=True)
        vm.check_if_servers_up()

    for vm in proxyprototest_vm:
        vm.create_server_context_ip_addrs()
        vm.load_server_context_haproxy_vsftpd()

    for vm in fwd_proxy_vm:
        vm.create_server_context_ip_addrs()
        vm.reload_server_context_apache(restart=True)

    for vm in siptest_vm:
        vm.create_server_context_ip_addrs()

def get_cloud_name_from_obj(obj_type, name=None, uuid=None, **kwargs):

    status_code, resp = get(obj_type, name=name, uuid=uuid, **kwargs)
    cloud_ref = resp.get('cloud_ref', None)
    if cloud_ref:
        return get_name_from_ref(cloud_ref, **kwargs)
    return None

def get_cloud_context_type():

    config = get_config()
    site_name = config.get_mode(key='site_name')
    cloud_name = config.get_mode(key='cloud')
    cloud_type = None
    cloud_type = config.testbed[site_name].cloud_obj[cloud_name].type
    if cloud_type:
        cloud_type = cloud_type.lower()
    return cloud_type

def get_server_by_handle(handle):
    """ Function helps to get the Server for given Server Handle """
    logger.debug('Server handle: %s' % handle)
    config = get_config()
    context_key = config.get_context_key()
    from avi_objects.pool import ServerModel
    server = ServerModel.handle_dict[context_key].get(handle,None)
    if server:
        return server
    else:
        fail('Server handle "%s" does not exist' % handle)

def get_all_server_handle():
    """ Function helps to get the all the Server Handle """
    config = get_config()
    context_key = config.get_context_key()
    from avi_objects.pool import ServerModel
    servers = ServerModel.handle_dict[context_key].keys()
    logger.debug('Server handle list: %s' % servers)
    return servers

def get_config():
    """ API helps to get the config Object """
    config = AviConfig.get_instance()
    return config


def get_se_vm_by_ip(ip):
    """

    :param ip:
    :return:
    """
    for vm in get_vm_of_type('se'):
        if vm.ip == ip or vm.name == ip:
            return vm
    return None


def include(cloud_list=None):
    '''A decorator to include the function to run on the desired cloud orchestrator '''
    if type(cloud_list) == type(''):
        cloud_list = [cloud_list]
    cloud_context = get_cloud_context_type()
    def outer(func):
        def inner(*args, **kwargs):
            if cloud_context in cloud_list:
                return func(*args, **kwargs)
            else:
                logger.info("Excluding %s for cloud %s" %(func.__name__, cloud_context))
        return inner
    return outer

def exclude(cloud_list=None):
    '''A decorator to include the function to run on the desired cloud orchestrator '''
    if type(cloud_list) == type(''):
        cloud_list = [cloud_list]
    cloud_context = get_cloud_context_type()
    def outer(func):
        def inner(*args, **kwargs):
            if cloud_context not in cloud_list:
                return func(*args, **kwargs)
            else:
                logger.info("Excluding %s for cloud %s" %(func.__name__, cloud_context))
        return inner
    return outer


def get_network_ip_by_handle(net_handle):
    config = get_config()
    ip = config.testbed[config.site_name].networks_json[net_handle]['ip']
    return ip


def setup_json_config(config_file):
    with open(config_file, 'r') as f:
        obj_types = json.load(f)

    for obj_type in obj_types:
        objs[obj_type.upper()] = obj_types[obj_type]
    return obj_types


def read_from_json_config(obj_type, obj_name):
    if obj_type.upper() not in objs or obj_name not in objs[obj_type.upper()]:
        raise RuntimeError('Object not found in json file: type:%s name:%s' %
                        (obj_type, obj_name))
    return objs[obj_type.upper()][obj_name]

def get_vm_cloud_sdkconn(vm_name):
    config = get_config()
    site_name = config.get_mode(key='site_name')

    tb_json = config.testbed[site_name].tb_json
    vm_json, cloud_json = get_vm_and_cloud_json(vm_name, tb_json)
    vm_cloud_sdk_conn = get_vm_cloud_sdk(cloud_json=cloud_json, vm_json=vm_json)

    if not vm_cloud_sdk_conn:
        error('Expected non-None vm_cloud_sdk_conn for vm %s' %vm_name)

    return vm_cloud_sdk_conn


def get_vm_cloud_type(vm_name):
    config = get_config()
    site_name = config.get_mode(key='site_name')
    tb_json = config.testbed[site_name].tb_json

    vm_json, cloud_json = get_vm_and_cloud_json(vm_name, tb_json)

    cloud_name = cloud_json['name']
    cloud_type = cloud_json['vtype']

    logger.info('The cloud is %s of type %s for vm %s' \
                    %(cloud_name, cloud_type, vm_name))
    return cloud_type

def clear_session(all_sessions=False):
    get_config().clear_session(all_sessions)

def get_cloud_sdkconn():
    config = get_config()
    site_name = config.get_mode(key='site_name')
    cloud_name = config.get_mode(key='cloud')
    tb_json = config.testbed[site_name].tb_json
    cloud_json = None
    logger.info('get_cloud_sdkconn for %s' %cloud_name)

    try:
        cloud_json = [cloud_json for cloud_json in tb_json.get('Cloud') \
                if cloud_json.get('name') == cloud_name][0]
    except TypeError:
        logger.info('Must be no-access cloud?')
    except IndexError:
        logger.info("Couldn't find a cloud matching name: %s" %cloud_name)

    if not cloud_json:
        cloud_json = None #Setting it back to None as it must have become an empty list
        try:
            # Check in vm clouds
            cloud_json = [cloud_json for cloud_json in tb_json.get('VmCloud') \
                if cloud_json.get('name') == cloud_name][0]
        except TypeError:
            logger.info('no VmCloud defined in the testbed')

    if not cloud_json:
        fail('cloud_json None, No Cloud defined in Testbed file')

    cloud_sdk_conn = get_vm_cloud_sdk(cloud_json=cloud_json)
    return cloud_sdk_conn

def get_ip_for_network(network, ip_host=None):
    """ IP address for given network """
    config = get_config()
    mode = config.get_mode()
    site_name = mode['site_name']
    network_obj = config.testbed[site_name].networks[network]
    new_ip = network_obj.get_ip_for_network(ip_host=ip_host)
    return new_ip

def reinitialize_vms():
    config = get_config()
    config._vm_list = {}
    vms = get_vm_of_type('controller')
