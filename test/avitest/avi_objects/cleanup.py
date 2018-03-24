import unicodedata
import time
import json
from logger import logger
import requests
from avi_objects.suite_vars import suite_vars
import sys
from avi_objects.avi_config import AviConfig
from avi_objects.rest import (put,
                              post,
                              get,
                              delete,
                              import_config,
                              update_admin_user,
                              create_session,
                              get_session,
                              get_uuid_by_name)
from avi_objects.logger_utils import aretry, asleep, error, fail
from avi_objects.infra_utils import switch_mode
from urlparse import urlparse

# REVIEW should use from bin.cli.avi_cli.common import pb_ordered + ['User']
obj_order = [
    'tenant',
    'cloud',
    'role',
    'user',
    'serviceenginegroup',
    'sslprofile',
    'sslkeyandcertificate',
    'sslkeyandcertificate_import',
    'pkiprofile',
    'hardwaresecuritymodulegroup',
    'stringgroup',
    'ipaddrgroup',
    'applicationprofile',
    'applicationpersistenceprofile',
    'networkprofile',
    'analyticsprofile',
    'authprofile',
    'vrfcontext',
    'healthmonitor',
    'serverautoscalepolicy',
    'autoscalelaunchconfig',
    'pool',
    'prioritylabels',
    'webhook',
    'poolgroupdeploymentpolicy',
    'poolgroup',
    'httppolicyset',
    'dnspolicy',
    'networksecuritypolicy',
    'wafpolicy',
    'vsdatascriptset',
    'sslcertificaterequest',
    'microservice',
    'microservicegroup',
    'trafficcloneprofile',
    'vsvip',
    'virtualservice',
    'gslb',
    'gslbservice',
    'gslbgeodbprofile',
    'alertscriptconfig',
    'alertsyslogconfig',
    'alertemailconfig',
    'actiongroupconfig',
    'alertconfig',
    'alert',
    'network',
    'staticroute',
    'snmptrapprofile',
]


@aretry(retry=5, delay=10, period=5)
def enable_controller_basic_authentication():
    config = AviConfig.get_instance()
    c_uri = config.get_vm_of_type('controller')[0].ip

    # REVIEW why isn't this using rest.post?
    def _log_out(session):
        logout_p = 'https://%s/logout' % c_uri
        rsp = session.post(logout_p, "{}", verify=False)
        if rsp.status_code >= 400:
            logger.info("ERROR when logout, return status %s" % rsp.status_code)

    logger.info('---change systemconfig to enable basic authentication')
    session = requests.Session()

    login_url = 'https://%s/login' % c_uri
    headers = {"Content-Type": "application/json"}
    session.headers.update(headers)
    system_path = 'https://%s/api/systemconfiguration' % c_uri
    login_success = False
    login_data = {'username': 'admin', 'password': 'admin'}
    rsp = session.post(login_url, json.dumps(login_data), headers=headers, verify=False)
    logger.info('Login API response with status %s' % rsp.status_code)
    csrftoken = requests.utils.dict_from_cookiejar(rsp.cookies).get('csrftoken', '')
    referer = 'https://%s/' % c_uri
    session.headers.update({"X-CSRFToken": csrftoken,
                            "Referer": referer})

    rsp = session.get(system_path, headers=headers, verify=False)
    data = rsp.json()
    if data.get('portal_configuration', {}).get('allow_basic_authentication'):
        logger.info('Controller already accepts basic auth')
        _log_out(session)
        return
    if 'portal_configuration' not in data:
        data['portal_configuration'] = {}
    data['portal_configuration']['allow_basic_authentication'] = True
    data['portal_configuration']['password_strength_check'] = False
    logger.info('Updating controller to allow basic auth')
    rsp = session.put(system_path, json.dumps(data), headers=headers, verify=False)
    _log_out(session)


def reboot_clean(update_admin_info=True, **kwargs):
    post('cluster', path='reboot', data=json.dumps({'mode': 'REBOOT_CLEAN'}))
    asleep(msg="Sleep before cluster wait check", delay=120)
    wait_until_cluster_ready()
    set_sysadmin_public_key()
    set_systemconfiguration()
    set_ha_mode_best_effort()
    if update_admin_info:
        config = AviConfig.get_instance()
        mode = config.get_mode()
        logger.debug("Current Default Mode %s" % mode)
        username = mode['user']
        password = 'avi123'
        mode["password"] = 'avi123'
        update_admin_user(username=username, password=password)
    switch_mode(**mode)


@aretry(retry=10, delay=10, period=5)
def set_sysadmin_public_key(enable_basic_auth=True, **kwargs):
    sysadmin_public_key_path = '/test/robot/new/lib/tools/id_sysadmin.pub'
    sysadmin_priv_key_path = '/test/robot/new/lib/tools/id_sysadmin'

    config = AviConfig.get_instance()
    controller_obj = config.get_vm_of_type('controller')[0].ip
    # first enable basic auth and then use REST API.
    if enable_basic_auth:
        enable_controller_basic_authentication()
    logger.info('Finish updating controller to allow basic auth')
    logger.info('-- set_sysadmin_public_key -- %s\n' % (controller_obj))
    data = {}
    data['action'] = 'create'
    workspace = suite_vars.workspace
    key_path = workspace + sysadmin_public_key_path
    key_str = None
    try:
        with open(key_path, 'r') as f:
            key_str = f.read()
    except:
        raise Exception('Could not ready sysadmin pub key')

    data['key'] = key_str
    logger.info('Data after: %s---' % data)

    try:
        # Try with 'adminkey'
        config = AviConfig.get_instance()
        current_password = config.get_mode()['password']
        config.switch_mode(password='admin')
        r = post('adminkey', data=json.dumps(data))
    except Exception as e:
        # Try with 'resetsysadminkey'
        logger.info("Got Exception %s with adminkey. Trying with resetsysadminkey" % e)
        r = post('resetsysadminkey', data=json.dumps(data))
    config.switch_mode(password=current_password)


def set_systemconfiguration(**kwargs):
    logger.info('-- set_systemconfiguration -- \n')
    _, data = get('systemconfiguration')

    data['portal_configuration']['password_strength_check'] = False
    logger.info('Data after: %s---' % data)

    if kwargs.get('dns_configuration', 'True') == 'True':
        ip_addr = {'addr': '10.10.0.100',
                   'type': 'V4'}

        data['dns_configuration']['server_list'] = []
        data['dns_configuration']['server_list'].append(ip_addr)

        data['dns_virtualservice_uuids'] = []

    if kwargs.get('dns_virtualservice_uuids'):
        vs_uuid = get_uuid_by_name('virtualservice',
                                   kwargs.get('dns_virtualservice_uuids'))  # REVIEW how does this work?
        data['dns_virtualservice_uuids'].append(vs_uuid)

    try:
        put('systemconfiguration', data=json.dumps(data))
    except Exception as e:
        logger.info('put failed %s. Retrying' % e)
        put('systemconfiguration', data=json.dumps(data))

    try:
        _, r = get('systemconfiguration')
    except Exception as e:
        logger.info('get systemconfiguration failed with %s. Retrying' % e)
        _, r = get('systemconfiguration')
    logger.info('\n --- Get system configuration: %s --- \n' % r)


def set_ha_mode_best_effort():
    logger.info('-- set_ha_mode_best_effort -- \n')

    # REVIEW is this used anywhere?
    @aretry(retry=10, delay=60, period=10)
    def get_serviceenginegroup():
        return get('serviceenginegroup')

    _, data = get('serviceenginegroup')
    for _data in data['results']:
        _data['ha_mode'] = 'HA_MODE_SHARED'
        _data['algo'] = 'PLACEMENT_ALGO_DISTRIBUTED'
        _data['buffer_se'] = 1
        _data['min_scaleout_per_vs'] = 1

        logger.info('Data after changing, before post: %s---' % _data)
        try:
            r = put('serviceenginegroup', uuid=_data['uuid'], data=json.dumps(_data))
        except Exception as e:
            logger.info('put failed %s. Retrying' % e)
            r = put('serviceenginegroup', uuid=_data['uuid'], data=json.dumps(_data))

        try:
            _, r = get('serviceenginegroup')
        except Exception as e:
            logger.info('put failed %s. Retrying' % e)
            _, r = get('serviceenginegroup')

        logger.info('\n --- Get serviceenginegroup: %s --- \n' % r)


@aretry(retry=15, delay=60, period=15)
def wait_until_cluster_ready(detailed_state_str="", **kwargs):
    """ Blocks until the controller cluster state is up or if a
    detailed_state_str was passed, then returns when the cluster reaches that
    state """
    # uses site_name or config
    config = AviConfig.get_instance()
    ctrl_vm = config.get_vm_of_type('controller')[0].ip
    logger.debug('controller used in wait until cluster ready: %s' % ctrl_vm)
    rsp = None
    try:
        session = get_session()
        session.password = 'admin'
        session.reset_session()
        status_code, rsp = get('cluster', path='runtime')
    except Exception as e:
        fail('Cluster api runtime exception %s' % str(e))
    if rsp and status_code == 200:  # REVIEW do we need this logic implicitly checking status code still?
        cluster_state = rsp.get('cluster_state', {})
        if ('CLUSTER_UP' in cluster_state.get('state', '') and
                not 'HA_NOT_READY' in cluster_state.get('state', '')):
            logger.info('Controller cluster is ready with cluster_state %s' % cluster_state)
        elif cluster_state.get('reason'):
            if (detailed_state_str and
                        detailed_state_str in cluster_state.get('reason')):
                logger.info('Controller cluster is ready with %s' % detailed_state_str)
            else:
                fail('cluster state[%s]: %s' % (ctrl_vm, cluster_state.get('state', 'unknown')))
        else:
            fail('cluster state[%s]: %s' % (ctrl_vm, cluster_state.get('state', 'unknown')))
    elif rsp is None:
        fail('Cluster api runtime exception: no response.')
    else:
        fail('Cluster api runtime returned %d' % status_code)


@aretry(retry=10, delay=60, period=10)
def get_and_delete_all_configs(skip_cloud=False, check_status_code=False, tenant_list=[], fix_url=True, **kwargs):
    move_all_se_to_group('Default-Group')

    session = get_session()
    config = AviConfig.get_instance()
    defaults = get('default-values').json()
    logger.info(defaults)
    tenant_resp = get('tenant').json()
    if not tenant_list:
        tenants = []
        tenants = [str(entry['name']) for entry in tenant_resp.get('results', [])]
    else:
        tenants = tenant_list

    for _tenant in tenants:
        switch_mode(tenant=_tenant)
        for obj_type in reversed(obj_order):
            if (((obj_type == 'cloud' or obj_type == 'tenant') and skip_cloud) or
                    (obj_type in ['sslcertificaterequest', 'staticroute'])):
                continue
            status_code, data = get(obj_type, check_status_code=check_status_code)
            if status_code > 400:
                continue
            for d in data['results']:
                if obj_type == 'cloud' and d['name'] == 'Default-Cloud':
                    if d['vtype'] != 'CLOUD_NONE':
                        logger.info('Update Default-Cloud from %s to no-access' % d['vtype'])
                        if d.get('vcenter_configuration'):
                            d.pop('vcenter_configuration')
                        elif d.get('openstack_configuration'):
                            d.pop('openstack_configuration')
                        elif d.get('aws_configuration'):
                            d.pop('aws_configuration')
                        elif d.get('cloudstack_configuration'):
                            d.pop('cloudstack_configuration')
                        elif d.get('vca_configuration'):
                            d.pop('vca_configuration')
                        elif d.get('apic_configuration'):
                            d.pop('apic_configuration')
                        d['vtype'] = 'CLOUD_NONE'
                        put('cloud', name=d['name'], data=json.dumps(d))  # review can we use uuid=d['uuid']?
                if obj_type in defaults.get('default', []) and \
                                d['uuid'] in defaults['default'][obj_type]:
                    continue
                logger.info('Deleting: %s:%s' % (obj_type, d['name']))
                if obj_type in ['sslcertificaterequest', 'sslkeyandcertificate_import']:
                    delete('sslkeyandcertificate', name=d['name'], check_status_code=False)
                else:
                    delete(obj_type, name=d['name'], check_status_code=False)


# cleanup_ses()
#    vrf_del_all_static_routes()


def move_all_se_to_group(se_group, **kwargs):
    se_list = get_all_se_uuid(**kwargs)
    for se_uuid in se_list:
        update_se_segroup(se_uuid, se_group, **kwargs)


@aretry(retry=4, delay=2)
def update_se_segroup(se_uuid, sg_name, **kwargs):
    logger.info('update segroup for se:%s to sg:%s' % (se_uuid, sg_name))
    _, json_data = get('serviceengine', uuid=se_uuid, **kwargs)
    if json_data.get('results'):
        json_data = json_data['results'][0]
    sg = json_data.get('se_group_ref')
    if not sg:
        fail('ERROR! Cannot get se_group from api')
    json_data['se_group_ref'] = '/api/serviceenginegroup?name=%s' % sg_name
    put('serviceengine', uuid=se_uuid, data=json.dumps(json_data), **kwargs)


def get_all_se_uuid(expect_se=0, **kwargs):
    expect_num_ses = int(expect_se)
    _, json_data = get('serviceengine', **kwargs)
    se_uuids = [res['uuid'] for res in json_data['results']]
    if expect_num_ses != 0:
        # Validate the SEs returned matches the expected number
        if expect_num_ses != len(se_uuids):
            fail('Expected num of SEs: %s, Actual: %s' %
                 (expect_num_ses, len(se_uuids)))
    return se_uuids


def cleanup_client_and_servers():
    config = AviConfig.get_instance()
    for vm in config.get_vm_of_type('client'):
        vm.killtcptest()
        vm.delete_netem_config()
        vm.cleanup_sub_ints()
        vm.flush_arp_cache_entries()

    for vm in config.get_vm_of_type('server'):
        vm.killtcptest()
        vm.delete_netem_config()
        vm.cleanup_sub_ints()
        vm.cleanup_server_context_nginx(False)
        vm.cleanup_server_context_apache(False)
        vm.flush_arp_cache_entries()

    mode = config.get_mode()
    site_name = mode['site_name']
    cloud = mode['cloud']
    cloud_obj = config.testbed[site_name].cloud_obj[cloud]
    cloud_obj.cleanup_all()
    # REVIEW from a hierarchical standpoint it makes more sense to do this from PoolModel
    from avi_objects.pool import ServerModel
    ServerModel.clear_servers()

def licenseinstall(c_ip, c_port=None):
    c_uri = c_ip + ':' + str(c_port) if c_port else c_ip
    workspace = suite_vars.workspace
    license_file = workspace + \
        '/controller/metrics_manager/licensing/license.lic'
    with open(license_file, 'r') as f:
        license = f.read()
    license_dict = {'license_text': license}
    status_code, resp = put('license', data=json.dumps(license_dict))
    status_code, resp = get('license')

    # retry
    logger.info('\n --- Get license: %s -- \n' % resp)
