import json
import requests
import math
import shlex
import random
import re
import string
import subprocess
import time
import os
import sys
import copy

from string import Template
from os.path import expanduser
from subprocess import Popen, PIPE
from avi.sdk.utils.mesos.mesos_testutils import MesosTestUtils
from avi_objects.avi_config import read_version
from avi_objects.logger_utils import aretry, asleep, error, fail
from avi_objects.logger import logger
from fabric.api import env, task, settings, hide, run
from fabric.tasks import execute
from avi_objects.suite_vars import suite_vars
from igraph import Graph
from avi_objects import infra_utils
from lib.openshift_lib import OpenshiftTestUtils
#from avi.protobuf import common_pb2, options_pb2, cloud_objects_pb2
#from avi.protobuf.ipam_profile_pb2 import (
#    IpamDnsType, IPAMDNS_TYPE_INTERNAL, IPAMDNS_TYPE_OPENSTACK,
#    IPAMDNS_TYPE_INTERNAL_DNS)

import lib.network_lib as network_lib
import avi_objects.rest as rest
import lib.system_lib as system_lib
import lib.webapp_lib as webapp_lib
import lib.ssl_lib as ssl_lib
import lib.metrics_lib as metrics_lib
import lib.controller_lib as controller_lib
import lib.performance_lib as performance_lib
import lib.vs_lib as vs_lib
import lib.ipam_lib as ipam_lib
import lib.common as common
import lib.pool_lib as pool_lib
import lib.se_lib as se_lib
import lib.ms_lib as ms_lib


ma_utils = MesosTestUtils()
AB_CMD_TMPL = Template("ab -l -C ${conns} -n ${count} http://$$(ip route | "
                       "grep default | awk \"{print \\\$$3}\"):${port}/${path}")

AB_NS_TMPL = Template("ab -l -C ${conns} -n ${count} http://${vip}:${port}/${path}")

MESOS_CONTAINER_GREP = Template(
    "docker inspect --format '{{.Config.Env}}' ${docker_id} "
    "| egrep -e '(/${app_name} )' | egrep -e '(${tenant})'")

OPENSHIFT_CONTAINER_GREP = Template(
    "docker ps | grep ${docker_id} "
    "| egrep -e '(k8s_${app_name}-)' | egrep -e '(${tenant})'")

CLOUD_CREATE_POLL_INTERVAL = 30

oshift_utils = OpenshiftTestUtils()

VS_PREFIX = ''  # REVIEW for in case the orchestrator mutates the name? deprecate?
CLOUD_CREATE_TIMEOUT=1800
CFG_CHK_ROUND_TIMEOUT = 15
SE_UP_CHK_ROUND_TIMEOUT = 15
DEFAULT_DOCKER_REGISTRY = '10.160.0.161:5000/'
OPENSTACK_IPAM_NAME = 'openstack-ipam'
IPAM_NS = 'ipam-ns'
IPAM_NS_DNS = 'ipam-ns-dns'
IPAM_EW = 'ipam-ew'
IPAM_EW_DNS = 'ipam-ew-dns'
OPENSHIFT_DEFAULT_TENANT = 'default'
SERVICE_DOMAIN = 'avi-container-dns.internal'
IPAM_PROFILE_PREFIX = '/api/ipamdnsproviderprofile?name='


class FabricAbortedException(Exception):
    pass


@task
def _fab_exec(cmd, warn_only=True, ssh_password='aviuser'):
    """

    :param cmd:
    :param warn_only:
    :param ssh_password:
    :return:
    """

    config = infra_utils.get_config()
    cloud_config = _get_cloud_config()
    ssh_user = 'aviuser'
    # take ssh username from the toplevel config if exists
    controller_vm = infra_utils.get_vm_of_type('controller')[0]
    if controller_vm and hasattr(controller_vm, 'ssh_access_username'):
        ssh_user = controller_vm.ssh_access_username
    elif 'ssh_user_uuid' in cloud_config:
        # use our mesos config for ssh credentials
        ssh_user = cloud_config['ssh_user_uuid']

    default_key_path = expanduser('~') + '/.ssh/id_rsa'
    if not os.path.isfile(default_key_path):
        default_key_path = None
    key_file_path = config.testbed[config.site_name].testbed_vars.get('ssh_access_key_path', default_key_path)

    logger.info('in fab exec running cmd %s with username %s' % (
        cmd, ssh_user))
    with settings(warn_only=warn_only), hide('everything'):
        env.user = ssh_user
        env.password = ssh_password
        env.abort_on_prompts = True
        env.key_filename = key_file_path
        env.abort_exception = FabricAbortedException
        # Set port to 22 in case its set to something else
        env.port = 22
        # Certain platforms have the slave nodes in private networks, only
        # reachable from the public master
        # if _is_aws_testbed() or _is_openstack_testbed(): # REVIEW maybe
        # abstract out to def needs_gateway(): return ...
        #     env.gateway = ssh_user + '@' + get_cluster_master_ip()
        out = ''
        try:
            out = run(cmd)
        except FabricAbortedException as e:
            # we don't actually want it to exit and abort the tests even if
            # warn_only is false
            logger.info('Fabric command aborted!')
            logger.info('Warning: fabric command %s did not complete exc %s' %
                        (cmd, e))
            if not warn_only:
                fail('Fabric command aborted!')
        return out


def _get_cloud_type():
    """

    :return:
    """

    config = infra_utils.get_config()
    return config.testbed[config.site_name].cloud[0]['vtype']


def _is_mesos_cloud():
    """

    :return:
    """

    return _get_cloud_type().upper() == 'CLOUD_MESOS'  # common_pb2.CLOUD_MESOS


def _is_aws_testbed():
    """

    :return:
    """

    ctrl_vm = infra_utils.get_vm_of_type('controller')[0]
    return ctrl_vm.platform == 'aws'


def _is_openshift_cloud():
    return _get_cloud_type() == "CLOUD_OSHIFT_K8S"


def _is_openstack_testbed():
    """

    :return:
    """

    ctrl_vm = infra_utils.get_vm_of_type('controller')[0]
    return ctrl_vm.platform == 'openstack'


def _check_cloud_state(status, **kwargs):
    """

    :param status:
    :param kwargs:
    :return:
    """

    timeout = kwargs.get('timeout', CLOUD_CREATE_TIMEOUT)
    round_timeout = CFG_CHK_ROUND_TIMEOUT
    rounds = int(timeout/round_timeout)
    logger.info('check_cloud state timeout=%d, rounds=%s' % (timeout, rounds))
    last_reason = None
    config = infra_utils.get_config()
    for round in xrange(rounds):
        logger.debug('checking cloud inventory iter %d:' % round)
        try:
            http_status, resp = rest.get('cloud-inventory')
        except Exception as e:
            logger.debug('Failed to get cloud inventory resp: %s' %
                         (str(e)))
            asleep(delay=round_timeout)
            continue
            #fail('Cloud inventory API failed')
        for cloud_obj in resp['results']:
            if cloud_obj['config']['vtype'] != config.testbed[config.site_name].cloud[0]['vtype']:
                #REVIEW only checking one/first cloud_object?
                continue
            cstatus = cloud_obj['status']['state']
            if cstatus == status:
                return True
            # review to guard against no reason
            last_reason = cloud_obj['status'].get('reason', '')
            logger.info('expected %s, actual %s, reason %s' % (
                status, cstatus, last_reason))
            break
        asleep(delay=round_timeout)
    fail(last_reason)


def setup_container_cloud(**kwargs):
    """

    :param kwargs:
    :return:
    """

    cloud_name = kwargs.get('cloud_name', 'Default-Cloud')
    tenant = kwargs.get('tenant', 'admin')
    system_lib.set_basic_dns_configuration(tenant=tenant)
    config = infra_utils.get_config()
    cloud_object = config.testbed[config.site_name].cloud[0]
    cloud_backup = copy.deepcopy(cloud_object)

    if _is_mesos_cloud():
        cloud_backup = setup_mesos_cloud(cloud_backup, **kwargs)
        cloud_backup['name'] = cloud_name
    elif _is_openshift_cloud():
        cloud_backup = setup_openshift_cloud(cloud_backup, **kwargs)
        cloud_backup['name'] = cloud_name
    else:
        fail('Did not find a supported cloud object configuration in your '
             'topo_conf')

    rest.put('cloud', name=cloud_name, data=cloud_backup)

    rsp_code, prop = rest.get('controllerproperties')
    prop['allow_unauthenticated_nodes'] = True
    rest.update('controllerproperties', data=prop)
    cloud_create_timeout = kwargs.get('cloud_create_timeout', CLOUD_CREATE_TIMEOUT)
    try:
        asleep(delay=100)
        _check_cloud_state(
            'CLOUD_STATE_PLACEMENT_READY', timeout=int(cloud_create_timeout),
            tenant=tenant)
    except Exception as e:
        fail('Cloud could not be configured %s' % str(e))

    # Check if all the SEs have come up, no point in going to next
    #  test cases if the cloud isn't ready.
    skip_se_check = kwargs.get('skip_se_check', None)
    if not skip_se_check:
        check_container_ses()


def get_mesos_auth_token(host_url=None, auth_type='token', username='admin',
                         password='avi123'):
    """
    get the auth token from doing a login to the mesos host;
    credentials from the testbed
    :param host_url:
    :param auth_type:
    :param username:
    :param password:
    :return:
    """


    if auth_type != 'token':
        return ''
    headers = _get_mesos_headers()
    login_info = {'uid': username, 'password': password}
    login_json = json.dumps(login_info)
    if not host_url:
        host_url = 'http://' + get_cluster_master_ip()
    url = host_url + '/acs/api/v1/auth/login'
    try:
        import requests
        logger.info('Url: %s\ndata: %s\nheader: %s' % (url, login_json, headers))
        login_rsp = requests.post(url, data=login_json, headers=headers)
        if (login_rsp.status_code == 400) or (login_rsp.status_code == 404):
            # assume this is a version of dcos that doesn't need auth
            logger.info('ignoring: token auth failed with %d, %s' %(
                        login_rsp.status_code, login_rsp.text))
            return ''
        elif login_rsp.status_code != 200:
            raise Exception("token auth failed with %d, %s"%(
                            login_rsp.status_code, login_rsp.text))
        login_rsp_json = login_rsp.json()
        if 'token' not in login_rsp_json.keys():
            raise Exception("No token key in auth response")
        token = login_rsp_json['token']
        logger.trace('got auth token %s' % str(token))
        return token
    except requests.exceptions.ConnectionError as e:
        logger.debug('Could not connect to url %s to login, assume it is not supported in this version of mesos' %url)
        return ''


def _get_cloud_config():
    """

    :return:
    """

    config = infra_utils.get_config()
    cloud_objects = config.testbed[config.site_name].cloud
    for cloud_object in cloud_objects: # REVIEW do we support more than 1?
        if 'mesos_configuration' in cloud_object:
            return cloud_object['mesos_configuration']
        elif 'oshiftk8s_configuration' in cloud_object:
            return cloud_object['oshiftk8s_configuration']
    fail('Did not find a supported cloud configuration in your topo_conf')


def get_cluster_master_ip():
    """

    :return:
    """

    cloud_config = _get_cloud_config()
    if _is_mesos_cloud():  # mesos config
        url = cloud_config['mesos_url']
    elif _is_openshift_cloud():  # openshift config
        url = cloud_config['master_nodes'][0]
    # For clarity, not brevity
    #from urlparse import urlparse
    #parsed_url = urlparse.parse(url)
    #if parsed_url.netloc:
    #  host_port = parsed_url.netloc # https://ip:port
    #else:
    #  host_port = parsed_url.path # ip:port
    #return host_port.split(':')[0]
    # trim the port, and any leading http://
    return url.split(':')[-2].split('//')[-1]


def _get_mesos_headers(token=None):
    """

    :param token:
    :return:
    """

    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json'}
    if token is not None:
        headers['Authorization'] = 'token=%s' % token
    return headers


def _get_mesos_slaves_from_master():
    """

    :return:
    """

    token = get_mesos_auth_token()
    headers = _get_mesos_headers(token=token)
    if token:
        slaves_rest_api_uri = 'http://' + get_cluster_master_ip() + \
                              '/mesos/slaves'
    else:
        slaves_rest_api_uri = _get_cloud_config()['mesos_url'] + \
                              '/master/slaves'
    rsp = requests.get(slaves_rest_api_uri, headers=headers)
    logger.info('get: %s' % slaves_rest_api_uri)
    logger.info('response status: %s' % rsp)
    logger.info('response text: %s' % rsp.text)
    rsp_obj = json.loads(rsp.text)
    return rsp_obj

def _get_openshift_slaves_from_master():
    slaves_obj = {'slaves': []}
    slaves = oshift_utils.get_openshift_slaves()
    for slave in slaves:
        slave_info = {}
        #slave_info['active'] = False if slave['spec']['unschedulable'] else True
        slave_info['active'] = False
        conditions = slave['status']['conditions']
        for condition in conditions:
            if condition['type'] == 'Ready' and condition['status'] == 'True':
                slave_info['active'] = True
        slave_info['hostname'] = slave['metadata']['name']
        slave_info['id'] = slave['metadata']['uid']
        slaves_obj['slaves'].append(slave_info)
    return slaves_obj


def get_slaves_from_master():
    """

    :return:
    """

    if _is_mesos_cloud():
        return _get_mesos_slaves_from_master()
    elif _is_openshift_cloud():
        return _get_openshift_slaves_from_master()
    else:
        fail('Did not find a supported cloud object configuration in your '
             'topo_conf')


# do we need/want a get_all_slave_count?
def get_active_slave_count_from_master():
    """
    Use the rest api to get the active slave count
    :return:
    """

    rsp_obj = get_slaves_from_master()
    slave_count = 0
    for slave in rsp_obj['slaves']:
        if slave['active']:
            slave_count += 1
    logger.info('found %d active slaves' % slave_count)
    return slave_count



def wait_for_n_ses(n, timeout=900, **kwargs):
    """

    :param n:
    :param timeout:
    :param kwargs:
    :return:
    """

    num_ses_expected = int(n)
    round_timeout = SE_UP_CHK_ROUND_TIMEOUT
    rounds = int(timeout/round_timeout)
    in_prog = []
    num_ses_ready = 0
    for _ in xrange(rounds):
        try:
            status, rsp = rest.get('serviceengine')
        except:
            logger.info('No service engines found yet')
            asleep(delay=round_timeout)
            continue
        in_prog = []
        try:
            for se in rsp['results']:
                if se['oper_status']['state'] != 'OPER_UP':
                    logger.info(' ServiceEngine %s not yet UP' % se['name'])
                    in_prog.append(se['name'])
            if not in_prog:
                num_ses_ready = int(rsp['count'])
                if num_ses_ready == num_ses_expected:
                    return True
                elif num_ses_ready > num_ses_expected:
                    logger.info('Found %d SEs but only expecting %d!' % (
                        num_ses_ready, num_ses_expected))
                else:
                    logger.info('Only found %d SEs ready but waiting for %d' % (
                        num_ses_ready, num_ses_expected))
        except KeyError:  # no status yet; ignore and retry
            pass
        asleep(delay=round_timeout)
    fail('Timed out waiting for %d SEs; up: %d, in progress: %s' %
               (num_ses_expected, num_ses_ready, in_prog))


def check_container_ses(timeout=900, **kwargs):
    """

    :param timeout:
    :param kwargs:
    :return:
    """

    num_slaves = get_active_slave_count_from_master()
    wait_for_n_ses(num_slaves, timeout=timeout, **kwargs)


def setup_mesos_cloud(cloud, **kwargs):
    """
    Build up the cloud pb with info from mesos_config and keyword args
    :param cloud:
    :param mesos_config:
    :param kwargs:
    :return:
    """

    disable_auto_frontend_service_sync = kwargs.get(
        'disable_auto_frontend_service_sync', None)
    disable_auto_backend_service_sync = kwargs.get(
        'disable_auto_backend_service_sync', None)
    if disable_auto_frontend_service_sync:
        cloud['mesos_configuration']['disable_auto_frontend_service_sync'] = \
            True

    if disable_auto_backend_service_sync:
        cloud['mesos_configuration']['disable_auto_backend_service_sync'] = \
            True
    marathon_configs = cloud['mesos_configuration']['marathon_configurations']
    for marathon_config in marathon_configs:
        marathon_config['private_port_range'] = {}
        if 'public_port_range' not in marathon_config:
            marathon_config['public_port_range'] = {}
            marathon_config['public_port_range']['start'] = 10000
            marathon_config['public_port_range']['end'] = 20000

        public_start_index = kwargs.get('public_start_index', None)
        public_end_index = kwargs.get('public_end_index', None)
        if public_start_index:
            marathon_config['public_port_range']['start'] = \
                int(public_start_index)

        if public_end_index:
            marathon_config['public_port_range']['end'] = \
                int(public_end_index)

        if 'private_port_range' not in marathon_config:
            marathon_config['private_port_range'] = {}
            marathon_config['private_port_range']['start'] = 30000
            marathon_config['private_port_range']['end'] = 60000

        private_start_index = kwargs.get('private_start_index', None)
        private_end_index = kwargs.get('private_end_index', None)
        if private_start_index:
            marathon_config['private_port_range']['start'] = \
                int(private_start_index)
        if private_end_index:
            marathon_config['private_port_range']['end'] = \
                int(private_end_index)

    if 'se_deployment_method' not in cloud['mesos_configuration']:
        cloud['mesos_configuration']['se_deployment_method'] = 'MESOS_SE_CREATE_SSH'

    ssh_user_uuid = cloud['mesos_configuration'].get('ssh_user_uuid', 'aviuser')
    cloud['mesos_configuration']['ssh_user_uuid'] = \
        rest.get_uuid_by_name('cloudconnectoruser', ssh_user_uuid)

    registry = kwargs.get('registry', None)
    if 'docker_registry_se' not in cloud['mesos_configuration']:
        cloud['mesos_configuration']['docker_registry_se'] = {}

    if registry:
        cloud['mesos_configuration']['docker_registry_se']['registry'] = registry
    elif 'registry' not in cloud['mesos_configuration']['docker_registry_se']:
        random_string = ''.join(
            random.choice(string.lowercase) for i in range(10))
        cloud['mesos_configuration']['docker_registry_se']['registry'] = \
            DEFAULT_DOCKER_REGISTRY + random_string

    repo_username = kwargs.get('repo_username', None)
    repo_password = kwargs.get('repo_password', None)


    if repo_username and repo_password:
        cloud['mesos_configuration']['docker_registry_se']['username'] = \
            repo_username
        cloud['mesos_configuration']['docker_registry_se']['password'] = \
            repo_password

    disable_docker_repo = kwargs.get('disable_docker_repo', False)
    disable_auto_se_creation = kwargs.get('disable_auto_se_creation', False)
    if disable_docker_repo:
        cloud['mesos_configuration']['docker_registry_se'][
            'se_repository_push'] = False
    if disable_auto_se_creation:
        cloud['mesos_configuration']['disable_auto_se_creation'] = True

    se_include_attribute = kwargs.get('se_include_attribute', None)
    se_exclude_attribute = kwargs.get('se_exclude_attribute', None)
    if se_include_attribute:
        cloud['mesos_configuration']['se_include_attributes'] = []
        se_include = {}
        se_include_attribute_kv = se_include_attribute.split(':')
        se_include['attribute'] = se_include_attribute_kv[0]
        se_include['value'] = se_include_attribute_kv[1]
        cloud['mesos_configuration']['se_include_attributes'].append(
            se_include)
    if se_exclude_attribute:
        cloud['mesos_configuration']['se_exclude_attributes'] = []
        se_exclude = {}
        se_exclude_attribute_kv = se_exclude_attribute.split(':')
        se_exclude['attribute'] = se_exclude_attribute_kv[0]
        se_exclude['value'] = se_exclude_attribute_kv[1]
        cloud['mesos_configuration']['se_exclude_attributes'].append(
            se_exclude)

    if 'east_west_placement_subnet' not in cloud['mesos_configuration']:
        cloud['mesos_configuration']['east_west_placement_subnet'] = {
            'ip_addr': {},
            'mask': 16
        }
        net_handle = kwargs.get('east_west_placement_network', None)
        logger.debug('Using given network %s to infer east-west placement '
                     'subnet' % net_handle)
        config = infra_utils.get_config()
        network = config.testbed[config.site_name].networks_json[net_handle]
        east_west_placement_ip = network['ip']
        east_west_placement_ip_split = east_west_placement_ip.split(".")
        east_west_placement_classAB = (
            east_west_placement_ip_split[0] + "." +
            east_west_placement_ip_split[1] + ".0.0")
        #east_west_placement_mask = config.cloud.networks.get(network)[2]
        # make this broad to accomodate multiple pgs
        east_west_placement_maskAB = 16
        cloud['mesos_configuration']['east_west_placement_subnet']['ip_addr'][
            'addr'] = east_west_placement_classAB
        cloud['mesos_configuration']['east_west_placement_subnet']['ip_addr'][
            'type'] = 'V4'
        cloud['mesos_configuration']['east_west_placement_subnet']['mask'] = 16

    logger.info('creating east-west placement ip and mask %s/%d' % (
        cloud['mesos_configuration']['east_west_placement_subnet']['ip_addr'][
            'addr'],
        cloud['mesos_configuration']['east_west_placement_subnet']['mask']))
    cloud['mesos_configuration']['use_bridge_ip_as_vip'] = True

    # Networks
    subnet_ip = get_se_subnet()
    # subnet based off master subnet
    subnet = {'prefix': {'ip_addr': {'addr': subnet_ip, 'type': 'V4'}, 'mask': 24}}
    # HACK for AV-12323
    safe_create_network('north_south_network', subnet)
    # for autoallocation of vips; make sure this doesn't conflict with .52-.63
    # range that we also use
    network_lib.network_set_subnet_static_range('north_south_network', '200', '220')

    # Create ipam profile for the mesos cloud for NS traffic
    ipam_lib.create_ipamdns_profile(IPAM_NS, 'IPAMDNS_TYPE_INTERNAL',
                                    usable_network='north_south_network')

    # IPAM
    # As per AV-20840, EW apps need their own ipam profile now
    safe_create_network('east_west_network', {'prefix': {'ip_addr': {'addr': '169.254.0.0', 'type': 'V4'}, 'mask': 16}})
    network_lib.network_set_subnet_static_range('east_west_network', '10', '250')
    ipam_lib.create_ipamdns_profile(
        IPAM_NS_DNS, 'IPAMDNS_TYPE_INTERNAL_DNS', service_domain=SERVICE_DOMAIN)
    ipam_lib.create_ipamdns_profile(
        IPAM_EW_DNS, 'IPAMDNS_TYPE_INTERNAL_DNS', service_domain=SERVICE_DOMAIN)
    ipam_lib.create_ipamdns_profile(
        IPAM_EW, 'IPAMDNS_TYPE_INTERNAL',
        usable_network='east_west_network')
    cloud['dns_provider_uuid'] = rest.get_uuid_by_name('ipamdnsproviderprofile', IPAM_NS_DNS)
    cloud['ipam_provider_uuid'] = rest.get_uuid_by_name('ipamdnsproviderprofile', IPAM_NS)
    cloud['east_west_dns_provider_uuid'] = rest.get_uuid_by_name('ipamdnsproviderprofile', IPAM_EW_DNS)
    cloud['east_west_ipam_provider_uuid'] = rest.get_uuid_by_name('ipamdnsproviderprofile', IPAM_EW)

    # openstack config
    if _is_openstack_testbed():
        openstack_ipam_provider_name = OPENSTACK_IPAM_NAME
        openstack_profile = \
            config.pb.ipamdnsproviderprofile_object.openstack_profile
        username = openstack_profile.username
        password = openstack_profile.password
        tenant = openstack_profile.tenant
        keystone_host = openstack_profile.keystone_host
        vip_network_name = openstack_profile.vip_network_name
        region = openstack_profile.region
        ipam_lib.create_ipamdns_profile(openstack_ipam_provider_name,
                               'IPAMDNS_TYPE_OPENSTACK',
                               username=username, password=password,
                               tenant=tenant, keystone_host=keystone_host,
                               vip_network_name=vip_network_name,
                               region=region)
        cloud.ipam_provider_uuid = openstack_ipam_provider_name

    return cloud


def safe_create_network(network_name, subnet):
    """
    Try delete the network of given name before creating a new one
    :param network_name:
    :param subnet:
    :return:
    """


    try:
        # REVIEW this is pretty fragile, depends on the runtime error string
        # format in avi_rest_lib.delete_over_rest
        # Maybe better to just call avi_rest_lib.delete('network',
        # network_name, force=True) and check the
        # response_code directly
        rest.delete('network', name=network_name, check_status_code=False, force=True)
    except:
        pass
    network_lib.network_create(network_name, subnet)


def get_se_subnet():
    slaves = get_active_slaves_ips()
    return get_subnet_for_ip(slaves[0])


def get_subnet_for_ip(ip):
    subnet_parts = ip.split('.')[:-1]
    subnet_parts.append('0')
    return '.'.join(subnet_parts)


def get_active_slaves_ips():
    slave_obj = get_slaves_from_master()
    slaves_list = []
    for slave in slave_obj['slaves']:
        if slave['active']:
            slaves_list.append(slave['hostname'])
    return slaves_list


def get_tenant_for_container(**kwargs):
    """
    special case handling for openshift, which by default creates apps in
    tenant 'default' instead of 'admin'
    :param kwargs:
    :return:
    """

    default_tenant = 'admin'
    if _is_openshift_cloud():
        default_tenant = OPENSHIFT_DEFAULT_TENANT
    tenant = kwargs.get('tenant', default_tenant)
    return tenant


def create_app(app_name, app_type='default', northsouth=0, vip_subnet='',
               vip_start_index=200, **kwargs):
    """

    :param app_name:
    :param app_type:
    :param northsouth:
    :param vip_subnet:
    :param vip_start_index:
    :param kwargs:
    :return:
    """

    config = infra_utils.get_config()
    tenant = get_tenant_for_container(**kwargs)
    # clear it from kwargs since we're going to use ours
    kwargs.pop('tenant', '')
    version = kwargs.pop('version', read_version())
    vip = kwargs.get('vip')
    northsouth = int(northsouth)
    # need to special case north-south for certain testbeds
    if _is_aws_testbed():
        logger.info('Creating all apps as East-West for AWS testbed')
        # TODO: need to use boto rest client to create ELB ports for the apps
        # we do want to be N/S
        northsouth = 0  # all apps in AWS should be E/W
    if _is_openstack_testbed():
        logger.info('Creating northsouth apps with floating ips for Openstack '
                    'testbed')
        app_type = 'floating'
        vip = 'floating_ip_placeholder'
    vips = vip.split(',') if vip else []

    # Switch openshift to use autoallocate for NS vips (review: should we
    # still support hardcoded vips?)
    if northsouth and not vip and _is_mesos_cloud():
        network = kwargs.get('network')
        if network:
            # hack to not use certain ips (e.g. a.b.c.64 is usually the
            # controller and that might be assigned by get_ip_for_network()
            # if we have > 12 NS vips starting from the default .53
            for _ in xrange(northsouth):
                vip = config.testbed[config.site_name].networks_json['net1']['ip']
                vips.append(vip)
                logger.info('resolved vip to %s network %s' % (vip, network))
        elif vip_subnet:
            ip_parts = vip_subnet.split('.')[:-1]
            vip_subnet = string.join(ip_parts, '.') + '.'
            for index in xrange(northsouth):
                vip = vip_subnet + str(index + int(vip_start_index))
                vips.append(vip)
                logger.info('added vip ', vip)
        logger.debug('resolved vip to %s' % vip)
    if northsouth and not vips and _is_mesos_cloud():
            fail('vip not provided for northsouth vs (auto-allocate vip not supported')

    if _is_mesos_cloud():
        app_ids = _create_mesos_app(app_name, app_type=app_type,
                                    northsouth=northsouth, vips=vips,
                                    tenant=tenant, version=version, **kwargs)
    elif _is_openshift_cloud():
        app_ids = _create_openshift_app(app_name, northsouth=northsouth, vips=vips,
                                        tenant=tenant, version=version, **kwargs)
    else:
        fail('Did not find a supported cloud object configuration in your '
             'topo_conf')

    asleep(delay=45)
    verify_vs = kwargs.get('verify_vs', True)
    if verify_vs:
        # check apps are running
        # REVIEW predicated on verify_vs because some negative tests may not
        # expect a healthy app after creating, but if we expect a VS then the
        # app must be running
        for app_id in app_ids:
            wait_for_healthy_app(app_id, tenant=tenant, **kwargs)
        # check vs is created
        logger.info("Checking for VSs %s" % app_ids)
        asleep(delay=30)
        vs_lib.check_for_vs(app_ids, tenant=tenant, **kwargs)
        # check vs is running
        for app in app_ids:
            vs_lib.check_vs_created(app, tenant=tenant, **kwargs)


def _create_mesos_app(app_name, app_type='default', num_instances=1,
                      num_apps=1, northsouth=0, vips=[], auth_type='',
                      no_healthcheck=True, **kwargs):
    """

    :param app_name:
    :param app_type:
    :param num_instances:
    :param num_apps:
    :param northsouth:
    :param vips:
    :param auth_type:
    :param no_healthcheck:
    :param kwargs:
    :return:
    """

    if not auth_type:
        auth_type = infer_auth_from_config(_get_default_marathon())
    external_pool = kwargs.get('external_pool',  None)
    pool = {}
    if external_pool:
        pool = {'servers':
                    [{ 'ip':
                        { 'addr': external_pool,
                          'type': 'V4'
                        }
                    }]
                }
    app_ids = ma_utils.createApp(
        get_marathon_url(auth_type), app_type, app_name, int(num_apps),
        num_instances=int(num_instances), northsouth=int(northsouth),
        vips=vips, virtualservice=kwargs.get('virtualservice', {}),
        pool=kwargs.get('pool', pool),
        auth_type=auth_type,
        auth_token=get_mesos_auth_token(auth_type=auth_type),
        username=get_marathon_username(auth_type),
        password=get_marathon_password(auth_type),
        ns_service_port=kwargs.get('ns_service_port', None),
        ew_service_port_start_index=kwargs.get(
            'ew_service_port_start_index', None),
        num_service_ports=int(kwargs.get('num_service_ports', 1)),
        constraints=kwargs.get('constraints', None),
        cpus=float(kwargs.get('cpus', 0.2)),
        mem=int(kwargs.get('mem', 128)),
        tenant=kwargs.get('tenant', 'admin'),
        no_healthcheck=no_healthcheck
      )

    return app_ids


def _get_marathon_configs():
    """

    :return:
    """
    config = infra_utils.get_config()
    return \
        config.testbed[config.site_name].cloud[0]['mesos_configuration']['marathon_configurations']


def _get_token_authenticated_marathon():
    """

    :return: the first configured marathon instance that has supplied
    credentials and wants to use token_auth
    """

    marathon_configs = _get_marathon_configs()
    for marathon_config in marathon_configs:
        if 'use_token_auth' in marathon_config and 'marathon_username' in \
                marathon_config and 'marathon_password' in marathon_config:
            return marathon_config
    fail('Could not find token authenticated marathon instance!')


def _get_basic_authenticated_marathon():
    """
    the first configured marathon instance that has supplied credentials
    and is not token_auth
    :return:
    """

    marathon_configs = _get_marathon_configs()
    for marathon_config in marathon_configs:
        if 'use_token_auth' not in marathon_config and 'marathon_username' in \
                marathon_config and 'marathon_password' in marathon_config:
            return marathon_config
    fail('Could not find basic authenticated marathon instance!')


def get_marathon_url(auth_type=''):
    """

    :param auth_type:
    :return:
    """

    if auth_type == 'token':
        return _get_token_authenticated_marathon()['marathon_url']
    elif auth_type == 'basic':
        return _get_basic_authenticated_marathon()['marathon_url']
    else:
        # return the first one -- whatever that may be
        return _get_default_marathon()['marathon_url']


def _get_default_marathon():
    """

    :return:
    """

    config = infra_utils.get_config()
    return \
        config.testbed[config.site_name].cloud[0]['mesos_configuration']['marathon_configurations'][0]


def infer_auth_from_config(marathon_config):
    """

    :param marathon_config:
    :return:
    """

    if 'use_token_auth' in marathon_config and \
            marathon_config['use_token_auth']:
        return 'token'
    elif 'marathon_username' in marathon_config and \
                    'marathon_password' in marathon_config:
        return 'basic'
    else:
        return ''


def get_marathon_username(auth_type=''):
    """

    :param auth_type:
    :return:
    """

    if auth_type == 'token':
        return _get_token_authenticated_marathon()['marathon_username']
    elif auth_type == 'basic':
        return _get_basic_authenticated_marathon()['marathon_username']
    else:
        return ''


def get_marathon_password(auth_type=''):
    """

    :param auth_type:
    :return:
    """

    if auth_type == 'token':
        return _get_token_authenticated_marathon()['marathon_password']
    elif auth_type == 'basic':
        return _get_basic_authenticated_marathon()['marathon_password']
    else:
        return ''


def wait_for_healthy_app(app_name, timeout=900, no_healthcheck=True, **kwargs):
    """

    :param app_name:
    :param timeout:
    :param no_healthcheck:
    :param kwargs:
    :return:
    """

    app_obj = get_app(app_name, **kwargs)
    instances = app_obj['app']['instances']
    start_time = time.time()
    if no_healthcheck:
        while app_obj['app']['tasksRunning'] != instances:
            if time.time() - start_time > int(timeout):
                fail('app %s was not running in %d seconds' % (
                    app_name, int(timeout)))
            asleep(delay=15)
            app_obj = get_app(app_name, **kwargs)
    else:
        while (app_obj['app']['tasksRunning'] != instances or
               app_obj['app']['tasksHealthy'] != instances):
            if time.time() - start_time > int(timeout):
                fail('app %s was not healthy in %d seconds' % (
                    app_name, int(timeout)))
                asleep(delay=15)
            app_obj = get_app(app_name, **kwargs)


def get_app(app_name, **kwargs):
    """

    :param app_name:
    :param kwargs:
    :return: object representing app
    """

    if _is_mesos_cloud():
        return _get_mesos_app(app_name, **kwargs)
    elif _is_openshift_cloud():
        return _get_openshift_app(app_name, **kwargs)
    else:
        fail('Did not find a supported cloud object configuration in your '
             'topo_conf')


def _get_mesos_app(app_name, auth_type='', **kwargs):
    """

    :param app_name:
    :param auth_type:
    :param kwargs:
    :return:
    """

    if not auth_type:
        auth_type = infer_auth_from_config(_get_default_marathon())

    # hack to support generate_microservice_traffic with apps
    # in multiple marathons
    if auth_type == 'hybrid':
        try:
            auth_type = infer_auth_from_config(_get_default_marathon())
            username = kwargs.get('username', get_marathon_username(auth_type))
            password = kwargs.get('password', get_marathon_password(auth_type))
            return ma_utils.getAppInfo(
                get_marathon_url(auth_type), app_name, auth_type=auth_type,
                auth_token=get_mesos_auth_token(
                    auth_type=auth_type, username=username, password=password),
                username=username, password=password)
        except Exception as e:
            auth_type = 'token'
            username = kwargs.get('username', get_marathon_username(auth_type))
            password = kwargs.get('password', get_marathon_password(auth_type))
            return ma_utils.getAppInfo(
                get_marathon_url(auth_type), app_name, auth_type=auth_type,
                auth_token=get_mesos_auth_token(
                    auth_type=auth_type, username=username, password=password),
                username=username, password=password)
    else:
        username = kwargs.get('username', get_marathon_username(auth_type))
        password = kwargs.get('password', get_marathon_password(auth_type))
        return ma_utils.getAppInfo(
            get_marathon_url(auth_type), app_name, auth_type=auth_type,
            auth_token=get_mesos_auth_token(
                auth_type=auth_type, username=username, password=password),
            username=username, password=password)


def create_erdos_renyi_graph(app_name, num_apps, prob, num_edges, northsouth=0,
                             loops=False, load=100, ip_client=''):
    """

    :param app_name:
    :param num_apps:
    :param prob:
    :param num_edges:
    :param orthsouth:
    :param loops:
    :param load:
    :param ip_client:
    :return:
    """

    num_apps = int(num_apps)
    num_edges = int(num_edges)
    northsouth = int(northsouth)
    if prob:
        prob = float(prob)
    msvc_map = Graph.Erdos_Renyi(n=num_apps, m=num_edges, directed=True,
                                 loops=loops)
    for node in msvc_map.vs:
        node['name'] = '%s-%d' % (app_name, node.index + 1)
        node['obj_type'] = 'virtualservice'
    traffic = int(load)
    for edge in msvc_map.es:
        edge['load'] = traffic
        edge['blocked'] = False

    if not ip_client:
        return msvc_map
    msvc_map.add_vertex(ip_client, obj_type='vm')
    ''' adding edges for the client '''
    for node in msvc_map.vs:
        vindex = node.index
        if (msvc_map.vcount() - 1) == vindex:
            continue # don't add the client as a destination for itself
        if northsouth and (vindex % int(num_apps/northsouth) == 0):
            msvc_map.add_edge(msvc_map.vcount()-1, node.index,
                              load=load, blocked=False)
        elif vindex % 5 == 1:
            msvc_map.add_edge(msvc_map.vcount()-1, node.index, load=load,
                              blocked=False)
    logger.info('all msvc edges:')
    for edge in msvc_map.es:
        logger.info('edge: source %s ->target: %s' % (msvc_map.vs[edge.source]['name'], msvc_map.vs[edge.target]['name']))
    return msvc_map


def generate_microservice_traffic(msvc_map, auth_type='', **kwargs):
    """
    - gets information for all the nodes once
    - sends traffic for each edge.
    :param msvc_map:
    :param auth_type:
    :param kwargs:
    :return:
    """

    start_time = None
    check_vs_up = kwargs.get('check_vs_up', True)
    for node in msvc_map.vs:
        # clear all the stats.
        vs = node['name']
        vs_name = VS_PREFIX + vs
        tenant = node.attributes().get('tenant')
        if not tenant:
            tenant = get_tenant_for_container(**kwargs)
        if node['obj_type'] != 'virtualservice':
            node['listener_ports'] = None
            node['config'] = None
            node['app_info'] = None
            continue
        if check_vs_up:
            logger.trace('generate_microservice_traffic: checking for VS %s '
                         'in tenant %s' % (vs_name, tenant))
            vs_lib.check_vs_created(vs_name, num_tries=10, tenant=tenant)
        # clear_all_stats_for_vs(vs_name)
        if not start_time:
            start_time = metrics_lib.get_start_time(vs_name, tenant=tenant)
        listener_ports = \
            vs_lib.get_vs_listener_port_from_runtime(vs_name, tenant=tenant)
        node['listener_ports'] = listener_ports
        node['config'] = vs_lib.get_vs(vs_name, tenant=tenant)
        app_info = get_app(vs_name, auth_type=auth_type, tenant=tenant)
        node['app_info'] = app_info
        if not app_info:
            fail('app %s not present' % vs_name)
        logger.trace('generate_microservice_traffic: vs %s, tenant %s, app_info'
                     ' %s, listener_ports %s' % (vs_name, tenant, app_info,
                                                 listener_ports))

    load_override = int(kwargs.get('load', 0))
    path = kwargs.get('path', '')
    for edge in msvc_map.es:
        blocked = edge['blocked']
        load = edge['load']
        if not load:
            load = int(kwargs.get('count', 500))
        if load_override:
            load = load_override
        num_conns = int(max(20, load * 20/1000))
        time_to_sleep = min(400, int((load / 200) + 10))
        # first task in the source send traffic to the dst.
        src_node = msvc_map.vs[edge.source]
        target_node = msvc_map.vs[edge.target]
        target_vs = target_node['name']
        vip = target_node['config']['vip'][0]['ip_address']['addr']
        logger.debug('src: %s -> target: %s, vs: %s, load: %s, dports: %s, '
                     'vip: %s' % (
            src_node['name'], target_node['name'], target_vs, load,
            target_node['listener_ports'], vip))
        if src_node['obj_type'] != 'virtualservice':
            logger.debug('using vm client for traffic src %s' % (src_node['name']))
            for port in target_node['listener_ports']:
                ramp_up_httpperf_traffic(src_node['name'], target_vs,
                                         port, '/', num_conns, load,
                                         num_conns, vip, time_to_sleep)
            continue

        for task in src_node['app_info']['app']['tasks']:
            src_host = task['host']
            logger.debug('src_node: %s, task: %s, src_host: %s' %
                         (src_node['name'], task, src_host))
            is_target_ew = target_node['config'].get('east_west_placement',
                                                     True)
            logger.debug('target vs: %s, ports: %s, host: %s, vip: %s, ew: %s' %
                         (target_vs, target_node['listener_ports'], src_host, vip,
                          is_target_ew))
            filter = src_node['name']
            tenant = src_node.attributes().get('tenant', '')
            # REVIEW now that both mesos and openshift EW apps use ipam,
            # send to VIP always
            #if is_target_ew and not _is_openshift_cloud():
            #    ab_from_app('', target_node['listener_ports'], load,
            #                filter=filter, tenant=tenant, slave_host_ip=src_host,
            #                path=path, blocked=blocked)
            #else:
                # we need to send traffic to the north south
            ab_from_app('', target_node['listener_ports'], load,
                        filter=filter, tenant=tenant, slave_host_ip=src_host,
                        path=path, vip=vip, blocked=blocked)
    asleep(delay=10)
    return start_time

def ramp_up_httpperf_traffic(src_node_name, target_vs, port, path, rate, load,
                             num_conns, vip, time_to_sleep, ramp=True):
    """

    :param src_node_name:
    :param target_vs:
    :param port:
    :param path:
    :param rate:
    :param load:
    :param num_conns:
    :param vip:
    :param time_to_sleep:
    :param ramp:
    :return:
    """

    #bugger
    nintervals = 4 if ramp and num_conns > 2000 else 1
    time_to_sleep = int(time_to_sleep/nintervals)
    for index in xrange(1, nintervals + 1):
        rt = int(index*rate/nintervals)
        nc = int(index*num_conns/nintervals)
        performance_lib.start_httperf_on_client(
            src_node_name, target_vs, port, path, rt, load,
            nc, vip=vip)
        time.sleep(time_to_sleep)
        performance_lib.stop_httperf_on_client(src_node_name)


def ab_from_app(slave, port_list, count, filter='', tenant='',
                slave_host_ip='', path='index.html', vip='', blocked=False):
    """

    :param slave:
    :param port_list:
    :param count:
    :param filter:
    :param tenant:
    :param slave_host_ip:
    :param path:
    :param vip:
    :param blocked:
    :return:
    """

    nsent = 0
    n_errs = 0
    logger.info('ab_from_app: slave=%s, port_list=%s, count=%d, filter=%s, '
                'tenant=%s, slave_host=%s, vip=%s' % (
        slave, port_list, count, filter, tenant, slave_host_ip, vip))
    for port in port_list:
        #print 'ab_from_app Port ', str(port)
        logger.info('ab_from_app: port=%s' % port)
        conns = 100 if count >= 10000 else 1
        if not vip:
            ab_cmd = AB_CMD_TMPL.substitute(conns=conns,count=count, port=port,
                                            path=path)
        else:
            ab_cmd = AB_NS_TMPL.substitute(conns=conns, count=count, vip=vip,
                                           port=port, path=path)
        results = execute_command_on_container(
            slave, ab_cmd, image_name='avinetworks/server', filter=filter,
            tenant=tenant, slave_host_ip=slave_host_ip, expect_failure=blocked)
        #nsent = nsent + int(count)
        if not results:
            logger.info('No results found trying to run ab command %s on slave '
                        '%s' % (ab_cmd, slave_host_ip))
            fail('Could not find source container to send traffic')
        for out in results:
            num_errs, num_reqs = parse_ab_out(out[1])
            nsent += num_reqs
            n_errs += num_errs
            if num_errs and not blocked:
                logger.info(
                    'Failed cmd %s on slave %s with count %d nsent %d num_reqs '
                    '%d err %d out %s' % (ab_cmd, slave_host_ip, count, nsent,
                                          num_reqs, num_errs, out))
                fail('ab cmd %s on container %s @ %s had failures %s'
                                   % (ab_cmd, out[0], slave_host_ip, num_errs))
            if not num_reqs and not blocked:
                logger.info(
                    'No traffic sent: cmd %s on slave %s with count %d nsent '
                    '%d num_reqs %d err %d out %s' % (
                        ab_cmd, slave_host_ip, count, nsent, num_reqs,
                        num_errs, out))
        logger.info('Ran cmd %s count %s' % (ab_cmd, nsent))
        logger.info(
            'Ran cmd %s on slave %s with count %d sent %s err %s out %s' % (
                ab_cmd, slave_host_ip, count, nsent, n_errs, results))

    return nsent


def parse_ab_out(ab_out):
    """

    :param ab_out:
    :return:
    """
    num_errs = None
    num_reqs = None
    for line in ab_out:
        if line.startswith('Non-2xx responses:'):
            num_errs = int(line.split('Non-2xx responses:')[1])
        elif line.startswith('Complete requests:'):
            num_reqs = int(line.split('Complete requests:')[1])
        if (num_errs is not None) and (num_reqs is not None):
            break
    logger.info('ab out total reqs %s errors %s' % (num_reqs, num_errs))
    num_errs = 0 if num_errs is None else num_errs
    num_reqs = 0 if num_reqs is None else num_reqs
    return num_errs, num_reqs


def execute_command_on_container(
        slave_id, cmd, image_name='', filter='', tenant='', slave_host_ip='',
        expect_failure=False, privileged=False):
    """

    :param slave_id:
    :param cmd:
    :param image_name:
    :param filter:
    :param tenant:
    :param slave_host_ip:
    :param expect_failure:
    :param privileged:
    :return:
    """

    privilege_flag = '--privileged' if privileged else ''
    return execute_docker_command_on_container(
        slave_id, image_name=image_name,
        docker_cmd="sudo docker exec -it %s ${docker_id} bash -c '%s'" % (
            privilege_flag, cmd),
        filter=filter, tenant=tenant, slave_host_ip=slave_host_ip,
        expect_failure=expect_failure)


def execute_docker_command_on_container(
        slave_id, image_name, docker_cmd, filter='', tenant='',
        slave_host_ip='', expect_failure=False):
    """

    :param slave_id:
    :param image_name:
    :param docker_cmd:
    :param filter:
    :param tenant:
    :param slave_host_ip:
    :param expect_failure:
    :return:
    """

    docker_ids = get_container_ids(slave_id, slave_host_ip, image_name)
    logger.info('Found container docker_ids %s on slave host %s' % (
        docker_ids, slave_host_ip))

    if _is_mesos_cloud():
        grep_template = MESOS_CONTAINER_GREP
    elif _is_openshift_cloud():
        grep_template = OPENSHIFT_CONTAINER_GREP

    results = []
    for docker_id in docker_ids:
        filter_cmd = grep_template.substitute(docker_id=docker_id,
                                              app_name=filter, tenant=tenant)
        filter_out = execute_command_on_slave(slave_id, slave_host_ip,
                                              filter_cmd)
        if filter_out:
            logger.info('Found matching container with command %s, out=%s' % (
                filter_cmd, filter_out))
            docker_cmd = docker_cmd.replace('${docker_id}', docker_id)
            logger.info('docker id %s docker_cmd %s' % (docker_id, docker_cmd))
            out = execute_command_on_slave(
                slave_id, slave_host_ip, docker_cmd, warn_only=expect_failure)
            results.append(out)
    if not results:
        logger.warning('No matching containers found for filter %s on slave %s '
                    'with docker ids %s' % (filter, slave_host_ip, docker_ids))
        for docker_id in docker_ids:
            inspect_cmd = "docker inspect --format '{{.Config.Env}}' %s" % \
                          docker_id
            out = execute_command_on_slave(slave_id, slave_host_ip,
                                           inspect_cmd)
            logger.info('inspect for docker_id %s: %s' % (docker_id, out))
    return zip(docker_ids, results)


def get_container_ids(slave_id, slave_host_ip, image_name, **kwargs):
    """

    :param slave_id:
    :param slave_host_ip:
    :param image_name:
    :return:
    """

    cmd = 'sudo docker ps | grep ' + image_name
    out = execute_command_on_slave(slave_id, slave_host_ip, cmd, **kwargs)
    #logger.info('%s got output %s' % (cmd, out))
    logger.info('cmd %s out %s' % (cmd, out))
    logger.info('-------')
    docker_ids = []
    for line in out:
        m = re.search('(\S+)\s+', line)
        if m:
            docker_ids.append(m.group(1))
    logger.info('docker ids %s' % docker_ids)
    return docker_ids


def execute_command_on_slave(slave_id, slave_host_ip, cmd, warn_only=True,
                             **kwargs):
    """

    :param slave_id:
    :param slave_host_ip:
    :param cmd:
    :param warn_only:
    :param kwargs:
    :return:
    """

    if slave_host_ip:
        config = infra_utils.get_config()
        if 'ssh_password' in kwargs:
            password = kwargs.get('ssh_password')
        elif _is_openshift_cloud() and config.testbed[config.site_name].cloud[0][
            'oshiftk8s_configuration']['ssh_user_uuid'] == 'root':
            password = 'avi123'
        else:
            password = 'aviuser'
        r = execute(_fab_exec, cmd, warn_only=warn_only,
                    ssh_password=password, hosts=[slave_host_ip])
        out = r[slave_host_ip].split('\n') if r[slave_host_ip] else ''
    elif slave_id:
        slave = infra_utils.get_vm_by_id(slave_id)
        out = slave.execute_command(cmd, noerr=warn_only)
    else:
        slave = infra_utils.get_vm_of_type('client')[0]
        out = slave.execute_command(cmd, noerr=warn_only)

    logger.info('cmd %s on slave returned:' % (cmd))
    for line in out:
        logger.info('%s >>> %s' % (slave_host_ip, line))
    return out


def validate_microservice_traffic(msvc_map, start_time):
    """

    :param msvc_map:
    :param start_time:
    :return:
    """

    # we need to resolve why SE state is not synced
    asleep(delay=15)
    logger.debug('validating msvc_map with start %s' % start_time)
    for edge in msvc_map.es:
        source_vs_name = VS_PREFIX + msvc_map.vs[edge.source]['name']
        source_vs_tenant = msvc_map.vs[edge.source].attributes().get('tenant')
        target_vs_name = VS_PREFIX + msvc_map.vs[edge.target]['name']
        target_vs_tenant = msvc_map.vs[edge.target].attributes().get('tenant')
        src_node = msvc_map.vs[edge.source]
        if src_node['obj_type'] != 'virtualservice':
            logger.debug('skipping src %s' % src_node['name'])
            continue
        #source_vs_config = msvc_map.vs[edge.source]['config']
        target_vs_config = msvc_map.vs[edge.target]['config']
        if not target_vs_config.get('east_west_placement', True):
            # if target is north south then only edge is 0.0.0.0
            continue

        check_microservice_metrics(
            source_vs_name, target_vs_name, source_vs_tenant=source_vs_tenant,
            target_vs_tenant=target_vs_tenant, start=start_time, limit=360,
            blocked=edge['blocked'], load=edge['load'],
            dimension_aggregation='avg', pad_missing_data=False)


def check_microservice_metrics(src_vs, dst_vs, **kwargs):
    """

    :param src_vs:
    :param dst_vs:
    :param kwargs:
    :return:
    """

    tenant = get_tenant_for_container(**kwargs)
    # can't use get(_, tenant) since it just returns None
    src_vs_tenant = kwargs.get('source_vs_tenant')
    if not src_vs_tenant:
        src_vs_tenant = tenant
    dst_vs_tenant = kwargs.get('target_vs_tenant')
    if dst_vs_tenant:
        tenant = dst_vs_tenant
    elif not dst_vs_tenant:
        dst_vs_tenant = tenant
    if 'step' not in kwargs:
        kwargs['step'] = 5
    logger.debug('check_microservice_metrics %s -> %s kwargs %s' % (
              src_vs, dst_vs, str(kwargs)))
    old_tenant = infra_utils.get_config().get_mode(key='tenant')
    infra_utils.switch_mode(tenant=tenant)
    mapi_test = metrics_lib.get_metrics_api_tests()
    infra_utils.switch_mode(tenant=src_vs_tenant)
    src_vs_uuid = rest.get_uuid_by_name('virtualservice', src_vs)
    infra_utils.switch_mode(tenant=dst_vs_tenant)
    dst_vs_uuid = rest.get_uuid_by_name('virtualservice', dst_vs)

    kwargs['dimension_aggregation'] = 'sum'
    mapi_test.microserviceEdgeTrafficCheck(src_vs_uuid, dst_vs_uuid,
                                           **kwargs)
    infra_utils.switch_mode(tenant=old_tenant)


def delete_app(app_name, force=False, verify_dns=True, dns_suffix='',
               **kwargs):
    """
    Delete app named app_name or a sequence of num_apps prefixed with app_name
    :param app_name:
    :param force:
    :param verify_dns:
    :param dns_suffix:
    :param kwargs:
    :return:
    """

    tenant = get_tenant_for_container(**kwargs)
    kwargs.pop('tenant', '')
    if _is_mesos_cloud():
        app_ids = _delete_mesos_app(app_name, **kwargs)
    elif _is_openshift_cloud():
        app_ids = _delete_openshift_app(app_name, tenant=tenant, **kwargs)
    else:
        fail('Did not find a supported cloud object configuration in your '
             'topo_conf')

    vs_lib.check_for_vs(app_ids, check_present=False, verify_dns=verify_dns,
                 dns_suffix=dns_suffix, tenant=tenant, **kwargs)
    if not force:
        return
    # cleanup all the other objects.
    for app in app_ids:
        ro = 'networksecuritypolicy'
        ro_name = app + '-' + ro
        logger.info('cleanup app %s obj %s/%s' % (app, ro, ro_name))
        try:
            http_code, rsp = rest.get(ro, name=ro_name)
            if http_code < 299:
                logger.info('deleting ro %s %s' % (ro, ro_name))
                rest.delete(ro, name=ro_name)
        except Exception as e:
            logger.debug('cleanup of networksecuritypolicy failed with %s' % str(e))
        try:
            try:
                http_code, rsp = rest.get('microservicegroup', name='vs-msg-%s' % app)
            except:
                logger.info('deleting msg %s rsp %s' % (ro_name, rsp.text))
                rest.delete('microservicegroup', name='vs-msg-%s' % app)
        except Exception as e:
            logger.debug('cleanup of microservicegroup failed with %s' % str(e))
        ro = 'microservice'
        ro_name = app + '-' + 'microservice'
        try:
            try:
                http_code, rsp = rest.get('microservice', name=ro_name)
            except:
                logger.info('deleting ro %s msg %s rsp %s' % (
                    ro, ro_name, rsp.text))
                rest.delete('microservice', name=ro_name)
        except Exception as e:
            logger.debug('cleanup of microservice failed with %s' % str(e))


def _delete_mesos_app(app_name, auth_type='', num_apps=1, **kwargs):
    """

    :param app_name:
    :param auth_type:
    :param num_apps:
    :param kwargs:
    :return:
    """

    if not auth_type:
        auth_type = infer_auth_from_config(_get_default_marathon())
    app_ids = ma_utils.deleteApp(
        get_marathon_url(auth_type), app_name, num_apps=int(num_apps),
        auth_type=auth_type, auth_token=get_mesos_auth_token(
            auth_type=auth_type), username=get_marathon_username(auth_type),
        password=get_marathon_password(auth_type))
    return app_ids


def add_edge(adj_list, source, target, source_tenant='', target_tenant='',
             load=100, blocked=False, src_type='virtualservice'):
    """

    :param adj_list:
    :param source:
    :param target:
    :param source_tenant:
    :param target_tenant:
    :param load:
    :param blocked:
    :param src_type:
    :return:
    """

    adj_tuple = source, source_tenant, target, target_tenant, int(load), blocked, src_type
    adj_list.append(adj_tuple)
    return adj_list


def create_microservice_map(adj_list=None, **kwargs):
    """
    It would build a igraph based on that which it would use
    for generating traffic and validation.
    :param adj_list: the list adjacency list of Tuples src, dst,
    amount of traffic
    :param kwargs:
    :return:
    """

    if not adj_list:
        adj_list = []

    msvc_map = Graph(directed=True)
    for edge in adj_list:
        source = edge[0]
        source_tenant = edge[1]
        target = edge[2]
        target_tenant = edge[3]
        if edge[4]:
            traffic = int(edge[4])
        else:
            traffic = int(kwargs.get('count', 2000))
        blocked = edge[5]
        src_type = edge[6]
        if not msvc_map.vcount():
            msvc_map.add_vertex(source)
        else:
            try:
                msvc_map.vs.find(name_eq=source)
            except ValueError:
                msvc_map.add_vertex(source)
        source_index = msvc_map.vs.find(source).index
        source_node = msvc_map.vs.find(name_eq=source)
        source_node['obj_type'] = src_type
        source_node['tenant'] = source_tenant
        try:
            msvc_map.vs.find(name_eq=target)
        except ValueError:
            msvc_map.add_vertex(target)
            target_node = msvc_map.vs.find(name_eq=target)
            target_node['obj_type'] = 'virtualservice'
            target_node['tenant'] = target_tenant
        target_index = msvc_map.vs.find(target).index
        msvc_map.add_edge(source_index, target_index, load=traffic,
                          blocked=blocked)
        logger.info('added edge: %s . %s -> %s . %s' % (source, source_tenant,
                                                       target, target_tenant))

    return msvc_map


def set_app_analytics_policy(vs_name, l7=True, realtime=True, timeout=120,
                             **kwargs):
    """

    :param vs_name:
    :param l7:
    :param realtime:
    :param timeout:
    :param kwargs:
    :return:
    """

    tenant = get_tenant_for_container(**kwargs)
    if l7 == 'on':
        app_profile_ref = rest.get_obj_ref(
            'applicationprofile', 'System-HTTP', tenant=tenant)
    else:
        app_profile_ref = rest.get_obj_ref(
            'applicationprofile', 'System-L4-Application', tenant=tenant)
    print 'app-prof = ', app_profile_ref
    _, vs_obj = rest.get('virtualservice', name=vs_name)
    vs_obj['application_profile_ref'] = app_profile_ref
    if 'analytics_policy' not in vs_obj:
        vs_obj['analytics_policy'] = {}
    apolicy = vs_obj['analytics_policy']
    apolicy['metrics_realtime_update'] = {}
    if realtime:
        apolicy['metrics_realtime_update']['enabled'] = True
        apolicy['metrics_realtime_update']['duration'] = 0
    else:
        apolicy['metrics_realtime_update']['enabled'] = False
        apolicy['metrics_realtime_update']['duration'] = 0

    update_app(vs_name, vs_obj=vs_obj, **kwargs)
    # Change time wait to atleast 60 secs which is the default
    #  app sync frequency in case marathon is not set up with
    #  http callback
    asleep(delay=timeout)
    _, vs_obj = rest.get('virtualservice', name=vs_name)
    assert (vs_obj['application_profile_ref'] == app_profile_ref)
    assert (vs_obj['analytics_policy']['metrics_realtime_update']['enabled'] ==
            apolicy['metrics_realtime_update']['enabled'])


def update_app(app_name, **kwargs):
    """
    updates the app_obj['app']['labels']['avi_proxy']['virtualservice']
    based on provided vs_obj or k,v from kwargs
    :param app_name:
    :param kwargs:
    :return:
    """

    if _is_mesos_cloud():
        return _update_marathon_app(app_name, **kwargs)
    elif _is_openshift_cloud():
        return _update_openshift_app(app_name, **kwargs)
    else:
        fail('Did not find a supported cloud object configuration in '
             'your topo_conf')


def _update_marathon_app(app_name, auth_type='', **kwargs):
    """

    :param app_name:
    :param auth_type:
    :param kwargs:
    :return:
    """
    if not auth_type:
        auth_type = infer_auth_from_config(_get_default_marathon())
    version = read_version()
    return ma_utils.updateApp(
        get_marathon_url(auth_type), app_name, auth_type=auth_type,
        auth_token=get_mesos_auth_token(auth_type=auth_type),
        username=get_marathon_username(auth_type),
        password=get_marathon_password(auth_type), avi_version=version,
        **kwargs)


def remove_container_cloud_config(**kwargs):
   """

   :param kwargs:
   :return:
   """

   cloud_name = kwargs.get('cloud_name', 'Default-Cloud')

   cloud = {}
   cloud['name'] = cloud_name
   cloud['vtype'] = 'CLOUD_NONE' # common_pb2.CLOUD_NONE
   cloud['license_type'] = 'LIC_CORES' #options_pb2.LIC_CORES

   # hack: cannot clear the ipam profiles yet, because some VSes (
   # e.g. the built in kubernetes) may still exist
   # the refs aren't resolved by json2pb back to uuids so
   # explicitly re-setting them
   # REVIEW only works if the ipam names are as the default ones created,
   # else we really need to get them from the json2pb
   if _is_openshift_cloud() or _is_mesos_cloud():
       cloud['dns_provider_ref'] = '%s%s' % (IPAM_PROFILE_PREFIX, IPAM_NS_DNS)
       cloud['ipam_provider_ref'] = '%s%s' % (IPAM_PROFILE_PREFIX, IPAM_NS)
       cloud['east_west_dns_provider_ref'] = '%s%s' % (IPAM_PROFILE_PREFIX, IPAM_EW_DNS)
       cloud['east_west_ipam_provider_ref'] = '%s%s' % (IPAM_PROFILE_PREFIX, IPAM_EW)

   rest.put('cloud', name=cloud_name, data=cloud)

   round_timeout = 20 #seconds
   start = time.time()
   remaining_ses = None
   while (time.time() - start) < 600:
       status, rsp = rest.get('serviceengine')
       remaining_ses = rsp['count']
       if remaining_ses == 0:
           logger.info("All SEs deleted after %d seconds!" %
                       int(time.time()-start))
           break
       else:
           logger.info("SEs: %s" % rsp['results'])
           asleep(delay=round_timeout)
   if remaining_ses > 0:
       logger.warning("%s SEs still not cleaned up after 3 minutes, giving up!" %
                   remaining_ses)

   # REVIEW  make sure we have enough time to clean up openshift objects,
   # if the SE deletion was really fast (e.g. the test didn't create any SEs
   if time.time() - start < 30:
       time_to_sleep = 30 - (time.time() - start)
       logger.info('Remove cloud config: sleeping an additional %d seconds to '
                   'allow background autodelete to complete' % time_to_sleep)
       asleep(delay=time_to_sleep)
   # clean up any other ipam/networks
   cloud.pop("dns_provider_ref")
   cloud.pop('ipam_provider_ref')
   cloud.pop('east_west_dns_provider_ref')
   cloud.pop('east_west_ipam_provider_ref')
   rest.put('cloud', name=cloud_name, data=cloud)

   if _is_openstack_testbed():
       ipam_lib.delete_ipam_profile(OPENSTACK_IPAM_NAME)

   ipam_lib.delete_ipam_profile(IPAM_NS)
   ipam_lib.delete_ipam_profile(IPAM_NS_DNS)
   ipam_lib.delete_ipam_profile(IPAM_EW)
   ipam_lib.delete_ipam_profile(IPAM_EW_DNS)
   nw_delete = kwargs.get("nw_delete", True)
   if nw_delete:
       network_lib.network_delete('north_south_network')
       network_lib.network_delete('east_west_network')
   if _is_openshift_cloud():
       common.delete_cert_and_key_if_seen('client_cert')
       common.delete_cert_and_key_if_seen('ca_cert')
   if cloud_name != 'Default-Cloud':
       rest.delete('cloud', name=cloud_name)


def _delete_all_openshift_apps():
    return oshift_utils.delete_all_openshift_apps()


def delete_all_apps(verify_vs=False, **kwargs):
    """

    :param verify_vs:
    :param kwargs:
    :return:
    """

    tenant = get_tenant_for_container(**kwargs)
    if _is_mesos_cloud():
        app_ids = _delete_all_mesos_apps()
    elif _is_openshift_cloud():
        app_ids = _delete_all_openshift_apps()
    else:
        fail('Did not find a supported cloud object configuration in your '
             'topo_conf')
    if verify_vs:
        vs_lib.check_for_vs(app_ids, check_present=False, tenant=tenant)


def _delete_all_mesos_apps():
    marathon_configs = _get_marathon_configs()
    app_ids = []
    for marathon_config in marathon_configs:
        app_ids = app_ids + _delete_all_mesos_apps_in_marathon(marathon_config)
    return app_ids


def _delete_all_mesos_apps_in_marathon(marathon_config):
    auth_type = infer_auth_from_config(marathon_config)
    app_infos = ma_utils.getAppInfos(
        marathon_config['marathon_url'], auth_type=auth_type,
        auth_token=get_mesos_auth_token(auth_type=auth_type),
        username=get_marathon_username(auth_type),
        password=get_marathon_password(auth_type))
    logger.info('found %i apps and deleting them' % len(app_infos['apps']))
    app_ids = []
    for app_info in app_infos['apps']:
        app_name = str(app_info['id'])  # maybe should encode('utf-8') instead?
        # ignore special marker for marathon instances
        if app_name.startswith('/marathon'):
            continue

        # seems like this is irrelevant to the delete
        app_count = int(app_info['instances'])
        logger.info('deleting app %s with %i instances' % (app_name, app_count))
        app_ids = app_ids + ma_utils.deleteApp(
            marathon_config['marathon_url'], app_name, num_apps=1,
            auth_type=auth_type,
            auth_token=get_mesos_auth_token(auth_type=auth_type),
            username=get_marathon_username(auth_type),
            password=get_marathon_password(auth_type))
    return app_ids


def check_vs_pool_and_ms(vs_name, proxy_timeout=70, **kwargs):
    """
    ported keyword from test suite because we need to deal with tenants
    :param vs_name:
    :param proxy_timeout:
    :param kwargs:
    :return:
    """

    # REVIEW should this go in vs_lib? does something similar already exist?
    northsouth = int(kwargs.get('northsouth', 0))
    tenant = get_tenant_for_container(**kwargs)
    verify_ms = kwargs.get('verify_ms', True)
    vs_lib.check_for_vs([vs_name], tenant=tenant)
    vs_lib.pool_should_be_up_from_vs_runtime(vs_name, tenant=tenant)
    pool_name = vs_lib.get_vs_default_pool_name(vs_name, tenant=tenant)
    start = time.time()
    elapsed = 0
    while elapsed <= proxy_timeout:
        task_count = get_app_task_count(vs_name, **kwargs)
        pool_servers = pool_lib.pool_get_server_count(pool_name, tenant=tenant)
        expected_instances = get_app_configured_instances(vs_name, **kwargs)
        if task_count == pool_servers and task_count == expected_instances:
            break
        else:
            asleep(delay=5)
            elapsed = int(time.time() - start)
    if task_count != pool_servers:
        fail('Task count %s does not equal pool servers %s' % (
            task_count, pool_servers))
    if task_count != expected_instances:
        fail('Task count %s does not equal app instances %s' % (
            task_count, expected_instances))
    if verify_ms:
        ms_lib.check_ms(vs_name + '-microservice', pool_name, tenant=tenant)
    if not northsouth:
        ms_lib.verify_ew_vs_placement(vs_name, tenant=tenant)


def get_app_task_count(app_name, **kwargs):
    """

    :param app_name:
    :param kwargs:
    :return:
    """

    app_info = get_app(app_name, **kwargs)
    return len(app_info['app']['tasks'])


def get_app_configured_instances(app_name, **kwargs):
    """

    :param app_name:
    :param kwargs:
    :return:
    """

    app_info = get_app(app_name, **kwargs)
    return int(app_info['app']['instances'])


def scale_up_app(app_name, **kwargs):
    """

    :param app_name:
    :param kwargs:
    :return:
    """

    app_obj = get_app(app_name, **kwargs)
    instances = int(app_obj['app']['instances'])
    _update_app_config(app_name, instances=(instances+1), **kwargs)


def _update_app_config(app_name, **kwargs):
    """
    updates the any toplevel field based on k,v from kwargs
    includes scaleup/scaledown, with instances argument
    :param app_name:
    :param kwargs:
    :return:
    """

    if _is_mesos_cloud():
        return _update_marathon_app_config(app_name, **kwargs)
    elif _is_openshift_cloud():
        return _update_openshift_app_config(app_name, **kwargs)
    else:
        fail('Did not find a supported cloud object configuration in your '
             'topo_conf')


def _update_marathon_app_config(app_name, auth_type='', **kwargs):
    """

    :param app_name:
    :param auth_type:
    :param kwargs:
    :return:
    """

    if not auth_type:
        auth_type = infer_auth_from_config(_get_default_marathon())
    return ma_utils.updateAppConfig(
        get_marathon_url(auth_type), app_name, auth_type=auth_type,
        auth_token=get_mesos_auth_token(auth_type=auth_type),
        username=get_marathon_username(auth_type),
        password=get_marathon_password(auth_type), **kwargs)


def scale_down_app(app_name, **kwargs):
    """

    :param app_name:
    :param kwargs:
    :return:
    """

    app_obj = get_app(app_name, **kwargs)
    instances = int(app_obj['app']['instances'])
    _update_app_config(app_name, instances=(instances-1), **kwargs)


def restart_app(app_name, **kwargs):
    """

    :param app_name:
    :param kwargs:
    :return:
    """

    if _is_mesos_cloud():
        return _restart_marathon_app(app_name, **kwargs)
    # elif _is_openshift_cloud():
    #     return _restart_openshift_app(app_name, **kwargs)
    else:
        fail('Did not find a supported cloud object configuration in your '
             'topo_conf')


def _restart_marathon_app(app_name, auth_type=''):
    """

    :param app_name:
    :param auth_type:
    :return:
    """

    if not auth_type:
        auth_type = infer_auth_from_config(_get_default_marathon())
    return ma_utils.restartApp(
        get_marathon_url(auth_type), app_name, auth_type=auth_type,
        auth_token=get_mesos_auth_token(auth_type=auth_type),
        username=get_marathon_username(auth_type),
        password=get_marathon_password(auth_type))


def update_app_analytics_policy(app_name, enable=True, **kwargs):
    """

    :param app_name:
    :param enable:
    :param kwargs:
    :return:
    """

    #app_obj = get_app(app_name, **kwargs)
    # Set duration to 30 to make sure that mesos_agent sets it to 0
    analytics_policy = {'full_client_logs':
                            {'enabled': enable,
                             'duration': 30}
                        }
    update_app(app_name, analytics_policy=analytics_policy, **kwargs)


def update_container_cloud(**kwargs):
    """

    :param kwargs:
    :return:
    """

    config = infra_utils.get_config()
    cloud_object = config.testbed[config.site_name].cloud[0]
    if _is_mesos_cloud():
        cloud = update_mesos_cloud(cloud_object['mesos_configuration'], **kwargs)
    # elif _is_openshift_cloud():
    #     cloud = update_openshift_cloud(cloud_object.oshiftk8s_configuration, **kwargs)
    else:
        fail('Did not find a supported cloud object configuration in your '
             'topo_conf')


def update_mesos_cloud(mesos_config, **kwargs):
    """

    :param mesos_config:
    :param kwargs:
    :return:
    """

    cloud_name = kwargs.get('cloud_name', 'Default-Cloud')
    status_code, cloud = rest.get('cloud', name=cloud_name)

    if not mesos_config:
        fail('No mesos config found in cloud_object section of your topo_conf')

    # the refs aren't resolved by json2pb back to uuids so
    # explicitly re-setting them
    # REVIEW only works if the ipam names are as the default ones created,
    # else we really need to get them from the json2pb
    cloud['dns_provider_uuid'] = rest.get_uuid_by_name('ipamdnsproviderprofile', IPAM_NS_DNS)
    cloud['ipam_provider_uuid'] = rest.get_uuid_by_name('ipamdnsproviderprofile', IPAM_NS)
    cloud['east_west_dns_provider_uuid'] = rest.get_uuid_by_name('ipamdnsproviderprofile', IPAM_EW_DNS)
    cloud['east_west_ipam_provider_uuid'] = rest.get_uuid_by_name('ipamdnsproviderprofile', IPAM_EW)

    ''' update_marathon_public_private_port_range '''
    # review should probably get the value from the testbed config if exists,
    # rather than these defaults
    public_start_index = int(kwargs.get('public_start_index', 10000))
    public_end_index = int(kwargs.get('public_end_index', 20000))
    private_start_index = int(kwargs.get('private_start_index', 30000))
    private_end_index = int(kwargs.get('private_end_index', 60000))
    marathon_configuration = \
        cloud['mesos_configuration']['marathon_configurations'][0]
    if 'public_port_range' not in marathon_configuration:
        marathon_configuration['public_port_range'] = {}
    if 'private_port_range' not in marathon_configuration:
        marathon_configuration['private_port_range'] = {}
    marathon_configuration['public_port_range']['start'] = public_start_index
    marathon_configuration['public_port_range']['end'] = public_end_index
    marathon_configuration['private_port_range']['start'] = private_start_index
    marathon_configuration['private_port_range']['end'] = private_end_index

    ''' update se docker repository credentials '''
    repo_username = kwargs.get('repo_username', None)
    repo_password = kwargs.get('repo_password', None)
    registry = kwargs.get('registry', None)
    disable_docker_repo = kwargs.get('disable_docker_repo', False)
    if registry:
        cloud['mesos_configuration']['docker_registry_se']['registry'] = \
            registry
    else:
        cloud['mesos_configuration']['docker_registry_se']['registry'] = \
            mesos_config['docker_registry_se']['registry']

    if repo_username and repo_password:
        cloud['mesos_configuration']['docker_registry_se']['username'] = \
            repo_username
        cloud['mesos_configuration']['docker_registry_se']['password'] = \
            repo_password
    elif 'username' in mesos_config['docker_registry_se'] and 'password' \
            in mesos_config['docker_registry_se']:
        cloud['mesos_configuration']['docker_registry_se']['username'] = \
            mesos_config['docker_registry_se']['username']
        cloud['mesos_configuration']['docker_registry_se']['password'] = \
            mesos_config['docker_registry_se']['password']

    if disable_docker_repo:
        cloud['mesos_configuration']['docker_registry_se'][
            'se_repository_push'] = False
    else:
        cloud['mesos_configuration']['docker_registry_se'][
            'se_repository_push'] = True
    ssh_user_uuid = kwargs.get('ssh_user_uuid', None)
    if ssh_user_uuid:
        cloud['mesos_configuration']['ssh_user_ref'] = ssh_user_uuid
    elif 'ssh_user_uuid' in mesos_config:
        cloud['mesos_configuration']['ssh_user_ref'] = \
            mesos_config['ssh_user_uuid']
    else:
        cloud['mesos_configuration']['ssh_user_ref'] = rest.get_uuid_by_name('cloudconnectoruser', 'aviuser')

    ''' update mesos auto service sync '''
    disable_auto_frontend_service_sync = \
        kwargs.get('disable_auto_frontend_service_sync', None)
    disable_auto_backend_service_sync = \
        kwargs.get('disable_auto_backend_service_sync', None)
    if disable_auto_frontend_service_sync:
        cloud['mesos_configuration']['disable_auto_frontend_service_sync'] = \
            True
    else:
        del cloud['mesos_configuration']['disable_auto_frontend_service_sync']

    if disable_auto_backend_service_sync:
        cloud['mesos_configuration']['disable_auto_backend_service_sync'] = \
            True
    else:
        del cloud['mesos_configuration']['disable_auto_backend_service_sync']

    cloud['mesos_configuration']['app_sync_frequency'] = 15

    se_include_attribute = kwargs.get('se_include_attribute', None)
    se_exclude_attribute = kwargs.get('se_exclude_attribute', None)
    if se_include_attribute:
        cloud['mesos_configuration']['se_include_attributes'] = []
        se_include = {}
        se_include_attribute_kv = se_include_attribute.split(':')
        se_include['attribute'] = se_include_attribute_kv[0]
        se_include['value'] = se_include_attribute_kv[1]
        cloud['mesos_configuration']['se_include_attributes'].append(
            se_include)
    elif 'se_include_attributes' in cloud:
        del cloud['se_include_attributes']
    if se_exclude_attribute:
        cloud['mesos_configuration']['se_exclude_attributes'] = []
        se_exclude = {}
        se_exclude_attribute_kv = se_exclude_attribute.split(':')
        se_exclude['attribute'] = se_exclude_attribute_kv[0]
        se_exclude['value'] = se_exclude_attribute_kv[1]
        cloud['mesos_configuration']['se_exclude_attributes'].append(
            se_exclude)
    elif 'se_exclude_attributes' in cloud:
        del cloud['se_exclude_attributes']

    # REVIEW would like to just return cloud here and have the parent
    # function do the update, which also lets the openshift update share
    # the code, but the verifications below need the info above, so
    # keep things together for now
    uuid = rest.get_uuid_by_name('cloud', 'Default-Cloud')
    rest.put('cloud', uuid=uuid, data=cloud)
    # REVIEW need to sleep a little bit to wait for the cloud to actually update else we just get the same state
    asleep(delay=5)
    cloud_create_timeout = kwargs.get('cloud_create_timeout',
                                      CLOUD_CREATE_TIMEOUT)
    try:
        _check_cloud_state('CLOUD_STATE_PLACEMENT_READY',
                           timeout=int(cloud_create_timeout))
    except Exception as e:
        fail('Cloud could not be configured %s' % str(e))

    status_code, response = rest.get('cloud', name=cloud_name)

    ''' Verify marathon public and private port range configuration '''
    marathon_configuration = \
        response['mesos_configuration']['marathon_configurations'][0]
    if not (marathon_configuration['public_port_range']['start'] ==
                public_start_index and marathon_configuration[
        'public_port_range']['end'] == public_end_index and
                    marathon_configuration['private_port_range']['start'] ==
                    private_start_index and marathon_configuration[
        'private_port_range']['end'] == private_end_index):
        fail('Public private port range are not updated')

    ''' Verify se docker repository credentials '''
    docker_repo_configuration = \
        response['mesos_configuration']['docker_registry_se']
    if repo_username and docker_repo_configuration['username'] != \
            repo_username:
        fail('Se docker credentials are not updated')
    if registry and docker_repo_configuration['registry'] != registry:
        fail('Docker registry is not updated')
    if bool(docker_repo_configuration['se_repository_push']) == \
            disable_docker_repo:
        fail('Se repository push is not updated')

    ''' Verify mesos auto service sync '''
    mesos_configuration = response['mesos_configuration']
    if disable_auto_frontend_service_sync and not \
            mesos_configuration['disable_auto_frontend_service_sync']:
        fail('Disable auto frontend service_sync is not updated')
    if disable_auto_backend_service_sync and not \
            mesos_configuration['disable_auto_backend_service_sync']:
        fail('Disable auto backend service_sync is not updated')


def check_ses_on_all_slaves():
    """

    :return:
    """

    num_slaves = get_active_slave_count_from_master()
    check_for_n_ses(num_slaves)


def check_for_n_ses(n):
    """

    :param n:
    :return:
    """

    num_ses_expected = int(n)
    # REVIEW this may be the same as wait_for_n_ses (se_connected=true vs
    # oper_status.state=OPER_UP)
    connected_ses = len(se_lib.get_connected_se_names())
    assert num_ses_expected == connected_ses, 'check for %d SEs, but got %d' % \
                                              (num_ses_expected, connected_ses)

# Deprecated. We create with json for the dns vs in the tests now
'''
def create_dns_vs_if_appropriate(dns_vs_name, **kwargs):
    """

    :param dns_vs_name:
    :return:
    """

    if _is_aws_testbed() or _is_openstack_testbed():
        # see AV-15393
        return
    else:
        # REVIEW is there a better static ip to use?
        dns_vs_vip = construct_vip_in_se_subnet(250)
        vs_lib.create_virtual_service('dns', name=dns_vs_name, network='net1',
                               ip_address_addr=dns_vs_vip, **kwargs)
        system_lib.set_dns_vs_system_configuration(dns_vs_name)
'''

def construct_vip_in_se_subnet(vip_octet):
    """

    :param vip_octet:
    :return:
    """

    slaves = get_active_slaves_ips()
    return construct_vip_in_subnet(slaves[0], vip_octet)


def construct_vip_in_subnet(subnet_ip, vip_octet):
    """

    :param subnet_ip:
    :param vip_octet:
    :return:
    """

    subnet_parts = subnet_ip.split('.')[:-1]
    subnet_parts.append(str(vip_octet))
    return '.'.join(subnet_parts)


def get_dns_vs_vip_if_exists(dns_vs_name, tenant='admin'):
    """

    :param dns_vs_name:
    :param tenant:
    :return:
    """

    try:
        return vs_lib.vs_get_vip(dns_vs_name, tenant=tenant)
    except RuntimeError:
        return None


def update_app_app_profile(vs_name, app_profile_name, timeout=120, **kwargs):
    """

    :param vs_name:
    :param app_profile_name:
    :param timeout:
    :param kwargs:
    :return:
    """

    tenant = get_tenant_for_container(**kwargs)
    app_profile_ref = rest.get_obj_ref(
            'applicationprofile', app_profile_name, tenant=tenant)
    logger.debug('app profile: %s = %s' % (app_profile_name, app_profile_ref))
    _, vs_obj = rest.get('virtualservice', name=vs_name)
    vs_obj['application_profile_ref'] = app_profile_ref

    update_app(vs_name, vs_obj=vs_obj, **kwargs)
    # Change time wait to atleast 60 secs which is the default
    #  app sync frequency in case marathon is not set up with
    #  http callback
    s = time.time()
    vs_obj = None
    el = 0
    while el <= timeout:
        _, vs_obj = rest.get('virtualservice', name=vs_name)
        if vs_obj['application_profile_ref'] == app_profile_ref:
            break
        el = int(time.time() - s)
        asleep(delay=5)
    assert vs_obj['application_profile_ref'] == app_profile_ref
    vs_lib.check_vs_created(vs_name, tenant=tenant, **kwargs)


def update_app_nw_profile(vs_name, nw_profile_name, timeout=120, **kwargs):
    """

    :param vs_name:
    :param nw_profile_name:
    :param timeout:
    :param kwargs:
    :return:
    """

    tenant = get_tenant_for_container(**kwargs)
    nw_profile_ref = rest.get_obj_ref(
            'networkprofile', nw_profile_name, tenant=tenant)
    logger.debug('nw_prof %s=%s' % (nw_profile_name, nw_profile_ref))
    _, vs_obj = rest.get('virtualservice', name=vs_name)
    vs_obj['network_profile_ref'] = nw_profile_ref

    update_app(vs_name, vs_obj=vs_obj, **kwargs)
    # Change time wait to atleast 60 secs which is the default
    #  app sync frequency in case marathon is not set up with
    #  http callback
    s = time.time()
    vs_obj = None
    el = 0
    while el <= timeout:
        _, vs_obj = rest.get('virtualservice', name=vs_name)
        if vs_obj['network_profile_ref'] == nw_profile_ref:
            break
        el = int(time.time() - s)
        asleep(delay=5)
    assert vs_obj['network_profile_ref'] == nw_profile_ref
    vs_lib.check_vs_created(vs_name, tenant=tenant, **kwargs)


# REVIEW specific to mesos for now, but eventually should work for all
# container clouds
def set_mesos_rt_collection(rt_flag):
    """

    :param rt_flag:
    :return:
    """

    controller_ip = controller_lib.get_controller_ip()
    controller_ip += ':' + controller_lib.get_controller_port()

    period = 1 if rt_flag else 60

    cli_cmds = []
    '''
    cli_cmds.append('debug controller mesos_metrics_debug')
    cli_cmds.append('filters')
    cli_cmds.append('mesos_metrics_debug_filter')
    cli_cmds.append('metrics_collection_frq %d' % period)
    cli_cmds.append('save')
    cli_cmds.append('save')
    '''
    # Newer way of setting mesos rt metrics
    cli_cmds.append('configure serviceenginegroup Default-Group')
    cli_cmds.append('realtime_se_metrics')
    cli_cmds.append('enabled')
    cli_cmds.append('duration 0')
    cli_cmds.append('save')
    cli_cmds.append('save')

    cmds_file = '/tmp/mesos_cli_cmds.txt'
    with open(cmds_file, 'w') as cf:
        cf.write(string.join(cli_cmds, '\n'))

    config = infra_utils.get_config()
    cmd =  suite_vars.workspace + (
        "/python/bin/cli/bin/shell_client.py --address %s --user %s --password "
        "%s --json --file %s" % (controller_ip, config.user,
                                 config.password, cmds_file))

    #FNULL = open(os.devnull, 'w')
    #out = subprocess.call(cmd, shell=True, stdout=FNULL, stderr=STDOUT)
    # see https://gist.github.com/sheilatron/2147199
    python_path = ":".join(sys.path)[1:] # strip leading colon
    p = Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True,
              env={'PYTHONPATH':python_path})
    stdout, stderr = p.communicate()
    os.system('rm -rf %s' % cmds_file)
    logger.debug('set rt collection output: %s, stderr: %s' % (stdout, stderr))
    return stdout


def get_pool_name_with_tenant(vs_name, **kwargs):
    """
    small wrapper around vs_lib.get_vs_default_pool_name that
    works with default tenant for openshift
    :param vs_name:
    :param kwargs:
    :return:
    """

    tenant = get_tenant_for_container(**kwargs)
    return vs_lib.get_vs_default_pool_name(vs_name, tenant=tenant)


def get_app_bad_auth(app_name, auth_type='', bad_username='', bad_password=''):
    """

    :param app_name:
    :param auth_type:
    :param bad_username:
    :param bad_password:
    :return:
    """

    try:
        logger.info('Attempting to get app with bad credentials:')
        logger.info('auth_type: %s' % auth_type)
        logger.info('username: %s' % bad_username)
        logger.info('password: %s' % bad_password)
        get_app(app_name, auth_type=auth_type,
                username=bad_username,
                password=bad_password)
    except Exception as e:
        if 'Authentication error' in str(e):
            return str(e)
        else:
            fail('Unexpected exception: %s' %str(e))
    fail('No failure happened with bad credentials!')


def verify_app_antiaffinity(app1, app2, **kwargs):
    """
    Checks that the apps are indeed placed on different slaves
    :param app1:
    :param app2:
    :param kwargs:
    :return:
    """

    app1_info = get_app(app1, **kwargs)
    app1_host = app1_info['app']['tasks'][0]['host']
    app2_info = get_app(app2, **kwargs)
    app2_host = app2_info['app']['tasks'][0]['host']
    logger.info('app1 on host %s, app2 on host %s' % (app1_host, app2_host))
    assert app1_host != app2_host


def add_cloud_with_name(cloud_name, **kwargs):
    """

    :param cloud_name:
    :param kwargs:
    :return:
    """

    # Adds a new cloud
    tenant = kwargs.get('tenant', 'admin')
    #status_code, response = rest.get('cloud', name=cloud_name)
    response = True   
    if response:
        cloud = {}
        cloud['name'] = cloud_name
        cloud['vtype'] = 'CLOUD_NONE'  #CLOUD_MESOS
        cloud['tenant_uuid'] = tenant
        cloud['apic_mode'] = False
        cloud['dhcp_enabled'] = True
        cloud['mtu'] = 1500
        cloud['prefer_static_routes'] = False
        cloud['enable_vip_static_routes'] = False
        cloud['license_type'] = 'LIC_CORES' #options_pb2.LIC_CORES
        rest.post("cloud", data=cloud)
        status_code, response = rest.get('cloud', name=cloud_name)

    config = infra_utils.get_config()
    config.cloud = cloud_name


def delete_vs_pool(vs_name, pool_name=None, **kwargs):
    """

    :param vs_name:
    :param pool_name:
    :param kwargs:
    :return:
    """

    tenant = get_tenant_for_container(**kwargs)
    if not pool_name:
        pool_name = vs_lib.get_vs_default_pool_name(vs_name, tenant=tenant)
    pg_name = vs_lib.get_pool_group_for_vs(vs_name, tenant=tenant)
    rest.delete('virtualservice', name=vs_name)
    rest.delete('poolgroup', name=pg_name)
    rest.delete('pool', name=pool_name)


# REVIEW mesos specific
def get_free_cpu_count_list_from_slaves():
    """

    :return:
    """

    rsp_obj = get_slaves_from_master()
    total_cpus = 0;
    used_cpus = 0;
    free_cpu_list = []
    for slave in rsp_obj['slaves']:
        total_cpus = float(slave['resources']['cpus'])
        used_cpus = float(slave['used_resources']['cpus'])
        free_cpus = float(total_cpus - used_cpus)
        logger.info('total cpus %f, used cpus %f, free cpus %f' % (
            total_cpus, used_cpus, free_cpus))
        free_cpu_list.append(free_cpus)
    return free_cpu_list


def get_registry_url(ip, port, tag):
    """

    :param ip:
    :param port:
    :param tag:
    :return:
    """

    return ip + ':' + port + '/' + tag


def remove_se_from_slaves():
    """

    :return:
    """

    host_ips = get_active_slaves_ips()
    for host in host_ips:
        # REVIEW note hardcoding of the default registry; should allow param
        # for a different one
        se_container_id = execute_command_on_slave(
            None, host, "docker ps | grep %s | awk {'print $1'}" %
                        DEFAULT_DOCKER_REGISTRY)
        logger.info("se container id : %s" % se_container_id)
        se_image_id = execute_command_on_slave(
            None, host, "docker images | grep %s | awk {'print $3'}" %
                        DEFAULT_DOCKER_REGISTRY)
        logger.info("se image id : %s" % se_image_id)
        command = ''
        if se_container_id and se_image_id:
            command = "sudo docker stop %s && sudo docker rmi -f %s" % (
                se_container_id[0], se_image_id[0])
        elif se_container_id:
            command = "sudo docker stop %s" % se_container_id[0]
        elif se_image_id:
            command = "sudo docker rmi -f %s" % se_image_id[0]
        if command:
            execute_command_on_slave(None, host, command)
            #REVIEW not sure this sleep is needed
            #time.sleep(120)


def update_app_external_pool(app_name, pool_ip, **kwargs):
    """

    :param app_name:
    :param pool_ip:
    :param kwargs:
    :return:
    """

    if _is_mesos_cloud():
        return _update_mesos_external_pool(app_name, pool_ip, **kwargs)
    elif _is_openshift_cloud():
        return _update_openshift_external_pool(app_name, pool_ip, **kwargs)
    else:
        fail('Did not find a supported cloud object configuration in your '
             'topo_conf')


def _update_mesos_external_pool(app_name, pool_ip, **kwargs):
    """
    Specify external pool in the avi proxy label
    :param app_name:
    :param pool_ip:
    :param kwargs:
    :return:
    """

    app_obj = get_app(app_name, **kwargs)
    avi_label = app_obj['app'].get('labels', {})
    avi_proxy = json.loads(avi_label.get('avi_proxy', {}))
    avi_proxy['pool'] = {'servers': [{ 'ip':
                                           { 'addr': pool_ip,
                                             'type': 'V4'
                                           }
                                          }]}
    logger.info('New avi_proxy = %s' % avi_proxy)
    avi_label['avi_proxy'] = json.dumps(avi_proxy)
    logger.info('New avi_label = %s' % avi_label)
    _update_app_config(app_name, labels=avi_label, **kwargs)


def drop_connections_from_container(app_name, image_name='avinetworks/server'):
    """

    :param app_name:
    :param image_name:
    :return:
    """

    host_ips = get_active_slaves_ips()
    iptables_cmd = 'iptables -A INPUT -p tcp --destination-port 80 -j DROP'
    for host in host_ips:
        execute_command_on_container(None, iptables_cmd, image_name=image_name,
                                     filter=app_name, slave_host_ip=host,
                                     privileged=True)


def curl_app_from_app(dest_app, src_app, expected_output='',
                      image_name='avinetworks/server', auth_type='', **kwargs):
    """

    :param dest_app:
    :param src_app:
    :param expected_output:
    :param image_name:
    :param auth_type:
    :param kwargs:
    :return:
    """

    tenant = get_tenant_for_container(**kwargs)
    listener_ports = vs_lib.get_vs_listener_port_from_runtime(dest_app, tenant=tenant)
    dest_info = get_app(src_app, auth_type=auth_type, tenant=tenant)
    dest_ip = dest_info['app']['tasks'][0]['host']
    src_info = get_app(src_app, auth_type=auth_type, tenant=tenant)
    for task in src_info['app']['tasks']:
        src_host = task['host']
        curl_cmd = 'curl -k %s:%s --max-time 30' %(src_host,listener_ports[0])
        logger.info('curling app %s from %s[task instance=%s] with cmd %s' % (
            dest_app, src_app, src_host, curl_cmd))
        results = execute_command_on_container(
            '', curl_cmd, image_name=image_name, filter=src_app,
            slave_host_ip=src_host, expect_failure=True)  # curl err #52
        logger.debug('curl got output: %s' % results)
        _, curl_response = results[0]
        # REVIEW currently failing as per
        #assert expected_output in curl_response[0], 'Did not find "%s" in %s'
        # %(expected_output, curl_response[0])


def delete_container_tenant(tenant):
    """
    For now, only applicable for openshift since we created projects to have the named tenants
    :param tenant:
    :return:
    """

    if _is_openshift_cloud():
        delete_openshift_project(tenant)

def delete_openshift_project(project_name):
    """

    :param project_name:
    :return:
    """

    return oshift_utils.delete_project(project_name)


def verify_se_container_not_up_on_slave():
    """

    :return:
    """

    host_ips = get_active_slaves_ips()
    for host in host_ips:
        se_container_id = execute_command_on_slave(
            None, host, "docker ps | grep %s | awk {'print $1'}" %
                        DEFAULT_DOCKER_REGISTRY)
        if se_container_id:
            fail('SE container is up on slave %s' % host)


def create_se_over_rest(ctrl_host, ctrl_port, se_host,
                        cloud_name="Default-Cloud", tenant="admin"):
    """
    try do this without using the mb framework
    :param ctrl_host:
    :param ctrl_port:
    :param se_host:
    :param cloud_name:
    :param tenant:
    :return:
    """
    # try do this without using the mb framework
    #import importlib
    #import sys
    #base_dir = subprocess.check_output('git rev-parse --show-toplevel',shell=True).strip('\n')
    #path = base_dir + '/test/scripts/mb-scripts/'
    #sys.path.insert(1, path)
    #api_utils = importlib.import_module('api_utils')
    #api = api_utils.Api(None, addr=ctrl_host, user='admin', password='avi123', tenant='admin')
    #api.create_mesos_se(cloud_name, se_host)

    data = {'cloud': cloud_name, 'host': se_host}
    # data = json.dumps(data)
    # REVIEW I think this won't work since it isn't an avi_config obj_type
    #avi_rest_lib.post('mesos-serviceengine', data, tenant=tenant)
    # headers = get_headers(tenant=tenant)
    # url = 'https://' + ctrl_host + ':' + ctrl_port + '/api/mesos-serviceengine'
    rest.post('mesos-serviceengine', data=data)


def get_app_service_port(app_name, **kwargs):
    """

    :param app_name:
    :param kwargs:
    :return:
    """

    app_info = get_app(app_name, **kwargs)
    # review: should this be a list? for all portmappings instead of just 0?
    return app_info['app']['container']['docker']['portMappings'][0][
        'servicePort']


def check_vs_poolgroup(app_name, tenant='default', **kwargs):
    """
    Verifies expected pool group list should match with poolgroups from vs
    http policy if vs is l7 or poolgroups from servicepoolselect if vs is l4
    :param app_name:
    :param tenant:
    :param kwargs:
    :return:
    """

    route_name = kwargs.get("route_name", None)
    expected_pool_groups = []
    app_resp = oshift_utils.rest_client.list_namespaced_service_0(
        label_selector='svc=%s' % app_name)
    app_resp = app_resp.to_dict()
    for port_data in app_resp["items"][0]["spec"]["ports"]:
        if route_name:
            poolgroup_name = "%s-aviroute-poolgroup-%s-%s" % (
                route_name, port_data["target_port"],
                port_data["protocol"].lower())
        else:
            poolgroup_name = "%s-poolgroup-%s-%s" % (
                app_name, port_data["target_port"],
                port_data["protocol"].lower())
        expected_pool_groups.append(poolgroup_name)
    if route_name:
        app_name = "%s.%s" % (app_name, SERVICE_DOMAIN)
    vs_resp = vs_lib.get_vs(app_name, tenant=tenant)
    l7_application_profiles = ["System-Secure-HTTP", "System-HTTP"]

    applicationprofile_uuid = webapp_lib.get_slug_from_uri(
        vs_resp["application_profile_ref"])
    resp_code, applicationprofile_resp = rest.get(
        "applicationprofile", uuid=applicationprofile_uuid)
    if applicationprofile_resp["name"] in l7_application_profiles:
        poolgroup_names = get_poolgroup_from_vs_httppolicies(
            app_name, tenant=tenant)
    else:
        poolgroup_names = get_poolgroup_from_vs_servicepoolselect(
            app_name, tenant=tenant)

    if set(poolgroup_names) != set(expected_pool_groups):
        fail("Expected pool groups %s does not match with vs pool "
                        "groups %s" % (expected_pool_groups, poolgroup_names))


def get_poolgroup_from_vs_httppolicies(vs_name, tenant='default'):
    """
    Returns the all poolgroup names associated with vs http policies
    :param vs_name:
    :param tenant:
    :return:
    """

    vs_resp = vs_lib.get_vs(vs_name, tenant=tenant)
    vs_http_policy_uuid = webapp_lib.get_slug_from_uri(vs_resp["http_policies"][0][
                                                "http_policy_set_ref"])
    resp_code, httppolicyset_resp = rest.get("httppolicyset", uuid=vs_http_policy_uuid)

    poolgroup_names = []
    for rule in httppolicyset_resp["http_request_policy"]["rules"]:
        pool_group_uuid = webapp_lib.get_slug_from_uri(rule["switching_action"][
                                                "pool_group_ref"])
        resp_code, poolgroup_resp = rest.get(
            "poolgroup", uuid=pool_group_uuid)
        poolgroup_names.append(poolgroup_resp["name"])
    return list(set(poolgroup_names))


def get_poolgroup_from_vs_servicepoolselect(vs_name, tenant='default'):
    """
    Returns the all poolgroup names associated with vs service_pool_select
    :param vs_name:
    :param tenant:
    :return:
    """

    vs_resp = vs_lib.get_vs(vs_name, tenant=tenant)
    poolgroup_names = []
    for service_pool in vs_resp["service_pool_select"]:
        pool_group_uuid = webapp_lib.get_slug_from_uri(
            service_pool["service_pool_group_ref"])
        resp_code, poolgroup_resp = rest.get(
            "poolgroup", uuid=pool_group_uuid)
        poolgroup_names.append(poolgroup_resp["name"])
    return poolgroup_names


def add_openshift_route(app_id, **kwargs):
    """

    :param app_id:
    :param kwargs:
    :return:
    """

    if not _is_openshift_cloud():
        fail('Cannot add route for non-openshift cloud')
    oshift_utils.create_route(app_id, **kwargs)


def check_route_vs(app_list, **kwargs):
    """

    :param app_list:
    :param kwargs:
    :return:
    """

    route_vs_list = []
    for app in app_list:
        # convention from openshift_lib.create_route
        # the vs for the route has name based on route_json['spec']['host']
        route_vs_list.append(app + '.' + SERVICE_DOMAIN)
    vs_lib.check_for_vs(route_vs_list, **kwargs)


def test_app_service(app_id, dns_vip, tenant='default',
                     service_type='east_west'):
    """
    Test traffic for app using fqdn
    :param app_id:
    :param dns_vip:
    :param tenant:
    :param service_type:
    :return:
    """

    if not _is_openshift_cloud():
        fail('Cannot test app service in non-openshift cloud')
    vs_fqdn = vs_lib.vs_get_fqdn(app_id, tenant=tenant)
    app_info = _get_openshift_app(app_id, tenant=tenant)
    tasks = app_info['app']['tasks']
    for task in tasks:
        app_host = task['host']
        dig_cmd = 'dig @%s %s +short' % (dns_vip, vs_fqdn)
        results = execute_command_on_container(
            '', dig_cmd, image_name='avinetworks/server', filter=app_id,
            slave_host_ip=app_host, expect_failure=False)
        logger.info('dig command output %s' % results)
        for dig_out in results:
            curl_cmd = 'curl %s' % (dig_out[1][0])
            results = execute_command_on_container(
                '', curl_cmd, image_name='avinetworks/server', filter=app_id,
                slave_host_ip=app_host, expect_failure=False)
            logger.info('curl command output %s' % results)
            if service_type=='north_south':
                results = os.system(curl_cmd)
                logger.info('curl command output for north_south %s' % results)


def _get_openshift_app(app_name, **kwargs):
    """
    For now, try emulate the json format of http://marathon/v2/apps/appid for
    compatibility with calling functions
    :param app_name:
    :param kwargs:
    :return:
    """

    app_obj = {}
    #app_obj['app'] = {}
    tenant = get_tenant_for_container(**kwargs)

    metadata = oshift_utils.get_openshift_app_metadata(app_name,
                                                       project=tenant)
    app_obj['app'] = metadata  # REVIEW is this right?
    app_obj['app']['labels'] = metadata['annotations']

    app_runtime = oshift_utils.get_openshift_app_runtime(app_name,
                                                         project=tenant)
    app_obj['app']['instances'] = app_runtime.instances
    app_obj['app']['tasksRunning'] = app_runtime.tasks_running
    app_obj['app']['tasksHealthy'] = app_runtime.tasks_healthy
    app_obj['app']['tasks'] = app_runtime.tasks
    # fake a service port
    app_obj['app']['container'] = \
        {'docker': {'portMappings': [{'servicePort': 0}]}}

    logger.info('returning openshift app %s' % app_obj)
    return app_obj


def check_pool_servers_endpoints(app_data, **kwargs):
    """

    :param app_data: list of apps eg. [app1, app2, app3] or dict of apps and
    corresponding ports, protocols. eg. app data = {app1:[{"port":port1,
    "protocol": protocol1},{"port":port2, "protocol":protocol2}, ...],..}
    :param kwargs:
    :return:
    """

    if not _is_openshift_cloud():
        fail('Cannot check route for non-openshift cloud')
    app_port_dict = {}
    for i in xrange(0, 2):
        res = _check_pool_servers_endpoints(app_data, **kwargs)
        if res:
            return
        time.sleep(60)
    fail('Pool servers mismatch with endpoints')


def _check_pool_servers_endpoints(app_data, **kwargs):
    """

    :param app_data: list of apps eg. {app1:[{"port":port1, "protocol":
    protocol1},{"port":port2, "protocol":protocol2}, ...],
    app2:[{"port":port1, "protocol": protocol1},...],...}
    :param kwargs:
    :return:
    """

    pool_servers = {}
    route_name = kwargs.get("route_name", None)
    for app in app_data:
        servers = set()
        # get server_ip and port of each pool of the app
        for port_data in app_data[app]:
            if route_name:
                pool_name = '%s-aviroute-pool-%s-%s' % (
                    route_name, port_data["port"], port_data["protocol"])
            else:
                pool_name = '%s-pool-%s-%s' % (app, port_data["port"],
                                               port_data["protocol"])
            servers = servers | pool_lib.get_server_ip_port_for_pool(
                pool_name, **kwargs)
        pool_servers[app] = servers
    logger.info("Pool servers %s" % pool_servers)

    namespace = kwargs.get('tenant', 'default')
    for app in app_data:
        endpoints = oshift_utils.get_endpoints(app, namespace)
        logger.info('app %s endpoints %s' % (app, endpoints))
        if endpoints != pool_servers[app]:
            logger.info('App %s Endpoints %s mismatch with pool servers %s' %
                        (app, endpoints, pool_servers[app]))
            return False
    return True


def get_pods_for_app(app_id, project='default'):
    """
    Returns the list of pods for svc app_id
    """
    resp_data = oshift_utils.rest_client.list_namespaced_pod_0(
        label_selector='name=%s-dc' % app_id)
    resp_data = resp_data.to_dict()
    pod_list = list()
    for pod in resp_data['items']:
        pod_list.append(pod['metadata']['name'])
    return pod_list


def verify_containerid_and_ip_for_ms(ms, pod_list, project="default"):
    """
    Verify container id and pod ip from microservice should match with
    container id and pod ip from os pod config
    :param ms:
    :param pod_list:
    :param project:
    :return:
    """


    ms_config = ms_lib.get_ms_config(ms)
    ms_containerid_podip = {}
    os_containerid_podip = {}

    if len(pod_list) == len(ms_config['containers']):
        for container in ms_config['containers']:
            ms_containerid_podip[container['ip']['addr']] = \
                container['container_id']
        for pod in pod_list:
            os_pod_config = oshift_utils.get_pod_config(pod, project)
            logger.info('pod %s config: %s' % (pod, os_pod_config))
            # pod container id eg. docker://
            # a6a2d2c224a2211ba2815c3550ac674984847d3d9f6f9814d938195060d41769
            container_id = os_pod_config["status"]["containerStatuses"][0][
                "containerID"].split("//")[-1]
            podIP = os_pod_config["status"]["podIP"]
            os_containerid_podip[podIP] = container_id
        if ms_containerid_podip == os_containerid_podip:
            return
        else:
            fail('Pod container IP and Ports: %s does not match '
                            'with microservice IP and Ports: %s' % (
                ms_containerid_podip, os_containerid_podip))
        fail('Number of Pods(%d) does not match with number of '
                        'containers(%d) in microservice' % (
            len(pod_list), len(ms_config['containers'])))


def get_expected_pools_for_app(app_name, project="default", **kwargs):
    """
    returns expected pools name for app
    :param app_name:
    :param project:
    :param kwargs:
    :return:
    """

    route_name = kwargs.get("route_name", None)
    pool_config = oshift_utils.get_pool_config_for_app(
        app_name, project=project)
    pool_name_list = []
    for pool in pool_config:
        if route_name:
            pool_name_list.append('%s-aviroute-pool-%s-%s' % (
                route_name, pool["port"], pool["protocol"]))
        else:
            pool_name_list.append("%s-pool-%s-%s" % (
                app_name, pool['port'], pool['protocol']))
    return pool_name_list


def scale_app(app_name, instances, **kwargs):
    """

    :param app_name:
    :param instances:
    :param kwargs:
    :return:
    """

    _update_app_config(app_name, instances=instances, **kwargs)


def delete_dns_vs_if_needed(dns_vs_name):
    """

    :param dns_vs_name:
    :return:
    """

    if _is_aws_testbed() or _is_openstack_testbed():
        # see AV-15393
        return
    else:
        system_lib.delete_dns_system_configuration()
        vs_lib.delete_vs(dns_vs_name)


def setup_openshift_cloud(cloud, **kwargs):
    """
    Build up the cloud pb with info from openshift_config and keyword args
    :param cloud:
    :param openshift_config:
    :param kwargs:
    :return:
    """

    cloud['vtype'] = 'CLOUD_OSHIFT_K8S'
    cloud_oshiftk8s_configuration = cloud['oshiftk8s_configuration']
    # Networks
    subnet_ip = get_se_subnet()
    subnet = subnet = {
        'prefix': {
            'ip_addr': {
                'addr': subnet_ip,
                'type': 'V4'
            },
            'mask': 24
        }
    }
    # HACK for AV-12323
    safe_create_network('north_south_network', subnet)
    # for autoallocation of vips; make sure this doesn't conflict with .52-.63 range that we also use
    network_static_range_end = kwargs.get('network_static_range_end', '220')
    network_lib.network_set_subnet_static_range('north_south_network', '200',
                                    '%s' % (network_static_range_end))

    use_service_cluster_ip_as_ew_vip = kwargs.get("use_service_cluster_ip_as_ew_vip", None)
    if use_service_cluster_ip_as_ew_vip:
        cloud_oshiftk8s_configuration['use_service_cluster_ip_as_ew_vip'] = use_service_cluster_ip_as_ew_vip
    # HACK for AV-12323
    if 'use_service_cluster_ip_as_ew_vip' in cloud_oshiftk8s_configuration:
        # kube proxy disabled
        safe_create_network('east_west_network', {
            'prefix': {'ip_addr': {'addr': '172.30.0.0', 'type': 'V4'},
                       'mask': 16}})
    else:
        # else use some other subnet for vip
        safe_create_network('east_west_network', {
            'prefix': {'ip_addr': {'addr': '169.254.0.0', 'type': 'V4'},
                       'mask': 16}})
    network_lib.network_set_subnet_static_range('east_west_network', '10', '250')

    # IPAM
    # Create the ipam profiles for the openshift cloud corresponding to the networks
    ipam_lib.create_ipamdns_profile(IPAM_NS,
                        'IPAMDNS_TYPE_INTERNAL',
                        usable_network='north_south_network')
    ipam_lib.create_ipamdns_profile(IPAM_NS_DNS,
                        'IPAMDNS_TYPE_INTERNAL_DNS',
                        service_domain=SERVICE_DOMAIN)
    ipam_lib.create_ipamdns_profile(IPAM_EW,
                        'IPAMDNS_TYPE_INTERNAL',
                        usable_network='east_west_network')
    ipam_lib.create_ipamdns_profile(IPAM_EW_DNS,
                        'IPAMDNS_TYPE_INTERNAL_DNS',
                        service_domain=SERVICE_DOMAIN)
    cloud['dns_provider_uuid'] = rest.get_uuid_by_name('ipamdnsproviderprofile', IPAM_NS_DNS)
    cloud['ipam_provider_uuid'] = rest.get_uuid_by_name('ipamdnsproviderprofile', IPAM_NS)
    cloud['east_west_dns_provider_uuid'] = rest.get_uuid_by_name('ipamdnsproviderprofile', IPAM_EW_DNS)
    cloud['east_west_ipam_provider_uuid'] = rest.get_uuid_by_name('ipamdnsproviderprofile', IPAM_EW)

#    cloud['dns_provider_uuid'] = IPAM_NS_DNS
#    cloud['ipam_provider_uuid'] = IPAM_NS
#    cloud['east_west_dns_provider_uuid'] = IPAM_EW_DNS
#    cloud['east_west_ipam_provider_uuid'] = IPAM_EW


    # read from source (i.e. topo conf) config and set the cloud's config
    # review: is there a better way to just do a direct copy?

    # read the key and cert files from topo, create the corresponding objects, then get and set the uuids in the cloud
    create_client_certificate_from_cloud_config('client_cert', tenant='admin')
    create_ca_certificate_from_cloud_config('ca_cert', tenant='admin')
    cloud_oshiftk8s_configuration['client_tls_key_and_certificate_uuid'] = rest.get_uuid_by_name('sslkeyandcertificate', 'client_cert')
    cloud_oshiftk8s_configuration['ca_tls_key_and_certificate_uuid'] = rest.get_uuid_by_name('sslkeyandcertificate', 'ca_cert')

    disable_auto_frontend_service_sync = kwargs.get('disable_auto_frontend_service_sync', None)
    disable_auto_backend_service_sync = kwargs.get('disable_auto_backend_service_sync', None)
    
    if disable_auto_frontend_service_sync:
        cloud_oshiftk8s_configuration['disable_auto_frontend_service_sync'] = True

    if disable_auto_backend_service_sync:
        cloud_oshiftk8s_configuration['disable_auto_backend_service_sync'] = True
    
    se_deployment_method = kwargs.get('se_deployment_method', None)
    if se_deployment_method == 1:
        cloud_oshiftk8s_configuration['se_deployment_method'] = 'SE_CREATE_SSH'
    elif se_deployment_method == 2:
        cloud_oshiftk8s_configuration['se_deployment_method'] = 'SE_CREATE_POD'

    if cloud_oshiftk8s_configuration['se_deployment_method'] == 'SE_CREATE_SSH':
        if 'ssh_user_uuid' in cloud_oshiftk8s_configuration:
            cloud_oshiftk8s_configuration['ssh_user_uuid'] = rest.get_uuid_by_name('cloudconnectoruser', cloud_oshiftk8s_configuration['ssh_user_uuid'])
        else:
            cloud_oshiftk8s_configuration['ssh_user_uuid'] = rest.get_uuid_by_name('cloudconnectoruser', 'aviuser')

    repo_username = kwargs.get('repo_username', None)
    repo_password = kwargs.get('repo_password', None)
    registry = kwargs.get('registry', None)
    disable_docker_repo = kwargs.get('disable_docker_repo', False)
    disable_auto_se_creation = kwargs.get('disable_auto_se_creation', False)

    disable_private_registry = kwargs.get('disable_private_registry', False)
    if disable_private_registry:
        cloud_oshiftk8s_configuration['docker_registry_se']['private'] = False
    else:
        cloud_oshiftk8s_configuration['docker_registry_se']['private'] = cloud_oshiftk8s_configuration['docker_registry_se']['private']
 
    if 'docker_registry_se' not in cloud_oshiftk8s_configuration:
        cloud_oshiftk8s_configuration['docker_registry_se'] = {}
    if registry:
        cloud_oshiftk8s_configuration['docker_registry_se']['registry'] = registry
    elif 'registry' not in cloud_oshiftk8s_configuration['docker_registry_se']:
        random_string = ''.join(random.choice(string.lowercase) for i in range(10))
        cloud_oshiftk8s_configuration['docker_registry_se']['registry'] = DEFAULT_DOCKER_REGISTRY + random_string

    if repo_username and repo_password:
        cloud_oshiftk8s_configuration['docker_registry_se']['username'] = repo_username
        cloud_oshiftk8s_configuration['docker_registry_se']['password'] = repo_password

    if disable_docker_repo:
        cloud_oshiftk8s_configuration['docker_registry_se']['se_repository_push'] = False
    if disable_auto_se_creation:
        cloud_oshiftk8s_configuration['disable_auto_se_creation'] = True

    se_include_attribute = kwargs.get('se_include_attribute', None)
    se_exclude_attribute = kwargs.get('se_exclude_attribute', None)
    if se_include_attribute:
        cloud_oshiftk8s_configuration['se_include_attributes'] = []
        se_include = {}
        se_include_attribute_kv = se_include_attribute.split(':')
        se_include['attribute'] = se_include_attribute_kv[0]
        se_include['value'] = se_include_attribute_kv[1]
        cloud_oshiftk8s_configuration['se_include_attributes'].append(se_include)
    if se_exclude_attribute:
        cloud_oshiftk8s_configuration['se_exclude_attributes'] = []
        se_exclude = {}
        se_exclude_attribute_kv = se_exclude_attribute.split(':')
        se_exclude['attribute'] = se_exclude_attribute_kv[0]
        se_exclude['value'] = se_exclude_attribute_kv[1]
        cloud_oshiftk8s_configuration['se_exclude_attributes'].append(se_exclude)

    logger.info('creating east-west placement ip and mask %s/%d'
             % (cloud['oshiftk8s_configuration']['east_west_placement_subnet']['ip_addr']['addr'],
                cloud['oshiftk8s_configuration']['east_west_placement_subnet']['mask']))

    http_svc_ports = kwargs.get('http_svc_ports', [])
    if http_svc_ports:
        cloud_oshiftk8s_configuration['container_port_match_http_service'] = False
        cloud_oshiftk8s_configuration['service_port_match_http_service'] = True
        if 'http_container_ports' not in cloud_oshiftk8s_configuration:
            cloud_oshiftk8s_configuration['http_container_ports'] = []
        for port in http_svc_ports:
            cloud_oshiftk8s_configuration['http_container_ports'].append(port) 
    
    http_container_ports = kwargs.get('http_container_ports', [])
    if 'http_container_ports' not in cloud_oshiftk8s_configuration:
        cloud_oshiftk8s_configuration['http_container_ports'] = []
    for port in http_container_ports:
        cloud_oshiftk8s_configuration['http_container_ports'].append(port)

    #deprecated
    #cloud.oshiftk8s_configuration.services_accessible_all_interfaces = openshift_config.services_accessible_all_interfaces

    # REVIEW in the future, should test with this off (default)/as an option and verify the SE counts

    use_scheduling_disabled_nodes = kwargs.get('use_scheduling_disabled_nodes', False) 
    if use_scheduling_disabled_nodes:
        cloud_oshiftk8s_configuration['use_scheduling_disabled_nodes'] = use_scheduling_disabled_nodes

    l4_health_monitoring = kwargs.get("l4_health_monitoring", None)
    if l4_health_monitoring:
        cloud_oshiftk8s_configuration['l4_health_monitoring'] = l4_health_monitoring
    
    #required
    cloud_oshiftk8s_configuration['sdn_overlay'] = True

    #if kube proxy disabled
    #cloud.oshiftk8s_configuration.use_service_cluster_ip_as_ew_vip = True

    return cloud


def get_app_pool_config(app_name, project="default", **kwargs):
    """
    returns pool config from app spec
    :param app_name:
    :param project:
    :param kwargs:
    :return:
    """

    if _is_openshift_cloud():
        return oshift_utils.get_pool_config_for_app(app_name, project=project)


def delete_all_openshift_routes():
    if not _is_openshift_cloud():
        fail('Cannot delete all routes for non-openshift cloud')
    oshift_utils.delete_all_routes()


def get_full_cert_path(file_path):
    """ If file_path starts with /, assume it's an absolute path, else
        assume it is relative to the config.testbed_config_file
    """
    config = infra_utils.get_config()
    full_path = ''
    if file_path.startswith('/'):
        full_path = file_path # assume absolute path

    tb_path = config.testbed[config.site_name].abspath
    cert_path = os.path.dirname(tb_path)
    full_path = os.path.join(cert_path, file_path)
    if not os.path.isfile(full_path):
        fail('Warning: File at absolute path %s does not exist!' % full_path)
    return full_path


def create_client_certificate_from_cloud_config(name, tenant='admin'):
    cloud_config = _get_cloud_config()
    if not ',' in cloud_config['client_tls_key_and_certificate_uuid']:
        fail('Did not find client tls key and certificate string in proper format in cloud config')
    client_key_file, client_cert_file = cloud_config['client_tls_key_and_certificate_uuid'].split(',')
    client_key_path = get_full_cert_path(client_key_file)
    client_cert_path = get_full_cert_path(client_cert_file)
    ssl_lib.import_key_and_certificate(data=None, name=name, key_file=client_key_path, cert_file=client_cert_path, tenant=tenant)


def create_ca_certificate_from_cloud_config(name, tenant='admin'):
    cloud_config = _get_cloud_config()
    ca_cert_file = cloud_config['ca_tls_key_and_certificate_uuid']
    ca_cert_path = get_full_cert_path(ca_cert_file)
    ssl_lib.import_key_and_certificate(data=None, name='ca_cert', cert_file=ca_cert_path, tenant=tenant)


def _create_openshift_app(app_name, num_instances=1, num_apps=1,
                          northsouth=0, vips=[], tenant='default', **kwargs):
    # REVIEW: do we need to support multiple service ports?
    app_ids = []
    num_apps = int(num_apps)
    num_instances = int(num_instances)
    for index in range(num_apps):
        app_id = (app_name + '-' + str(index + 1)
                  if num_apps > 1 else app_name)
        app_ids.append(app_id)

        if num_instances < 0:
            num_instances = index % 3 + 1

        #if northsouth and vips and (index % math.ceil(float(num_apps)/northsouth) == 0):
        if northsouth and (index % math.ceil(float(num_apps)/northsouth) == 0):
            is_northsouth = True
            #ns_index = int(index / (num_apps/northsouth))
            #vip = vips[ns_index]
            vip = ''
        else:
            is_northsouth = False
            vip = ''
        oshift_utils.create_openshift_app_from_template(is_northsouth, app_id, num_instances, vip, tenant=tenant, **kwargs)
    return app_ids


def _delete_openshift_app(app_name, num_apps=1, tenant='default', **kwargs):
    app_ids = []
    # REVIEW use api?
    #delete_namespaced_service?
    num_apps = int(num_apps)
    for index in range(num_apps):
        app_id = (app_name + '-' + str(index + 1)
                  if num_apps > 1 else app_name)
        app_ids.append(app_id)
        oshift_utils.delete_openshift_app(app_id, project=tenant)

    return app_ids


def test_kubernetes_service(app_id, **kwargs):
    if not _is_openshift_cloud():
        fail('Cannot test kubernetes service in non-openshift cloud')
    kube_vip = vs_lib.vs_get_vip('kubernetes', tenant='default')
    app_info = _get_openshift_app(app_id, **kwargs)
    tasks = app_info['app']['tasks']
    for task in tasks:
        app_host = task['host']
        curl_cmd = 'curl -k https://%s' %kube_vip
        results = execute_command_on_container('', curl_cmd, image_name='avinetworks/server',
                                               filter=app_id, slave_host_ip=app_host, expect_failure=False)
        logger.info('curl command returned %s' % results)
        assert 'paths' in str(results)

        dig_cmd = 'dig @%s' % kube_vip
        results = execute_command_on_container('', dig_cmd, image_name='avinetworks/server',
                                               filter=app_id, slave_host_ip=app_host, expect_failure=False)
        logger.info('dig command returned %s' %results)
        assert 'Got answer:' in str(results)

        dig_cmd_tcp = 'dig @%s +tcp' % kube_vip
        results = execute_command_on_container('', dig_cmd_tcp, image_name='avinetworks/server',
                                               filter=app_id, slave_host_ip=app_host, expect_failure=False)
        logger.info('dig +tcp command returned %s' % results)
        assert 'Got answer:' in str(results)


def verify_ip_rule_and_route(app_name, tenant='default', rule_show=True,
                             route_show=True, **kwargs):
    """

    :param app_name:
    :param tenant:
    :param rule_show:
    :param route_show:
    :param kwargs:
    :return:
    """

    vs_config = vs_lib.get_vs(app_name, tenant=tenant)
    route_vs_vip_addr = vs_config['vip'][0]['ip_address']['addr']
    primary_se_name = vs_lib.vs_get_primary_se_name(app_name, tenant=tenant)
    host_ip = primary_se_name.split('--')[0]
    host_ips = get_active_slaves_ips()
    if rule_show:
        cmd = "ip rule show"
        for host in host_ips:
            response = execute_command_on_slave(None, host, cmd, **kwargs)
            for data in response:
                if route_vs_vip_addr in data and host != host_ip:
                    fail('found ip rule show on unexpected host %s' % host)
    if route_show:
        cmd = "ip route show table avi"
        data_to_check = "%s via 172.18.0.2" % route_vs_vip_addr
        for host in host_ips:
            response = execute_command_on_slave(None, host, cmd, **kwargs)
            for data in response:
                if data_to_check in data and host != host_ip:
                    fail('found ip route show table on unexpected host %s' % host)



def check_route_status(app_id, route_name=None, project='default'):
    """

    :param app_id:
    :param route_name:
    :param project:
    :return:
    """

    if not _is_openshift_cloud():
        logger.trace('Cannot verify routes status for non-openshift cloud')
    if not route_name:
        route_name = app_id + '-route'
    oshift_utils.check_route(route_name, project=project)


def get_expected_poolgroup_for_app(app_name, project="default", **kwargs):
    """
    returns expected poolgroups name for app
    """
    route_name_list = kwargs.get("route_name_list", None)
    pool_config = oshift_utils.get_pool_config_for_app(app_name, project=project)
    poolgroup_name_list = []
    for pool in pool_config:
        if route_name_list:
            for route_name in route_name_list:
                poolgroup_name_list.append('%s-aviroute-poolgroup-%s-%s' % (route_name, pool["port"], pool["protocol"]))
        else:
            poolgroup_name_list.append("%s-poolgroup-%s-%s" % (app_name, pool['port'], pool['protocol']))
    return poolgroup_name_list


def verify_route_path_from_vs_httppolicies(app_id, route_vs, route_name=None, tenant='default', project='default'):
    if not _is_openshift_cloud():
        logger.trace('Cannot verify route path for non-openshift cloud')
    if not route_name:
        route_name = app_id + '-route'
    oshift_utils.get_route_path_from_vs_httppolicies(route_vs, route_name, tenant=tenant, project=project)


def send_traffic_with_curl(vs_name, **kwargs):
    if "avi-container-dns.internal" in vs_name:
        app_name = vs_name.split(".avi-container-dns.internal")[0]
    else:
        app_name = vs_name
    status_code, vs_data = rest.get('virtualservice', name=vs_name)
    vip_ip = vs_data["vip"][0]["ip_address"]["addr"]
    east_west = kwargs.get("east_west", True)
    slaves = get_active_slaves_ips()

    # Get cloud info by admin tenant and switching back to current tenant.
    config = infra_utils.get_config()
    current_tenant = config.tenant
    infra_utils.switch_mode(tenant='admin')
    status_code, cloud_data = rest.get('cloud')
    infra_utils.switch_mode(tenant=current_tenant)

    http_container_ports = []
    # Traffic will work only for port that matches cloud container port
    if 'http_container_ports' in cloud_data['results'][0]['oshiftk8s_configuration']:
        http_container_ports.extend(cloud_data['results'][0]['oshiftk8s_configuration']['http_container_ports'])
    else:
        # Default cloud container port is 80
        http_container_ports = [80]

    for slave_id in slaves:
        for service in vs_data["services"]:
            if service["port"] not in http_container_ports:
                continue
            if service["enable_ssl"]:
                vs_domain = "https://%s:%s" % (vip_ip, service["port"])
            else:
                vs_domain = "http://%s:%s" % (vip_ip, service["port"])
            curl_cmd = 'curl -k %s' % vs_domain
            logger.info("Curl command: %s" % curl_cmd)
            results = execute_command_on_container('', curl_cmd,
                                                   image_name='avinetworks/server',
                                                   slave_host_ip=slave_id,
                                                   filter=app_name,
                                                   expect_failure=True,
                                                   )
            logger.info(results)
            if results:
                for result in results:
                    check_curl_output(str(result[1]), service, **kwargs)
            if not east_west:
                output = subprocess.check_output(shlex.split(curl_cmd))
                logger.info(output)
                check_curl_output(str(output), service, **kwargs)


def check_curl_output(curl_output, service_data, **kwargs):
    edge_allow = kwargs.get("edge_allow", None)
    edge_redirect = kwargs.get("edge_redirect", None)
    reencrypt_termination = kwargs.get("reencrypt_termination", None)
    logger.info("Curl output: %s" % curl_output)
    if (edge_redirect and not service_data["enable_ssl"]) or (reencrypt_termination and not service_data["enable_ssl"]):
        if '301 Moved Permanently' in str(curl_output):
            logger.info('Got 301 Moved Permanently')
        else:
            fail("Traffic failed")
    elif (edge_redirect and service_data["enable_ssl"]) or (edge_allow and service_data["enable_ssl"]):
        pass
    else:
        if "Welcome" not in curl_output:
            fail("Traffic failed")


def check_openshift_routes(app_list, **kwargs):
    if not _is_openshift_cloud():
        fail('Cannot add route for non-openshift cloud')
    namespace = kwargs.get('tenant', 'default')
    status = kwargs.get('status', False)
    invalid_routes = list()
    for app in app_list:
        # REVIEW per https://github.com/avinetworks/avi-dev/pull/15074 the route's VS name
        # will now be the hostname instead of the ${routename}-aviroute
        # so we will keep the implementation opaque to the test and the test will
        # no longer explicitly pass -aviroute to its vs name list
        route = app + '-route' # convention for route name from openshift_lib.create_route
        #if route.endswith('-aviroute'):
        #    route = vs[:len(vs)-len('-aviroute')]
        valid, rsp = oshift_utils.check_route(route, namespace, status=status)
        logger.info("[Route status %s:%s] : %s" % (namespace, route, rsp))
        if not valid:
            invalid_routes.append('%s:%s' % (namespace, route))
    if invalid_routes:
        fail("Route status not valid for routes: %s" % invalid_routes)
    else:
        logger.info("Routes' status check PASS for %s" % app_list)


def test_dedicated_traffic_routes(vs_name, protocol='http', timeout=30, **kwargs):
    """ Test the Route VS """
    backend_protocol = kwargs.get('backend_protocol', 'http')
    _curl_app_by_service_name(vs_name, protocol=backend_protocol, **kwargs)

    route_url = vs_name + '.' + SERVICE_DOMAIN
    url = protocol + '://' + route_url
    if 'path' in kwargs:
        url = url + kwargs['path']
    dns_vs = kwargs.get('dns_vs', '')
    dig_url(route_url, dns_vs)
    out = _curl_url_from_host(url, '', timeout=timeout) # no ip -> use test client
    check_str = 'Welcome to Avi '
    if 'server_name' in kwargs:
        check_str = check_str + kwargs['server_name'] + ' '
    if 'path' in kwargs:
        check_str = check_str + kwargs['path'].replace('/', '') + ' '
    check_str += 'test server'
    logger.info('check_str %s out %s' % (check_str, out))
    assert check_str in out


def dig_url(url, dns_vs=''):
    if dns_vs:
        # DNS VS is always in admin tenant so switching tenant
        # to admin and resetting it back after getting dns VIP
        config = infra_utils.get_config()
        current_tenant = config.tenant
        infra_utils.switch_mode(tenant='admin')
        dns_vs_vip = vs_lib.vs_get_vip(dns_vs)
        infra_utils.switch_mode(tenant=current_tenant)
        cmd = 'dig @%s %s' %(dns_vs_vip, url)
    else:
        cmd = 'dig %s' %url
    results = execute_command_on_slave('', '', cmd, warn_only=False) # no slave id/ip -> dig from test client
    logger.info('dig command returned %s' % results)
    assert 'Got answer:' in str(results)


def _curl_app_by_service_name(vs_name, protocol='http', app_type=1, timeout=30, **kwargs):
    """ Test the EW VS directly """
    app_type = int(app_type)
    tenant = get_tenant_for_container()
    ew_url = vs_name + '.%s.%s' %(tenant, SERVICE_DOMAIN)
    out = _curl_url_from_host(protocol + '://' + ew_url, get_cluster_master_ip(), timeout=timeout)
    if app_type == 1:
        if 'server_name' in kwargs:
            check_str = 'Welcome to Avi %s test server' % kwargs['server_name']
        else:
            check_str = 'Welcome to Avi test server'
        assert check_str in out
    else:
        assert 'nginx web server is successfully installed' in out # default index for app of type 2


def _curl_url_from_host(url, host, timeout=30):
    cmd = 'curl -k %s --max-time %d' % (url, timeout)
    try:
        out = execute_command_on_slave('', host, cmd, warn_only=False)
        if '301 Moved Permanently' in str(out):
            logger.info('Got 301 Moved Permanently')
            fail('301 Moved Permanently') # may be expected, e.g. hitting http->https redirect
        return str(out)
    except Exception as e:
        if 'Connection timed out after' in str(e):
            logger.info('Connect timed out after %s sec trying to curl %s on %s' % (timeout, url, host))
            fail('Connect timed out') # may be expected, e.g. hitting https on http VS
        else:
            raise


def count_lines_in_cloud_connector_log(line, log_name='cc_agent_Default-Cloud.log'):
    cmd = 'grep \'%s\' /opt/avi/log/%s | wc -l' %(line, log_name)
    out = execute_controller_command(cmd)
    result = out[0]
    logger.trace('Found %s lines matching string "%s"' % (result, line))
    return int(result)


def execute_controller_command(cmd):
    controller_ip = controller_lib.get_controller_ip()
    out = []
    config = infra_utils.get_config()
    vm = config.get_vm_of_type('controller')[0]
    if vm.deployment == 'CONTAINER_DEPLOYMENT':
        # exec the docker container to run the command
        docker_ids = get_container_ids(None, controller_ip, 'avicontroller')
        if not docker_ids:
            logger.warning('Could not find the controller container at %s' % controller_ip)
        else:
            docker_cmd = 'sudo docker exec -it %s bash -c "%s"' %(docker_ids[0], cmd)
            out = execute_command_on_slave(None, controller_ip, docker_cmd) # technically not a slave
    else:
        out = execute_command_on_slave(None, controller_ip, cmd) # technically not a slave
    return out


def check_pool_runtime_for_ew_vs(vs_name, all_se=False):
    ''' As per AV-20910 check that get of the pool/runtime/internal fails if
        vs scale per SE > num of SEs. Must use the filter all_se=True
    '''
    tenant = get_tenant_for_container()
    ew_pool = get_pool_name_with_tenant(vs_name)
    params = {}
    if all_se:
        params['all_se'] = True

    stats = pool_lib.get_pool_internal(ew_pool, tenant=tenant, params=params, ret_all=True)
    num_stats = len(stats)
    num_ses = get_active_slave_count_from_master()
    if num_stats != num_ses:
        fail('Expected stats from %d ses but got %d' %(num_ses, num_stats))
    logger.trace('As expected, can use filter all_se=True to get pool runtime for all %d SEs' % num_ses)

def delete_openshift_service(app_id):
    if not _is_openshift_cloud():
        fail('Cannot delete service for non-openshift cloud')
    oshift_utils.delete_service(app_id)

def _update_openshift_app_config(app_name, **kwargs):
    instances = kwargs.get('instances', None)
    annotations = kwargs.get('labels', '')

    if instances is not None:
        if not annotations:
            # only need to rescale
            oshift_utils.scale_openshift_app(app_name, int(instances))
            return
        else:
            # instances and annotations changed
            oshift_utils.update_openshift_app(app_name, int(instances), annotations)
    # else no change, or only annotations changed
    oshift_utils.update_openshift_app(app_name, None, annotations)

def check_no_dhclient_on_ses():
    host_ips = get_active_slaves_ips()
    for host in host_ips:
        # REVIEW note hardcoding of the default registry; should allow param for a different one
        se_container_id = execute_command_on_slave(None, host,
                                                   "docker ps | grep %s | awk {'print $1'}" %DEFAULT_DOCKER_REGISTRY)
        logger.info('se container id : %s' % se_container_id)
        command = 'sudo docker exec -it %s bash -c "ps -efa | grep [d]hclient"' % se_container_id[0]
        out = execute_command_on_slave(None, host, command)
        logger.info('%s>>> ps -efa | grep dhclient: %s' % (host, out))
        if out:
            fail('Found dhclient processes %s running in SE host %s' % (out, host))


def check_vs_conns(vs_name, total_conn):
    f_conn = vs_lib.get_vs_runtime_detail_agg(vs_name, 'fel4stats', 'finished_conns')
    if int(f_conn) != int(total_conn):
        fail('ERROR! Virtual service connection number %s is not equal to %s ' %
                           (str(f_conn), str(total_conn)))

def delete_openshift_route(app_id, route_name=None, project='default'):
    if not _is_openshift_cloud():
        fail('Cannot delete route for non-openshift cloud')
    oshift_utils.delete_route(app_id, route_name=route_name, project=project)
# FIXME: Check and fix
def get_expected_alternatebackends_pool(app_name, route_name, backend_app_name, project="default"):
    pool_config = oshift_utils.get_pool_config_for_app(app_name, project=project)
    pool_name_list = []
    for pool in pool_config:
        pool_name_list.append('%s-%s-aviroute-pool-%s-%s' % (route_name, backend_app_name, pool["port"], pool["protocol"]))
    return pool_name_list

# FIXME: Check and fix
def get_pool_ratio(vs_name, tenant='default'):
    """
    Returns the all pools ratio associated with vs poolgroup
    """
    vs_resp = vs_lib.get_vs(vs_name, tenant=tenant)
    vs_http_policy_uuid = webapp_lib.get_slug_from_uri(vs_resp["http_policies"][0]["http_policy_set_ref"])
    resp_code, httppolicyset_resp = rest.get("httppolicyset", uuid=vs_http_policy_uuid)

    pool_ratio_list = []
    for rule in httppolicyset_resp["http_request_policy"]["rules"]:
        pool_group_uuid = webapp_lib.get_slug_from_uri(rule["switching_action"]["pool_group_ref"])
        resp_code, poolgroup_resp = rest.get("poolgroup", uuid=pool_group_uuid)
        for pool_info in poolgroup_resp['members']:
             pool_ratio_list.append(pool_info["ratio"])
    return list(set(pool_ratio_list))

# FIXME: Check and fix
def check_expected_pool_ratio(vs_name, pool_ratio_list, retries=6, tenant='default'):
    """
    check expected_pool_ratio associated with vs poolgroup
    """
    for i in range(retries):
        new_pool_ratio_list = get_pool_ratio(vs_name, tenant=tenant)
        if new_pool_ratio_list != pool_ratio_list:
            return True
        else:
            time.sleep(30)
    fail("Not found expected pool ratio")

# FIXME: Check and fix
def verify_app_pool_healthmonitor(app_name, expected_hm=[], tenant="default"):
    pool_name_list = get_expected_pools_for_app(app_name, project=tenant)
    for pool_name in pool_name_list:
        hm_list = pool_lib.get_all_health_monitors_of_pool(pool_name, tenant=tenant)
        if len(hm_list)  == 0:
            fail("Healthmonotor not found in app %s for pool %s" %(app_name, pool_name))
        if expected_hm and expected_hm != hm_list:
            fail("Expected Healthmonotors %s not found in app %s for pool %s" %(expected_hm, app_name, pool_name))


def update_app_spec(app_name, **kwargs):
    if _is_openshift_cloud():
        return oshift_utils.update_openshift_app(app_name, None, False, **kwargs)


def update_app_pool(app_name, **kwargs):
    '''
    update openshift app spec
    '''
    app_obj = _get_openshift_app(app_name, **kwargs)
    avi_proxy = json.loads(app_obj['app']['labels']['avi_proxy'])
    pool_cfg = avi_proxy.get('pool')
    for k, v in kwargs.iteritems():
        pool_cfg[k] = v
    version = read_version()
    avi_proxy['version'] = version
    avi_proxy['pool'] = pool_cfg
    annotations = {'avi_proxy': json.dumps(avi_proxy)}
    _update_openshift_app_config(app_name, labels=annotations, **kwargs)

def get_svc_clusterIP(app_name, tenant="default"):
    svc_config = oshift_utils.get_openshift_svc_config(app_name, project=tenant)
    return svc_config['spec']['clusterIP']


def get_daemon_set(expected_pod_count, tenant='default', **kwargs):
    return oshift_utils.get_openshift_daemon_set(expected_pod_count, tenant=tenant, **kwargs)


def delete_docker_container(container_id, slave_host_ip, **kwargs):
    cmd = 'docker rm -f %s' % container_id
    out = execute_command_on_slave(None, slave_host_ip, cmd, **kwargs)


def get_match_se_name(match_se_ip, tenant='admin'):
    se_name_list = se_lib.get_all_se_name_list()
    indices = [i for i, s in enumerate(se_name_list) if '%s' % match_se_ip in s]
    for index in indices:
        return se_name_list[index]


def check_se_container_id(se_name, container_id, tenant='admin', **kwargs):
    retries = kwargs.get('retries', 5)
    for i in range(retries):
        status_code, response = rest.get("serviceengine", name=se_name)
        new_container_id = response['container_id']
        if container_id not in new_container_id:
            return True
        else:
            asleep(delay=30)
    else:
        fail("Serviceengine %s not updated with new container id" % se_name)


def update_disable_auto_se_creation(disable_auto_se_creation=False):
    status_code, response = rest.get("cloud")
    response['results'][0]['oshiftk8s_configuration']['disable_auto_se_creation'] = disable_auto_se_creation
    rest.put('cloud', uuid=response['results'][0]['uuid'], data=response['results'][0])


def get_replicationcontroller(app_id, replicationcontroller_name=None, tenant='default'):
    if not _is_openshift_cloud():
        logger.trace('Cannot verify replicationcontroller for non-openshift cloud')
    if not replicationcontroller_name:
        replicationcontroller_name = app_id + '-avi-egress-pod'
    return oshift_utils.get_replicationcontroller_for_egress_service(replicationcontroller_name, tenant=tenant)

def get_replicationcontroller_pod(app_id, replicationcontroller_name=None, tenant='default'):
    if not _is_openshift_cloud():
        logger.trace('Cannot verify replicationcontroller pod for non-openshift cloud')
    if not replicationcontroller_name:
        replicationcontroller_name = app_id + '-avi-egress-pod'
    return oshift_utils.get_pod_from_replicationcontroller(replicationcontroller_name, tenant=tenant)

def verify_valid_ip_allocation(app_id, network_name, replicationcontroller_name=None, tenant='default'):
    response = get_replicationcontroller(app_id, replicationcontroller_name=replicationcontroller_name, tenant=tenant)
    for env in response['spec']['template']['spec']['containers'][0]['env']:
        if env['name'] == 'EGRESS_SOURCE':
            source_ip = env['value']
            break
    infra_utils.switch_mode(tenant='admin')
    status_code, network_response = rest.get("networkruntime", name=network_name, tenant='admin')
    infra_utils.switch_mode(tenant=tenant)
    for valid_ip in network_response['subnet_runtime'][0]['ip_alloced']:
        if valid_ip['ip']['addr'] == source_ip:
            logger.info("Found valid egress source configuration IP")
            break
    else:
        fail("Not found valid egress source configuration IP ")


def verify_replicationcontroller_fields(app_id, expected_keys_values={}, replicationcontroller_name=None, tenant='default'):
    response = get_replicationcontroller(app_id, replicationcontroller_name=replicationcontroller_name, tenant=tenant)
    exp_keys=[]
    for keys in expected_keys_values:
        exp_keys.append(keys)
    for env in response['spec']['template']['spec']['containers'][0]['env']:
        if env['name'] in exp_keys:
            if env['value'] != str(expected_keys_values[env['name']]):
                fail("Expected keys and values not present")

def get_serviceaccounts(tenant='default'):
    status_code, response = rest.get("cloud")
    #service account name format is avivantage-cloud_uuid
    serviceaccounts_name = 'avivantage-%s' % response['results'][0]['uuid'].split('cloud-')[1]
    return oshift_utils.get_serviceaccounts_for_egress_service(serviceaccounts_name, tenant=tenant)

def get_securitycontextconstraints(tenant='default'):
    if not _is_openshift_cloud():
        logger.trace('Cannot get securitycontextconstraints for non-openshift cloud')
    status_code, response = rest.get("cloud")
    #securitycontextconstraints name format is avivantage-scc-cloud_uuid
    scc_name = 'avivantage-scc-%s' % response['results'][0]['uuid'].split('cloud-')[1]
    return oshift_utils.get_scc_for_egress_service(scc_name, tenant=tenant)

def get_openshift_projects(tenant='default'):
    return oshift_utils.get_projects(tenant=tenant)

def set_secure_egress_mode(secure_egress_mode, tenant='default'):
    infra_utils.switch_mode(tenant='admin')
    if not _is_openshift_cloud():
        logger.trace('Cannot update secure_egress_mode for non-openshift cloud')
    res_code, response = rest.get("cloud")
    response['results'][0]['oshiftk8s_configuration']['secure_egress_mode'] = secure_egress_mode
    rest.put('cloud', uuid=response['results'][0]['uuid'], data=response['results'][0])

def check_openshift_object_created_or_deleted(object_type, object_name, action='create', tenant='Default', **kwargs):
    return oshift_utils.get_object_status(object_type, object_name, action=action, tenant=tenant, **kwargs)

def check_serviceaccount_ref_in_scc(project_name, tenant='default', flag=True, **kwargs):
    retries = kwargs.get('retries', 5)
    for i in range(retries):
        response = get_securitycontextconstraints(tenant=tenant)
        for key in response['users']:
            if flag and project_name in key:
                return True
            if not flag and project_name not in key:
                return True
        else:
            time.sleep(30)
    else:
        return False

def verify_no_ip_reuse(vs_list, replicationcontroller_name=None, tenant='default'):
    source_ip_list = []
    for vs_name in vs_list:
        response = get_replicationcontroller(vs_name, replicationcontroller_name=replicationcontroller_name,
                                             tenant=tenant)
        for env in response['spec']['template']['spec']['containers'][0]['env']:
            if env['name'] == 'EGRESS_SOURCE':
                source_ip = env['value']
                source_ip_list.append(source_ip)
                break
    opt = [item for item in set(source_ip_list) if source_ip_list.count(item) > 1]
    if opt:
        fail("IP reuse for secure service creation")
    return True

def create_openshift_serviceaccount(serviceaccount_name, tenant='default'):
    return oshift_utils.create_serviceaccount(serviceaccount_name,tenant=tenant)

def create_openshift_clusterrole(clusterrole_config, tenant='default'):
    return oshift_utils.create_clusterrole(clusterrole_config, tenant=tenant)

def set_oadm_policy_to_serviceaccount(clusterrole_name, clusterrole_type, serviceaccount_name, tenant='default', **kwargs):
    cmd = 'oadm policy %s %s system:serviceaccount:default:%s' % (clusterrole_type, clusterrole_name, serviceaccount_name)
    return oshift_utils.run_oc_cmd(cmd, project=tenant)

def set_service_account_token_to_cloud(serviceaccount_name, tenant='default', **kwargs):
    infra_utils.switch_mode(tenant='admin')
    service_account_token = kwargs.get('service_account_token', None)
    if not service_account_token:
        service_account_token = oshift_utils.get_serviceaccount_token(serviceaccount_name, tenant=tenant)
    status_code, response = rest.get("cloud")
    response['results'][0]['oshiftk8s_configuration']['client_tls_key_and_certificate_ref'] = False
    response['results'][0]['oshiftk8s_configuration']['ca_tls_key_and_certificate_ref']= False
    response['results'][0]['oshiftk8s_configuration']['service_account_token'] = service_account_token
    rest.put('cloud', uuid=response['results'][0]['uuid'], data=response['results'][0])

def delete_openshift_clusterrole(clusterrole_name, tenant='default'):
    return oshift_utils.delete_clusterrole(clusterrole_name, tenant=tenant)

def delete_openshift_serviceaccount(serviceaccount_name, tenant='default'):
    return oshift_utils.delete_serviceaccount(serviceaccount_name, tenant=tenant)

def add_update_alternatebackends_to_route(app_id, backend_vs_name_list, weight_list, route_name=None, project='default', **kwargs):
    if not _is_openshift_cloud():
        logger.trace('Cannot update routes alternatebackends for non-openshift cloud')
    if not route_name:
        route_name = app_id + '-route'
    oshift_utils.add_update_alternatebackends(route_name, backend_vs_name_list, weight_list, project=project, **kwargs)

def update_disable_auto_frontend_service_sync(disable_auto_frontend_service_sync=False):
    status_code, response = rest.get("cloud")
    response['results'][0]['oshiftk8s_configuration']['disable_auto_frontend_service_sync'] = disable_auto_frontend_service_sync
    rest.put('cloud', uuid=response['results'][0]['uuid'], data=response['results'][0])


def update_disable_auto_backend_service_sync(disable_auto_backend_service_sync=False):
    status_code, response = rest.get("cloud")
    response['results'][0]['oshiftk8s_configuration']['disable_auto_backend_service_sync'] = disable_auto_backend_service_sync
    rest.put('cloud', uuid=response['results'][0]['uuid'], data=response['results'][0])


def check_openshift_cloud_state(expected_status, **kwargs):
    """ verify that cloud is in the expected state before continuing """
    timeout = kwargs.get('timeout', CLOUD_CREATE_TIMEOUT)
    poll_interval = kwargs.get('poll_interval', CLOUD_CREATE_POLL_INTERVAL)
    # poll_interval is the amount of time to sleep between rounds; time spent in the rest call is not included.
    rounds = int(timeout/poll_interval)
    for round_ in xrange(rounds):
        status_code, response = rest.get("cloud")
        if response:
            status_code, cloud_status = rest.get("cloud", uuid=response['results'][0]['uuid'], path="/status")
            if cloud_status['state'] == expected_status:
                return True
            else:
                asleep(delay=poll_interval)
    else:
        fail('cloud state check failed')


def set_label_to_host(node_ip, key, value, tenant='default'):
    return oshift_utils.set_label_to_host_in_openshift(node_ip, key, value, tenant=tenant)


def delete_pod(pod_name, tenant='default'):
    return oshift_utils.delete_openshift_pod(pod_name, tenant=tenant)


def update_use_scheduling_disabled_nodes(use_scheduling_disabled_nodes=True):
    res_code, response = rest.get("cloud")
    response['results'][0]['oshiftk8s_configuration']['use_scheduling_disabled_nodes'] = use_scheduling_disabled_nodes
    rest.put("cloud", uuid=response['results'][0]['uuid'] , data=response['results'][0])


def check_all_slaves_connected():
    """

    :return:
    """

    c_count = 0
    slist = get_all_mesos_slaves()
    for vm in slist:
        se_name = vm['ip'] + '-avitag-1'
        if not se_lib.is_se_connected(se_name):
            print se_name + " Not Connected"
        else:
            c_count = c_count + 1
            logger.info('%s Connected' % se_name)

    if c_count != len(slist):
        return 0
    else:
        return 1


def get_all_mesos_slaves():
    """

    :return:
    """

    mlist=[]
    slist = infra_utils.get_vm_of_type('client')
    for vm in slist:
        if vm.name == 'mesos-slave':
            mlist.append(vm)
    return mlist


def get_mesos_vs_se_num_total(vs_name):
    """

    :param vs_name:
    :return:
    """

    vs_data = vs_lib.get_vs_runtime(vs_name)
    if vs_data['vip_summary'][0]:
        return vs_data['vip_summary'][0]['num_se_assigned']


def _update_openshift_app(app_name, vs_obj=None, **kwargs):
    app_obj = _get_openshift_app(app_name, **kwargs)
    avi_proxy = json.loads(app_obj['app']['labels']['avi_proxy'])

    if not vs_obj:
        vs_cfg = avi_proxy.get('virtualservice')
    else:
        vs_cfg = vs_obj
    for k, v in kwargs.iteritems():
        vs_cfg[k] = v
    version = read_version()
    avi_proxy['version'] = version
    avi_proxy['virtualservice'] = vs_cfg
    annotations = {'avi_proxy': json.dumps(avi_proxy)}
    _update_openshift_app_config(app_name, labels=annotations, **kwargs)


def set_schedulable_on_master(schedulable):
    master_ip = get_cluster_master_ip()
    cmd = 'oadm manage-node %s --schedulable=%s' % (master_ip, schedulable)
    stdout, stderr = oshift_utils.run_oc_cmd(cmd=cmd)
    if schedulable:
        assert '%s   Ready    ' % (master_ip) in stdout
    else:
        assert '%s   Ready,SchedulingDisabled' % (master_ip) in stdout


