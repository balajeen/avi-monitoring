import pytest
import subprocess
import re
from logger import logger
from testbed import AviTestbed
from vm import Vm, Client, Server, Controller
from logger_utils import fail, abort, error
from suite_vars import suite_vars
import avi_objects.cloud_sdk.vcenter
import avi_objects.cloud_sdk.openstack
import avi_objects.cloud_sdk.aws
import avi_objects.cloud_sdk.avitest_azure

def read_version():
    _version = suite_vars.api_version
    if not _version:
        with open(suite_vars.workspace + '/version', 'r') as versionfile:
            _version = re.search('^version:\s+(.*)$', versionfile.read(), re.MULTILINE).group(1)
            logger.debug('Version from file is: %s' %_version)
    else:
        logger.debug('Version configured is %s' %_version)
    # REVIEW should this also update the suite_vars.api_version?
    # Is there a use case for keeping it to the command line option?
    return _version

def vm_cloud_sdk(vm_name):
    pass

def get_vm_and_cloud_json(vm_name, tb_json):

    vm_json = [vm_json for vm_json in tb_json.get('Vm') \
                if vm_json.get('name') == vm_name][0]
    cloud_name = vm_json.get('cloud_name', 'Default-Cloud')

    cloud_json = None
    logger.info('vm name %s cloud name %s', vm_name, cloud_name)


    try:
        cloud_json = [cloud_json for cloud_json in tb_json.get('Cloud') \
                if cloud_json.get('name') == cloud_name][0]
    except TypeError:
        logger.info('Must be no-access cloud?')
        cloud_json = None
    except IndexError:
        logger.info("Can't find vm cloud under Clouds for %s" %vm_name)
        logger.info("IndexError cloud_json %s" %cloud_json)
        cloud_json = None

    logger.info('cloud_json %s' %cloud_json)

    if not cloud_json:
        cloud_json = None #Setting it back to None as it must have become an empty list
        try:
            # Check in vm clouds
            cloud_json = [cloud_json for cloud_json in tb_json.get('VmCloud') \
                if cloud_json.get('name') == cloud_name][0]
        except TypeError:
            logger.info('no VmCloud defined in the testbed')

    if not vm_json:
        error('Expected a valid vm_json in the testbed for vm %s' %vm_name)

    if not cloud_json:
        logger.info('cloud_json None, no access cloud?')

    logger.info('vm_json %s, cloud_json %s' %(vm_json, cloud_json))

    return vm_json, cloud_json

def get_vm_cloud_sdk(cloud_json, vm_json=None):
    sdk_conn = None

    try:
        if cloud_json.get('vtype') == 'CLOUD_VCENTER':
            sdk_conn = avi_objects.cloud_sdk.vcenter.Vcenter \
            (cloud_configuration_json=cloud_json.get('vcenter_configuration'), \
            vm_json=vm_json)
        elif cloud_json.get('vtype') == 'CLOUD_OPENSTACK':
            sdk_conn = avi_objects.cloud_sdk.openstack.Openstack \
            (cloud_configuration_json=cloud_json.get('openstack_configuration'), \
            vm_json=vm_json)
        elif cloud_json.get('vtype') == 'CLOUD_AWS':
            sdk_conn = avi_objects.cloud_sdk.aws.Aws \
            (cloud_configuration_json=cloud_json.get('aws_configuration'), \
            vm_json=vm_json)
        elif cloud_json.get('vtype') == 'CLOUD_AZURE':
            sdk_conn = avi_objects.cloud_sdk.avitest_azure.Azure \
            (cloud_configuration_json=cloud_json.get('azure_configuration'), \
            vm_json=vm_json)
        else:
            logger.info('Not implemented yet!!')
    except AttributeError as e:
        logger.info('cloud_json None, Got Exp: %s' % e.message)

    if cloud_json and not sdk_conn:
        # TODO: Once we have SDK classes defined for all clouds
        # we need to change this to error(..) instead
        logger.info('Expected a valid sdk_conn. vm_json %s cloud_json %s' \
            %(vm_json, cloud_json))

    return sdk_conn

class AviConfig(object):

    tenant = 'admin'
    user = 'admin'
    version = None
    vrfcontext = 'global'
    site_name = 'default'
    cloud = 'Default-Cloud'
    password = 'xxxxxx' # TODO: set this to the controller password
    session = None

    def __new__(cls):
       if not hasattr(cls, 'instance'):
           cls.instance = super(AviConfig, cls).__new__(cls)
       return cls.instance

    @classmethod
    def get_instance(cls):
       if hasattr(cls, 'instance'):
           return cls.instance
       else:
           assert False, "AviConfig is yet not initialized"

    def __init__(self):

        self.testbeds = pytest.config.getoption("--testbed")
        self._testbed = {}
        self._vm_list = {}
        self.sessions = {}
        self.version = read_version()
        self.site_objs = {}
        self.appclient = {}
        # TODO/Enhancements:
        # Without this, get_vm_of_type('controller')
        # seems to fail; not exactly sure how the lazy_init would kick in.
        # So for now, readding the earlier removed code snippet.
        for testbed in self.testbeds:
            testbed = AviTestbed(testbed)
            self.testbed[testbed.site_name] = testbed
            self.vm_list[testbed.site_name] = []

            tb_json = testbed.tb_json
            for vm in testbed.vm_list:
                vm_json, cloud_json = get_vm_and_cloud_json(vm.get('name'), tb_json)
                vm_cloud_sdk_conn = get_vm_cloud_sdk(cloud_json=cloud_json, vm_json=vm_json)
                if vm['type'].lower() == 'client':
                    vm_ins = Client(vm_json = vm, networks_detail = testbed.networks, \
                        vm_cloud_sdk_conn=vm_cloud_sdk_conn)
                elif vm['type'].lower() == 'server':
                    vm_ins = Server(vm_json = vm, networks_detail = testbed.networks, \
                    vm_cloud_sdk_conn=vm_cloud_sdk_conn)
                elif vm['type'].lower() == 'controller':
                    vm_ins = Controller(vm_json = vm, vm_cloud_sdk_conn=vm_cloud_sdk_conn)
                elif vm['type'].lower() == 'se':
                    continue
                else:
                    vm_ins = Vm(vm_json=vm, vm_cloud_sdk_conn=vm_cloud_sdk_conn)
                self.vm_list[testbed.site_name].append(vm_ins)

    @property
    def testbed(self):
        if not self._testbed:
            for testbed_file in self.testbeds:
                testbed = AviTestbed(testbed_file)
                self._testbed[testbed.site_name] = testbed
        return self._testbed

    @property
    def vm_list(self):
        logger.debug("Geting vm_list")
        if not self._vm_list:
            for site_name, testbed in self.testbed.iteritems():
                self._vm_list[site_name] = []

                tb_json = testbed.tb_json
                for vm in testbed.vm_list:
                    vm_json, cloud_json = get_vm_and_cloud_json(vm.get('name'), tb_json)
                    vm_cloud_sdk_conn = get_vm_cloud_sdk(cloud_json=cloud_json, vm_json=vm_json)
                    if vm['type'].lower() == 'client':
                        vm_ins = Client(vm_json = vm, networks_detail = testbed.networks, \
                                        vm_cloud_sdk_conn=vm_cloud_sdk_conn)
                    elif vm['type'].lower() == 'server':
                        vm_ins = Server(vm_json = vm, networks_detail = testbed.networks, \
                                        vm_cloud_sdk_conn=vm_cloud_sdk_conn)
                    elif vm['type'].lower() == 'controller':
                        vm_ins = Controller(vm_json = vm, vm_cloud_sdk_conn=vm_cloud_sdk_conn)
                    elif vm['type'].lower() == 'se':
                        continue
                    else:
                        vm_ins = Vm(vm_json=vm, vm_cloud_sdk_conn=vm_cloud_sdk_conn)
                    self._vm_list[site_name].append(vm_ins)
        return self._vm_list

    def switch_mode(self,**kwargs):
        """Sets the mode parameters for current configuration

        :param tenant: tenant for the current mode
        :param type: str
        :param user: user for the current mode
        :param type: str
        :param vrfcontext: vrfcontext for the current mode
        :param type: str
        :param site_name: site_name for the current mode
        :param type: str
        :param version: api version for the current mode
        :param type: str
        :param password: user password for the current mode
        :param type: str
        :param cloud: cloud context for the current mode
        :param type: str
        :param session: avi sdk controller session  for the current mode
        :param type: str
        """
        if 'tenant' in kwargs:
            self.tenant = kwargs['tenant']

        if 'user' in kwargs:
            self.user = kwargs['user']

        if 'vrfcontext' in kwargs:
            self.vrfcontext = kwargs['vrfcontext']

        if 'site_name' in kwargs:
            self.site_name = kwargs['site_name']

        if 'version' in kwargs:
            self.version = kwargs['version']

        if 'password' in kwargs:
            self.password = kwargs['password']

        if 'cloud' in kwargs:
            self.cloud = kwargs['cloud']

        if 'session' in kwargs:
            self.session = kwargs['session']


    def get_mode(self, key=None):

        if key:
            return getattr(self,key)
        mode = {'tenant': self.tenant,
                'vrfcontext': self.vrfcontext,
                'user': self.user,
                'site_name': self.site_name,
                'cloud': self.cloud,
                'version': self.version,
                'password': self.password,
                'session': self.session
               }
        return mode

    def get_context_key(self):
        mode = self.get_mode()
        key = str(mode['site_name']) + ',' + \
              str(mode['tenant']) + ',' + \
              str(mode['user']) + ',' + \
              str(mode['cloud'])

        return key

    def get_vm_of_type(self, vm_type, site_name=None, network=None):

        if not site_name:
            site_name = self.site_name
        vm_list = self.vm_list.get(site_name, [])
        ret_vm = []
        for vm in vm_list:
            if vm.type == vm_type:
                if network:
                    if network in vm.networks['data'] or unicode(network) in vm.networks['data']:
                        ret_vm.append(vm)
                else:
                    ret_vm.append(vm)
        return ret_vm

    def get_vm_by_id(self, vm_id):
        for vm in self.vm_list[self.site_name]:
            try:
                if vm.name == vm_id or vm.ip == vm_id:
                    return vm
            except AttributeError:
                pass
        fail("ERROR! get_vm_by_id " + str(vm_id))

    def get_testbed(self):
        return self.testbed[self.site_name]

    def get_vm_by_ip(self, vm_ip):
        """
        FixMe: AV-34041: infra should provide vm object with ip(dhcp case)
        :param vm_ip:
        :return:
        """
        for vm in self.vm_list[self.site_name]:
            try:
                if vm.name == vm_ip or vm.ip == vm_ip:
                    return vm
            except AttributeError:
                pass
        fail("ERROR! get_vm_by_id " + str(vm_ip))

    def clear_session(self, all_sessions=False):
        self.session = None
        if all_sessions:
            self.sessions = {}
        else:
            context_key = self.get_context_key()
            if context_key in self.sessions:
                del self.sessions[context_key]
