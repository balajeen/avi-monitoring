from avi_objects.logger import logger
from avi_objects.logger_utils import fail, error, aretry, asleep
from avi_objects.rest import (get_session, get_cloud_context, get, put)
from keystoneclient.v2_0 import client as keystone_client
from novaclient.client import Client as NovaClient
import time
from glanceclient import Client as GlanceClient


class Openstack(object):

    def __init__(self, cloud_configuration_json, vm_json):
        self.configuration = cloud_configuration_json
        self.vm_json = vm_json
        #self.nova = None
        self.nova = self.sdk_connect()
        self.ks_client = self.get_keystone_client()
        self._init_glance_client()

    def sdk_connect(self):

        auth_url = self.configuration['auth_url']
        user = self.configuration['username']
        password = self.configuration['password']
        logger.debug('password from config = %s' % password)
        # FIXME read from rc
        password = 'avi123'
        project_id = user
        nova = NovaClient('2', user, password,
                        project_id, auth_url)
        return nova

    def get_keystone_client(self):
        ks_client = keystone_client.Client(username=self.configuration['username'],
                                          #password=self.configuration['password'],
                                          password = 'avi123', # FIXME
                                          auth_url=self.configuration['auth_url'],
                                          tenant_name="admin")
        return ks_client

    def _init_glance_client(self):
        # To handle the token timeout issues
        # Default timeout is 1 hour
        # Re authenticate and get a new token
        self.ks_client.authenticate()
        glance_endpoint = self.ks_client.service_catalog.url_for(service_type='image', endpoint_type='publicURL')
        self.glance = GlanceClient('2', glance_endpoint, token=self.ks_client.auth_token)

    def get_vm_ip_for_name(self):
        mgmt_ip = ''
        vm_name = self.vm_json.get('name')
        management = self.vm_json.get('networks').get('mgmt')

        s_obj = self.nova.servers.find(name=vm_name)
        nw_obj = self.nova.networks.find(label=management)
        mgmt_nw_uuid = nw_obj.id
        _info = [(intf.net_id, intf.fixed_ips[0]['ip_address']) for intf in s_obj.interface_list()]
        for nw_uuid, ip in _info:
            if mgmt_nw_uuid == nw_uuid:
                mgmt_ip = ip
                break
        logger.info('mgmt_ip %s' % mgmt_ip)
        if not mgmt_ip:
            raise Exception('Management ip for vm %s not found' % vm_name)
        return mgmt_ip

    def delete_instance(self,vm_name=None):
        # Check if vm_name is passed, if not extract from vm_json
        if not vm_name:
           vm_name = self.vm_json.get('name')
        logger.info('Getting VM object for vm : %s' % vm_name)
        try:
            server_obj = self.nova.servers.find(name=vm_name)
        except Exception as e:
            logger.info("error: %s. that's OK" % e)
            return
        logger.info('Deleting VM object with name: %s' % vm_name)
        server_obj.delete()

    def delete_vms_by_prefix(self, prefix=None):
        if not prefix:
            logger.info("No Prefix provided. Returning")
            return
        logger.info("prefix passed : %s" % prefix)
        vm_list = self.nova.servers.list()
        for vm in vm_list:
            if prefix in vm.name:
                self.delete_instance(vm.name)

    def deploy_vm_from_qcow(self, **kwargs):
        #Get QCOW path
        qcow_path = kwargs.get('qcow_path')
        if not qcow_path:
            raise RuntimeError('Must specify a qcow path')
        #Get image name
        ova_image = kwargs.get('ova_image')
        if not ova_image:
            raise RuntimeError('Must specify a image name for ova')

        mgmt_net = kwargs.get('mgmt_net')
        if not mgmt_net:
            mgmt_net = self.vm_json.get('networks')['mgmt']
        vm_type = kwargs.get('vm_type') or self.vm_json.get('type')
        if not vm_type:
            raise RuntimeError('VM type should be specified')

        if vm_type == 'controller':
            flavor = 'm1.controller'
        else:
            flavor = 'm1.se'
        vm_name = kwargs.get('name')
        if not vm_name:
            raise RuntimeError('VM name must be specified')

        fixed_ip = self.vm_json.get('ip') or kwargs.get('ip_address')
        if not fixed_ip:
            fixed_ip = ''

        # Create image
        logger.info("Creating Image in glance.....")
        self.create_glance_image(name=ova_image, qcow_path=qcow_path)
        # Create controller instance
        logger.info("Creating controller instance.....")
        self.create_avi_instance(instance_name=vm_name, flavor=flavor, image_name=ova_image, fixed_ip=fixed_ip)

    def delete_image_by_name(self, name):
        # To handle the token timeout issues
        self._init_glance_client()
        image_list = self.glance.images.list()
        for image in image_list:
            if name in image.name:
                logger.info("deleting image with name: %s and id is %s" %(image.name, image.id))
                self.glance.images.delete(image.id)

    @aretry(retry=120, delay=30, period=10)
    def wait_until_vm_is_up(self, vm_name=None):
        if not vm_name:
            vm_name = self.vm_json.get('name')
        try:
            vm_obj = self.nova.servers.find(name=vm_name)
            mgmt = self.vm_json.get('networks').get('mgmt')
            vm_ip = vm_obj.networks[mgmt][0]
            if vm_ip:
                logger.info('vm ip is: %s' % vm_ip)
                return
        except Exception as e:
            fail("VM not yet up with error: %s" %e.message)

    def create_glance_image(self, name="", disk_format="qcow2", container_format="bare", qcow_path=""):
        if not name or not qcow_path:
            raise RuntimeError('Must specify name and qcow_path')
        image_already_exist = False
        image_list = self.glance.images.list()
        for image in image_list:
            if name in image.name:
                image_already_exist = True
        if not image_already_exist:
            logger.info("Image not present , hence creating")
            image = self.glance.images.create(name=name, disk_format="qcow2", container_format="bare")
            image_upload = self.glance.images.upload(image.id, open(qcow_path , 'rb'))
            if image.status.lower() == 'active':
                logger.info("upload successfull")
        else:
            logger.info("Image already present , hence skipping")

    def create_avi_instance(self, instance_name="", flavor="m1.controller", image_name="", fixed_ip=""):
        if not instance_name or not instance_name or not flavor:
            raise RuntimeError('Must specify all method attributes')
        nw_list = self.nova.networks.list()
        for net in nw_list:
            if 'mgmt' in net.label:
                net_id = net.id
        logger.info('Management_network_ID: %s' %net_id)
        # nics = [{"net-id": net_id, "v4-fixed-ip": ''}]
        nics = [{"net-id": net_id, "v4-fixed-ip": fixed_ip }]
        logger.info("creating vm with name:%s and nics: %s" %(instance_name, str(nics)))
        meta_data = {"AVISETYPE":"NETWORK_ADMIN","CreatedBy":"AviNetworksInc", "TenantId":"global"}
        image_obj = self.nova.images.find(name=image_name)
        flavor_obj = self.nova.flavors.find(name=flavor)
        logger.info("Creating the controller VM")
        instance = self.nova.servers.create(name=instance_name,  flavor=flavor_obj, image=image_obj, meta = meta_data, config_drive=True, nics = nics )
        # Poll continuously to check the vm status is 'ACTIVE'
        self.check_vm_status(instance_name, 'ACTIVE')

    def poweron(self, vm_name=None):
        """ Power on openstack vm """
        if not vm_name:
            vm_name = self.vm_json.get('name')
        vm = None
        try:
            vm = self.nova.servers.find(name='%s' % vm_name)
            logger.info('vm state %s' %vm.status)
            if vm.status == 'ACTIVE':
                logger.info('vm is already powered on state, return')
                return True
        except Exception as e:
            error("can't find vm %s in openstack, exp: %s" % (vm_name, e))
        if vm:
            logger.debug('Found vm: %s to poweron' % vm_name)
            vm.start()
        return (self.check_vm_status(vm_name, 'ACTIVE'))

    @aretry(retry=30, delay=10, period=5)
    def check_vm_status(self, vm_name, exp_status):
        """ Helps to check VM expected status """
        vm = self.nova.servers.find(name='%s' % vm_name)
        if vm.status == exp_status:
            logger.info('VM: %s in expected state: %s' % (vm_name, exp_status))
            return True
        else:
            fail('VM: %s , not in expected state, Actual:%s, Expected: %s'\
                % (vm_name, vm.status, exp_status))

    def poweroff(self, vm_name=None):
        """ Power off openstack vm """
        if not vm_name:
            vm_name = self.vm_json.get('name')
        vm = None
        try:
            vm = self.nova.servers.find(name='%s' % vm_name)
            logger.info('vm state %s' %vm.status)
            if vm.status == 'SHUTOFF':
                logger.info('vm is already powered off, return')
                return True
        except Exception:
            error("can't find vm %s in openstack, exp: %s" % (vm_name, e))
        if vm:
            logger.debug('Found vm: %s to poweroff' % vm_name)
            vm.stop()
        return (self.check_vm_status(vm_name, 'SHUTOFF'))

    def restart(self, wait_time=0):
        self.poweroff()
        logger.info('wait %s after vm is powered off' %wait_time)
        time.sleep(wait_time)
        self.poweron()

    def disconnect(self):
        # TODO
        pass

    def setup_openstack_rolemapping(self, **kwargs):
        cloud_name = get_cloud_context()
        _, data = get('cloud', name=cloud_name)

        role_mapping = []
        # sort the keys to force '*' to go to the end
        for kw in sorted(kwargs.keys(), reverse=True):
            role_mapping.append({'os_role': kw, 'avi_role': kwargs[kw]})
        data['openstack_configuration']['role_mapping'] = role_mapping
        put('cloud', name=cloud_name, data=data)
        from avi_objects.infra_utils import check_cloud_state
        check_cloud_state(cloud_name=cloud_name)

    def create_keystone_tenant(self, tenant):
        logger.debug('Creating keystone tenant %s' %tenant)
        self.ks_client.tenants.create(tenant)

    def delete_keystone_tenant(self, tenant):
        logger.debug('Deleting keystone tenant %s' %tenant)
        tenant_id = self.ks_client.tenants.find(name=tenant).id
        self.ks_client.tenants.delete(tenant_id)

    def create_keystone_role(self, role):
        logger.debug('Creating keystone role %s' %role)
        self.ks_client.roles.create(role)

    def delete_keystone_role(self, role):
        logger.debug('Deleting keystone role %s' %role)
        role_id = self.ks_client.roles.find(name=role).id
        self.ks_client.roles.delete(role_id)

    def create_keystone_user(self, username, password, tenant=None):
        logger.debug('Creating keystone user %s' %username)
        if tenant is None:
            tenant_id = self.ks_client.auth_ref.project_id
        else:
            tenant_id = self.ks_client.tenants.find(name=tenant).id
        self.ks_client.users.create(username, password, tenant_id=tenant_id)

    def delete_keystone_user(self, username):
        logger.debug('Deleting keystone user %s' %username)
        user_id = self.ks_client.users.find(username=username).id
        self.ks_client.users.delete(user_id)

    def add_keystone_role(self, username, tenant, role):
        ks_user_obj = self.ks_client.users.find(username=username)
        if not ks_user_obj or ks_user_obj.username != username:
            fail("Did not find the needed user in keystone!")

        ks_role_obj = self.ks_client.roles.find(name=role)
        if not ks_role_obj or ks_role_obj.name != role:
            fail("Did not find the needed role in keystone!")

        if tenant == '*':
            for ks_tenant_obj in self.ks_client.tenants.list():
                ks_tenant_obj.add_user(ks_user_obj, ks_role_obj)
        else:
            ks_tenant_obj = self.ks_client.tenants.find(name=tenant)
            if not ks_tenant_obj or ks_tenant_obj.name != tenant:
                fail("Did not find the needed tenant in keystone!")
            ks_tenant_obj.add_user(ks_user_obj, ks_role_obj)

    def extract_roles_from_users(self, user_data):
        roles = []
        for user in user_data:
            for access in user['access']:
                role_ref = access['role_ref']
                role_name = role_ref.split('name=')[1].split('&')[0]
                if role_name not in roles:
                    roles.append(role_name)
        return roles

    def process_openstack_data(self, tenant_data, user_data, operation):
        """
        Implements openstack-specific handling for data to be created/deleted in horizon
        """
        tenants = [t['name'] for t in tenant_data]
        users = [u['name'] for u in user_data]
        roles = self.extract_roles_from_users(user_data)
        logger.debug('extracted openstack specific configs: tenants=%s, users=%s, roles=%s' %(tenants, users, roles))

        if operation == 'create':
            for tenant in tenants:
                # REVIEW should these ignore errors if already existing?
                self.create_keystone_tenant(tenant)
            for user in user_data:
                self.create_keystone_user(user['username'], user['password']) # FIXME tenant?
            for role in roles:
                self.create_keystone_role(role)
            self.setup_openstack_rolemapping(**{r:r for r in roles})

            # add keystone role mapping
            for user in user_data:
                username = user['name']
                for access in user['access']:
                    role_ref = access['role_ref']
                    role_name = role_ref.split('=')[1]
                    tenant_name = None
                    tenant_ref = access.get('tenant_ref', None)
                    if tenant_ref:
                        tenant_name = tenant_ref.split('=')[1]
                    elif access.get('all_tenants'):
                        tenant_name = '*'
                    self.add_keystone_role(username, tenant_name, role_name)

            # REVIEW: create? get? switch_mode(some other user?)
            get_session().reset_session()
        elif operation == 'delete':
            for tenant in tenants:
                try:
                    self.delete_keystone_tenant(tenant)
                except Exception as e:
                    # REVIEW should these take flags similar to ignore_deleted?
                    if '404' in str(e):
                        pass
                    else:
                        raise e
            for user in user_data:
                try:
                    self.delete_keystone_user(user['username'])
                except Exception as e:
                    if '404' in str(e):
                        pass
                    else:
                        raise e
            for role in roles:
                try:
                    self.delete_keystone_role(role)
                except Exception as e:
                    if '404' in str(e):
                        pass
                    else:
                        raise e
            # We don't sync deletes, instead call this API explicitly
            get('openstack-cleanup')
        else:
            fail('Unsupported operation %s' % operation)

    def get_available_az(self):
        """
        Find list of AZ's in openstack that have one or more compute hosts available for use
        """
        logger.info('Getting list of AZs in nova')
        azones = self.nova.availability_zones.list(detailed=True)
        azs_compute = dict()
        for azone in azones:
            logger.info('Found AZ %s Available %s' %
                        (azone.zoneName, azone.zoneState['available']))
            if not azone.zoneState['available']:
                continue
            num_compute_hosts = 0
            for hname, hattrs in azone.hosts.iteritems():
                if ('nova-compute' in hattrs and
                        hattrs['nova-compute']['active'] and
                        hattrs['nova-compute']['available']):
                    num_compute_hosts += 1
            if num_compute_hosts:
                azs_compute[azone.zoneName] = num_compute_hosts
        logger.info('AZs found in nova with available compute capacity %s' % azs_compute)
        return azs_compute
