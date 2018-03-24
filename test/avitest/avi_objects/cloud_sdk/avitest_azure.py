import os
import time
import json
import ipaddress
import re
import yaml
from avi_objects.logger import logger
from avi_objects.logger_utils import error, fail, asleep, aretry
from azure.mgmt.compute.models import (VirtualMachine, HardwareProfile, StorageProfile,
                                       OSDisk, VirtualHardDisk, DiskCreateOptionTypes,
                                       OperatingSystemTypes, OSProfile, NetworkProfile,
                                       NetworkInterfaceReference)
from azure.mgmt.network.models import (NetworkInterface, NetworkInterfaceIPConfiguration, Subnet)
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.storage.blob import PageBlobService

def get_credentials(cloud_type, cloud_name):
    try:
        with open('/home/aviuser/avitest_rc.json') as json_data:
            jd = json.load(json_data)
            logger.info("Trying to read credentials for cloud type=%s cloud name=%s" %(cloud_type, cloud_name))
            credentials = jd[cloud_type][cloud_name]
            json_data.close()
            return credentials
    except Exception as e:
        fail("Failed to read default credential file: /home/aviuser/avitest_rc.json with %s" %e)

class Azure(object):
    """ Function for Azure communication """

    def __init__(self, cloud_configuration_json=None, vm_json=None, **kwargs):
        self.configuration = cloud_configuration_json
        self.vm_json = vm_json
        self.subscription_id = kwargs.get('subscription_id', None)
        self.application_id = kwargs.get('application_id', None)
        self.secret_key = kwargs.get('secret_key', None)
        self.tenant_id = kwargs.get('tenant_id', None)
        self.resource_group = kwargs.get('resource_group', None)
        self.compute_client = kwargs.get('compute_client', None)
        self.network_client = kwargs.get('network_client', None)
        self.vnet_id = kwargs.get('vnet_id', None)
        self.subnet_uuid = kwargs.get('subnet_uuid', None)
        self.cloud_type = kwargs.get('type', 'azure')
        self.credentials = kwargs.get('credentials', False)
        self.cloud_name = kwargs.get('cloud_name', 'Default-Cloud')
        self.sdk_connect()

    def sdk_connect(self):
        """
        Init the AZURE object from configuration params
        """
        if not self.credentials:
            from avi_objects.avi_config import AviConfig
            config = AviConfig.get_instance()
            site_name = config.get_mode().get('site_name')
            self.cloud_name = self.configuration.get('name', 'Default-Cloud')
        credentials = get_credentials(self.cloud_type, self.cloud_name)
        if not self.subscription_id:
            self.subscription_id = self.configuration.get('subscription_id', None)
            if self.subscription_id:
                self.subscription_id = str(self.subscription_id)
        if not self.application_id:
            self.cc_user_info = config.testbed[site_name].pre_configuration['CloudConnectorUser'][0]
            self.application_id = self.cc_user_info['azure_serviceprincipal'].get('application_id', None)
        if not self.secret_key:
            self.secret_key = credentials.get('secret_key', None)
        if not self.tenant_id:
            self.tenant_id = self.cc_user_info['azure_serviceprincipal'].get('tenant_id', None)
        if not self.resource_group:
            self.resource_group = self.configuration.get('resource_group', None)
        if not self.vnet_id:
            self.vnet_id = self.configuration['network_info'][0].get("virtual_network_id")
        if not self.subnet_uuid:
            self.subnet_uuid = self.configuration['network_info'][0].get('se_network_id')

#        # Below 4 params needed for setting up the testbed
#        if not self.subnet_id:
#            self.subnet_id = self.configuration.get("virtual_network_id") + '/subnets/' + self.configuration.get('se_network_id')
#        if not self.storage_account:
#            self.storage_account = get_testbed_variable(variable='storage_account')
#        if not self.storage_account:
#            self.storage_account_key = get_testbed_variable(variable='storage_account_key')
#        if not self.storage_account:
#            self.container_name = get_testbed_variable(variable='container_name')
      
        if (not self.subscription_id or not self.application_id or 
            not self.application_id or not self.tenant_id or not self.resource_group):
            logger.info('Either or all of subscription_id, secret key, client id, tenant id, resource_group  are empty')
            return
        logger.info("Initializing Azure with %s %s %s %s" %(self.subscription_id,
                    self.tenant_id, self.resource_group, self.vnet_id))
        self.azure_init()

    def azure_init(self):
        """
        AZURE connection clients init
        """
        if not self.credentials:
            try:
                self.credentials = ServicePrincipalCredentials(client_id = self.application_id,
                                                               secret = self.secret_key, tenant = self.tenant_id)
            except Exception as e:
                fail('AZURE credentials are wrong and failed with error:%s' % str(e))

        if not self.compute_client:
            logger.info('Connecting to AZURE Compute client')
            try:
                self.compute_client = ComputeManagementClient(self.credentials, self.subscription_id)
            except Exception as e:
                fail('AZURE Compute client failed with error:%s' % str(e))

        if not self.network_client:
            logger.info('Connecting to AZURE Network client')
            try:
                self.network_client = NetworkManagementClient(self.credentials, self.subscription_id)
            except Exception as e:
                fail('AZURE Network client failed with error:%s' % str(e))

    def get_vm_ip_for_name(self, vm_name=None, public_ip_address=False):
        """ Get IP address for given vm """
        vm_ip_addr = None
        if not vm_name:
            vm_name = self.vm_json.get('name')
        try:
            vm_obj = self.compute_client.virtual_machines.get(self.resource_group, vm_name)
            for interface in vm_obj.network_profile.network_interfaces:
                logger.debug('Got interface details ..: %s' % interface.id)
                nic_name=" ".join(interface.id.split('/')[-1:])
                #sub="".join(interface.id.split('/')[4])
                ip_addr_objs = self.network_client.network_interfaces.get(self.resource_group, nic_name).ip_configurations
                for ip_obj in ip_addr_objs:
                    logger.info(" Private IP Address: %s , for Nic: %s, IP Config obj:%s"
                                 % (ip_obj.private_ip_address, nic_name, ip_obj.name))
                    if ip_obj.primary:
                        if public_ip_address:
                            vm_ip_addr = ip_obj.public_ip_address
                        else:
                            vm_ip_addr = ip_obj.private_ip_address
                            logger.info("IP Address: %s , for Nic: %s" % (vm_ip_addr, nic_name))
                return vm_ip_addr
        except Exception as e:
            fail('Error while getting the ip address for vm, exp: %s' % e.message)

    def poweron(self, vm_name=None):
        """ Power ON VM """
        if not vm_name:
            vm_name = self.vm_json.get('name')
        logger.info('Going to Power ON VM name: %s' % vm_name)
        try:
            vm_start = self.compute_client.virtual_machines.start(self.resource_group, vm_name)
            vm_start.wait()
        except Exception as e:
            fail('Error while power on VM: %s ' % e.message)

    def poweroff(self, vm_name=None):
        """ Power OFF VM """
        if not vm_name:
            vm_name = self.vm_json.get('name')
        logger.info('Going to Power OFF VM name: %s' % vm_name)
        try:
            vm_stop = self.compute_client.virtual_machines.power_off(self.resource_group, vm_name)
            vm_stop.wait()
        except Exception as e:
            fail('Error while power off VM: %s ' % e.message)

    def restart(self, vm_name=None):
        """ Restart VM """
        if not vm_name:
            vm_name = self.vm_json.get('name')
        logger.info('Going to Restart VM name: %s' % vm_name)
        try:
            vm_restart = self.compute_client.virtual_machines.restart(self.resource_group, vm_name)
            vm_restart.wait()
        except Exception as e:
            fail('Error while power on VM: %s ' % e.message)

    def vm_deployment(self):
        """ VM Deployment Setting/Credentials and param details population """
        from avi_objects.infra_utils import get_testbed_variable
        # Below 4 params needed for setting up the testbed
        self.subnet_id = self.vnet_id + '/subnets/' + self.subnet_uuid
        self.storage_account = get_testbed_variable(variable='storage_account')
        self.storage_account_key = get_testbed_variable(variable='storage_account_key')
        self.container_name = get_testbed_variable(variable='container_name')

    def get_ip_from_azure(self):
        """ Get IP from Azure """
        vnet_id = self.configuration['network_info'][0].get("virtual_network_id").split('/')
        master_vnet_name = vnet_id[vnet_id.index("virtualNetworks")+1]
        master_resource_group = vnet_id[vnet_id.index("resourceGroups")+1]
        subnet_obj = self.network_client.subnets.get(master_resource_group, master_vnet_name,
                                                     self.subnet_uuid) 
        random_ip = str(subnet_obj.address_prefix).split('/')[0]
        vnet_subnet_net = self.network_client.virtual_networks.check_ip_address_availability(master_resource_group,
                                      master_vnet_name, random_ip)
        logger.info('Got Random 5 IPs: %s' % vnet_subnet_net.available_ip_addresses)
        return vnet_subnet_net.available_ip_addresses[0]

    def get_vhd_url(self, build_dir):
        vhd_name = 'controller'
        version_file = build_dir + '/VERSION'
        try:
            with open(version_file, 'r') as f:
                ver_dic = yaml.load(f)
            vhd_name = vhd_name + '-%s-%s.vhd' % (ver_dic['Version'], ver_dic['build'])
            vhd_url = "https://%s.blob.core.windows.net/%s/%s" % (self.storage_account, self.container_name, vhd_name)
            return vhd_url, vhd_name
        except Exception as e:
            fail('Error while getting VERSION, Exp:%s' % e.message)
    
    def get_nic_params(self, controller_ip):
        location = self.configuration.get('location')
        vm_name = self.vm_json.get('name')
        try:
            return NetworkInterface(
                    location=location,
                    ip_configurations=[NetworkInterfaceIPConfiguration(
                        name='%s-%s'%(vm_name,controller_ip),
                        private_ip_address=controller_ip,
                        private_ip_allocation_method='Static', private_ip_address_version='IPv4',
                        subnet=Subnet(id=self.subnet_id))])
        except Exception as e:
            fail('Error while getting nic parameters %s'%str(e))

    def get_nic_id(self, vm_name=None):
        """ Get NIC ID for given vm instence """
        if not vm_name:
            vm_name = self.vm_json.get('name')
        nic_name = "%s-NIC"%vm_name
        try:
            nic = self.network_client.network_interfaces.get(self.resource_group, nic_name)
            return nic.id
        except Exception as e:
            fail('Error while getting NIC id: %s'%str(e))

    def create_nic(self, vm_name=None):
        """ Create Network interface """
        if not vm_name:
            vm_name = self.vm_json.get('name')

        controller_ip = self.get_ip_from_azure()
        nic_name = "%s-NIC"%vm_name
        try:
            nic = self.network_client.network_interfaces.create_or_update(
                self.resource_group, nic_name, parameters=self.get_nic_params(controller_ip))
            asleep(msg='Creating NIC in-progress .. internal wait is there ...', delay=10)
            nic.wait()
            return controller_ip
        except Exception as e:
            fail('Error while creating a NIC %s'%str(e))

    def vm_parameters(self, vhd_url, nic_id, vhd_name):
        '''
        :param1 vhd_url: controller vhd url
        :param2 args: command line arguments
        :param3 pb: testbed file details
        :param4 roles: roles from testbed file - controller, se, client and server
        :param5 nic_id: Azure controller NIC resource id
        :param6 vhd_name: desired vhd name
        '''
        vm_size = self.vm_json.get('vm_size', 'Standard_F4s')
        # jay-smoke-ctrl-1-osDisk-controller-18.1.1-5220.vhd
        vm_name = self.vm_json.get('name')
        vhd_name = vm_name + '-osDisk-' + vhd_name
        self.delete_vm_vhd(vm_name=vm_name, vhd_name=vhd_name)

        return VirtualMachine(
            location=self.configuration.get('location'),
            hardware_profile=HardwareProfile(vm_size=vm_size),
            storage_profile=self.get_storage(vhd_url, vhd_name),
            os_profile=self.get_os(),
            network_profile=self.get_network(nic_id)
        )

    def get_network(self, nic_id):
        """ Get Network Object for given Network ID"""
        return NetworkProfile(
            network_interfaces=[
                NetworkInterfaceReference(
                    id=str(nic_id),
                    primary=True
                )
            ]
        )

    def get_os(self):
        """ Get base Operating System  """
        os_username = self.vm_json.get('os_username', 'aviadmin')
        os_password = self.vm_json.get('os_password', 'Aviuser123$%')
        vm_name = self.vm_json.get('name')
        return OSProfile(
            admin_username=os_username,
            admin_password=os_password,
            computer_name=vm_name
        )

    def get_storage(self, vhd_url, vhd_name):
        """ Get Storage for given VHD name and VHD URL"""
        vm_name = self.vm_json.get('name')
        vhd_name = "%s-osDisk-%s"%(vm_name,vhd_name)
        return StorageProfile(
            os_disk=OSDisk(
                name=vm_name,
                image=VirtualHardDisk(uri=vhd_url),
                vhd=VirtualHardDisk(
                    uri='https://%s.blob.core.windows.net/%s/%s'%(self.storage_account, self.container_name, vhd_name)),
                disk_size_gb=64,
                create_option=DiskCreateOptionTypes.from_image,
                caching='ReadWrite',
                os_type=OperatingSystemTypes.linux
            )
        )

    def vhd_exists(self, vhd_name):
        page_blob_service = PageBlobService(account_name=self.storage_account, account_key=self.storage_account_key)
        try:
            page_blob_service.get_blob_metadata(self.container_name, vhd_name)
            return True
        except:
            logger.info('%s does not exists' % vhd_name)
            return False

    def upload_vhd_to_azure(self, build_dir, vhd_name):
        """ Upload VHD image to Azure Storage from given build directory """
        vhd_file = build_dir + '/controller.vhd'
        try:
            page_blob_service = PageBlobService(account_name=self.storage_account, account_key=self.storage_account_key)
            logger.info('%s started uploading....'%vhd_name)
            page_blob_service.create_blob_from_path(self.container_name, vhd_name, vhd_file)
            logger.info('%s file uploaded'%vhd_name)
            page_blob_service.set_blob_metadata(self.container_name, vhd_name,metadata={'status':'done'})
            # Have taken care vai once usage is done going to delete vhd
            # self.delete_oldest_vhd(vhd_name)
        except Exception as e:
            fail('Error while uploading .vhd to container: %s'%str(e))

    def create_vm(self, **kwargs):
        """ Create Azure VM with given build
            
        """
        self.vm_deployment()
        build_dir = kwargs.get('build_dir')
        vm_name = self.vm_json.get('name')

        # Delete VMs and NIcs if already exists
        self.delete_instance(vm_name=vm_name, raise_error=False)
        
        vhd_url, vhd_name = self.get_vhd_url(build_dir)
        logger.info("Got VHD URL : %s \n VHD name: %s " % (vhd_url, vhd_name))
        if not self.vhd_exists(vhd_name):
            logger.info('Deleting previous controller vhd ..')
            self.upload_vhd_to_azure(build_dir, vhd_name)

        # vNetwork name + Subnet 
        controller_ip = self.create_nic(vm_name=vm_name)
        nic_id = self.get_nic_id(vm_name=vm_name)
        try:
            result = self.compute_client.virtual_machines.create_or_update(self.resource_group, \
                    vm_name, self.vm_parameters(vhd_url, nic_id, vhd_name))
            asleep(msg='Creating Virtual in-progress .. internal wait is there.', delay=10)
        except Exception as e:
            fail('Error while creating Controller Virtual Machine: %s' % e.message)
        result.wait()
        logger.info('Controller : %s Created withIP address: %s' % (vm_name, controller_ip))

    def check_vm_exist(self, vm_name=None):
        """ """
        if not vm_name:
            vm_name = self.vm_json.get('name')
        try:
            result = self.compute_client.virtual_machines.get(self.resource_group, vm_name)
            return True
        except Exception as e:
            logger.info('Previous Controller %s does not exists, Exp:%s' % (vm_name, e.message))
            return False

    def check_nic_exist(self, nic_name=None, vm_name=None):
        """ Check NIC existing  """
        if not vm_name:
            vm_name = self.vm_json.get('name')
        nic_name = "%s-NIC"%vm_name
        try:
            self.network_client.network_interfaces.get(self.resource_group, nic_name)
            return True
        except Exception as e:
            logger.info('Previous NIC %s does not exists' % nic_name)
            return False

    def check_vm_vhd_exists(self, vm_name=None, vhd_name=None):
        """ Check VM VHD Exists ... """
        if not vm_name:
            vm_name = self.vm_json.get('name')
        if not vhd_name:
	    vhd_name = vm_name + '-osDisk-' + vm_name + '-osDisk-controller'
        try:
            page_blob_service = PageBlobService(account_name=self.storage_account, account_key=self.storage_account_key)
            # page_blob_service.get_blob_metadata(self.container_name, vhd_name)
            # return True
            blob_list = page_blob_service.list_blobs(self.container_name)
            for blob_vhd_name in blob_list:
                if vhd_name in blob_vhd_name.name:
                    logger.info('VM VHD exists: %s ' % blob_vhd_name.name)
                    return True
        except:
            return False

    def delete_instance(self, vm_name=None, raise_error=True):
        """ Delete VM related """
        self.vm_deployment()
        if not vm_name:
            vm_name = self.vm_json.get('name')
        nic_name = "%s-NIC"%vm_name

        ctrl_vhd = False
        if self.check_vm_exist(vm_name=vm_name):
            logger.info('Previous Controller %s exists' % vm_name)
            logger.info('Deleting Controller VM: %s ...'% vm_name)
            self.delete_vm(vm_name=vm_name, raise_error=raise_error)
            ctrl_vhd = True
        if self.check_nic_exist(nic_name):
            logger.info('Previous NICr %s exists' % vm_name)
            logger.info('Deleting NIC for Controller:%s' % vm_name)
            self.delete_nic(nic_name=nic_name, raise_error=raise_error)

        if self.check_vm_vhd_exists(vm_name):
            self.delete_vm_vhd(vm_name)

    def delete_vm_vhd(self, vm_name=None, vhd_name=None):
        """ Delete VM VHD """
        if not vm_name:
            vm_name = self.vm_json.get('name')
        if not vhd_name:
            vhd_name = 'controller'
            ctrl_vhd_name = '%s-%s.vhd' % (vm_name, vhd_name)
            # Note: Azure VHD name: smoke-sanity-ctlr-avitest-2-osDisk-smoke-sanity-ctlr-avitest-2-osDisk-controller-18.1.1-16297.vhd
            vhd_name = vm_name + '-osDisk-' + vm_name + '-osDisk-'
        for i in range(3):
            try:
                block_blob_service = PageBlobService(account_name=self.storage_account, account_key=self.storage_account_key)
                # List the blobs in container
                blob_list = block_blob_service.list_blobs(self.container_name)
                for blob_vhd_name in blob_list:
                    if vhd_name in blob_vhd_name.name:
                        logger.info('Going to delete .. vhd name: %s ' % blob_vhd_name.name)
                        block_blob_service.delete_blob(self.container_name, blob_vhd_name.name)

                #logger.info("List of blobs : %s" % blob_list.items)
                break
            except Exception as e:
                logger.info('Error while deleting controller vhd: %s' % e.message)
                logger.info('Retrynig again for vhd deletion')

    def delete_nic(self, vm_name=None, nic_name=None, raise_error=True):
        """ Delete NIC from Azure """
        if not vm_name:
            vm_name = self.vm_json.get('name')
        if not nic_name:
            nic_name = "%s-NIC"%vm_name
        try:
            result = self.network_client.network_interfaces.delete(self.resource_group, nic_name)
            result.wait()
        except Exception as e:
            logger.info("Got Exception while deleting NIC: %s , Exp: %s" % (nic_name, e.message))
            if raise_error:
                fail('Error while Deleting NIC , Exp: %s' % e.message)

    def delete_vm(self, vm_name=None, raise_error=True):
        """ Delete VM instance """
        if not vm_name:
            vm_name = self.vm_json.get('name')
        try:
            result = self.compute_client.virtual_machines.delete(self.resource_group, vm_name)
            asleep(msg='Delete Virtual in-progress .. internal wait is there.', delay=10)
            result.wait()
        except Exception as e:
            logger.info("Got Exception while deleting VM: %s , Exp: %s" % (vm_name, e.message))
            if raise_error:
                fail('Error while Deleting Controller Virtual Machine: %s', str(e))

    def get_all_vms(self):
        """ Get All VMs """
        vms = list()
        all_vms = self.compute_client.virtual_machines.list(self.resource_group)
        for vm in all_vms:
            vms.append(vm.name)
        return vms

    def wait_until_vm_is_up(self, vm_name=None):
        """ Wait for VM to come up """
        if not vm_name:
            vm_name = self.vm_json.get('name')
        return (self.check_vm_status(vm_name, 'VM running'))

    @aretry(retry=10, delay=10, period=5)
    def check_vm_status(self, vm_name, exp_status):
        """ Helps to check VM expected status """
        try:
            vm = self.compute_client.virtual_machines.get(self.resource_group, vm_name, expand='instanceView')
            vm_status = vm.instance_view.statuses[1].display_status
            if exp_status == vm.instance_view.statuses[1].display_status:
                logger.info('VM: %s in expected state: %s', vm_name, exp_status)
                return True
            else:
                fail('VM: %s, not in expected state, Actual:%s, Expected: %s',
                      vm_name, vm_status, exp_status)
        except Exception as e:
            logger.info("Got Exception while Getting the vm status: %s , Exp: %s" % (vm_name, e.message))

    def delete_vms_by_prefix(self, vm_prefix):
        """ Delete VM by VM Name Prefix """
        all_vms = self.get_all_vms()
        for vm_name in all_vms:
            if vm_prefix in vm_name:
                self.delete_instance()

    def delete_vhd_by_name(self, **kwargs):
        """ Delete VHD by name """
        build_dir = kwargs.get('build_dir')
        vhd_url, vhd_name = self.get_vhd_url(build_dir)
        logger.info('Got Requests to delete VHD Name:%s' % vhd_name)

        try:
            block_blob_service = PageBlobService(account_name=self.storage_account, account_key=self.storage_account_key)
            generator = block_blob_service.list_blobs(self.container_name)
            storage_vhds = list()
            for blob in generator:
                storage_vhds.append(blob.name)
                if vhd_name == blob.name:
                    logger.info('vhd_name: %s Found going to delete it' % vhd_name)
                    block_blob_service.delete_blob(self.container_name, vhd_name)
                    return True
            logger.info('Did not found VHD Name in Storage Blob VHD Name: %s' % vhd_name)
            logger.info('List of VHD Name in Storage Blob VHD Name: %s' % ', '.join(storage_vhds))
        except Exception as e:
            fail('Error while deleting the VHD name:%s ,exp: %s' % (vhd_name, e.message))

    def delete_oldest_vhd(self, vhd_name):
        blob_list = []
        vhd = vhd_name.split('-')
        try:
            block_blob_service = PageBlobService(account_name=self.storage_account, account_key=self.storage_account_key)
            generator = block_blob_service.list_blobs(self.container_name)
            delete_vhd = "%s-%s"%(vhd[0], vhd[1])
            for blob in generator:
                # get specific version vhd files
                if delete_vhd in blob.name:
                    blob_list.append(blob)
        except Exception as e:
            fail('Error while getting vhd list: %s' % e.message)

        # keep last 4 controller vhd
        if len(blob_list) < 4:
            return
        old_date = blob_list[0].properties.last_modified
        oldest = blob_list[0]
        for blob in blob_list:
            if blob.properties.last_modified < old_date:
                old_date = blob.properties.last_modified
                oldest = blob
        try:
            logger.info('Deleting %s'%oldest.name)
            block_blob_service.delete_blob(self.container_name, oldest.name)
        except Exception as e:
            fail('Error while deleting vhd file: %s' % e.message)

    def disconnect(self):
        """ Graceful disconnect of Azure componets conenction objects """
        # Yet to implement - in progress
        pass



    if __name__ == "__main__":
        """ Helps to test stand alone it self"""
#    azure_obj = Azure(subscription_id='6526c00d-a373-4f6c-b5c8-d0c5b5f9038a',
#                      application_id='bd77b4b4-b35f-4b01-8404-69efc05a85db',
#                      tenant_id='07f53873-c252-4521-8c71-591a3d5b42b6',
#                      resource_group='jayakumar-jenkins-resource-group',
#                      vnet_id='/subscriptions/6526c00d-a373-4f6c-b5c8-d0c5b5f9038a/resourceGroups/\
#                               avi-jenkins-resource-group/providers/Microsoft.Network/virtualNetworks/\
#                               avi-multiaz-jenkins-vnet')
#
#    azure_obj.get_ip_from_azure()
    pass
