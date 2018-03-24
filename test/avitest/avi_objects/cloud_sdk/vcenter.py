
import os

from avi_objects.logger import logger
from avi_objects.logger_utils import error, fail, asleep, aretry, abort

#vcenter
from pysphere import VIServer, VIProperty, MORTypes
from pysphere.vi_virtual_machine import VIVirtualMachine
from pysphere.resources.vi_exception import VIException, VIApiException
from pysphere.resources import VimService_services as VI
from pysphere.vi_task import VITask

class Vcenter(object):
    """
        Class for Vcenter operations
    """
    def __init__(self, cloud_configuration_json, vm_json):
        """
        Vcenter object for Vcenter operations
        """
        self.configuration = cloud_configuration_json
        self.vm_json = vm_json
        self.server = None
        self.server = self.sdk_connect()

    def sdk_connect(self):

        self.ip = self.configuration.get('vcenter_url', None)
        self.user = self.configuration.get('username', None)
        self.password = self.configuration.get('password', None)
        self.datacenter = self.configuration.get('datacenter', None)

        logger.info('url %s user %s password %s' %(self.ip, self.user, self.password))
        logger.info('datacenter %s' %(self.datacenter))
        server = VIServer()
        server.connect(
                self.ip, self.user, self.password, trace_file='/tmp/debug.txt')
        return server

    def get_vm_ip_for_name(self):
        ip = None
        vm_name = self.vm_json.get('name')
        '''
        if not self.datacenter:
            logger.info('get_vm_ip_for_name %s' %vm_name)
            vm = self.server.get_vm_by_name(vm_name)
        else:
            logger.info('get_vm_ip_for_name %s datacenter %s' %(vm_name, self.datacenter))
            vm = self.server.get_vm_by_name(vm_name, self.datacenter)
        '''
        vm = self.server.get_vm_by_name(vm_name, self.datacenter)
        try:
            props = vm.get_properties()
            for prop in props['net']:
                if prop['network'] and 'manage' in prop['network'].lower():
                    ip = prop['ip_addresses'][0]
                    break
            if not ip:
                ip = vm.get_properties()['ip_address']
        except KeyError:
            abort('ERROR! ip address for vm %s not found' % vm_name)
        return ip

    def disconnect(self):
        try:
            self.server.disconnect()
        except VIApiException:
            logger.info('Exception in sdk disconnect. vm: %s' %self.vm_json['name'])

    def __get_dcmor_for_vm(self):
        vm_name = self.vm_json.get('name')
        logger.info('__get_dcmor_for_vm vm_name %s' %vm_name)
        dcmor = None
        s = self.server
        datacenters = s.get_datacenters()
        for i in datacenters:
            all_vms = self.server._get_managed_objects(
                MORTypes.VirtualMachine, from_mor=i)
            for mor, k in all_vms.items():
                if vm_name == k:
                    dcmor = i
                    break
        if dcmor is None:
            raise Exception('__get_dcmor_for_vm None for ', vm_name)
        return dcmor

    def __get_pgmor_for_network(self, dcmor, network_name):
        dcprops = VIProperty(self.server, dcmor)
        # "networkFolder managed object reference"
        nfmor = dcprops.networkFolder._obj
        dvpg_mors = self.server._retrieve_properties_traversal(property_names=['name'],
                                                               from_node=nfmor, obj_type='Network')
        # "get the portgroup managed object."
        dvpg_mor = None
        for dvpg in dvpg_mors:
            if dvpg_mor:
                break
            for p in dvpg.PropSet:
                if p.Name == "name" and p.Val == network_name:
                    dvpg_mor = dvpg
                if dvpg_mor:
                    break
        if dvpg_mor:
            # "Get the portgroup key"
            return dvpg_mor._obj
        else:
            return None

    def __get_network_for_pgmor(self, dcmor, pgmor):
        dcprops = VIProperty(self.server, dcmor)
        # "networkFolder managed object reference"
        nfmor = dcprops.networkFolder._obj
        dvpg_mors = self.server._retrieve_properties_traversal(property_names=['name'],
                                                               from_node=nfmor, obj_type='Network')
        # "get the portgroup managed object."
        for dvpg in dvpg_mors:
            logger.info('dvpg obj: %s' %dvpg._obj)
            if dvpg._obj == pgmor:
                for p in dvpg.PropSet:
                    if p.Name == "name":
                        return p.Val
        return None

    def __get_dvs_uuid(self, dcmor, pgmor):
        dcprops = VIProperty(self.server, dcmor)
        nfmor = dcprops.networkFolder._obj
        # "Grab the dvswitch uuid and portgroup properties"
        dvswitch_mors = self.server._retrieve_properties_traversal(property_names=['uuid', 'portgroup'],
                                                                   from_node=nfmor, obj_type='DistributedVirtualSwitch')
        dvswitch_mor = None
        # "Get the appropriate dvswitches managed object"
        for dvswitch in dvswitch_mors:
            if dvswitch_mor:
                break
            for p in dvswitch.PropSet:
                if p.Name == "portgroup":
                    pg_mors = p.Val.ManagedObjectReference
                    for pg_mor in pg_mors:
                        if dvswitch_mor:
                            break
                        key_mor = self.server._get_object_properties(
                            pg_mor, property_names=['key'])
                        for key in key_mor.PropSet:
                            if key.Val == pgmor:
                                dvswitch_mor = dvswitch
        # Get the switches uuid
        dvswitch_uuid = None
        if dvswitch_mor:
            for p in dvswitch_mor.PropSet:
                if p.Name == "uuid":
                    dvswitch_uuid = p.Val
        return dvswitch_uuid

    def __get_dvpg_nic_backing(self, dvswitch_uuid, pg_mor):
        nic_backing_port = VI.ns0.DistributedVirtualSwitchPortConnection_Def(
            "nic_backing_port").pyclass()
        nic_backing_port._switchUuid = dvswitch_uuid
        nic_backing_port._portgroupKey = pg_mor
        nic_backing = VI.ns0.VirtualEthernetCardDistributedVirtualPortBackingInfo_Def(
            "nic_backing").pyclass()
        nic_backing._port = nic_backing_port
        return nic_backing

    def __get_vm_net_device(self, vm_obj, mac):
        # Find Virtual Nic device
        net_device = None
        for dev in vm_obj.properties.config.hardware.device:
            if dev._type in ["VirtualE1000", "VirtualE1000e",
                             "VirtualPCNet32", "VirtualVmxnet3"]:
                logger.info(dev.macAddress)
                if dev.macAddress == mac:
                    net_device = dev._obj
                    break
        if not net_device:
            raise Exception("NIC not found")
        return net_device

    def __get_vm_net_device_by_label(self, vm_obj, label):
        # Find Virtual Nic device
        logger.info('vNic Label : %s' %label)
        net_device = None
        for dev in vm_obj.properties.config.hardware.device:
            if dev._type in ["VirtualE1000", "VirtualE1000e",
                             "VirtualPCNet32", "VirtualVmxnet3"]:
                logger.info(dev.macAddress)
                dev_info = dev.deviceInfo
                logger.info(dev_info.label)
                if str(label) == str(dev_info.label):
                    net_device = dev._obj
                    break
        if not net_device:
            raise Exception("NIC not found")
        return net_device

    def __execute_net_device_reconfig_task(self, vm_obj, net_device):
        request = VI.ReconfigVM_TaskRequestMsg()
        _this = request.new__this(vm_obj._mor)
        _this.set_attribute_type(vm_obj._mor.get_attribute_type())
        request.set_element__this(_this)
        spec = request.new_spec()
        dev_change = spec.new_deviceChange()
        dev_change.set_element_operation("edit")
        dev_change.set_element_device(net_device)
        spec.set_element_deviceChange([dev_change])
        request.set_element_spec(spec)
        ret = self.server._proxy.ReconfigVM_Task(request)._returnval
        # Wait for the task to finish
        task = VITask(ret, self.server)
        status = task.wait_for_state([task.STATE_SUCCESS, task.STATE_ERROR])
        if status == task.STATE_SUCCESS:
            logger.info ("Net device reconfig task on vm %s successful " %
                   (vm_obj.properties.name))
        elif status == task.STATE_ERROR:
            raise Exception("Error: Net device reconfig task on vm %s msg %s" %
                            (vm_obj.properties.name, task.get_error_message()))

    def clone(self, hostname, template, clone_name):
        '''
        cloneVM clones a vm based on a previous vm:
        **to clone based on a template see deployVM
        vm_name is the name of the new vm
        clone_vm is what you are cloning from
        '''
        vm_name = self.vm_json.get('name')
        if template == "server":
            clname = "ServerTemplate"
            cluster_name = "TestNet"
        elif template == "test":
            clname = "TestingTemplate"
            cluster_name = "TestNet"
        elif template == "se":
            clname = "SETemplate"
            cluster_name = "TestNet"
        elif template == "controller":
            clname = "ControllerTemplate"
            cluster_name = "TestNet"
        elif template == "unittest":
            clname = "jenkins-clone-unit-test"
            cluster_name = "TestNet"
        all_vms = self.server._get_managed_objects(
            MORTypes.VirtualMachine, from_mor=None)
        vm = None
        target_name = clname
        for mor, name in all_vms.iteritems():
            if name == target_name:
                vm = VIVirtualMachine(self.server, mor)
                break
        if not vm:
            raise Exception("VM template not found")
        resource_pool = "/Resources"
        cluster = [
            k for k, v in self.server.get_clusters().items() if v == cluster_name][0]
        rpmor = [k for k, v in self.server.get_resource_pools(
            from_mor=cluster).items() if v == resource_pool][0]
        try:
            logger.info("Starting Clone operation \n")
            vm.clone(clone_name, resourcepool=rpmor)
            logger.info("Clone Successful, please check vmware in about 20 minutes to see it.")
        except VIException:
            logger.info("VI Exception")

    def reconfigure_ip(self, port, new_ip):
        '''Reconfigure the original ip
        Arguments:
        vm_name: the vm that you wish to dev_change
        port: port you wish to change
        new_ip: new ip address you are changing the vm to
        '''
        vm_name = self.vm_json.get('name')
        # get original ip
        logger.info('configIP \n')
        vm = self.server.get_vm_by_name(vm_name, self.datacenter)
        ssh_ip = vm.get_properties()['ip_address']
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ssh_ip, username='aviuser', password='aviuser')
        stdint, stdout, stderr = ssh.exec_command('ifconfig')
        output = stdout.readlines()
        found_port = False
        mask = ''
        for line in output:
            if found_port:
                tmp = re.search('Mask:(\S+)', line)
                if tmp:
                    mask = tmp.group(1)
                    break
            if port in line:
                found_port = True
        mask = '255.255.255.0'
        command = "echo aviuser | sudo -S ifconfig " + \
            port + " " + new_ip + " netmask " + mask + " up"
        ssh.exec_command(command)
        logger.info("Successfully updated ip address")

    def find(self):
        '''
        find a vm based on the name. returns None if Exception is raised
        '''
        vm_name = self.vm_json.get('name')
        try:
            vm = self.server.get_vm_by_name(name, self.datacenter)
            return vm
        except VIException:
            return None

    def deploy(self, cluster_name, template_name, new_vm):
        '''
        deployVM is similar to a clone, but based off of a template
        Arguments:
        cluster_name: e.g.: TestNet
        template_name: template you wish to clone from, e.g.: apache-template
        new_vm: name of the new vm
        '''
        # like clone but only based off of a template. clone can only work with
        # a vm
        s = self.server
        # find all vms that are templates
        all_vms = s._get_managed_objects(
            MORTypes.VirtualMachine, from_mor=None)
        # you can filter from cluster, datacenter, host, etc by setting
        # 'from_mor' parameter to a managed object reference
        vm = None
        target_name = template_name
        for mor, name in all_vms.iteritems():
            if name == target_name:
                vm = VIVirtualMachine(s, mor)
                break
        if not vm:
            raise Exception("VM Template Not found")
        resource_pool = "/Resources"
        cluster = [
            k for k, v in s.get_clusters().items() if v == cluster_name][0]
        rpmor = [k for k, v in s.get_resource_pools(
            from_mor=cluster).items() if v == resource_pool][0]
        vm_name = new_vm
        try:
            test_exist = s.get_vm_by_name(name, self.datacenter)
        except VIException:
            test_exist = None
        if test_exist is None:
            logger.info('ERROR: %s already exists' % vm_name)
        else:
            clone = vm.clone(new_vm, resourcepool=rpmor)
            logger.info("Cloned! Powering on now")
            clone.power_on()
            logger.info("Powered on")
            return clone

    def restart(self, retry=False):
        '''
        Restart VM restarts the vm given
        arguments:
        vm_name: vm you wish to restart
        '''
        vm_name = self.vm_json.get('name')
        count = 1
        if retry:
            count = 3
        i = 0
        vm = None

        # TODO: We could use @aretry here, waiting to finalize on its usage
        # within an exception.
        while i < count:
            i = i + 1
            try:
                vm = self.server.get_vm_by_name(vm_name, self.datacenter)
                break
            except VIException as e:
                logger.info('%s VIException: %s' % (time.asctime(), e.message))
                self.disconnect()
                self.reconnect_with_vcenter()
                time.sleep(2)
                continue
        if not vm:
            raise Exception('Could not find VM %s after %d retries' %
                            (vm_name, count))
        vm.power_off()
        vm.power_on()

    def is_instance_poweredoff(self):
        '''
        returns true if VM powered off
        arguments:
        vm_name
        '''
        vm_name = self.vm_json.get('name')
        try:
            vm = self.server.get_vm_by_name(vm_name, self.datacenter)
            if vm.is_powered_off():
                return True
        except:
            pass

    def suspend(self, vm_name=None):
        '''
        Suspend a given VM
        arguments:
        vm_name: vm you wish to suspend
        '''
        if not vm_name:
            vm_name = self.vm_json.get('name')
        vm = self.server.get_vm_by_name(vm_name, self.datacenter)
        vm.suspend()

    def resume(self, vm_name=None):
        '''
        Resume a suspended VM
        arguments:
        vm_name: vm you wish to resume
        '''
        if not vm_name:
            vm_name = self.vm_json.get('name')
        vm = self.server.get_vm_by_name(vm_name, self.datacenter)
        vm.power_on()

    def poweroff(self, vm_name=None):
        '''
        Power off a VM
        arguments:
        vm_name: vm you wish to resume
        '''
        if not vm_name:
            vm_name = self.vm_json.get('name')
        @aretry(retry=10, delay=2, period=2)
        def getVm():
            vm = self.server.get_vm_by_name(vm_name)
            return vm
        vm = getVm()
        if vm:
            vm.power_off()
            if vm.get_status() != "POWERED OFF":
                fail("VM could not power off. It is in "+vm.get_status()+" state")
            logger.info('vm : %s powered off, status: %s' % (vm_name, vm.get_status()))
        else:
            logger.debug( 'DEBUG: all_vms: %s' % self.server.get_registered_vms())
            fail("Can't find the vm %s" % vm_name)

    def poweron(self, vm_name=None):
        '''
        Power on a VM
        arguments:
        vm_name: vm you wish to resume
        '''
        if not vm_name:
            vm_name = self.vm_json.get('name')
        @aretry(retry=10, delay=2, period=2)
        def getVm():
            vm = self.server.get_vm_by_name(vm_name)
            return vm
        vm = getVm()
        try:
            vm.power_on()
            if vm.get_status() != "POWERED ON":
                fail("VM could not power on. It is in "+vm.get_status()+" state")
            logger.info('vm : %s powered on, status: %s' % (vm_name, vm.get_status()))
        except VIException as e:
            # If VM is already is powered on, ignore error
            if 'current state (Powered on)' in str(e):
                logger.info('vm: %s already is powered on ..' % vm_name)
            else:
                fail(e)

    def show_all_vms(self):
        '''
        show_all_vms prints a list of all vms that are currently get_registered_vms
        on the server
        Arguments: The function takes no arguments.
        '''
        vmlist = self.server.get_registered_vms()
        logger.info(vmlist)

    def add_vnic(self, network):
        '''
        addVNIC adds a vnic to the desired vm_name
        Arguments:
        vm_name is the name of the vm that you wish to add the vnic to.
        network: the name of the vnic that you are adding
        **Note**
        Vnics must be removed wih each time this class is instantiated.
        VNICs are stored in a temporary dictionary, so if VNICs are not
        removed at the end of this class instance, then they will have
        to be manually removed in the vcenter
        '''
        vm_name = self.vm_json.get('name')
        # datacentername = "Dev_Datacenter"
        # hostname = "esx14.mgt.hawaii.edu"
        network_name = network
        s = self.server
        dcmor = None
        datacenters = s.get_datacenters()
        logger.info('datacenters ', datacenters)
        # "GET INITIAL PROPERTIES AND OBJECTS"
        for i in datacenters:
            vm_list = s.get_registered_vms(i)  # list of vms
            for k in vm_list:
                if vm_name in k:
                    vm = k
                    dcmor = i
                    break
        if dcmor is None:
            logger.info("Datacenters: %s " % (datacenters))
            for k, v in datacenters.items():
                # When a VM is renamed, pysphere query to vcenter does not seem
                # to find the new vm name in any data center. So when we don't
                # find a vm in any data center, we assume it belongs in
                # Sunnyvale datacenter.
                # TODO(bindu): add an option to testbed file to pass this as
                # an option.
                if v == 'Sunnyvale':
                    logger.info('Datacenter for Sunnyvale %s' %k)
                    logger.info('Failed to find VM %s in any data center %s' %vm_name)
                    logger.info('   VM might have been renamed. Assume datacenter Sunnyvale')
                    dcmor = k
                    break
            # raise Exception("Failed to find VM %s in any data center" % (vm_name))
        dcprops = VIProperty(s, dcmor)
        # "networkFolder managed object reference"
        nfmor = dcprops.networkFolder._obj
        dvpg_mors = s._retrieve_properties_traversal(property_names=['name', 'key'],
                                                     from_node=nfmor, obj_type='DistributedVirtualPortgroup')
        # "get the portgroup managed object."
        dvpg_mor = None
        for dvpg in dvpg_mors:
            if dvpg_mor:
                break
            for p in dvpg.PropSet:
                if p.Name == "name" and p.Val == network_name:
                    dvpg_mor = dvpg
                if dvpg_mor:
                    break
        if dvpg_mor is None:
            raise Exception(
                "Didn't find the dvpg %s, exiting now" % (network_name))
        # "Get the portgroup key"
        portgroupKey = None
        for p in dvpg_mor.PropSet:
            if p.Name == "key":
                portgroupKey = p.Val
        # "Grab the dvswitch uuid and portgroup properties"
        dvswitch_mors = s._retrieve_properties_traversal(property_names=['uuid', 'portgroup'],
                                                         from_node=nfmor, obj_type='DistributedVirtualSwitch')
        dvswitch_mor = None
        # "Get the appropriate dvswitches managed object"
        for dvswitch in dvswitch_mors:
            if dvswitch_mor:
                break
            for p in dvswitch.PropSet:
                if p.Name == "portgroup":
                    pg_mors = p.Val.ManagedObjectReference
                    for pg_mor in pg_mors:
                        if dvswitch_mor:
                            break
                        key_mor = s._get_object_properties(
                            pg_mor, property_names=['key'])
                        for key in key_mor.PropSet:
                            if key.Val == portgroupKey:
                                dvswitch_mor = dvswitch
        # Get the switches uuid
        dvswitch_uuid = None
        for p in dvswitch_mor.PropSet:
            if p.Name == "uuid":
                dvswitch_uuid = p.Val
        # create_vm_request = VI.CreateVM_TaskRequestMsg()
        # config = create_vm_request.new_config()
        vm_obj = s.get_vm_by_name(vm_name, self.datacenter)
        vm = vm_obj
        net_device_mac = []
        for dev in vm.properties.config.hardware.device:
            if (dev._type in ["VirtualE1000", "VirtualE1000e", "VirtualPCNet32", "VirtualVmxnet3"]):
                    # print dev.macAddress
                net_device_mac.append(dev.macAddress)
        vm_obj = s.get_vm_by_name(vm_name, self.datacenter)
        # Invoke ReconfigVM_Task
        request = VI.ReconfigVM_TaskRequestMsg()
        _this = request.new__this(vm_obj._mor)  # get the resource pool
        _this.set_attribute_type(vm_obj._mor.get_attribute_type())
        request.set_element__this(_this)
        spec = request.new_spec()
        # add a NIC. the network Name must be set as the device name.
        dev_change = spec.new_deviceChange()
        dev_change.set_element_operation("add")
        nic_ctlr = VI.ns0.VirtualPCNet32_Def("nic_ctlr").pyclass()
        # nic_backing = VI.ns0.VirtualEthernetCardNetworkBackingInfo_Def("nic_backing").pyclass()
        # nic_backing.set_element_deviceName(label)
        nic_backing_port = VI.ns0.DistributedVirtualSwitchPortConnection_Def(
            "nic_backing_port").pyclass()
        nic_backing_port.set_element_switchUuid(dvswitch_uuid)
        nic_backing_port.set_element_portgroupKey(portgroupKey)
        nic_backing = VI.ns0.VirtualEthernetCardDistributedVirtualPortBackingInfo_Def(
            "nic_backing").pyclass()
        nic_backing.set_element_port(nic_backing_port)
        # print inspect.getmembers(nic_backing)
        # nic_backing.deviceName == network
        nic_ctlr.set_element_addressType("generated")
        nic_ctlr.set_element_backing(nic_backing)
        nic_ctlr.set_element_key(4)
        dev_change.set_element_device(nic_ctlr)
        spec.set_element_deviceChange([dev_change])
        request.set_element_spec(spec)
        ret = self.server._proxy.ReconfigVM_Task(request)._returnval
        # net_device.Connectable.Connected = True
        # Wait for the task to finish
        task = VITask(ret, self.server)
        status = task.wait_for_state([task.STATE_SUCCESS, task.STATE_ERROR])
        vm = self.server.get_vm_by_name(vm_name, self.datacenter)
        for dev in vm.properties.config.hardware.device:
            if (dev._type in ["VirtualE1000", "VirtualE1000e", "VirtualPCNet32", "VirtualVmxnet3"] and
                    dev.macAddress not in net_device_mac):
                # print dev.macAddress
                self.vm_vnics[(vm_name, network)] = (
                    dev.deviceInfo.label, dev.macAddress)
        if status == task.STATE_SUCCESS:
            logger.info("vnic %s on vm %s successfully added" % (dev.macAddress, vm_name))
        elif status == task.STATE_ERROR:
            logger.info("Error adding vm: %s" % vm_name, task.get_error_message())
        return dev.macAddress

    def remove_vnic(self, label):
        '''Function removes a vnic network from an existing vcenter.
        Arguments:
        vm: vm from which vnic should be removed,
        label: name of vnic
        **Note**
        Vnics must be removed wih each time this class is instantiated.
        VNICs are stored in a temporary dictionary, so if VNICs are not
        removed at the end of this class instance, then they will have
        to be manually removed in the vcenter
        '''
        vm = self.vm_json.get('name')
        vm_obj = self.server.get_vm_by_name(vm, self.datacenter)
        if not vm_obj:
            raise Exception("VM %s not found" % vm)
        net_device = None
        if (vm, label) not in self.vm_vnics:
            raise Exception(
                "vcenter removeVNIC error: vm_vnics not found: " + str((vm, label)))
        # Find Virtual Nic device
        for dev in vm_obj.properties.config.hardware.device:
            if (dev._type in ["VirtualE1000", "VirtualE1000e",
                              "VirtualPCNet32", "VirtualVmxnet3"]
                    and dev.deviceInfo.label == self.vm_vnics[(vm, label)][0]):
                net_device = dev._obj
                break
        if not net_device:
            raise Exception("NIC not found")
        # Reconfigure
        request = VI.ReconfigVM_TaskRequestMsg()
        _this = request.new__this(vm_obj._mor)
        _this.set_attribute_type(vm_obj._mor.get_attribute_type())
        request.set_element__this(_this)
        spec = request.new_spec()
        dev_change = spec.new_deviceChange()
        dev_change.set_element_operation("remove")
        dev_change.set_element_device(net_device)
        spec.set_element_deviceChange([dev_change])
        request.set_element_spec(spec)
        ret = self.server._proxy.ReconfigVM_Task(request)._returnval
        # Wait for the task to finish
        task = VITask(ret, self.server)
        status = task.wait_for_state([task.STATE_SUCCESS, task.STATE_ERROR])
        if status == task.STATE_SUCCESS:
            logger.info("   removing vnic in %s on vm %s successful " % (label, vm))
        elif status == task.STATE_ERROR:
            raise Exception("Error removing vnic in %s on vm %s msg %s" % (
                label, vm, task.get_error_message()))

    def change_vnic_pg(self, mac, network_name):
        '''
        Change vnic port-group to specified distributed virtual port-group
        or VM Network
        Arguments:
        vm_name: Name of virtual machine in vcenter
        mac: MAC address of vnic being modified
        network_name: Network name to switch to
        '''
        vm_name = self.vm_json.get('name')
        # Find VM object
        vm_obj = self.server.get_vm_by_name(vm_name, self.datacenter)
        if not vm_obj:
            raise Exception("VM %s not found" % vm_name)
        # Find Virtual Nic device
        net_device = None
        try:
            net_device = self.__get_vm_net_device(vm_obj, mac)
        except Exception as e:
            logger.info('Net device not found vm %s mac %s' % (vm_name, mac))
            raise Exception(
                'Net device not found vm %s mac %s, exception %s' % (vm_name, mac, e))
        # Find Datacenter MOR for this VM
        dc_mor = self.__get_dcmor_for_vm(vm_name)
        if not dc_mor:
            logger.info('Datacenter not found vm %s' % (vm_name))
            raise Exception('Datacenter not found vm %s' % (vm_name))
        # Find Network MOR given network name
        pg_mor = self.__get_pgmor_for_network(dc_mor, network_name)
        if pg_mor is None:
            raise Exception(
                "Didn't find the pg %s, exiting now" % (network_name))
        logger.info('PortGroupKey: %s' % pg_mor)
        if 'vsPGAdmin' in network_name:
            nic_backing = VI.ns0.VirtualEthernetCardNetworkBackingInfo_Def(
                'nic_backing').pyclass()
            nic_backing.set_element_deviceName(network_name)
            net_device._backing = nic_backing
            self.__execute_net_device_reconfig_task(vm_obj, net_device)
            return
        # Find Distributed Virtual Switch UUID
        dvswitch_uuid = self.__get_dvs_uuid(dc_mor, pg_mor)
        nic_backing = self.__get_dvpg_nic_backing(dvswitch_uuid, pg_mor)
        if network_name == 'VM Network' or network_name == 'Avi Internal':
            nic_backing = VI.ns0.VirtualEthernetCardNetworkBackingInfo_Def(
                'nic_backing').pyclass()
            nic_backing.set_element_deviceName(network_name)
            nic_backing.set_element_network(pg_mor)
            nic_backing.set_element_inPassthroughMode(False)
        net_device._backing = nic_backing
        # Edit vnic port-group
        self.__execute_net_device_reconfig_task(vm_obj, net_device)

    def change_vnic_pg_by_vnic_label(self, vnic_label, network_name):
        '''
        Change vnic port-group to specified distributed virtual port-group
        or VM Network
        Arguments:
        vm_name: Name of virtual machine in vcenter
        mac: MAC address of vnic being modified
        network_name: Network name to switch to
        '''
        vm_name = self.vm_json.get('name')
        # Find VM object
        vm_obj = self.server.get_vm_by_name(vm_name, self.datacenter)
        if not vm_obj:
            raise Exception("VM %s not found" % vm_name)
        # Find Virtual Nic device
        net_device = None
        try:
            net_device = self.__get_vm_net_device_by_label(vm_obj, vnic_label)
        except Exception as e:
            logger.info('Net device not found vm %s label %s' % (vm_name, vnic_label))
            raise Exception(
                'Net device not found vm %s label %s, exception %s' % (vm_name, vnic_label, e))
        # Find Datacenter MOR for this VM
        dc_mor = self.__get_dcmor_for_vm(vm_name)
        if not dc_mor:
            logger.info('Datacenter not found vm %s' % (vm_name))
            raise Exception('Datacenter not found vm %s' % (vm_name))
        # Find Network MOR given network name
        pg_mor = self.__get_pgmor_for_network(dc_mor, network_name)
        if pg_mor is None:
            raise Exception(
                "Didn't find the pg %s, exiting now" % (network_name))
        logger.info('PortGroupKey: %s' % pg_mor)
        if 'vsPGAdmin' in network_name:
            nic_backing = VI.ns0.VirtualEthernetCardNetworkBackingInfo_Def(
                'nic_backing').pyclass()
            nic_backing.set_element_deviceName(network_name)
            net_device._backing = nic_backing
            self.__execute_net_device_reconfig_task(vm_obj, net_device)
            return
        # Find Distributed Virtual Switch UUID
        dvswitch_uuid = self.__get_dvs_uuid(dc_mor, pg_mor)
        nic_backing = self.__get_dvpg_nic_backing(dvswitch_uuid, pg_mor)
        if network_name == 'VM Network' or network_name == 'Avi Internal':
            nic_backing = VI.ns0.VirtualEthernetCardNetworkBackingInfo_Def(
                'nic_backing').pyclass()
            nic_backing.set_element_deviceName(network_name)
            nic_backing.set_element_network(pg_mor)
            nic_backing.set_element_inPassthroughMode(False)
        net_device._backing = nic_backing
        # Edit vnic port-group
        self.__execute_net_device_reconfig_task(vm_obj, net_device)

    def set_vnic_connected_status(self, mac, conn_status=True):
        '''
        Set VNIC status to connected or disconnected
        Arguments:
        vm_name: Name of virtual machine in vcenter
        mac: MAC address of vnic being modified
        conn_status: Connected or Disconnected status
        '''
        vm_name = self.vm_json.get('name')
        vm_obj = self.server.get_vm_by_name(vm_name, self.datacenter)
        if not vm_obj:
            logger.info("VM %s not found" % vm_name)
            raise Exception("VM %s not found" % vm_name)
        net_device = None
        try:
            net_device = self.__get_vm_net_device(vm_obj, mac)
        except Exception as e:
            logger.info('Net device not found vm %s mac %s' % (vm_name, mac))
            raise Exception(
                'Net device not found vm %s mac %s, exception %s' % (vm_name, mac, e))
        vnic_connect = net_device.get_element_connectable()
        vnic_connect.set_element_connected(conn_status)
        vnic_connect.set_element_startConnected(conn_status)
        self.__execute_net_device_reconfig_task(vm_obj, net_device)

    def delete_instance(self, name=None):
        # Check if name is passed, if not extract from vm_json
        if not name:
            name = self.vm_json.get('name')

        # Initialise vcenter handle
        vcenter_handle = self.server
        try:
            vm = vcenter_handle.get_vm_by_name(name)
        except Exception:
            logger.info('VM %s not present in vCenter. This is OK' % name)
            return
        # Power off if not already
        if not vm.is_powered_off():
            vm.power_off()
        # Invoke Destroy_Task
        request = VI.Destroy_TaskRequestMsg()
        _this = request.new__this(vm._mor)
        _this.set_attribute_type(vm._mor.get_attribute_type())
        request.set_element__this(_this)
        ret = vcenter_handle._proxy.Destroy_Task(request)._returnval

        # Wait for the task to finish
        task = VITask(ret, vcenter_handle)

        status = task.wait_for_state([task.STATE_SUCCESS, task.STATE_ERROR])
        if status == task.STATE_SUCCESS:
            logger.info('VM %s successfully deleted from disk' % name)
        elif status == task.STATE_ERROR:
            logger.info('Error removing vm: %s' % task.get_error_message())

    def delete_vms_by_prefix(self, prefix=None):
        vcenter_handle = self.server
        vm_paths = vcenter_handle.get_registered_vms()
        if not prefix:
            logger.info("No Prefix provided. Returning")
            return
        logger.info("prefix passed : %s" % prefix)
        for vm_path in vm_paths:
            try:
                vm = vcenter_handle.get_vm_by_path(vm_path)
                props = vm.get_properties()
                vm_name = props.get('name')
                if not vm_name:
                    continue
                if prefix in vm_name:
                    try:
                        logger.info("prefix found in vm : %s" % vm_name)
                        self.delete_instance(vm_name)
                    except Exception as e:
                        logger.info(e.message)
            except Exception as e:
                logger.info(e.message)

    def wait_until_vm_is_up(self, vm_name=None, timeout=3600):
        if not vm_name:
            vm_name = self.vm_json.get('name')
        vcenter_handle = self.server
        num_loops = int(timeout) / 30
        i = 0
        while i < num_loops:
            vm = vcenter_handle.get_vm_by_name(vm_name)
            props = vm.get_properties()
            if 'net' in props.keys():
                logger.info('vm network info: %s' % (props.get('net')))
                return
            asleep(msg='Waiting for vm to come up', delay=30)
            i += 1

    def deploy_vm_from_ova(self, **kwargs):
        vcenter_handle = self.server
        vm_type = kwargs.get('type') or self.vm_json.get('type')
        if not vm_type:
            raise RuntimeError('Must specify a vm type. controller or se')
        dc_name = kwargs.get('datacenter') or self.vm_json.get('datacenter')
        host_ip = kwargs.get('host') or self.vm_json.get('host')
        vcenter_ip = kwargs.get('vcenter_ip') or self.ip
        mgmt_dvpg = kwargs.get('mgmt_dvpg')
        if not mgmt_dvpg:
            mgmt_dvpg = self.vm_json.get('networks')['mgmt']
        ova_path = kwargs.get('ova_path')
        if not ova_path:
            raise RuntimeError('OVA path is not specified')
        controller_ip = kwargs.get('controller_ip')    # Used for getting se pkg from already existing controller
        if not controller_ip:
            controller_ip = '0.0.0.0'
        data_dvpg = kwargs.get('data_dvpg')
        if not data_dvpg:
            data_dvpg = 'Avi Internal'
        mgmt_ip = kwargs.get('ip')
        if not mgmt_ip:
            mgmt_ip = self.vm_json.get('ip') or '0.0.0.0'
        gw_ip = kwargs.get('gateway') or self.vm_json.get('gateway')
        if not gw_ip:
            gw_ip = '0.0.0.0'
        name = kwargs.get('name')
        if not name:
            name = self.vm_json.get('name') or 'Unknown'
        reserve_mem = kwargs.get('reserve_mem')
        if not reserve_mem:
            reserve_mem = 'No_need'
        poweron = kwargs.get('powerOn')
        if not poweron:
            poweron = 'enable'
        if kwargs.get('workspace'):
            _ws = kwargs.get('workspace')
        mask = kwargs.get('mask')
        if not mask:
            mask = self.vm_json.get('mask') or '24'

        script = _ws + '/test/robot/new/lib/tools/generate_vm_from_ova.py'

        parameter = ' -T ' + vm_type + ' -D ' + dc_name + ' -H ' + host_ip + ' -S ' + ova_path + \
            ' -V ' + vcenter_ip + ' -M "' + mgmt_dvpg + '" -I ' + controller_ip + ' -P "' + data_dvpg + \
            '" -B ' + mgmt_ip + ' -K ' + str(mask) + ' -G ' + gw_ip + ' -N ' + \
            name + ' -R ' + reserve_mem + ' -O ' + poweron

        if str(kwargs.get('cluster')).lower() != 'none':
            parameter = parameter + ' -C ' + kwargs.pop('cluster')
        elif self.vm_json.get('cluster', None):
            parameter = parameter + ' -C ' + self.vm_json.get('cluster')
        if str(kwargs.get('datastore')).lower() != 'none':
            parameter = parameter + ' -A "' + kwargs.pop('datastore') + '"'
        else:
            parameter = parameter + ' -A "' + self.vm_json.get('datastore') + '"'


        cmd = script + parameter
        logger.info('start to deploy controller %s' % cmd)
        completed = False
        for i in range(10):
            if completed is False:
                process  = os.popen(cmd)
                output = process.read()
                logger.info(output)
                output = output.split('\n')
                for line in output:
                    if line == 'Completed successfully':
                        completed = True
                        break
            else:
                break
        logger.info("closing the popen connection")
        process.close()
