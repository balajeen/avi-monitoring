"""
    Module defines access routines for all clouds.
"""

import os
import time
import json
import ipaddress
import re

from avi_objects.logger import logger, ErrorError, FailError
from avi_objects.logger_utils import error, fail, asleep, aretry
from avi_objects.vm import App
from avi_objects.suite_vars import suite_vars
from sets import Set
#vcenter
from pysphere import VIServer, VIProperty, MORTypes
from pysphere.vi_virtual_machine import VIVirtualMachine
from pysphere.resources.vi_exception import VIException, VIApiException
from pysphere.resources import VimService_services as VI
from pysphere.vi_task import VITask
#aws
import boto
from boto import (ec2, vpc)
# azure
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import NetworkInterfaceIPConfiguration, Subnet
# gcp
from oauth2client.client import GoogleCredentials
from googleapiclient import discovery as GCP_discovery
from googleapiclient.http import HttpError


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



class Virtualization(object):
    """
       Generic Class for cloud operations
    """

    def __init__(self, vtype, cloud_name):
        self.type = vtype
        self.name = cloud_name

    def create_server_context(self, vm ,server):
        """create_server_context """
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for app in vm.app_servers.get(context_key,[]):
            if app.handle == server.handle:
                logger.debug("%s already configured"  %server.handle)
                return
                #fail('Adding duplicate handle to app_servers')
        app = App()
        app.server = server
        app.app_type = server.app_type()
        app.net = server.net
        app.net_name = server.net_name
        app.handle = server.handle
        app.ip = server.ip()
        app.ssl_enabled = server.ssl_enabled()
        if not vm.is_network_present(app.net):
            fail('create server: vnic/network %s does not exist on the vm '
                    '%s' % (app.net, vm.name))
        app.mask = vm.networks_detail[str(app.net)].mask
        app.eth_int, app.mac, _ = vm.get_interface_details(app.net)
        app.eth_index = vm.get_ethernet_index(app.eth_int, app.net)
        vm.app_servers.setdefault(context_key,[]).append(app)

    def create_server_context_ip_addrs(self, vm):
        """ Create a server context """
        servers_ips = []
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for app in vm.app_servers.get(context_key,[]):
            if app.eth_ip_configured:
                continue

            logger.debug('Creating Server with IP %s on Interface %s' %(
                app.ip, app.eth_int))
            if type(ipaddress.ip_address(unicode(app.ip))) == ipaddress.IPv6Address:
                netmask = app.mask
                cmd = 'ifconfig %s:%s inet6 add %s/%s up' % (
                    app.eth_int, app.eth_index, app.ip, netmask)
            else:
                netmask = str(vm.get_dotted_netmask_for_cidr(app.mask))
                cmd = 'ifconfig %s:%s %s netmask %s up' % (
                    app.eth_int, app.eth_index, app.ip, netmask)
            logger.info(
                'a.eth_int: %s, a.eth_index: %s, a.ip: %s, netmask: %s' % (
                    app.eth_int, app.eth_index, app.ip, netmask))
            logger.debug('create_server_context ip addrs:: %s' % cmd)
            out = vm.execute_command(cmd)
            logger.debug('out:: %s' % out)
            # TBD: For AWS we need to fix the route for asymetric routing.
            if str(out).find('Invalid argument') != -1:
                fail('ERROR!! create server: sub-int config failed, msg: %s' % out)
            app.eth_ip_configured = 1

    def create_client_context_all(self, vm, how_many, network, prefix, app_type, ip_addrs, start_idx):

        from avi_config import AviConfig
        config = AviConfig.get_instance()
        for i in range(int(how_many)):
            handle = prefix + str(i + start_idx)
            ip = self.create_client_context(
                      vm, network, handle, app_type, ip_addrs[i])
            config.appclient[handle] = [vm, ip]
            logger.debug('[%s] Created Client: %s IP: %s' % (vm.ip, handle, ip))


    def create_client_context(self, vm, network, handle, app_type='', ip=None):
        """ Creates a client context on VM"""

        client = vm.client_handle_must_be_unique(handle)
        if not client:
            client = App()

        # the fields that a client needs and more.
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        mode = config.get_mode()
        site_name = mode['site_name']
        m_sub = re.search('([a-zA-Z]+)(\d+)', network)
        if m_sub:
            net_ip = config.testbed[site_name].networks[network].get_ip_for_network(ip_host = ip)
        else:
            ip, net = config.testbed[site_name].networks_queue.get_ip_for_network(vm=vm)
            net_ip = ip
            network = net
        client.network = network
        if not vm.is_network_present(client.network):
            fail('Create client: vnic/network %s does not exist on the vm %s' % (
                    client.network, vm.name))

        # Get client interface name, MAC address and IP from VM Info
        client.eth_int, client.mac, client.ip = vm.get_interface_details(network)
        if app_type == 'geoip':
            # If it's a GEO IP based client, we need to create interface with IP
            # passed by calling function
            client.ip = ip
            config.testbed[site_name].networks[client.network].release_ip_for_network(net_ip)
        elif app_type != 'httperf' or not suite_vars.auto_gateway:
            # If it's httperf or auto gateway -> use main interface
            # else get a new IP from list of available IPs
            client.ip = net_ip

        client.handle = handle
        client.mask = config.testbed[site_name].networks[str(network)].mask
        client.eth_index = vm.get_ethernet_index(client.eth_int, client.network)

        if app_type == '':
            client.app_type = 'nginx'
        else:
            client.app_type = app_type

        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        vm.app_clients.setdefault(context_key,[]).append(client)
        #vm.app_clients.append(client)
        logger.debug('creating client:: %s, %s, %s, %s, %s, %s' % (
            client.ip, client.mask, client.mac, client.eth_int,
            client.handle, client.eth_index))

        if suite_vars.auto_gateway or app_type == 'httperf':
            logger.debug('Autogateway mode, not creating any sub interfaces')
            return client.ip

        if type(ipaddress.ip_address(unicode(client.ip))) == ipaddress.IPv6Address:
            cmd = 'ifconfig %s:%s inet6 add %s/%s up' % (
                client.eth_int, client.eth_index, client.ip, client.mask)
        else:
            netmask = str(vm.get_dotted_netmask_for_cidr(client.mask))
            cmd = 'ifconfig %s:%s %s netmask %s up' % (
                client.eth_int, client.eth_index, client.ip, netmask)

        try:
            logger.debug('create_client_context:: %s' % cmd)
            out = vm.execute_command(cmd, log_error=False)
            logger.debug('create_client_context_out:: %s' % out)
        except Exception as e:
            pass

        if str(out).find('Invalid argument') != -1:
            fail('ERROR!! create client: sub-int config failed, msg: %s' % out)

        return client.ip


    def cleanup_all(self):
        """Cleanup testbed with respect to the cloud """
        pass

    def add_remove_ip_rules(self, *args, **kwargs):
        """ Add/Remove ip route list on Client/Server """
        #Dummy function. Actual definition in AWS Class
        pass

    def cleanup_secondary_ips(self, instance_name, vpc_id=None):
        """ Cleanup Secondary IP """
        #Dummy function. Actual definition in AWS Class
        pass


class Vcenter(Virtualization):
    """
        Class for Vcenter operations
    """
    def __init__(self, configuration, cloud_name):
        """
        Vcenter object for Vcenter operations
        """
        self.ip = None
        self.user = None
        self.password = None
        self.datacenters = None
        self.type = None
        super(Vcenter, self).__init__('vcenter', cloud_name)
        self._init(configuration)

    def _init(self, config):
        """
        Init the Vcenter object from configuration params
        """
        logger.debug("Got Following configuration for Vcenter Cloud %s" %config)
        self.ip = config.get('vcenter_url', None)
        self.user = config.get('username', None)
        try:
            self.password = get_credentials(self.type, self.name).get('password')
        except Exception as e:
            logger.info("Fail to retreive password from credential's file with err %s" %e)
            self.password = 'vmware'
        self.datacenters = config.get('datacenters', None)
        if self.ip:
            self.vcenter_init()

    def vcenter_init(self):
        """
        Vcenter connection handlers init
        """
        self.server = VIServer()
        self.server.connect(
                self.ip, self.user, self.password, trace_file='/tmp/debug.txt')

class Baremetal(Virtualization):
    """
        Class for Baremetal operations
    """
    def __init__(self, configuration, cloud_name):
        """
        Baremetal object for Baremetal operations
        """
        self.type = None
        super(Baremetal, self).__init__('baremetal', cloud_name)

class Aws(Virtualization):
    """
        Class for AWS operations.
    """

    def __init__(self, configuration, cloud_name):
        """
        AWS object for aws operations
        """
        self.access_key = None
        self.secret_key = None
        self.aws_region = None
        self.vpc_id = None
        self.vpc_handle = None
        self.ec2_handle = None
        self.type = None
        super(Aws, self).__init__('aws', cloud_name)
        self._init(configuration)

    def _init(self, config):
        """
        Init the AWS object from configuration params
        """

        credentials = get_credentials(self.type, self.name)
        if not self.access_key:
            self.access_key = credentials.get('access_key')
        if not self.secret_key:
            self.secret_key = credentials.get('secret_key')
        if not self.aws_region:
            self.aws_region = config.get('region', None)
        if not self.vpc_id:
            self.vpc_id = config.get('vpc_id', None)

        if not self.access_key or not self.secret_key or not self.aws_region or not self.vpc_id:
            fail('Either or all of access_key, secret_key, aws_region, vpc_id are empty')
            return
        self.aws_init()

    def aws_init(self):
        """
        AWS connection handlers init
        """
        if not self.vpc_handle:
            logger.info('Connecting to AWS VPC region:%s' % (self.aws_region))
            try:
                self.vpc_handle = vpc.connect_to_region(self.aws_region,
                                                        aws_access_key_id=self.access_key,
                                                        aws_secret_access_key=self.secret_key)
            except Exception as e:
                fail('AWS VPC connection failed with err:%s' % str(e))
        if not self.ec2_handle:
            logger.info('Connecting to AWS EC2 region:%s' % (self.aws_region))
            try:
                self.ec2_handle = ec2.connect_to_region(self.aws_region,
                                                        aws_access_key_id=self.access_key,
                                                        aws_secret_access_key=self.secret_key)
            except Exception as e:
                fail('AWS EC2 connection failed with err:%s' % str(e))

    def create_server_context_ip_addrs(self, vm):
        """ Create a server context """
        servers_ips = []
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for app in vm.app_servers.get(context_key,[]):
            if app.eth_ip_configured:
                continue

            logger.debug('Creating Server with IP %s on Interface %s' %(
                app.ip, app.eth_int))
            self.assign_secondary_ip(vm.name, app.net_name, app.ip,
                                                   mac_addr=app.mac)
            if type(ipaddress.ip_address(unicode(app.ip))) == ipaddress.IPv6Address:
                netmask = app.mask
                cmd = 'ifconfig %s:%s inet6 add %s/%s up' % (
                    app.eth_int, app.eth_index, app.ip, netmask)
            else:
                netmask = str(vm.get_dotted_netmask_for_cidr(app.mask))
                cmd = 'ifconfig %s:%s %s netmask %s up' % (
                    app.eth_int, app.eth_index, app.ip, netmask)
            logger.info(
                'a.eth_int: %s, a.eth_index: %s, a.ip: %s, netmask: %s' % (
                    app.eth_int, app.eth_index, app.ip, netmask))
            logger.debug('create_server_context ip addrs:: %s' % cmd)
            out = vm.execute_command(cmd)
            logger.debug('out:: %s' % out)
            # TBD: For AWS we need to fix the route for asymetric routing.
            if str(out).find('Invalid argument') != -1:
                fail('ERROR!! create server: sub-int config failed, msg: %s' % out)
            app.eth_ip_configured = 1

            #Add/Remove ip rules
            self.add_remove_ip_rules(vm=vm)

    def create_client_context_all(self, vm, how_many, network, prefix, app_type, ip_addrs, start_idx):

        from avi_config import AviConfig
        config = AviConfig.get_instance()
        for i in range(int(how_many)):
            handle = prefix + str(i + start_idx)
            ip = self.create_client_context(
                      vm, network, handle, app_type, ip_addrs[i])
            config.appclient[handle] = [vm, ip]
            logger.debug('[%s] Created Client: %s IP: %s' % (vm.ip, handle, ip))

    def create_client_context(self, vm, network, handle, app_type='', ip=None):
        """ Creates a client context on VM"""

        client = vm.client_handle_must_be_unique(handle)
        if not client:
            client = App()

        # the fields that a client needs and more.
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        mode = config.get_mode()
        site_name = mode['site_name']
        m_sub = re.search('([a-zA-Z]+)(\d+)', network)
        if m_sub:
            net_ip = config.testbed[site_name].networks[network].get_ip_for_network(ip_host = ip)
        else:
            ip, net = config.testbed[site_name].networks_queue.get_ip_for_network(vm=vm)
            net_ip = ip
            network = net
        client.network = network
        client.network_name = config.testbed[site_name].networks[str(client.network)].name
        if not vm.is_network_present(str(client.network)):
            fail('Create client: vnic/network %s does not exist on the vm %s' % (
                    client.network, vm.name))

        # Get client interface name, MAC address and IP from VM Info
        client.eth_int, client.mac, client.ip = vm.get_interface_details(client.network)
        if app_type == 'geoip':
            # If it's a GEO IP based client, we need to create interface with IP
            # passed by calling function
            client.ip = ip
            config.testbed[site_name].networks[str(client.network)].release_ip_for_network(net_ip)
        elif app_type != 'httperf' or not suite_vars.auto_gateway:
            # If it's httperf or auto gateway -> use main interface
            # else get a new IP from list of available IPs
            client.ip = net_ip

        client.handle = handle
        client.mask = config.testbed[site_name].networks[str(client.network)].mask
        client.eth_index = vm.get_ethernet_index(client.eth_int, client.network)

        if app_type == '':
            client.app_type = 'nginx'
        else:
            client.app_type = app_type

        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        vm.app_clients.setdefault(context_key,[]).append(client)
        #vm.app_clients.append(client)
        logger.debug('creating client:: %s, %s, %s, %s, %s, %s %s' % (
            client.ip, client.mask, client.mac, client.eth_int,
            client.handle, client.eth_index, client.network_name))

        if suite_vars.auto_gateway or app_type == 'httperf':
            logger.debug('Autogateway mode, not creating any sub interfaces')
            return client.ip

        self.assign_secondary_ip(vm.name, client.network_name, client.ip, mac_addr=client.mac)
        if type(ipaddress.ip_address(unicode(client.ip))) == ipaddress.IPv6Address:
            cmd = 'ifconfig %s:%s inet6 add %s/%s up' % (
                client.eth_int, client.eth_index, client.ip, client.mask)
        else:
            netmask = str(vm.get_dotted_netmask_for_cidr(client.mask))
            cmd = 'ifconfig %s:%s %s netmask %s up' % (
                client.eth_int, client.eth_index, client.ip, netmask)

        try:
            logger.debug('create_client_context:: %s' % cmd)
            out = vm.execute_command(cmd, log_error=False)
            logger.debug('create_client_context_out:: %s' % out)
        except Exception as e:
            pass

        if str(out).find('Invalid argument') != -1:
            fail('ERROR!! create client: sub-int config failed, msg: %s' % out)

        return client.ip

    def _get_vpc_handle(self):
        """
        Provide AWS VPC handler to the caller
        """
        vpc_conn = self.vpc_handle
        if not vpc_conn:
            self.aws_init()
            vpc_conn = self.vpc_handle
        if not vpc_conn:
            fail('AWS VPC connection is not available')
        return vpc_conn

    def _get_ec2_handle(self):
        """
        Provide AWS EC2 handler to the caller
        """
        ec2_conn = self.ec2_handle
        if not ec2_conn:
            self.aws_init()
            ec2_conn = self.ec2_handle
        if not ec2_conn:
            fail('AWS VPC connection is not available')
        return ec2_conn

    def get_subnet_id(self, subnet_name, vpc_id=None):
        """
        Provide the AWS subnet_id used for AWS operation
        from subnet_name.
        subnet_name : The name of subnet for which subnet_id is required
        vpc_id (optional) : The VPC ID where the subnet belongs
        """
        subnet_id = None
        vpconn = self._get_vpc_handle()
        vpcid = vpc_id if vpc_id else self.vpc_id
        logger.info('Fetching list of subnets of VPC:%s' % vpcid)
        qfilter = {'vpc-id': vpcid, 'state': 'available'}
        try:
            subnets = vpconn.get_all_subnets(filters=qfilter)
        except Exception as e:
            fail('Fetching of subnets failed for VPC:%s with err:%s' % (vpcid, str(e)))
            return None
        for subnet in subnets:
            if 'Name' in subnet.tags.keys() and \
                    subnet.tags['Name'] == subnet_name:
                subnet_id = subnet.id
                break
        return subnet_id

    def get_ip_for_network(self, subnet_name, subnet_id=None, vpc_id=None):
        """
        Allocate ENI/NIC in AWS in the provided subnet and return the IP of the ENI/NIC.
        subnet_name : The name of subnet in which IP is to be allocated.
        subnet_id (optional): Subnet id of the subnet, if provided lookup in AWS
            for subnet_id is skipped.
        vpc_id (optional) : The VPC ID where the subnet belongs
        """
        ip = None
        vpconn = self._get_vpc_handle()
        sub_id = subnet_id if subnet_id else self.get_subnet_id(subnet_name, vpc_id)
        if not sub_id:
            fail('Invalid subnet id for the subnet=%s' % (subnet_name))
            return None
        try:
            pintf = vpconn.create_network_interface(sub_id, description="AVITEST$")
            tags = pintf.tags
            from avi_config import AviConfig
            config = AviConfig.get_instance()
            tb_name = config.testbed[config.get_mode(key='site_name')].name
            tags.update({'avitest_tb_tag': tb_name})
            pintf.add_tags(tags)
            ip = pintf.private_ip_address
            logger.info('Created IP:%s in subnet:%s,subnet_id:%s' % (ip, subnet_name, sub_id))
        except Exception as e:
            fail('Failed to create interface in subnet=%s with err=%s' % (subnet_name, str(e)))
            return None
        return ip

    def release_ip_for_network(self, subnet_name, ip, subnet_id=None, vpc_id=None, ignr_desc=False):
        """
        Release the IP in the provided subnet and delete the ENI/NIC if primary IP.
        ip : IP to be released.
        subnet_name : The name of subnet in which ip belongs.
        subnet_id (optional): Subnet id of the subnet, if provided lookup in AWS
            for subnet_id is skipped.
        vpc_id (optional) : The VPC ID where the subnet belongs
        ignr_desc (optional): Ignore description of the interface to delete, when test
            creates the ENI/NIC we add AVITEST$ as description, while releasing
            we would want to release only allocated by us but in case of assiging ip
            we need to release the IP irrespective of the ENI it belongs to.
        """
        vpconn = self._get_vpc_handle()
        vpcid = vpc_id if vpc_id else self.vpc_id
        sub_id = subnet_id if subnet_id else self.get_subnet_id(subnet_name, vpc_id)
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        tb_name = config.testbed[config.get_mode(key='site_name')].name
        if not sub_id:
            fail('Invalid subnet id for the subnet=%s' % (subnet_name))
            return None
        qfilter = {'vpc-id': vpcid, 'addresses.private-ip-address': ip}
        try:
            ports = vpconn.get_all_network_interfaces(filters=qfilter)
            if not ports:
                logger.info(msg='The ip:%s, qfilter=%s, is not present in subnet=%s - attempt 1' % (ip, qfilter, subnet_name))
                asleep(delay=30)
                ports = vpconn.get_all_network_interfaces(filters=qfilter)
                if not ports:
                    logger.info(msg='The ip:%s, qfilter=%s, is not present in subnet=%s - attempt 2' % (ip, qfilter, subnet_name))
                    return
            p = ports[0]
            for eni in p.private_ip_addresses:
                if eni.private_ip_address != ip:
                    continue
                if eni.primary:
                    if not p.attachment and (ignr_desc or p.description == "AVITEST$") \
                        and ('avitest_tb_tag' in p.tags and p.tags['avitest_tb_tag'] == tb_name):
                        vpconn.delete_network_interface(p.id)
                else:
                    vpconn.unassign_private_ip_addresses(p.id, private_ip_addresses=ip)
                break
            logger.info(msg='Released IP:%s with port:%s' % (ip, p))
        except Exception as e:
            logger.info(msg='Failed to release IP:%s with err:%s' % (ip, str(e)))
        return

    def _get_instance_and_id(self, instance_name, **kwargs):
        """
        Return the instance and instance id with the instance_name in the 'Name' tag
        instance_name : The name of the instance in the 'Name' tag
        vpc_id (optional) : The VPC ID where the instance belongs
        """
        instance = self._get_instance(instance_name, **kwargs)
        return (instance, instance.id)

    def _get_instance_id(self, instance_name, **kwargs):
        """
        Return the instance id with the instance_name in the 'Name' tag
        instance_name : The name of the instance in the 'Name' tag
        vpc_id (optional) : The VPC ID where the instance belongs
        """
        instance = self._get_instance(instance_name, **kwargs)
        return instance.id

    def _get_instance(self, instance_name, **kwargs):
        """
        Return the instance object with the instance_name in the 'Name' tag
        instance_name : The name of the instance in the 'Name' tag
        vpc_id (optional) : The VPC ID where the instance belongs
        """
        state = kwargs.get('state', None)
        vpcid = kwargs.get('vpc_id', self.vpc_id)
        ec2_con = self._get_ec2_handle()
        qfilter = {'vpc-id': vpcid}
        logger.info('Fetching all reservations from AWS VPC:%s' % (vpcid))
        try:
            reservations = ec2_con.get_all_instances(filters=qfilter)
            for reservation in reservations:
                for instance in reservation.instances:
                    tags = instance.tags
                    if 'Name' not in tags.keys():
                        continue
                    if tags['Name'].lower() == instance_name.lower():
                        logger.info('Found instance ID [%s]: %s' % (instance_name, instance.id))
                        if state is not None:
                            if state.lower() == instance.update():
                                return instance
                            else:
                                logger.info('Instance %s not in expected state: %s, current state: %s' % (
                                    instance_name, state, instance.update()))
                        else:
                            return instance
        except Exception as e:
            fail('Failed to get instance:%s with err:%s' % (instance_name, str(e)))

    def assign_secondary_ip(self, instance_name, subnet_name, ip, mac_addr=None, subnet_id=None, vpc_id=None):
        """
        Assign the 'ip' to the interface belonging to 'subnet_name' on the instance 'instance_name'
        instance_name : The name of the instance in the 'Name' tag.
        subnet_name : The name of subnet in which instance belongs.
        subnet_id (optional) : subnet id of the subnet_name
        vpc_id (optional) : The VPC ID where the instance belongs.
        """
        ec2_con = self._get_ec2_handle()
        vpcid = vpc_id if vpc_id else self.vpc_id
        sub_id = subnet_id if subnet_id else self.get_subnet_id(subnet_name, vpc_id)
        interface = None
        instance = self._get_instance(instance_name, state='running', vpc_id=vpcid)
        if not instance:
            fail('Instance:%s not found in VPC:%s' % (instance_name, vpcid))
            return
        # May be we can validate ip belongs to subnet,
        # but ideal would be to do it in caller.
        for intf in instance.interfaces:
            if intf.subnet_id == sub_id:
                if not mac_addr:
                    interface = intf
                    break
                elif mac_addr and intf.mac_address == mac_addr:
                    interface = intf
                    continue
        if interface is None:
            fail('Failed to find interface on VM: %s subnet: %s' % (
                instance_name, subnet_name))
            return
        # Make sure to free the IP before assigning to the instance,
        # even though it can be same instance.
        self.release_ip_for_network(subnet_name, ip, subnet_id=sub_id, vpc_id=vpcid, ignr_desc=True)
        try:
            ec2_con.assign_private_ip_addresses(interface.id,
                                                private_ip_addresses=[ip], allow_reassignment=True)
            logger.info('Adding %s to interface %s on instance %s' % (ip, interface.id, instance_name))
        except Exception as e:
            fail('Failed to assign IP:%s to instance:%s with err:%s' % (ip, instance_name, str(e)))
        return

    def unassign_secondary_ip(self, instance_name, subnet_name, ip, subnet_id=None, vpc_id=None):
        """
        Unassign the 'ip' to the interface belonging to 'subnet_name' on the instance 'instance_name'
        instance_name : The name of the instance in the 'Name' tag.
        subnet_name : The name of subnet in which instance belongs.
        subnet_id (optional) : subnet id of the subnet_name
        vpc_id (optional) : The VPC ID where the instance belongs.
        """
        ec2_con = self._get_ec2_handle()
        vpcid = vpc_id if vpc_id else self.vpc_id
        sub_id = subnet_id if subnet_id else self.get_subnet_id(subnet_name, vpc_id)
        interface = None
        instance = self._get_instance(instance_name, state='running', vpc_id=vpcid)
        if not instance:
            fail('Instance:%s not found in VPC:%s' % (instance_name, vpcid))
            return
        for intf in instance.interfaces:
            priv_addrs = [addr.private_ip_address for addr in intf.private_ip_addresses]
            if intf.subnet_id == sub_id and ip in priv_addrs:
                interface = intf
                break
        if interface is None:
            logger.info('No interface with ip:%s,subnet:%s on instance:%s' % (
                ip, subnet_name, instance_name))
        else:
            try:
                ec2_con.unassign_private_ip_addresses(interface.id, private_ip_addresses=[ip])
                logger.info('Removing IP:%s from interface:%s of instance:%s' % (
                    ip, interface.id, instance_name))
            except Exception as e:
                fail('Failed to unassign IP:%s, instance:%s with err:%s' % (
                    ip, instance_name, str(e)))
        return

    def cleanup_secondary_ips(self, instance_name, vpc_id=None):
        """
         Remove all secondary IPs of all ENIs/NICs on the given instance
         instance_name: The name of the isntance in the 'Name' tag.
         vpc_id (optional) : The VPC ID where the instance belongs.
        """
        ec2_con = self._get_ec2_handle()
        vpcid = vpc_id if vpc_id else self.vpc_id
        instance = self._get_instance(instance_name, state='running')
        if not instance:
            fail('Instance:%s not found in VPC:%s' % (instance_name, vpcid))
            return
        for intf in instance.interfaces:
            ip_addrs = []
            for priv_addr in intf.private_ip_addresses:
                if not priv_addr.primary:
                    ip_addrs.append(priv_addr.private_ip_address)
            if not ip_addrs:
                logger.info('No secondary IPs on the instance:%s, intf:%s ' % (
                    instance_name, intf))
                continue
            logger.info('Cleaning IPs:[%s] of intf:%s on instance:%s' % (
                ip_addrs, intf, instance_name))
            try:
                ec2_con.unassign_private_ip_addresses(intf.id, private_ip_addresses=ip_addrs)
            except Exception as e:
                fail('Failed to clean the IPs:[%s] of intf:%s on instance:%s with err:%s' % (
                    ip_addrs, intf, instance_name, str(e)))

    def cleanup_all(self):
        """Cleanup testbed with respect to the cloud """
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        for vm in config.get_vm_of_type('client'):
            self.add_remove_ip_rules(vm=vm)
        for vm in config.get_vm_of_type('server'):
            self.add_remove_ip_rules(vm=vm)

    def add_remove_ip_rules(self, vm, eth_infs=None, operation=''):
        """ Helps to Add/Remove ip route list on Client

        kwrgs:
            :param vm: client/server vm object
            :type vm: Object
            :param eth_infs: list of eth interface
            :type eth_infs: list
            :param operation: operation add/delete (default add)
            :type operation: str

        Returns:
            None
        """
        if not eth_infs:
            eth_infs = []
            vm_data_nets = vm.networks.get('data', [])
            for net in vm_data_nets:
                eth, eth_mac, eth_ip = vm.get_interface_details(net)
                eth_infs.append(eth)

        for eth_inf in eth_infs:
            cmd = 'bash /root/common/scripts/configure-defgw.sh ' + eth_inf + ' all del'
            cmd += "&> /tmp/configure-defgw_del_all_log"
            out = vm.execute_command(cmd, background=True)
            asleep(delay=5)
            if operation == 'del':
                continue
            cmd = 'bash /root/common/scripts/configure-defgw.sh %s all' % eth_inf
            cmd += "&> /tmp/configure-defgw_add_all_log"
            out = vm.execute_command(cmd, background=True)


class Azure(Virtualization):
    """
        Class for Azure operations.
    """

    def __init__(self, configuration, cloud_name):
        """
        Azure object for azure operations
        """
        self.subscription_id = None
        self.application_id = None
        self.secret_key = None
        self.tenant_id = None
        self.resource_group = None
        self.compute_client = None
        self.network_client = None
        self.vnet_id = None
        self.type = None
        self.credentials = None
        super(Azure, self).__init__('azure', cloud_name)
        self._init(configuration)

    def _init(self, config):
        """
        Init the AZURE object from configuration params
        """

        from avi_objects.avi_config import AviConfig
        _config = AviConfig.get_instance()
        site_name = _config.get_mode().get('site_name')
        self.testbed_name = _config.testbed[site_name].name
        self.route_prefix = self.testbed_name.replace('_','-') + '-tb-'
        credentials = get_credentials(self.type, self.name)
        if not self.subscription_id:
            self.subscription_id = config.get('subscription_id', None)
            if self.subscription_id:
                self.subscription_id = str(self.subscription_id)
            else:
                self.subscription_id = config['cc_info'].get('subscription_id', None)
                if self.subscription_id:
                    self.subscription_id = str(self.subscription_id)
        if not self.application_id:
            self.application_id = config['cc_info']['azure_serviceprincipal'].get('application_id', None)
        if not self.secret_key:
            self.secret_key = credentials.get('secret_key', None)
        if not self.tenant_id:
            self.tenant_id = config['cc_info']['azure_serviceprincipal'].get('tenant_id', None)
        if not self.resource_group:
            self.resource_group = config.get('resource_group', None)
            if not self.resource_group:
                self.resource_group = config['cc_info'].get('resource_group', None)
        if not self.vnet_id:
            self.vnet_id = config.get('virtual_network_ids', None)
            if not self.vnet_id:
                self.vnet_id = config['network_info'][0].get('virtual_network_id', None)
        if not self.subscription_id or not self.application_id or not self.application_id or not self.tenant_id or not self.resource_group:
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
                self.credentials = ServicePrincipalCredentials(client_id = self.application_id, secret = self.secret_key, tenant = self.tenant_id)
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

    def create_server_context_ip_addrs(self, vm):
        """ Create a server context """
        servers_ips = []
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for app in vm.app_servers.get(context_key,[]):
            if app.eth_ip_configured:
                continue

            logger.debug('Creating Server with IP %s on Interface %s' %(
                app.ip, app.eth_int))

            servers_ips.append(app.ip)
            if type(ipaddress.ip_address(unicode(app.ip))) == ipaddress.IPv6Address:
                netmask = app.mask
                cmd = 'ifconfig %s:%s inet6 add %s/%s up' % (
                    app.eth_int, app.eth_index, app.ip, netmask)
            else:
                netmask = str(vm.get_dotted_netmask_for_cidr(app.mask))
                cmd = 'ifconfig %s:%s %s netmask %s up' % (
                    app.eth_int, app.eth_index, app.ip, netmask)
            logger.info(
                'a.eth_int: %s, a.eth_index: %s, a.ip: %s, netmask: %s' % (
                    app.eth_int, app.eth_index, app.ip, netmask))
            logger.debug('create_server_context ip addrs:: %s' % cmd)
            out = vm.execute_command(cmd)
            logger.debug('out:: %s' % out)
            # TBD: For AWS we need to fix the route for asymetric routing.
            if str(out).find('Invalid argument') != -1:
                fail('ERROR!! create server: sub-int config failed, msg: %s' % out)
            app.eth_ip_configured = 1
        if len(servers_ips):
            server_name = vm.name
            self.assign_secondary_ip(server_name,servers_ips)

    def create_client_context_all(self, vm, how_many, network, prefix, app_type, ip_addrs, start_idx):

        from avi_config import AviConfig
        config = AviConfig.get_instance()
        for i in range(int(how_many)):
            handle = prefix + str(i + start_idx)
            ip = self.create_client_context(
                      vm, network, handle, app_type, ip_addrs[i])
            config.appclient[handle] = [vm, ip]
            logger.debug('[%s] Created Client: %s IP: %s' % (vm.ip, handle, ip))

    def create_client_context(self, vm, network, handle, app_type='', ip=None):
        """ Creates a client context on VM"""

        client = vm.client_handle_must_be_unique(handle)
        if not client:
            client = App()

        # the fields that a client needs and more.
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        mode = config.get_mode()
        site_name = mode['site_name']
        m_sub = re.search('([a-zA-Z]+)(\d+)', network)
        if m_sub:
            net_ip = config.testbed[site_name].networks[network].get_ip_for_network(ip_host = ip)
        else:
            ip, net = config.testbed[site_name].networks_queue.get_ip_for_network(vm=vm)
            net_ip = ip
            network = net
        client.network = network
        if not vm.is_network_present(client.network):
            fail('Create client: vnic/network %s does not exist on the vm %s' % (
                    client.network, vm.name))

        # Get client interface name, MAC address and IP from VM Info
        client.eth_int, client.mac, client.ip = vm.get_interface_details(network)
        if app_type == 'geoip':
            # If it's a GEO IP based client, we need to create interface with IP
            # passed by calling function
            client.ip = ip
            config.testbed[site_name].networks[client.network].release_ip_for_network(net_ip)
        elif app_type != 'httperf' or not suite_vars.auto_gateway:
            # If it's httperf or auto gateway -> use main interface
            # else get a new IP from list of available IPs
            client.ip = net_ip

        client.handle = handle
        client.mask = config.testbed[site_name].networks[str(network)].mask
        client.eth_index = vm.get_ethernet_index(client.eth_int, client.network)

        if app_type == '':
            client.app_type = 'nginx'
        else:
            client.app_type = app_type
        
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        vm.app_clients.setdefault(context_key,[]).append(client)
        #vm.app_clients.append(client)
        logger.debug('creating client:: %s, %s, %s, %s, %s, %s' % (
            client.ip, client.mask, client.mac, client.eth_int,
            client.handle, client.eth_index))

        if suite_vars.auto_gateway or app_type == 'httperf':
            logger.debug('Autogateway mode, not creating any sub interfaces')
            return client.ip

        self.assign_secondary_ip(vm.name, client.ip)
        if type(ipaddress.ip_address(unicode(client.ip))) == ipaddress.IPv6Address:
            cmd = 'ifconfig %s:%s inet6 add %s/%s up' % (
                client.eth_int, client.eth_index, client.ip, client.mask)
        else:
            netmask = str(vm.get_dotted_netmask_for_cidr(client.mask))
            cmd = 'ifconfig %s:%s %s netmask %s up' % (
                client.eth_int, client.eth_index, client.ip, netmask)

        try:
            logger.debug('create_client_context:: %s' % cmd)
            out = vm.execute_command(cmd, log_error=False)
            logger.debug('create_client_context_out:: %s' % out)
        except Exception as e:
            pass

        if str(out).find('Invalid argument') != -1:
            fail('ERROR!! create client: sub-int config failed, msg: %s' % out)

        return client.ip
    
    @aretry(retry=20, delay=10)
    def secondary_ip_status(self, vnic_name):
        
        vnic = self.network_client.network_interfaces.get(self.resource_group, vnic_name)
        ip_configurations = vnic.ip_configurations
        for ip in ip_configurations:
            if str(ip.provisioning_state) != str('Succeeded'):
                fail('Secondary ip is not in succeeded state %s' % (ip.private_ip_address))

    def assign_secondary_ip(self, vm_name, ips_list):
        """
        AZURE assign secondary ips to client or server vm nics
        """
        if type(ips_list) in [str, unicode]:
            ips_list = [str(ips_list)]
        vm = self.compute_client.virtual_machines.get(self.resource_group, vm_name)
        vnic_id = vm.network_profile.network_interfaces[0].id
        temp = vnic_id.split('/')
        vnic_name = temp[-1]
        vnic = self.network_client.network_interfaces.get(
            self.resource_group,
            vnic_name)

        subnet_id = vnic.ip_configurations[0].subnet.id
        old_ips = [ip.private_ip_address for ip in vnic.ip_configurations]
        old_ips = Set(old_ips)
        ips_list = Set(ips_list)
        new_ips = ips_list - old_ips
        temp_ips = []
        if len(new_ips):
            # new ips are present
            for ip in new_ips:
                name = self.get_ip_config_name(ip)
                temp_ips.append(NetworkInterfaceIPConfiguration(
                    subnet=Subnet(id=subnet_id),
                    name=name,
                    private_ip_address=ip,
                    private_ip_allocation_method='Static'))
            vnic.ip_configurations.extend(temp_ips)
            try:
                self.network_client.network_interfaces.create_or_update(self.resource_group, vnic_name, vnic)
                asleep('waiting for azure seconday ip update', delay=5)
            except Exception as e:
                fail('ERROR! adding secondary ip to NIC failed, %s' % str(e))
            self.secondary_ip_status(vnic_name)
        else:
            # new ips are not present
            logger.info('No new ips are present')

    def get_ip_config_name(self, vip):
        return '%s-%s' %(self.route_prefix,vip)

    def unassign_secondary_ips(self, vm_name):

        vm = self.compute_client.virtual_machines.get(self.resource_group, vm_name)
        vnic_id = vm.network_profile.network_interfaces[0].id
        temp = vnic_id.split('/')
        vnic_name = temp[-1]
        vnic = self.network_client.network_interfaces.get(
            self.resource_group,
            vnic_name)
        ipconfigs = vnic.ip_configurations
        new_ipconfigs = [ipc for ipc in vnic.ip_configurations if ipc.primary]
        vnic.ip_configurations = new_ipconfigs
        try:
            self.network_client.network_interfaces.create_or_update(self.resource_group, vnic_name, vnic)
            asleep('waiting for azure seconday ip update', delay=5)
        except Exception as e:
            fail('ERROR! deleting secondary ips from NIC failed, %s' % str(e))
        self.secondary_ip_status(vnic_name)
    
    def unassign_secondary_ip(self, vm_name, vm_ip):

        vm = self.compute_client.virtual_machines.get(self.resource_group, vm_name)
        vnic_id = vm.network_profile.network_interfaces[0].id
        temp = vnic_id.split('/')
        vnic_name = temp[-1]
        vnic = self.network_client.network_interfaces.get(
            self.resource_group,
            vnic_name)
        ipconfigs = vnic.ip_configurations
        new_ipconfigs = [ipc for ipc in vnic.ip_configurations if ipc.primary or ipc.private_ip_address != vm_ip]
        vnic.ip_configurations = new_ipconfigs
        try:
            self.network_client.network_interfaces.create_or_update(self.resource_group, vnic_name, vnic)
            asleep('waiting for azure seconday ip update', delay=5)
        except Exception as e:
            fail('ERROR! deleting secondary ip from NIC failed, %s' % str(e))
        self.secondary_ip_status(vnic_name)

    def cleanup_all(self):
        from avi_objects.avi_config import AviConfig
        config = AviConfig.get_instance()
        for vm in config.get_vm_of_type('client'):
            self.unassign_secondary_ips(vm.name)
        for vm in config.get_vm_of_type('server'):
            self.unassign_secondary_ips(vm.name)

    @aretry(retry=25, delay=20)
    def check_scale_set_status(self, scale_set_name):
        """
        :param scale_set_name: Azure scale set name
        """
        vm_list = []
        try:
            vm_list = self.compute_client.virtual_machine_scale_set_vms.list(self.resource_group, scale_set_name)
        except Exception as e:
            fail('Error while getting vmss %s status'%scale_set_name, str(e))
        for vm in vm_list:
            if vm.provisioning_state not in ['Succeeded', 'Updating']:
                fail('scale set %s not in succeeded state'%scale_set_name)
        logger.info('scale set %s succeeded'%scale_set_name)
        return
        
 
class Gcp(Virtualization):
    """
        Class for GCP operations
    """

    def __init__(self, configuration, cloud_name):
        """
        GCP object for gcp operations
        """
        self.project = None
        self.zone = None
        self.google_application_credentials = None
        self.gcp = None
        self.testbed_name = None
        super(Gcp, self).__init__('gcp', cloud_name)
        self._init(configuration)

    def _init(self,tb):
        """
        Init the GCP object from configuration params
        """
       
        from avi_objects.avi_config import AviConfig
        config = AviConfig.get_instance()
        site_name = config.get_mode().get('site_name')
        self.testbed_name = config.testbed[site_name].name
        self.route_prefix = self.testbed_name.replace('_','-') + '-tb-route-'
        try:
            credentials = get_credentials(self.type, self.name)
        except Exception as e:
            logger.info("Could not retreive password from credential's file with err %s. Using Defaults" %e)
            credentials = {}
        if not self.project:
            self.project = credentials.get('project', 'astral-chassis-136417')
        if not self.google_application_credentials:
            self.google_application_credentials = credentials.get('google_application_credentials',
                        '/home/aviuser/.config/gcloud/application_default_credentials.json')
        if not self.zone:
             self.zone = credentials.get('zone', 'us-central1-a')

        self.gcp_init()

    def gcp_init(self):
        """
        GCP connection handlers
        """
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = self.google_application_credentials
        credentials = GoogleCredentials.get_application_default()
        self.gcp = GCP_discovery.build('compute', 'v1', credentials=credentials)

    def create_server_context(self, vm ,server):
        """create_server_context """
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        for app in vm.app_servers.get(context_key,[]):
            if app.handle == server.handle:
                logger.debug("%s already configured"  %server.handle)
                return
                #fail('Adding duplicate handle to app_servers')
        app = App()
        app.server = server
        app.app_type = server.app_type()
        app.net = server.net
        app.net_name = server.net_name
        app.handle = server.handle
        app.ip = server.ip()
        app.ssl_enabled = server.ssl_enabled()
        management_network = vm.vm_info['networks'][0]['mgmt1']
        for intf in management_network:
            app.gcp_net = management_network[intf]['network']
        if not vm.is_network_present(app.gcp_net):
            fail('create server: vnic/network %s does not exist on the vm '
                    '%s' % (app.gcp_net, vm.name))
        app.mask = 32
        app.eth_int, app.mac, _ = vm.get_interface_details(app.gcp_net)
        app.eth_index = vm.get_ethernet_index(app.eth_int, app.gcp_net)
        vm.app_servers.setdefault(context_key,[]).append(app)
        route_id = self.route_prefix + app.ip.replace('.','-')
        logger.debug("Creating Google Route %s, destRange %s, nexthop %s" %(route_id, app.ip, server._vm.ip))
        instance_name = vm.name
        network = self.get_network(instance= instance_name)
        try:
            result = self.create_route(name=route_id, destRange=app.ip, network=network, nextHopIp=server._vm.ip)
            logger.debug("Route Created %s" %(route_id))
        except HttpError as exp:
            reason = exp._get_reason()
            if re.search('already exists', reason):
                logger.debug("Already Exists%s" %(route_id))
                pass
            else:
                fail('Google Route Creation failed with %s %s' %(exp, reason))
        # Create Static routes for each server entry
        from avi_objects.avi_config import AviConfig
        from avi_objects.rest import get_uuid_by_name, put, get
        config = AviConfig.get_instance()
        vrf = config.get_mode()['vrfcontext']
        uuid = get_uuid_by_name('vrfcontext', vrf)
        status_code, data = get('vrfcontext/%s' %uuid)
        static_route = {}
        static_route['prefix'] = {"ip_addr": {"addr": app.ip, "type" : "V4"}, "mask": 32}
        static_route['next_hop'] = {"addr": server._vm.ip, "type" : "V4"}
        static_route['route_id'] = route_id
        if 'static_routes' in data:
            data['static_routes'].append(static_route)
        else:
            data['static_routes'] = [static_route]
        status_code, resp = put('vrfcontext/%s' %uuid, data=json.dumps(data))

    def create_client_context_all(self, vm, how_many, network, prefix, app_type, ip_addrs, start_idx):

        from avi_config import AviConfig
        routes_exists_list = []
        config = AviConfig.get_instance()
        for i in range(int(how_many)):
            handle = prefix + str(i + start_idx)
            ip, exists = self.create_client_context(
                      vm, network, handle, app_type, ip_addrs[i])
            config.appclient[handle] = [vm, ip]
            routes_exists_list.append(exists)
            logger.debug('[%s] Created Client: %s IP: %s' % (vm.ip, handle, ip))

        create_count = routes_exists_list.count(False)
        sleep_timer = min(45*create_count, 120)
        asleep(msg="Waiting for Google route to get settle down", delay = sleep_timer)

    def create_client_context(self, vm, network, handle, app_type='', ip=None):
        """ Creates a client context on VM"""

        client = vm.client_handle_must_be_unique(handle)
        if not client:
            client = App()

        # the fields that a client needs and more.
        from avi_config import AviConfig
        config = AviConfig.get_instance()
        mode = config.get_mode()
        site_name = mode['site_name']
        m_sub = re.search('([a-zA-Z]+)(\d+)', network)
        if m_sub:
            net_ip = config.testbed[site_name].networks[network].get_ip_for_network(ip_host = ip)
        else:
            ip, net = config.testbed[site_name].networks_queue.get_ip_for_network(vm=vm)
            net_ip = ip
            network = net
        management_network = vm.vm_info['networks'][0]['mgmt1']
        for intf in management_network:
            client.gcp_network = management_network[intf]['network']
        client.network = network
        if not vm.is_network_present(client.gcp_network):
            fail('Create client: vnic/network %s does not exist on the vm %s' % (
                    client.network, vm.name))

        # Get client interface name, MAC address and IP from VM Info
        client.eth_int, client.mac, client.ip = vm.get_interface_details(client.gcp_network)
        if app_type == 'geoip':
            # If it's a GEO IP based client, we need to create interface with IP
            # passed by calling function
            client.ip = ip
            config.testbed[site_name].networks[client.network].release_ip_for_network(net_ip)
        elif app_type != 'httperf' or not suite_vars.auto_gateway:
            # If it's httperf or auto gateway -> use main interface
            # else get a new IP from list of available IPs
            client.ip = net_ip

        client.handle = handle
        client.mask = 32
        client.eth_index = vm.get_ethernet_index(client.eth_int, client.gcp_network)

        if app_type == '':
            client.app_type = 'nginx'
        else:
            client.app_type = app_type

        from avi_config import AviConfig
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        vm.app_clients.setdefault(context_key,[]).append(client)
        #vm.app_clients.append(client)
        logger.debug('creating client:: %s, %s, %s, %s, %s, %s' % (
            client.ip, client.mask, client.mac, client.eth_int,
            client.handle, client.eth_index))

        if suite_vars.auto_gateway or app_type == 'httperf':
            logger.debug('Autogateway mode, not creating any sub interfaces')
            return client.ip

        if type(ipaddress.ip_address(unicode(client.ip))) == ipaddress.IPv6Address:
            cmd = 'ifconfig %s:%s inet6 add %s/%s up' % (
                client.eth_int, client.eth_index, client.ip, client.mask)
        else:
            netmask = str(vm.get_dotted_netmask_for_cidr(client.mask))
            cmd = 'ifconfig %s:%s %s netmask %s up' % (
                client.eth_int, client.eth_index, client.ip, netmask)

        try:
            logger.debug('create_client_context:: %s' % cmd)
            out = vm.execute_command(cmd, log_error=False)
            logger.debug('create_client_context_out:: %s' % out)
        except Exception as e:
            pass

        if str(out).find('Invalid argument') != -1:
            fail('ERROR!! create client: sub-int config failed, msg: %s' % out)

        route_id = self.route_prefix + client.ip.replace('.','-')
        logger.debug("Creating Google Route %s, destRange %s, nexthop %s" %(route_id, client.ip, vm.ip))
        exists = False
        instance_name = vm.name
        network = self.get_network(instance= instance_name)
        try:
            result = self.create_route(name=route_id, destRange=client.ip, network=network, nextHopIp=vm.ip)
            logger.debug("Route Created %s" %(route_id))
        except HttpError as exp:
            reason = exp._get_reason()
            if re.search('already exists', reason):
                logger.debug("Already Exists%s" %(route_id))
                exists = True
                pass
            else:
                fail('Google Route Creation failed with %s %s' %(exp, reason))

        return client.ip, exists

    def get_routes(self, filters=None):
        if not filters:
            filters = 'name eq ' + self.route_prefix + '.*'
        routes = []
        logger.info("Getting Google Cloud Routes with filters %s" %filters)
        request = self.gcp.routes().list(project=self.project, filter=filters)
        while request is not None:
            response = request.execute()
            if 'items' in response:
                for route in response['items']:
                    routes.append(route['name'])
            request = self.gcp.routes().list_next(previous_request=request, previous_response=response)

        return routes

    def delete_route(self,route=None):
        request = self.gcp.routes().delete(project=self.project, route=route)
        response = request.execute()
        return response

    def create_route(self, name, destRange, network, nextHopIp):
        route_data = {'name': name,
                      'destRange': destRange, 'network': network,
                       'nextHopIp': nextHopIp}
        response = self.gcp.routes().insert(project=self.project, body=route_data).execute()
        return response

    def get_network(self, instance, zone=None):
        if not zone:
            zone = self.zone
        return self.gcp.instances().get(project=self.project,zone=zone, instance=instance).execute()['networkInterfaces'][0]['network']

    def clear_routes(self, filters=None):
        logger.info("Clearing Routes")
        routes = self.get_routes(filters=filters)
        for route in routes:
             logger.debug('Deleting route %s' %route)
             resp = self.delete_route(route = route)
        count = 0
        routes = self.get_routes()
        while routes and count <=30:
            routes = self.get_routes()
            logger.debug('Still Routes are not empty.Will Poll again in 10 seconds.')
            count +=1
            asleep("Waiting for routes to be empty.", delay = 10)

    def clear_static_routes(self):

        from avi_objects.avi_config import AviConfig
        from avi_objects.rest import get_uuid_by_name, put, get
        config = AviConfig.get_instance()
        vrf = config.get_mode()['vrfcontext']
        uuid = get_uuid_by_name('vrfcontext', vrf)
        status_code, data = get('vrfcontext', uuid=uuid)
        data.pop('static_routes', None)
        status_code, resp = put('vrfcontext', uuid=uuid, data=json.dumps(data))

    def cleanup_all(self):
        
        self.clear_routes()
        self.clear_static_routes()

class OpenStack(Virtualization):
    """
        Class for openstack operations
    """
    def __init__(self, configuration, cloud_name):
        """
        Baremetal object for Baremetal operations
        """
        self.type = None
        super(OpenStack, self).__init__('openstack', cloud_name)
