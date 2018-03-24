import simplejson as json
import os
import sys
import re

from cloud_manager import (Aws, Azure, Gcp,\
                           Vcenter, Virtualization,\
                           Baremetal, OpenStack)
from logger import logger
from logger_utils import fail, abort
from suite_vars import suite_vars

import ipaddress
from jsonschema import validate

class AviTestbed():

    def __init__(self, testbed):
        self.abspath = None
        self.name = None
        self.cloud = None
        self.networks_json = None
        self.configuration = None
        self.pre_configuration = None
        self.networks = {}
        self.tb_json = None
        self.site_name = 'default'
        self.virtualization = {}
        self.testbed_vars = {}
        # TBD: Might have to change the way we keep the cloud objects
        self.tb_cloud_obj = None
        self.vm_list = []
        self.abspath, self._dir, self.name = self.__testbed_find(testbed)
        self.__validate()
        self.parse_testbed()

    def __validate(self):

        testbed_data = open(self.abspath).read()
        workspace = suite_vars.workspace
        schema_fullpath = workspace + '/test/avitest/avi_objects/testbed_schema.json'
        schema=open(schema_fullpath).read()
        try:
            schema_data = json.loads(schema)
            logger.info('schema loaded')
        except Exception as e:
            abort('Json load failed testbed_schema with Exception %s' % e)
        try:
            self.tb_json = json.loads(testbed_data)
            logger.info('test_bed loaded')
        except Exception as e:
            abort('Json load failed for testbed file %s with Exception %s' % (self.abspath,e))
        try:
            validate(self.tb_json,schema_data)
            logger.info('Testbed is valid')
        except Exception as e:
            abort('Script not complying with schema! Following is the error: %s' % e)
            

    def __testbed_find(self,testbed):

        testbed_abspath = self.__testbed_filename_get(testbed=testbed)
        testbed_dir, testbed_name = os.path.split(testbed_abspath)
        testbed_name = os.path.splitext(testbed_name)[0]
        sys.path.append(testbed_dir)
        logger.info(msg='TestBed File name is %s' %testbed_name)
        logger.info(msg='TestBed absolute path is %s' %testbed_abspath)

        return (testbed_abspath, testbed_dir, testbed_name)

    def __testbed_filename_get(self,testbed):

        if testbed == "":
            abort("TestBed file Missing")

        if not os.path.isfile(testbed):
            abort('Could not locate Test Bed file %s' %testbed)
        return os.path.abspath(testbed)

    def parse_testbed(self):

        self.site_name = self.site_name  if "site_name" in self.tb_json else 'default'
        self.vm_list = []
        self.cloud_obj = CloudDict()
        for vm in self.tb_json['Vm']:
            self.vm_list.append(vm)
        self.cloud = self.tb_json["Cloud"] if "Cloud" in self.tb_json else None
        self.configuration = self.tb_json['Configuration'] if 'Configuration' in self.tb_json else None
        self.pre_configuration = self.tb_json['preConfiguration'] if 'preConfiguration' in self.tb_json else None
        self.networks_json = self.tb_json["Networks"] if "Networks" in self.tb_json else None
        self.networks_queue = NetworksQueue()
        self.testbed_vars.update(self.tb_json.get("Variables", {}))
        self.ip_dict = {}
        if self.networks_json:
            for network in self.networks_json:
                net_obj = Network(network, self.networks_json[network], tb=self)
                self.networks[str(net_obj)] = net_obj
                if not re.search('mgmt|management', str(net_obj)):
                    self.networks_queue.enqueue(net_obj)
        logger.info("Networks Queue= %s" %[network.name for network in self.networks_queue.networks])

    def get_cloud_json(self, cloud_name):
        cloud_json = None
        try:
            cloud_json = [cloud_json for cloud_json in self.tb_json.get('Cloud') \
                    if cloud_json.get('name') == cloud_name][0]
        except TypeError:
            logger.info('Must be no-access cloud?')
        except IndexError:
            logger.info("Can't find cloud under Clouds for %s" %cloud_name)

        if not cloud_json:
            cloud_json = None #Setting it back to None as it must have become an empty list
            try:
                # Check in vm clouds
                cloud_json = [cloud_json for cloud_json in self.tb_json.get('VmCloud') \
                    if cloud_json.get('name') == cloud_name][0]
            except TypeError:
                logger.info('no VmCloud defined in the testbed')

        if not cloud_json:
            cloud_json = None #Setting it back to None as it must have become an empty list

        return cloud_json
             

class Network():

    def __init__(self, network, network_details, tb=None):
        self.network = network
        self.name = network_details['name']
        self.ip_addr = network_details['ip']
        self.mask = network_details['mask']
        self.cloud_name = network_details.get('cloud_name', 'Default-Cloud')
        self.testbed = tb
        self.virt = None
        self.subnet_id = None
        self.cloud_obj = None
        self.network_type = network_details['type'] if 'type' in network else None
        if type(ipaddress.ip_address(unicode(self.ip_addr))) == ipaddress.IPv6Address:
            self.ip_addr_type = 'V6'
        else:
            self.ip_addr_type = 'V4'
        self.addr_list = []

    def __str__(self):
        return self.network

    @staticmethod
    def __last_ip_group__(ip):
        '''
        return last int of ip, for sorting
        '''
        if type(ipaddress.ip_address(unicode(ip))) == ipaddress.IPv6Address:
            return int(ip.split(':')[-1])
        else:
            return int(ip.split('.')[-1])

    def assign_cloud_obj(self):
        cloud_name = self.cloud_name
        self.cloud_obj = self.testbed.cloud_obj[cloud_name]
        if self.cloud_obj.type == 'aws' and self.subnet_id == None:
            self.subnet_id = self.cloud_obj.get_subnet_id(self.name)
        else:
            self.parse_networks()

    def get_ip_addresses_assigned(self):
        import avi_objects.rest as rest
        from avi_objects.avi_config import AviConfig
        ip_list = []
        config = AviConfig.get_instance()
        mode = config.get_mode()
        current_tenant = mode['tenant']
        current_cloud = mode['cloud']
        config.switch_mode(tenant='*', cloud= None)
        # Get Virtualservice IPs
        st, virtualservices = rest.get('virtualservice?page_size=1000')
        virtualservices = virtualservices['results']
        for vs_name in virtualservices:
            vips_obj = vs_name.get('vip',[])
            for vip in vips_obj:
                if 'ip_address' in vip:
                    ip_list.append(vip['ip_address']['addr'])
                if 'ip6_address' in vip:
                    ip_list.append(vip['ip6_address']['addr'])
        # Get Pool Servers IPs
        st, pools = rest.get('pool?page_size=1000')
        pools = pools['results']
        for pool in pools:
            servers = pool.get('servers',[])
            for server in servers:
                ip_list.append(server['ip']['addr'])
        config.switch_mode(tenant = current_tenant, cloud = current_cloud)
        logger.trace('Configured IP Addresses %s' %ip_list)
        return ip_list

    def parse_networks(self):
        ip_list_assigned = self.get_ip_addresses_assigned()
        if self.ip_addr_type == 'V4':
            ip_addr = self.ip_addr
            v4network = unicode(
                ip_addr + '/' + str(self.mask))
            skip_counter = 0
            for ip in ipaddress.IPv4Network(v4network):
                if skip_counter > 60 and unicode(ip) not in ip_list_assigned:
                    if not (str(ip).endswith('.255') or
                            str(ip).endswith('.1') or
                            str(ip).endswith('.0')):
                        self.addr_list.append(str(ip))
                else:
                    skip_counter = skip_counter + 1
        else:
            ipv6_addr = self.ip_addr
            v6network = unicode(
                ipv6_addr + '/' + str(self.mask))
            counter = 0
            for ip in ipaddress.IPv6Network(v6network):
                if counter > 60 and unicode(ip) not in ip_list_assigned:
                    self.addr_list.append(str(ip))
                counter = counter + 1
                if counter > 255:
                    break

    def get_ip_for_network(self, ip_host=None):
        ''' Returns the first available address in the list and removes it from the list
        '''
        ip = None
        if self.cloud_obj == None:
            self.assign_cloud_obj()
        if self.cloud_obj.type == 'aws':
            return self.cloud_obj.get_ip_for_network(self.name)
        if not ip_host:
            ip = self.addr_list.pop(0)
        else:
            if self.ip_addr_type == 'V4':
                _tmp = self.ip_addr.split('.')[:-1]
                _tmp.append(str(ip_host))
                ip = '.'.join(_tmp)
            else:
                ip = self.ip_addr + str(ip_host)
        return ip

    def release_ip_for_network(self, ip):
        
        if self.cloud_obj.type == 'aws':
            self.cloud_obj.release_ip_for_network(self.name, ip)
            return

        self.addr_list.append(ip)
        self.addr_list = self._sort_ip_address(self.addr_list)

    def _sort_ip_address(self, ipaddr_list):
        '''
        Helps to Sort the Both IPv4 and IPv6 Address
        But all IPs should be of same type(V4/V6)
        '''
        add_list = [ipaddress.ip_address(unicode(ip)) for ip in ipaddr_list]
        add_list.sort()
        ipaddr_list = [str(ip) for ip in add_list]
        return ipaddr_list


class NetworksQueue():

    def __init__(self):
        self.networks = []

    def isEmpty(self):
        return self.networks == []

    def enqueue(self, network):
        self.networks.insert(0,network)

    def dequeue(self):
        return self.networks.pop()

    def size(self):
        return len(self.networks)

    def get_ip_for_network(self, ip_host=None, vm=None, iter_count = 1):
        if iter_count > self.size():
            vm_name = vm.name if vm else ''
            fail('No Networks found for VM %s' % vm_name)
        net = self.dequeue()
        self.enqueue(net)
        use_net = True
        if vm:
            if net.network not in vm.networks['data']:
                use_net = False
        if use_net:
            ip = net.get_ip_for_network(ip_host=ip_host)
            return (ip, str(net))
        return self.get_ip_for_network(ip_host=ip_host, vm=vm, iter_count = iter_count + 1)

class CloudDict(dict):

    def __setitem__(self, cloud_name, cloud_obj):
        self.__dict__[cloud_name] = cloud_obj

    def __getitem__(self, cloud_name):
        if cloud_name not in self.__dict__ or self.__dict__[cloud_name] == None:
                from avi_objects.infra_utils import get_config
                config = get_config()
                mode = config.get_mode()
                cloud_name = mode.get('cloud')
                cloud_json = config.testbed[config.get_mode(key='site_name')].get_cloud_json(cloud_name=cloud_name)
                if cloud_json:
                    cloud_type = cloud_json['vtype']
                    if cloud_type == 'CLOUD_AWS':
                        configuration = cloud_json['aws_configuration']
                        self.__dict__[cloud_name] = Aws(configuration, cloud_name)
                    elif cloud_type == 'CLOUD_AZURE':
                        configuration = cloud_json['azure_configuration']
                        try:
                            configuration['cc_info'] = config.testbed[config.get_mode(key='site_name')].tb_json['preConfiguration']['CloudConnectorUser'][0]
                        except KeyError:
                            logger.fail('CloudConnectorUser information for azure cloud is missing from testbed file')
                        self.__dict__[cloud_name] = Azure(configuration, cloud_name)
                    elif cloud_type == 'CLOUD_VCENTER':
                        configuration = cloud_json['vcenter_configuration']
                        self.__dict__[cloud_name] = Vcenter(configuration, cloud_name)
                    elif cloud_type == 'CLOUD_OPENSTACK':
                        configuration = cloud_json['openstack_configuration']
                        self.__dict__[cloud_name] = OpenStack(configuration, cloud_name)
                    else:
                        self.__dict__[cloud_name] = Virtualization(cloud_type, cloud_name)
                else:
                    import avi_objects.rest as rest
                    cloud_type, configuration = rest.get_cloud_type(get_configuration = True)
                    if cloud_type == 'aws':
                        self.__dict__[cloud_name] = Aws(configuration, cloud_name)
                    elif cloud_type == 'gcp':
                        self.__dict__[cloud_name] = Gcp(configuration, cloud_name)
                    elif cloud_type == 'azure':
                        self.__dict__[cloud_name] = Azure(configuration, cloud_name)
                    elif cloud_type == 'vcenter':
                        self.__dict__[cloud_name] = Vcenter(configuration, cloud_name)
                    elif cloud_type == 'baremetal':
                        self.__dict__[cloud_name] = Baremetal(configuration, cloud_name)
                    elif cloud_type == 'openstack':
                        self.__dict__[cloud_name] = OpenStack(configuration, cloud_name)
                    else:
                        self.__dict__[cloud_name] = Virtualization(cloud_type, cloud_name)
        return self.__dict__[cloud_name]

    def __repr__(self):
        return repr(self.__dict__)
