import re
import ipaddress
import copy

from logger_utils import fail
from logger import logger
from avi_config import AviConfig
from rest import get


aws_sub_ip = None
aws_port = 0

class PoolModel(object):

    def __init__(self, json_data=None, pool_name=None, **kwargs):
        self.servers = {}
        if json_data is not None:
            self.json_data = json_data
        elif pool_name is not None:
            _, self.json_data = get('pool', name=pool_name)
        else:
            fail("Either json or pool name should be provided")
        config_vars = kwargs.get('config_vars', {})
        self.parse_json(config_vars=config_vars)
        ret_json = parse_json_config_vars(self.json_data, config_vars)
        self.json_data = ret_json

    def __repr__(self):
        return "%r(%r)" % (self.__class__, self.__dict__)

    def parse_json(self, **kwargs):
        servers = self.json_data.get('servers',[])
        for server in servers:
            s = ServerModel(server, **kwargs)
            self.addServer(s)

    def get_json(self):
        # Take pool Pb and iterate over server, adding their pb
        # TODO: persistence fixup when changing from one type to the next
        servers = self.json_data.get('servers',[])
        if not servers:
            return self.json_data
        self.json_data.pop('servers')
        self.json_data['servers'] = []
        for k, v in self.servers.items():
            self.json_data['servers'].append(v.json_data)
        return self.json_data

    def findServer(self, handle):
        if handle not in self.servers:
            fail('Server "%s" not found in pool' % (handle))
        return self.servers[handle]

    def addServer(self, server):
        if server.handle in self.servers:
            fail('Server "%s" already in pool' % (server.handle))
        self.servers[server.handle] = server
        server.pool(self)
        return server

    def newServer(self, handle, server_json, **kwargs):
        if handle in self.servers:
            fail('Server "%s" already in pool' % (handle))
        kwargs['handle'] = handle
        server = ServerModel(server_json, **kwargs)
        self.servers[server.handle] = copy.deepcopy(server)
        server.pool(self)
        return server

    def removeServer(self, handle):
        if handle not in self.servers:
            fail('Server "%s" not found in pool' % (handle))
        else:
            # TODO: This method should be called delete server,
            # a new method called detach server should do this check
            # if not self.servers[handle].get_pb().port:
            #     raise RuntimeError('Attempting to remove a server from pool without a port assigned')
            # else:
            server = ServerModel.get_server(handle)
            server.pool(None)
            self.servers.pop(handle)
            server.remove_handle()

    def name(self):
        return self.json_data['name']

    def get_all_servers(self):
        return self.servers


class ServerModel(object):

    handle_dict = {}

    def __init__(self, json_data, pool = None, **kwargs):
        self.num_ip =  kwargs.get('num_ip')
        self.json_data = json_data
        self._pool = pool
        self.net = None
        self.net_name = None
        config = AviConfig.get_instance()
        mode = config.get_mode()
        self.site_name = mode['site_name']
        config_vars = kwargs.get('config_vars', {})
        self.parse_json()
        ret_json = parse_json_config_vars(self.json_data, config_vars)
        self.json_data = ret_json
        self.handle = self.json_data['handle'] if 'handle' in self.json_data else None
        self.add_handle()
        # Lazy load vm when vm() is called
        self._vm = None

    def __repr__(self):
        return "%r(%r)" % (self.__class__, self.__dict__)

    @staticmethod
    def get_server(handle):
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        try:
            server = ServerModel.handle_dict[context_key][handle]
            return server
        except KeyError:
            fail('Handle %s not found' % (handle))

    @staticmethod
    def clear_servers():
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        ServerModel.handle_dict[context_key] = {}

    def updateServer(self, **kwargs):
        parseKwargsToPb(self.pb, kwargs, self.non_pb_kwargs)

    def refreshBackend(self):
        vm = self.vm()
        app_type = self.app_type()
        if app_type in ['httptest', 'policytest']:
            vm.reload_server_context_nginx()

    def pushBackendConfigs(self, restart=False):
        app_type = self.app_type()
        if app_type in ['ixia', 'shenick']:
            logger.info('app_type is %s, return' % app_type)
            return
        vm = self.vm()
        if app_type == 'redmine_upstream':
            vm.create_server_context_ip_addrs()
            vm.configure_redmine_upstream()
        elif app_type == 'redmine':
            vm.create_server_context_ip_addrs()
            vm.reload_server_context_nginx()
        elif app_type in ['tcptest', 'dnsapp']:
            vm.create_server_context_ip_addrs()
        elif app_type == 'scapytest':
            vm.create_server_context_ip_addrs()
        elif app_type == 'contenttest':
            vm.create_server_context_ip_addrs()
            vm.reload_server_context_nginx()
        elif app_type == 'nodejs':
            vm.create_server_context_ip_addrs()
            vm.start_node(self.ip(), self.port())
        elif app_type == 'nodejs_ws':
            vm.create_server_context_ip_addrs()
            vm.start_node(self.ip(), self.port(), file_name='start_node_ws.sh')
        elif app_type == 'python':
            vm.create_server_context_ip_addrs()
            vm.start_python()
        elif app_type == 'autobahntest':
            vm.create_server_context_ip_addrs()
            vm.start_go_server(self.ip(), self.port(), server_location='/root/goServer')
            if self.pb.autobahn_nginx == 'true':
                vm.reload_server_context_nginx(True)
        elif app_type in ['httptest', 'policytest', 'sslpolicyupdatetest', 'reselecttest']:
            vm.create_server_context_ip_addrs()
            vm.reload_server_context_nginx(restart)

    def createAppServers(self):
        logger.info('app_type %s' % self.app_type())
        if self.app_type() in ['ixia', 'shenick']:
            logger.info('app_type is ixia, return')
            return
        vm = self.vm()
        app_type = self.app_type()
        if len(app_type) > 0:
            if vm:
                vm.create_server_context(self)

    def deleteBackend(self, cleanup_backend=True):
        # TODO(joec): Move cleanup_backend into server model
        # similar to redmine upstream_ip/port
        self.vm().delete_server_context(self.handle, cleanup_backend)
        logger.debug('deleteBackend %s' %cleanup_backend)
        if cleanup_backend:
            app_type = self.app_type()
            if app_type in ['httptest', 'policytest', 'sslpolicyupdatetest', 'reselecttest']:
                self.vm().reload_server_context_nginx()
            elif app_type == 'nodejs' or app_type == 'nodejs_ws':
                self.vm().execute_command('pkill node')
            elif app_type == 'autobahntest':
                logger.debug('deleteBackend %s' % app_type)
                out = self.vm().execute_command('pkill -9 server')

    def pool(self, pool=None):
        if pool:
            self._pool = pool
        else:
            return self._pool

    def ssl_enabled(self):
        if self.pool().json_data.get('ssl_profile_uuid'):
            return True
        else:
            return False

    def get_ssl_cert_filename(self):
        if 'ssl_cert_filename' in self.json_data:
            return self.json_data['ssl_cert_filename']
        else:
            return self.pool().get_ssl_cert_filename()

    def get_ssl_privkey_filename(self):
        if 'ssl_privkey_filename' in self.json_data:
            return self.json_data['ssl_privkey_filename']
        else:
            return self.pool().get_ssl_privkey_filename()

    def get_ssl_validate_client_cert(self):
        if 'ssl_validate_client_cert' in self.json_data:
            return self.json_data['ssl_validate_client_cert']
        else:
            return self.pool().get_ssl_validate_client_cert()

    def get_pki_validate_client_cert(self):
        if 'pki_validate_client_cert' in self.json_data:
            return self.json_data['pki_validate_client_cert']
        else:
            return self.pool().get_pki_validate_client_cert()

    def ip(self):
        return self.json_data['ip']['addr']

    def hostname(self):
        return self.json_data['nat_hostname']

    def vm(self):
        config = AviConfig.get_instance()
        if not self._vm:
            vms = config.get_vm_of_type('server', network = self.net)
            # TODO: Look at vm load and distribute accordingly
            if len(vms) > 0:
                self._vm = vms[0]
            else:
                fail("None of the servers found in network %s" %self.net)
        return self._vm

    def port(self):
        pool_obj = self.pool()
        pool_json = pool_obj.get_json()
        if pool_json.get('use_service_port', False):
            pass
            # TBD: get vs service ports
            #vs_name = pool_obj.vs()
            #if vs_name:
            #    ports = get_vs_listener_port(vs_name)
            #    if len(ports) == 1:
            #        return ports[0]
            #    return ports
        if self.json_data.get('port'):
            return self.json_data.get('port')
        else:
            if pool_obj:
                return pool_json.get('default_server_port')
            else:
                fail('Server is not in a pool and has no port')

    def network(self):
        return self.json_data['network']

    def nw_uuid(self):
        return self.json_data['nw_uuid']

    def app_type(self):
        return self.json_data['app_type']

    def get_json(self):
        return self.json_data

    def add_handle(self):
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        if not ServerModel.handle_dict.get(context_key):
            ServerModel.handle_dict[context_key] = {}
        if self.handle in ServerModel.handle_dict[context_key]:
            fail('Handle %s already in use' % (self.handle))
        else:
            ServerModel.handle_dict[context_key][self.handle] = self

    def remove_handle(self):
        config = AviConfig.get_instance()
        context_key = config.get_context_key()
        try:
            ServerModel.handle_dict[context_key].pop(self.handle)
        except KeyError:
            fail('Server handle %s was not being tracked' % (self.handle))

    def reset_aws_sub_ip_port(self):
        global aws_port
        global aws_sub_ip
        aws_port = None
        aws_sub_ip = None


    def parse_json(self, vm_uuid=None):
        json_data = self.json_data
        config = AviConfig.get_instance()
        logger.info('parsing pool: %s' %str(json_data))
        m = re.search('^\${(([a-zA-Z0-9]+)_(.+))}', json_data['ip']['addr'])
        if m:
            self.net = m.group(2)
            keyword = m.group(3)
            foundIp = config.testbed[self.site_name].ip_dict.get(m.group(1))
            if foundIp:
                json_data['ip']['addr'] = foundIp
            else:
                ip_host = keyword if keyword.isdigit() else None
                m_sub = re.search('([a-zA-Z]+)(\d+)', self.net)
                if m_sub:
                    json_data['ip']['addr'] = \
                        config.testbed[self.site_name].networks[self.net].get_ip_for_network(ip_host=ip_host)
                else:
                    ip, net = \
                        config.testbed[self.site_name].networks_queue.get_ip_for_network(ip_host=ip_host)
                    json_data['ip']['addr'] = ip
                    self.net = str(net)
                config.testbed[self.site_name].ip_dict[m.group(1)] = json_data['ip']['addr']
            self.net_name = config.testbed[self.site_name].networks[self.net].name
        m = re.search('^\$\{([a-zA-Z]+\w+)}$', json_data['ip']['addr'])
        if m:
            self.net = m.group(1)
            m_sub = re.search('([a-zA-Z]+)(\d+)', self.net)
            if m_sub:
                json_data['ip']['addr'] = config.testbed[self.site_name].networks[self.net].get_ip_for_network()
            else:
                ip, net = config.testbed[self.site_name].networks_queue.get_ip_for_network()
                json_data['ip']['addr'] = ip
                self.net = str(net)
            self.net_name = config.testbed[self.site_name].networks[self.net].name

        # Set vm_uuid if there in test conf file
        #logger.info('vcenter access: %s' %self.cloud_access_pb.type)
        #if vm_uuid is not None and len(vm_uuid) > 0 and ('no_access' not in self.cloud_access_pb.type):
        #    pb.vm_uuid = vm_uuid
        #    vm = self.vcenter.get_vm_by_id(pb.vm_uuid)
        #    logger.info('bugger: vcenter vm %s pb_obj %s %s' %(vm.name,str(pb),pb.vm_uuid))
        #    self.vm_uuid = vm.name
        #    pb.vm_uuid = vm.name
        #    #pb.hostname = vm.name
        #    pb.nw_uuid = self.net
        # else:
        #    pb.hostname = pb.ip.addr
        if type(ipaddress.ip_address(unicode(json_data['ip']['addr']))) == ipaddress.IPv6Address:
            json_data['ip']['type'] = 'V6'
        else:
            json_data['ip']['type'] = 'V4'


    def parse_redmine(self):
        ip = self.non_pb_kwargs.get('upstream_ip')
        port = self.non_pb_kwargs.get('upstream_port')
        if ip and port:
            self.upstream_ip = ip
            self.upstream_port = port
            del self.non_pb_kwargs['upstream_ip']
            del self.non_pb_kwargs['upstream_port']
        else:
            raise ValueError(
                'Upstream ip and port must be set for redmine app type')


def parse_json_config_vars(json_data, config_vars={}):
    if isinstance(json_data, dict):
        ret_data = {}
        for key, value in json_data.iteritems():
            ret_val = parse_json_config_vars(value, config_vars=config_vars)
            ret_data[key] = ret_val

    elif isinstance(json_data, list):
        ret_data = []
        for value in json_data:
            ret_data.append(parse_json_config_vars(value, config_vars=config_vars))
    else:
        ret_data = json_data
        if not any(isinstance(ret_data, tp) for tp in [str, unicode]):
            return ret_data
        config = AviConfig.get_instance()
        mode = config.get_mode()
        site_name = mode['site_name']
        ret_data = json_data
        testbed_vars = copy.deepcopy(config.get_testbed().testbed_vars)
        testbed_vars.update(config_vars)
        m = re.search('^([\s\S]*)\${(([a-zA-Z0-9]+)_(.+))}([\s\S]*)', ret_data)
        if m:
            if m.group(2) in testbed_vars:
                ret_data = testbed_vars[m.group(2)]
                return m.group(1) + ret_data + m.group(5)
        m = re.search('^([\s\S]*)\$\{([a-zA-Z]+\w+)}([\s\S]*)', ret_data)
        if m:
            if m.group(2) in testbed_vars:
                ret_data = testbed_vars[m.group(2)]
                return m.group(1) + ret_data + m.group(3)
    return ret_data
