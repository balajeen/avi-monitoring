from avi_objects.logger import logger
import avi_objects.logger_utils as logger_utils
import boto.ec2
import boto.vpc
import boto.route53
import time

SEC_GROUP = {
    "client": ['static-vpc-sg-private'],
    "server": ['static-vpc-sg-private'],
    "se": ['static-vpc-sg-private'],
    "controller": ['static-vpc-sg-private']
}

INSTANCE_SIZE = {
    "client": "c4.xlarge",
    "server": "c4.xlarge",
    "se": "c4.xlarge",
    "controller": "c4.2xlarge"
}

class Aws(object):
    """ Function for AWS communication """

    def __init__(self, cloud_configuration_json, vm_json=None):
        self.configuration = cloud_configuration_json
        self.vm_json =vm_json
        self.ec2 = None
        self.vpc = None
        self.r53 = None
        self.vpc_id = None
        self.sdk_connect()

    def sdk_connect(self):
        region = self.configuration.get('region')
        access_key = self.configuration.get('access_key_id')
        secret_key = self.configuration.get('secret_access_key')
        self.vpc_id = self.configuration.get('vpc_id')

        self.ec2 = boto.ec2.connect_to_region(
                    region, aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key)
        self.vpc = boto.vpc.connect_to_region(
                    region, aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key)
        self.r53 = boto.route53.connect_to_region(
                    region, aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key)

    def _get_instance_id(self, instance_name, **kwargs):
        """ Return instance Id from name """
        instance = self._get_instance(instance_name, **kwargs)
        return instance.id

    def _get_instance_and_id(self, instance_name, **kwargs):
        """ Return instance Id from name """
        instance = self._get_instance(instance_name, **kwargs)
        return (instance, instance.id)

    def _get_instance(self, instance_name, **kwargs):
        """ Return instance Id from name """
        state = kwargs.get('state', None)
        logger.info('Fetching list of reservations from AWS')
        sfilter = {'vpc-id': self.vpc_id}
        reservations = self.ec2.get_all_instances(filters=sfilter)
        for reservation in reservations:
            for instance in reservation.instances:
                tags = instance.tags
                if 'Name' not in tags.keys():
                    continue

                if tags['Name'].lower() == instance_name.lower():
                    logger.info('Found instance ID [%s]: %s' % (
                        instance_name, instance.id))
                    if state is not None:
                        if state.lower() == instance.update():
                            return instance
                        else:
                            logger.info(
                                'Instance %s not in expected state: %s, \
                                    current state: %s' % (
                                    instance_name, state, instance.update()))
                    else:
                        return instance

    def get_subnet_id(self, subnet_name):
        """ Return subnet id from name """
        logger.info('Fetching list of subnets from VPC')
        sfilter = {'vpc-id': self.vpc_id, 'state': 'available'}
        subnets = self.vpc.get_all_subnets(filters=sfilter)
        for subnet in subnets:
            if 'Name' in subnet.tags.keys() and \
                    subnet.tags['Name'] == subnet_name:
                return subnet.id
        raise RuntimeError('Not able to find subnet id for %s' % subnet_name)

    def get_vm_ip_for_name(self):
        """ Return Ip Address given name """
        vm_name = self.vm_json.get('name')
        management = self.vm_json.get('networks').get('mgmt')

        instance = self._get_instance(vm_name)
        subnet = self.get_subnet_id(subnet_name=management)
        for interface in instance.interfaces:
            if interface.subnet_id == subnet:
                return interface.private_ip_address
        raise RuntimeError('%s: No IP found for eth0' % vm_name)

    def _get_ami_id(self, name):
        """Return AMI id given name"""
        images = self.ec2.get_all_images(filters={'name': name})
        if not images:
            logger_utils.fail('Cannot get image id with name %s' % name)
        return images[0].id

    def _get_sec_grp_ids(self, sec_groups):
        """ Return list of security group Ids """

        sec_grp_ids = []
        all_grps = self.ec2.get_all_security_groups()
        for sec_grp in all_grps:
            if sec_grp.name in sec_groups:
                sec_grp_ids.append(sec_grp.id)
        if len(sec_grp_ids) != len(sec_groups):
            logger_utils.fail('Not all sec groups found')
        return sec_grp_ids

    def _get_subnet(self, subnet_name):
        """ Return subnet id from name """
        logger.info('Fetching list of subnets from VPC')
        subnets = self.vpc.get_all_subnets()
        for subnet in subnets:
            if 'Name' in subnet.tags.keys() and \
                    subnet.tags['Name'] == subnet_name:
                return subnet
        logger_utils.fail('Not able to find subnet id: %s' % subnet_name)

    def _set_mgmt_interfaces(self, networks, offset, sec_grps):
        """ Return a NetworkInterfaceCollection object for an instance """
        interfaces = []
        logger.debug('networks: %s' % networks)
        device_index = 0
        vm_ip = self.vm_json.get('ip', None)
        for key, network in networks.iteritems():
            key_var = '${' + str(key) + '}'
            subnet = self._get_subnet(network)
            if key == 'management' or 'mgmt':
                logger.debug(
                    'Adding management network on device: %s' % device_index)
                # Assumption: Everything is DHCP in management network.
                logger.debug('subnet: %s, subnet.id: %s' % (subnet, subnet.id))
                if vm_ip:
                    interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(
                        subnet_id=subnet.id,
                        groups=sec_grps,
                        device_index=device_index,
                        private_ip_address=vm_ip)
                else:
                    interface = boto.ec2.networkinterface.NetworkInterfaceSpecification(
                        subnet_id=subnet.id,
                        groups=sec_grps,
                        description='Mgmt',
                        device_index=device_index)
                interfaces.append(interface)

        interfaces = boto.ec2.networkinterface.NetworkInterfaceCollection(
            *interfaces)
        return interfaces

    def create_instance(self, wait=True, **kwargs):
        """ Create an instance from AMI """
        instance_type = self.vm_json.get('type')
        networks = self.vm_json.get('networks')
        offset = kwargs.pop('offset', 10)
        version_tag = kwargs.pop('version_tag', None)
        iam_role = None
        if version_tag is None and instance_type in ['se', 'controller']:
            logger_utils.fail(
                'Please specify version tag of AMI for creating SE/Controller')

        if instance_type == 'controller':
            ami_name = 'Avi-Controller-%s' % version_tag
            iam_role = kwargs.get('iam_role', None)
        elif instance_type == 'se':
            ami_name = 'Avi-SE-%s' % version_tag
        elif instance_type == 'client':
            ami_name = 'Jenkins Client'
        elif instance_type == 'server':
            ami_name = 'jenkins-server'

        image_id = self._get_ami_id(ami_name)
        sec_grps = self._get_sec_grp_ids(SEC_GROUP[instance_type])
        interfaces = self._set_mgmt_interfaces(networks, offset, sec_grps)

        try:
            # http://boto.readthedocs.org/en/latest/ref/ec2.html#boto.ec2.connection.EC2Connection.run_instances
            self.reservation = self.ec2.run_instances(
                #placement=REGION + 'a',
                image_id=image_id,
                instance_type=INSTANCE_SIZE[instance_type],
                network_interfaces=interfaces,
                instance_profile_name=iam_role)#,
                #**kwargs)
        except Exception as e:
            logger_utils.fail(e)
        logger.info('Created reservation for instance: %s' % self.reservation)
        if wait:
            instance = self.reservation.instances[0]
            logger_utils.asleep(delay=10)
            logger.info('Wait until instance %s goes to running state' %
                        instance.id)
            ip_addr = self._wait_until_instance_in_state(instance)
            try:
                vm_name = self.vm_json.get('name')
                instance.add_tag('Name', vm_name)
                instance.add_tag('Owner', vm_name)
                wait_until_vm_ready([ip_addr])
                logger.debug('Set data interfaces for instance: %s' % instance.id)
                #offset = self.__set_data_interfaces(
                    #instance, vm, networks, offset, sec_grps)
            except Exception as e:
                logger_utils.fail(e)
            return instance, offset

    def wait_until_vm_is_up(self):
        instance = self.reservation.instances[0]
        logger_utils.asleep(delay=10)
        logger.info('Wait until instance %s goes to running state' %
                    instance.id)
        ip_addr = self._wait_until_instance_in_state(instance)
        try:
            vm_name = self.vm_json.get('name')
            instance.add_tag('Name', vm_name)
            instance.add_tag('Owner', vm_name)
            wait_until_vm_ready([ip_addr])
            logger.debug('Set data interfaces for instance: %s' % instance.id)
            #offset = self.__set_data_interfaces(
                #instance, vm, networks, offset, sec_grps)
        except Exception as e:
            logger_utils.fail(e)
        return instance

    def disconnect(self):
        # TODO
        pass

    def _get_zone(self):
        for i in self.r53.get_zones():
            if i.name == JENKINS_NS % self.domain_name and i.config.PrivateZone == 'true':
                self.r53_zone = i
                break
        return

    def _wait_until_instance_in_state(self, instance, mgmt_network='2A-nw-1', state='running'):
        """ Wait until EC2 instance is state """
        retry = 100
        curr_state = instance.update()
        logger.info('Instance=%s, curr_state=%s, req_state=%s' % (instance, curr_state, state))
        while curr_state != state:
            retry = retry - 1
            logger_utils.asleep(delay=5)
            logger.info('Retry=%d curr_state=%s, req_state=%s', 100 - retry, curr_state, state)
            curr_state = instance.update()
            if retry < 1:
                logger_utils.fail(
                     '%s is not in %s state, current state is %s' % (instance.tags['Name'], state, instance.update()))
        subnet = self._get_subnet(mgmt_network)
        for interface in instance.interfaces:
            if interface.subnet_id == subnet.id:
                return interface.private_ip_address

    def poweroff(self):
        """ Power off VM on EC2 """

        instance_name = self.vm_json.get('name')
        (instance, instance_id) = self.__get_instance_and_id(instance_name, state='running')
        logger.info('Powering off instance: %s:%s' % (instance_name, instance))
        # This will request a graceful stop of each of the specified
        # instances. If you wish to request the equivalent of unplugging your
        # instance(s), simply add force=True keyword argument to the call above.
        try:
            self.ec2.stop_instances(instance_ids=[instance_id])
        except Exception as e:
            raise RuntimeError("Failed stopping instance:%s, err=%s", instance_id, str(e))
        self._wait_until_instance_in_state(instance, 'stopped')
        logger.info('Powered Off instance: %s' % instance_name)

    def poweron(self):

        (instance, instance_id) = self.__get_instance_and_id(instance_name, state='stopped')
        logger.info('Powering On instance: %s' % instance_name)
        try:
            self.ec2.start_instances(instance_ids=[instance_id])
        except Exception as e:
            raise RuntimeError("Failed starting instance:%s, err=%s", instance_id, str(e))
        self._wait_until_instance_in_state(instance)
        logger.info('Powered On instance: %s' % instance_name)

    def restart(self, wait_time=0):

        '''
        Restart the VM on EC2
        '''
        instance_name = self.vm_json.get('name')
        instance_id = self._get_instance_id(instance_name)
        if instance_id:
            logger.info('Restarting instance: %s' % instance_name)
            self.poweroff()
            time.sleep(wait_time)
            self.poweron()
            logger.info('Restarted instance: %s' % instance_name)
            return True
        else:
            logger.error('Could not find VM %s after %d retries' %
                            (instance_name, count))

    def create_snapshot(self, volume, **kwargs):
        """ Create a snapshot """
        pass

    def register_snapshot(self, snapshot_name, ami_name):
        """ Register a snapshot to create an AMI out of it """
        pass

    def delete_instance(self):
        instance_name = self.vm_json.get('name')
        logger.trace("deleting instance %s"%instance_name)
        self.terminate_instance(instance_name)

    def terminate_instance(self, instance_name):
        """ Terminate instance on AWS """
        self.sdk_connect()
        instance_id = self._get_instance_id(instance_name)
        logger.info('Terminate instance: %s', instance_name)
        self.ec2.terminate_instances(instance_ids=[instance_id])
        # TODO: Check instance state as Terminate and should release IP
        logger_utils.asleep('Sleeping for instance to terminate and release IP', delay=60, period=20)

    def delete_vms_by_prefix(self, prefix):
        logger.info('Fetching list of reservations from AWS')
        sfilter = {'vpc-id': self.vpc_id}
        reservations = self.ec2.get_all_instances(filters=sfilter)
        instances = []
        for reservation in reservations:
            for instance in reservation.instances:
                tags = instance.tags
                if 'Name' not in tags.keys():
                    continue

                if prefix in tags['Name'].lower():
                    logger.info('Found instance ID [%s]: %s' % (
                        tags['Name'], instance.id))
                    instances.append(instance.id)
        if instances:
            self.ec2.terminate_instances(instance_ids=instances)
        else:
            logger.info("No vms found with prefix %s" % prefix)

    def _get_rrname(self, stip):
        stip = stip.replace('.', '-')
        tmp = JENKINS_RRNAME % (self.tb_name, stip, self.domain_name)
        return tmp

def wait_until_vm_ready(host, retry=15):
    import socket
    from time import sleep
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    waiting = 0
    ready = False
    for i in range(0, retry):
        try:
            s.connect((host[0],22))
            logger.info('VM %s ready' % host)
        except:
            waiting = waiting + 20
            # logger.info('Waiting for %s seconds' % waiting)
            sleep(20)
            continue
        ready = True
        break
    return ready

