import argparse
import sys
import os
import subprocess
import simplejson
from avi_objects.logger import logger
from avi_objects.logger_utils import abort,fail, asleep, aretry, error
from avi_objects.cloud_sdk.aws import Aws





def parse_arguments():
    parser = argparse.ArgumentParser(
        description='Cleanup AWS environment from testbed file')
    parser.add_argument(
        '-n',
        '--testbed-name',
        help='testbed config file name', default='')
    return parser.parse_args()

def main():
    args = parse_arguments()
    testbed_path = args.testbed_name
    testbed_abspath, testbed_dir, testbed_name = __testbed_find(testbed_path)
    logger.info("Cleanup Processing for testbed %s" %testbed_name)
    try:
        testbed_data = open(testbed_abspath).read()
        tb_json = simplejson.loads(testbed_data)
        logger.info('test_bed loaded')
    except Exception as e:
        abort('Json load failed for testbed file %s with Exception %s' % (testbed_abspath,e))

    aws_clouds = get_aws_clouds_tb_json(tb_json)
    if not aws_clouds:
        abort("No AWS Clouds Found. Aborting")

    for aws_cloud in aws_clouds:
        cloud_name = aws_cloud.get('name')
        sdk_conn = Aws(cloud_configuration_json= aws_cloud.get('aws_configuration'))
        logger.info("AWS SDK connection successfull for cloud %s" %cloud_name)
        filters = {'tag-key':'avitest_tb_tag', 'tag-value': testbed_name}
        terminate_instances(sdk_conn, filters)
        asleep(msg="Settling with Instances delete" , delay = 10)
        delete_images(sdk_conn, filters)
        delete_network_interfaces(sdk_conn, filters)
        asleep(msg="Settling with Network Interfaces Deletion" , delay = 30)
        delete_security_groups(sdk_conn, filters)
        sdk_conn.disconnect()

    clean_secondary_ips_on_client_server(tb_json)


def clean_secondary_ips_on_client_server(tb_json):
    client_server_vms = [vm_json for vm_json in tb_json.get('Vm') \
                if vm_json.get('type') in ['client', 'server']]
    for vms in client_server_vms:
        cloud_name = vms.get('cloud_name', 'Default-Cloud') 
        try:
            cloud_json = [cloud_json for cloud_json in tb_json.get('Cloud') \
                    if cloud_json.get('name') == cloud_name][0]
        except TypeError:
            logger.info('Must be no-access cloud?')
        except IndexError:
            logger.info("Can't find vm cloud under Clouds for %s" %vms['name'])

        if not cloud_json:
            cloud_json = None #Setting it back to None as it must have become an empty list
            try:
                # Check in vm clouds
                cloud_json = [cloud_json for cloud_json in tb_json.get('VmCloud') \
                    if cloud_json.get('name') == cloud_name][0]
            except TypeError:
                logger.info('no VmCloud defined in the testbed')
        
        if not cloud_json:
            logger.info('cloud_json None, no access cloud?')
            continue
        sdk_conn = None

        try:
            if cloud_json.get('vtype') == 'CLOUD_AWS':
                sdk_conn = Aws(cloud_configuration_json= cloud_json.get('aws_configuration'))
                logger.info("AWS SDK connection successfull for cloud %s" %cloud_json.get('name'))
                logger.info("Finding instance for %s " %vms['name'])
                instance = sdk_conn._Aws__get_instance(vms['name'])
                for interface in instance.interfaces:
                    sec_ips = [ ip.private_ip_address for ip in interface.private_ip_addresses if ip.primary == False ]
                    logger.info('Unassigning secondary IPs : %s from interface %s' % (sec_ips, interface.id))
                    if sec_ips:
                        interface.connection.unassign_private_ip_addresses(
                                    network_interface_id=interface.id, private_ip_addresses=sec_ips)
        except Exception as e:
            error("clean_secondary_ips_on_client_server failed due to %s" %e)
    sdk_conn.disconnect()


def terminate_instances(sdk_conn, filters):

    logger.info("Terminate instances")
    reservation_list = sdk_conn.ec2.get_all_instances(filters=filters)
    for reservation in reservation_list:
        instance_list = reservation.instances
        for instance in instance_list:
            logger.info("Deleting Instance %s " %instance.id)
            @aretry(retry=5, delay=5)
            def ins_ter_retry():
                try:
                    instance.terminate()
                except Exception as e:
                    error("Delete instance failed with exception %s " %e)
            ins_ter_retry()

def delete_images(sdk_conn, filters):

    logger.info("Deleting Images")
    image_list = sdk_conn.ec2.get_all_images(filters=filters)
    for image in image_list:
        logger.info("Deleting Image %s " %image.name)
        @aretry(retry=5, delay=5)
        def img_del_retry():
            try:
                image.deregister(delete_snapshot=True)
            except Exception as e:
                error("Delete image failed with exception %s " %e)
        img_del_retry()
        

def delete_security_groups(sdk_conn, filters):
    logger.info("Deleting Security Groups")
    sg_group_list = sdk_conn.vpc.get_all_security_groups(filters=filters)
    for sg_group in sg_group_list:
        logger.info("Deleting Security Group  %s " %sg_group.name)
        @aretry(retry=5, delay=5)
        def sg_del_retry():
            try:
                sdk_conn.vpc.delete_security_group(group_id=sg_group.id)
            except Exception as e:
                error("Delete security group failed with exception %s " %e)
        sg_del_retry()

def delete_network_interfaces(sdk_conn, filters):
    logger.info("Deleting Network Interfaces")
    ni_list = sdk_conn.vpc.get_all_network_interfaces(filters=filters)
    for ni in ni_list:
        if str(ni.status) == 'available':
            logger.info("Deleting Network Interface %s " %ni.id)
            @aretry(retry=5, delay=5)
            def ni_del_retry():
                try:
                    sdk_conn.vpc.delete_network_interface(ni.id)
                except Exception as e:
                    error("Delete Network Interface failed with exception %s " %e)
            ni_del_retry()
def get_aws_clouds_tb_json(tb_json):

    cloud_json = None
    try:
        cloud_json = [cloud_json for cloud_json in tb_json.get('Cloud') \
                        if cloud_json.get('vtype') == 'CLOUD_AWS']
    except TypeError:
        logger.info('Must be no-access cloud?')

    return cloud_json

def __testbed_find(testbed):

    if not os.path.isfile(testbed):
        abort('Could not locate Test Bed file %s' %testbed)
    testbed_abspath = os.path.abspath(testbed)
    testbed_dir, testbed_name = os.path.split(testbed_abspath)
    testbed_name = os.path.splitext(testbed_name)[0]
    sys.path.append(testbed_dir)
    logger.info(msg='TestBed File name is %s' %testbed_name)
    logger.info(msg='TestBed absolute path is %s' %testbed_abspath)

    return (testbed_abspath, testbed_dir, testbed_name)

if __name__ == '__main__':
    main()

