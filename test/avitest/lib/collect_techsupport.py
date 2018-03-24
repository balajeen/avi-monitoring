import time
import subprocess
from fabric.tasks import execute
from fabric.api import sudo, env, get
import requests
from avi_objects.logger import logger
import avi_objects.rest as rest
import avi_objects.infra_utils as infra_utils
import avi_objects.logger_utils as logger_utils


env.user = 'admin'
env.password = 'avi123'


def scp_techsupport(dest_path):
    """

    :param dest_path:
    :return:
    """

    # Generate tech support
    cmd = '/opt/avi/python/lib/avi/tech_support/tech_support.sh --level debuglogs'
    sudo(cmd)
    src_path = '/opt/avi/tech_support/*.tar.gz'
    get(src_path, dest_path)


def collect_techsupport(c_list, dest_path, jobname, jobnum, techsupport_type='debuglogs', is_baremetal=False):
    """

    :param c_list:
    :param dest_path:
    :param jobname:
    :param jobnum:
    :param techsupport_type:
    :param is_baremetal:
    :return:
    """

    instance_type = 'Controllers' if techsupport_type=='debuglogs' else 'SEs'
    logger.info('Collecting tech-support from the %s' % instance_type)
    jobnum = str(jobnum)
    for c_ip in c_list:
        c_port = 443
        if ':' in c_ip:
            c_ip, c_port = c_ip.split(':')
        if dest_path is None:
            dest_path = '/mnt/files/robot-results/latest/' + jobname

        date_time = time.strftime("%Y%m%d-%H%M%S")
        folder_name = 'jobname_' + jobname + '_jobnum_' + jobnum
        subprocess.call('mkdir -p ' + dest_path + '/' + folder_name, shell=True)
        dest = dest_path + '/' + folder_name + '/techsupport_' + c_ip + '_'+ date_time + '.tar'

        subprocess.call('touch ' + dest, shell=True)
        subprocess.call('chmod 757 ' + dest, shell=True)
        logger.info('on controller %s and saving at %s \n' % (c_ip, dest))
        uri = 'techsupport/%s' % techsupport_type
        logger.info('URI: %s' % uri)
        try:
            status_code, rsp = rest.get(uri)
        except:
            infra_utils.switch_mode(user='admin', password='admin')
            status_code, rsp = rest.get(uri)
        infra_utils.switch_mode(user='admin', password='avi123')
        controller_error = []
        if rsp:
            with open(dest, 'wb') as f:
                for chunk in rsp.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
                        f.flush()
        else:
            logger.info('Tech support collection failed - status %s' % status_code)
            if is_baremetal:
                c_ip = c_ip + ':5098'
            try:
                execute(scp_techsupport, dest_path=dest, hosts=[c_ip])
            except:
                try:
                    env.password = 'admin'
                    execute(scp_techsupport, dest_path=dest, hosts=[c_ip])
                except Exception as e:
                    msg_error = 'Tech support collection failed on node %s - error %s \n' % (c_ip, e)
                    logger.info(msg_error)
                    controller_error.append(msg_error)
        if controller_error:
            logger_utils.fail(controller_error)
        logger.info('\n    DONE \n')

def request_techsupport(c_list, dest_path, version='18.1.1', is_baremetal=False):

    logger.info('Collecting Debuglogs tech-support')
    for c_ip in c_list:
        c_port = 443
        if ':' in c_ip:
            c_ip, c_port = c_ip.split(':')

        date_time = time.strftime("%Y%m%d-%H%M%S")
        dest = dest_path + '/techsupport_' + c_ip + '_'+ date_time + '.tar'
        logger.info('Techsupport for %s will be saved at: %s' % (c_ip, dest))
        subprocess.call('touch ' + dest, shell=True)
        subprocess.call('chmod 757 ' + dest, shell=True)
        uri = 'https://{ip}/api/techsupport/debuglogs'.format(ip=c_ip)
        header = {}
        header["X-Avi-Version"] = version
        resp = requests.get(uri, auth=('admin', 'avi123'), verify=False, headers=header)
        if resp.status_code == 200:
            with open(dest, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
                        f.flush()
        else:
            logger.info('Tech support collection failed - status %s' % resp.status_code)
        logger.info('\n DONE \n')

