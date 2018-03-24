import argparse
import copy
import google.protobuf
import google.protobuf.json_format
import json
import os
import re
from requests.exceptions import RequestException
import sys
from avi.protobuf import options_pb2
from avi.protobuf.robot_topology_pb2 import Topology
import google.protobuf.text_format
from avi.sdk import avi_api
from bin.cli.avi_cli.common import pb_ordered

order = pb_ordered.pb_ordered[:]
order.append('User')
'''
order = [
        "SSLKeyAndCertificateImport",
        "ControllerLicense",
        "SeProperties",
        "UserActivity",
        "SecureChannelToken",
        "UserAccountProfile",
        "SecureChannelMapping",
        "VIMgrIPSubnetRuntime",
        "Tenant",
        "ControllerProperties",
        "CloudProperties",
        "SecureChannelAvailableLocalIPs",
        "Role",
        "AuthProfile",
        "CloudConnectorUser",
        "CloudRuntime",
        "VIPGNameInfo",
        "SnmpTrapProfile",
        "HardwareSecurityModuleGroup",
        "VIDCInfo",
        "Gslb",
        "SCVsStateInfo",
        "GslbGeoDbProfile",
        "SCPoolServerStateInfo",
        "ApplicationPersistenceProfile",
        "GslbApplicationPersistenceProfile",
        "NetworkRuntime",
        "DebugController",
        "AutoScaleLaunchConfig",
        "CertificateManagementProfile",
        "LogControllerMapping",
        "Webhook",
        "AnalyticsProfile",
        "VIMgrControllerRuntime",
        "WafProfile",
        "WafPolicy",
        "StringGroup",
        "Cluster",
        "DebugServiceEngine",
        "PKIProfile",
        "JobEntry",
        "MicroService",
        "APICLifsRuntime",
        "AlertSyslogConfig",
        "SSLProfile",
        "CustomIpamDnsProfile",
        "AlertObjectList",
        "AlertScriptConfig",
        "NetworkProfile",
        "IpAddrGroup",
        "BackupConfiguration",
        "SSLKeyAndCertificate",
        "MicroServiceGroup",
        "IpamDnsProviderProfile",
        "DnsPolicy",
        "ApplicationProfile",
        "Scheduler",
        "SystemConfiguration",
        "GslbHealthMonitor",
        "HealthMonitor",
        "NetworkSecurityPolicy",
        "Cloud",
        "Backup",
        "AlertEmailConfig",
        "GslbService",
        "VrfContext",
        "PriorityLabels",
        "PoolGroupDeploymentPolicy",
        "VIMgrVMRuntime",
        "DebugVirtualService",
        "ActionGroupConfig",
        "VIMgrHostRuntime",
        "AlertConfig",
        "VIMgrNWRuntime",
        "VIMgrClusterRuntime",
        "VIMgrSEVMRuntime",
        "ServerAutoScalePolicy",
        "Network",
        "VIMgrDCRuntime",
        "VsVip",
        "TrafficCloneProfile",
        "ServiceEngineGroup",
        "Pool",
        "VIMgrVcenterRuntime",
        "ServiceEngine",
        "PoolGroup",
        "HTTPPolicySet",
        "VSDataScriptSet",
        "VirtualService",
        "Application",
        "Alert"]
'''

class AvisyConfig():

    def __init__(self, config_file, cip):
        self.config_file = config_file
        self.config_file_abspath, self.config_file_dir, self.config_file_name = self.__config_file_find(self.config_file)
        self.session = None
        if cip:
            try:
                self.session = avi_api.ApiSession(cip, username='admin', tenant='admin',password='avi123', port=443)
            except RequestException as e:
                print 'Could not connect to controller at %s port 443: Exception %s' %(cip, str(e))


    def __config_file_find(self, config_file):
        config_file_abspath = self.__config_filename_get(config_file=config_file)
        config_file_dir, config_file_name = os.path.split(config_file_abspath)
        sys.path.append(config_file_dir)
        print 'config_file File name is %s' %config_file_name
        print 'config_file absolute path is %s' %config_file_abspath

        return (config_file_abspath, config_file_dir, config_file_name)

    def __config_filename_get(self,config_file):
        filename, file_extension = os.path.splitext(config_file)
        if not os.path.isfile(config_file):
            print 'Could not locate Config file %s' %config_file

        return os.path.abspath(config_file)

    # REVIEW I'm not sure if this actually serves a purpose -- can we get rid of it?
    def _can_get_uri_for_admin(self, uri):
        if self.session:
            resp = self.session.get(uri)
            if resp.status_code == 200:
                data = resp.json()
                if 'count' in data and data['count'] != 0:
                    print 'Found results for uri %s' %uri
                    return True
        print 'Did not get uri %s' %uri
        return False

    def convert_pb_to_json(self, pb, skip_fix_ref=False):
        # dict = protobuf_json.pb2json(pb)
        json_dict = {}
        for fieldDesc, fieldVal in pb.ListFields():
            if pb.DESCRIPTOR.name == 'AlertConfig' and fieldDesc.name == 'obj_uuid':
                json_dict[fieldDesc.name] = fieldVal
            elif pb.DESCRIPTOR.name == 'SSLKeyAndCertificateImport' and fieldDesc.name == 'certificate':
                json_dict['certificate'] = {}
                json_dict['certificate'][fieldDesc.name] = fieldVal
            elif fieldDesc.type == fieldDesc.TYPE_MESSAGE:
                if fieldDesc.label == fieldDesc.LABEL_REPEATED:
                    json_dict[fieldDesc.name] = []
                    for val in fieldVal:
                        json_dict[fieldDesc.name].append(
                            self.convert_pb_to_json(val, skip_fix_ref))
                else:
                    json_dict[fieldDesc.name] = {}
                    json_dict[fieldDesc.name] = self.convert_pb_to_json(fieldVal, skip_fix_ref)
            elif fieldDesc.name.endswith('uuids'):
                new_name = fieldDesc.name[:-5] + 'refs'
                json_dict[new_name] = []
                extensions = fieldDesc.GetOptions().Extensions
                refers_to_field = (
                    extensions[options_pb2.refers_to].lower() or
                    extensions[options_pb2.weak_refers_to].lower() or
                    extensions[options_pb2.belongs_to].lower() or
                    extensions[options_pb2.hyperlink_to].lower() or
                    extensions[options_pb2.disp_hyperlink_to].lower())
                for value in fieldVal:
                    # This maintains the existing behavior of dropping empty/null values only when skip_fix_ref is not
                    # enabled.  This behavior may have been unintentional.   This is not intended to imply that this
                    # behavior is desired; it only makes this inconsistency more visible.
                    if not skip_fix_ref:
                        if value is not None and value != "":
                            if '/api' not in value:
                                json_dict[new_name].append('/api/%s/?name=%s' % (refers_to_field, value))
                                uri = '/%s?name=%s' % (refers_to_field, value)
                                if self._can_get_uri_for_admin(uri):
                                    json_dict[new_name].append('/api/%s/?tenant=admin&name=%s' % (refers_to_field, value))
                            else: # if '/api' in value:
                                json_dict[new_name].append(value)
                        else: # if value is None or value == "":
                            #logger.warn("convert_pb_to_json: Ignoring/dropping empty %s field in %s protobuf" %
                            #            (new_name, pb.DESCRIPTOR.full_name))
                            print("convert_pb_to_json: protobuf containing dropped field:\n%s" % pb)
                    else: # if skip_fix_ref:
                        if value is None or value == "":
                            print("convert_pb_to_json: Not dropping empty %s field in %s protobuf" %
                                        (new_name, pb.DESCRIPTOR.full_name))
                        json_dict[new_name].append(value)
            elif fieldDesc.name == 'uuid':
                if fieldVal != 'uuid':
                    json_dict[fieldDesc.name] = fieldVal
            elif fieldDesc.name.endswith('uuid'):
                new_name = fieldDesc.name[:-4] + 'ref'
                extensions = fieldDesc.GetOptions().Extensions
                refers_to_field = (
                    extensions[options_pb2.refers_to].lower() or
                    extensions[options_pb2.weak_refers_to].lower() or
                    extensions[options_pb2.belongs_to].lower() or
                    extensions[options_pb2.hyperlink_to].lower() or
                    extensions[options_pb2.disp_hyperlink_to].lower())
                # This maintains the existing behavior of dropping empty/null values.  This behavior may have been
                # unintentional.  This is not intended to imply that this behavior is desired; it only makes it more
                # visible.
                if fieldVal is not None and fieldVal != "" and new_name.lower() != 'tenant_ref':
                    if not skip_fix_ref and refers_to_field and '/api' not in fieldVal:
                        json_dict[new_name] = '/api/%s/?name=%s' % (refers_to_field, fieldVal)
                        uri = '/%s?name=%s' % (refers_to_field, fieldVal)
                        if self._can_get_uri_for_admin(uri):
                            json_dict[new_name] = '/api/%s/?tenant=admin&name=%s' % (refers_to_field, fieldVal)
                    else: # if skip_fix_ref or '/api' in fieldVal:
                        json_dict[new_name] = fieldVal
                elif pb.DESCRIPTOR.full_name == 'Robot_Server' and new_name == 'nw_ref' and fieldVal == "":
                    pass # OK to silently drop Robot_Server.nw_ref
                else: # if fieldVal is None or fieldVal == "":
                    pass
                    #logger.warn("convert_pb_to_json: Ignoring/dropping empty %s field in %s protobuf" %
                    #            (new_name, pb.DESCRIPTOR.full_name))
                    #print("convert_pb_to_json: protobuf containing dropped field:\n%s" % pb)
            elif fieldDesc.name.find('management_network') != -1:
                new_name = fieldDesc.name
                extensions = fieldDesc.GetOptions().Extensions
                refers_to_field = (
                    extensions[options_pb2.refers_to].lower() or
                    extensions[options_pb2.weak_refers_to].lower() or
                    extensions[options_pb2.belongs_to].lower() or
                    extensions[options_pb2.hyperlink_to].lower() or
                    extensions[options_pb2.disp_hyperlink_to].lower())
                # This maintains the existing behavior of dropping empty/null values.  This behavior may have been
                # unintentional.  This is not intended to imply that this behavior is desired; it only makes it more
                # visible.
                if fieldVal is not None and fieldVal != "":
                    if not skip_fix_ref and '/api' not in fieldVal:
                        json_dict[new_name] = '/api/%s?name=%s' % (refers_to_field, fieldVal)
                        uri = '/%s?name=%s' % (refers_to_field, fieldVal)
                        if self._can_get_uri_for_admin(uri):
                            json_dict[new_name] = '/api/%s/?tenant=admin&name=%s' % (refers_to_field, fieldVal)
                    else: # if skip_fix_ref or '/api' in fieldVal:
                        json_dict[new_name] = fieldVal
                else: # if fieldVal is None or fieldVal == "":
                    #logger.warn("convert_pb_to_json: Ignoring/dropping empty %s field in %s protobuf" %
                    #            (new_name, pb.DESCRIPTOR.full_name))
                    print("convert_pb_to_json: protobuf containing dropped field:\n%s" % pb)
            else:
                if fieldDesc.label == fieldDesc.LABEL_REPEATED:
                    json_dict[fieldDesc.name] = []
                    for val in fieldVal:
                        if fieldDesc.type == fieldDesc.TYPE_ENUM:
                            val = fieldDesc.enum_type.values_by_number[val].name
                        json_dict[fieldDesc.name].append(val)
                else:
                    if fieldDesc.type == fieldDesc.TYPE_ENUM:
                        fieldVal = fieldDesc.enum_type.values_by_number[fieldVal].name
                    json_dict[fieldDesc.name] = fieldVal
        return json_dict

    def append_config_file(self,src_dir, source):
        lines = ''
        ifile = os.path.join(src_dir, source)
        if not os.path.isfile(ifile):
            ifile = '../../robot/new/testsuites/data/' + source
        with open(ifile) as f:
            count = 0
            for line in f.readlines():
                count =  count + line.count('{')
                count =  count - line.count('}')
                if 'source' in line and count == 0:
                    lines += self.append_config_file(src_dir, line.rstrip().split(': ')[-1][1:-1])
                else:
                    lines += line
        return lines

    def get_json(self):
        #s = ''
        sp = self.append_config_file(self.config_file_dir, self.config_file_name)
        #with open(self.config_file_abspath, 'r') as f:
        #    s = f.read()
        pb = Topology()
        try:
            google.protobuf.text_format.Merge(sp, pb)
            js = self.convert_pb_to_json(pb)
            return js
        except Exception as e:
            raise

def json_get(args):
    print "Config File: %s" %args.src_config_file
    config = AvisyConfig(args.src_config_file, args.cip)
    #json_data = json.loads(config.get_json())
    json_data = config.get_json()
    json_data_new = {}
    #order_lower = [obj_l.lower() for obj_l in order]
    for obj in json_data:
        print 'Processing %s' %obj
        match = re.search('(.*)_object', obj)
        if not match:
             print '++++++++++++++++ Ignoring %s +++++++++++++++' %obj
             continue
        obj_name = match.group(1)
        #ind = order_lower.index(obj_name)
        #obj_new = order[ind]
        match = [name for name in order if name.lower() == obj_name]
        if match:
            obj_new = match[0]
        else:
            print '+++++++ obj in pb: %s is not in obj order list +++++++' %obj
            continue
        #if obj_new == 'SSLKeyAndCertificateImport':
        #    obj_new = 'SSLKeyAndCertificate'
        json_data_new[obj_new] = json_data[obj]

    print "Destination file ", args.dst_config_file
    with open(args.dst_config_file, 'w') as outfile:
        str_ = json.dumps(json_data_new,
                      indent=4, sort_keys=True,
                      separators=(',', ': '), ensure_ascii=False)
        outfile.write(unicode(str_))

        #outfile.write(str(json_data_new))
        #json.dump(json_data_new, outfile)
    #print "Json Data: \n%s" %json_data


def main():
    #local_dir = os.getcwd()
    parser = argparse.ArgumentParser()
    parser.add_argument('src_config_file', nargs='?', help='Source Protobuf config file', default='')
    parser.add_argument('dst_config_file', nargs='?', help='Destination Json Config to save', default='')
    parser.add_argument('cip', nargs='?', help='A controller ip with system defaults', default='')

    if len(sys.argv) < 3:
        print '[ERROR] Missing arguments. \n'
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()
    json_get(args)


if __name__ == '__main__':
    main()
