import argparse
from collections import OrderedDict
import json
import os
import re
import sys

from jinja2 import Environment, PackageLoader, select_autoescape

from avi_objects.logger import logger

env = Environment(loader=PackageLoader('avi_tools.jinja', 'templates'),
                  autoescape=select_autoescape(['html', 'xml']))

template = env.get_template('testbed.template')

# Copied over from ~/robot/new/lib/tools/setup_env.py for defining subnets and masks for mgmt networks
# TODO should we reference it directly?
management_map = {}
management_map['dvPGManage'] = ['20', '10.10.0.1']
management_map['dvPGManagement'] = ['20', '10.10.0.1']
management_map['Management'] = ['20', '10.10.0.1']
management_map['dvPGJenkinsManagement'] = ['22', '10.10.56.1']
management_map['dvPGManage157'] = ['23', '10.10.48.1']
management_map['Mgmt_N3k'] = ['23', '10.10.22.1']
management_map['Mgmt_N3k_2'] = ['23', '10.10.30.1']
management_map['Mgmt_Arista'] = ['23', '10.10.24.1']
management_map['Mgmt_Arista_2'] = ['23', '10.10.26.1']
management_map['Mgmt_Arista_3'] = ['23', '10.10.28.1']
management_map['MGMT'] = ['23', '10.130.2.1']
management_map['PG-Mgmt'] = ['23', '10.128.6.1']
management_map['PG-Mgmt-CCUS'] = ['23', '10.160.0.1']
management_map['mesos_vc_management'] = ['24', '10.126.0.1']
management_map['Mgmt_netgear'] = ['22', '10.140.4.1']
management_map['Mgmt_Cumulus2'] = ['22', '10.164.0.1']

def load_pb(input_file):
    from avi.protobuf.robot_topology_pb2 import Topology
    # DO NOT move this import: Required to set only after we import Topology.
    from google.protobuf import text_format
    pb = Topology()
    testbed_resources = {}
    match = '(\S+)\s+=\s+(\S+)\n'
    with open(input_file, 'r') as f:
        s = f.read()
        for line in re.findall(match, s):
            testbed_resources[line[0]] = line[1]
        pb_data = re.sub(match, '', s)
        #pb.ParseFromString(f.read())
    text_format.Merge(pb_data, pb)
    return pb, testbed_resources

def parse_pb(pb_obj):
    """ Recurse through pb object to parse fields and populate a json dict of the items """
    json_dict = {}
    for fieldDesc, fieldVal in pb_obj.ListFields():
        if fieldDesc.type == fieldDesc.TYPE_MESSAGE:
            if fieldDesc.label == fieldDesc.LABEL_REPEATED:
                json_dict[fieldDesc.name] = []
                for val in fieldVal:
                    json_dict[fieldDesc.name].append(parse_pb(val))
            else:
                json_dict[fieldDesc.name] = {}
                json_dict[fieldDesc.name] = parse_pb(fieldVal)
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

def extract_field(dict_obj, field):
    """ Return the field from the dictionary, if it exists, and remove it """
    if field in dict_obj:
        return dict_obj.pop(field)
    else:
        return ''

def is_empty(json_obj):
    empty = True
    if json_obj is not None:
        if not isinstance(json_obj, (dict, list)):
            return False
        if isinstance(json_obj, list):
            for elem in json_obj:
                empty &= is_empty(elem)
        else:
            for k,v in json_obj.iteritems():
                empty &= is_empty(v)
    return empty

def convert(input_file, output_file):
    """ Take input pb testbed file and map it to new json format """
    logger.info('Converting testbed file %s to %s' %(input_file, output_file))

    tb_info = {}
    tb_info['source'] = input_file
    
    pb, testbed_resources = load_pb(input_file)
    #logger.debug('pb: %s' %pb)
    #logger.debug('testbed_resources: %s' %testbed_resources)
    pb_json = parse_pb(pb)
    logger.debug('pb_json: %s' %pb_json)
    
    tb_info['networks'] = OrderedDict()
    networks = pb_json['virtualization'].pop('networks', [])
    for network in networks:
        network_name = str(extract_field(network, 'name'))[2:-1]
        pg_for_net = testbed_resources.get(network_name, '')
        if not pg_for_net:
            logger.warning('No PG mapping found for network name %s' %network_name)
        tb_info['networks'][network_name] = OrderedDict()
        tb_info['networks'][network_name]['name'] = pg_for_net
        tb_info['networks'][network_name]['ip'] = extract_field(network['ip_subnet'][0]['prefix']['ip_addr'], 'addr')
        extract_field(network['ip_subnet'][0]['prefix']['ip_addr'], 'type') # REVIEW do we need the type?
        tb_info['networks'][network_name]['mask'] = extract_field(network['ip_subnet'][0]['prefix'], 'mask')

        if not is_empty(network):
            logger.warning('network %s still contains fields: %s' %(network_name, network))
            tb_info['networks'][network_name]['unused'] = network

    if not tb_info['networks'].get('management'):
        logger.debug('No management network declared; creating one from defined mapping')
        management = testbed_resources.get('management')
        if management:
            tb_info['networks']['management'] = OrderedDict()
            tb_info['networks']['management']['name'] = management
            mgmt_info = management_map.get(management)
            if not mgmt_info:
                logger.warning('Could not identify management network %s' %management)
            else:
                tb_info['networks']['management']['ip'] = mgmt_info[1]
                tb_info['networks']['management']['mask'] = mgmt_info[0]

    tb_info['vms'] = []
    vms = pb_json['virtualization'].pop('vm', [])
    for vm in vms:
        vm_info = OrderedDict()
        vm_info['name'] = extract_field(vm, 'name')
        extract_field(vm, 'id') # REVIEW do we need this field?
        vm_info['type'] = extract_field(vm, 'type')
        vm_info['ip'] = extract_field(vm, 'vm_ip')
        vm_info['mask'] = '255.255.255.0'
        vm_info['static'] = 'no'
        vm_info['host'] = extract_field(vm, 'hostip')
        vm_info['datastore'] = extract_field(vm, 'datastore')
        vm_info['memory'] = extract_field(vm, 'memory')
        vm_info['cpu_cores'] = extract_field(vm, 'cpu_cores')
        vm_info['cluster'] = extract_field(vm, 'cluster')
        dc = extract_field(pb_json['virtualization'], 'datacenters')
        datacenter = dc[0] if dc else '' # assume only 1
        vm_info['datacenter'] = datacenter

        vm_info['networks'] = {}
        management = testbed_resources.get('management')
        if management:
            vm_info['networks']['mgmt'] = management # REVIEW is the name always mgmt?
        if vm.get('nw_uuids'):
            vm_info['networks']['data'] = []
            for net in vm['nw_uuids']:
                network_name = net[2:-1]
                vm_info['networks']['data'].append(network_name)
            vm.pop('nw_uuids')
        tb_info['vms'].append(vm_info)
        if not is_empty(vm):
            logger.warning('vm %s still contains fields: %s' %(vm_info['name'], vm))
            vm_info['unused'] = vm

    # Cloud -- REVIEW beta support; will copy over but not render since we don't know all the fields
    if 'cloud_object' in pb_json:
        tb_info['clouds'] = json.dumps(pb_json['cloud_object'])
    
    # REVIEW: pb.virtualization.test_tag_config?
    
    # REVIEW: pb.virtualization.addr_pool_start_index?

    # write to desired output file
    content = template.render(tb_info=tb_info)
    output_dir = os.path.dirname(output_file)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    with open(output_file, 'w') as f:
        f.write(content)
        logger.info('wrote testbed json file %s' %output_file)

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('input', nargs='*',
            help='pb-formatted topo conf file(s) or directory')
    parser.add_argument('-o', '--output',
            help = 'json-formatted testbed file or directory (for multiple or directory inputs)', default='')
    args = parser.parse_args()
    if not args.input:
        parser.print_help()
        parser.exit()
    return args

def main(input_ext, output_ext):
    args = parse_args()
    input_name = args.input
    output_name = args.output
    output_path = os.path.expanduser(os.path.expandvars(output_name))
    output_path = os.path.normpath(os.path.abspath(output_path))

    if len(input_name) > 1:
        logger.info('Converting multiple inputs %s' %input_name)
        if os.path.isfile(output_path):
            raise RuntimeError('A directory must be specified as the output for multiple inputs')
        for one_input in input_name:
            input_path = os.path.expanduser(os.path.expandvars(one_input))
            input_path = os.path.normpath(os.path.abspath(input_path))
            file_name = os.path.basename(input_path)
            file_name = os.path.splitext(file_name)[0]
            _output_path = os.path.join(output_path, file_name + output_ext)
            convert(input_path, _output_path)
    else:
        input_name = args.input[0]
        input_path = os.path.expanduser(os.path.expandvars(input_name))
        input_path = os.path.normpath(os.path.abspath(input_path))
        if os.path.isdir(input_path):
            logger.info('Converting input dir %s' %input_path)
            if os.path.isfile(output_path):
                raise RuntimeError('A directory must be specified as the output for directory inputs')
            for path, subdirs, files in os.walk(input_path):
                for name in files:
                    if name.endswith(input_ext):
                        input_filename = os.path.join(path, name)
                        output_filename = os.path.splitext(name)[0]
                        output_filename = output_filename + output_ext
                        rel_path = os.path.relpath(path, input_path) # maintain the relative folder structure
                        output_filename = os.path.join(output_path, rel_path, output_filename)
                        output_filename = os.path.normpath(os.path.abspath(output_filename))
                        output_dir = os.path.dirname(output_filename)
                        if not os.path.exists(output_dir):
                            logger.debug('Creating output folder %s' %output_dir)
                            os.makedirs(output_dir)
                        convert(input_filename, output_filename)
        else:
            logger.info('Converting single input %s' %input_path)
            if not output_name:
                file_name = os.path.splitext(input_path)[0]
                output_path = file_name + output_ext
            else:
                ext = os.path.splitext(output_name)[1]
                if ext and ext != output_ext:
                    raise RuntimeError('Unsupported output filename %s (should be %s file)' %(output_name, output_ext))
                if not ext: # assume folder
                    file_name = os.path.basename(input_path)
                    file_name = os.path.splitext(file_name)[0]
                    output_path = os.path.join(output_path, file_name + output_ext)
            convert(input_path, output_path)


if __name__ == '__main__':
    main('.conf', '.json')