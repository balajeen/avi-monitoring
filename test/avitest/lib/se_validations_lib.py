from netaddr import IPNetwork, IPAddress
from avi_objects.rest import get, get_uuid_by_name, get_uuid_from_ref
from avi_objects.logger_utils import fail, abort, error, asleep, aretry
from avi_objects.infra_utils import get_cloud_context_type
from lib.se_lib import get_se_info, get_se_list_in_group, get_se_runtime_summary
from avi_objects.logger import logger
import lib.webapp_lib as webapp_lib
from lib.se_lib import get_cidr


class SEWellnessCheck(object): 

    def __init__(self, se_uuid, oper_state, timeout):
        self.se_uuid = se_uuid
        self.oper_state = oper_state
        self.se_connected = False
        self.timeout = timeout
        self.failed_validations = []
        self.se_data = dict()
        self.runtime_data = dict()
        self.runtime_details_data = dict()
        self.se_vnicdb_data = dict()
        self.route_data = []
        self.interface_data = []
        self.seagent_data = []
        self.uri = "serviceengine/%s" % self.se_uuid
        self.vnicdb_uri = "serviceengine/%s/vnicdb" % self.se_uuid
        self.interface_uri = "serviceengine/%s/interface" % self.se_uuid
        self.route_uri = "serviceengine/%s/route" % self.se_uuid
        self.runtime_uri = "serviceengine/%s/runtime" % self.se_uuid
        self.runtime_details_uri = "serviceengine/%s/runtime/detail" % self.se_uuid
        self.seagent_uri = "serviceengine/%s/seagent" % self.se_uuid
        self.placement_uri = "serviceengine/%s/placement" % self.se_uuid
        self.graphdb_uri = "serviceengine/%s/graphdb" % self.se_uuid
        self.mgmt_and_data_vnics = []
        self.vnicdb_vnics = []
        self.data_vnics_with_ips = []
        self.vnicdb_vnics_with_ips = []
        self.interface_vnics = []
        self.placement_data = dict()
        self.graphdb_data = dict()
        self.mallocstats_uri = "serviceengine/%s/mallocstats" % self.se_uuid
        self.mallocstats_data = dict()

    def se_check(self):
        """
        This function performs multiple checks and validations for SEs.
        """
    
        # Check whether the oper_state is as expected
        try:
            self.__wait_for_expected_se_state(self.se_uuid, self.oper_state)
        except Exception as e:
            logger.info("The SE is not in the expected state. %s" % str(e))
            fail("The SE is not in the expected state. %s" % str(e))

        # Get API data
        status_code, self.se_data = get(self.uri)
        status_code1, self.runtime_data = get(self.runtime_uri)
        status_code2, self.runtime_details_data = get(self.runtime_details_uri)
        status_code3, temp_placement_data = get(self.placement_uri)

        self.se_connected = self.runtime_details_data.get("se_connected", False)
        temp_graphdb_data = None
        if self.se_connected:
            status_code4, self.se_vnicdb_data = get(self.vnicdb_uri)
            status_code5, self.interface_data = get(self.interface_uri)
            status_code6, self.route_data = get(self.route_uri)
            status_code7, self.seagent_data = get(self.seagent_uri)
            status_code8, temp_graphdb_data = get(self.graphdb_uri)
            status_code9, self.mallocstats_data = get(self.mallocstats_uri)

        # Lists for internal usage
        self.mgmt_and_data_vnics = [self.se_data["mgmt_vnic"]] + self.se_data.get("data_vnics", [])
        self.vnicdb_vnics = self.se_vnicdb_data[0]["vnic"] if self.se_connected else []

        self.data_vnics_with_ips = [
            x for x in self.se_data.get("data_vnics", []) if "vnic_networks" in x]
        self.vnicdb_vnics_with_ips = [x for x in self.vnicdb_vnics if "nw" in x]
        self.interface_vnics = self.interface_data[0].get("vnics", []) if self.se_connected else []
        self.placement_data = temp_placement_data[0]
        self.graphdb_data = temp_graphdb_data[0] if self.se_connected else []

        """
        Validate SE vnic match across SE config object, SE vnic DB and
        SE DP interfaces
        """
        cloud_type = get_cloud_context_type()
        # Check if the number of vnics is the same in both lists
        self.failed_validations += self.__validate_len_vnics()

        # Check if the exact set of vnics is in both lists
        self.failed_validations = self.failed_validations + self.__validate_set_of_vnics()
        if cloud_type not in ['baremetal']:
            # Check if the fields in the vnics have the same values.
            self.failed_validations = self.failed_validations + self.__validate_vnic_fields()
        if cloud_type not in ['gcp','azure','baremetal']:
            # Compare the vnics that have IPs assigned across three APIs
            self.failed_validations = self.failed_validations + self.__validate_vnics_with_ips()
        if cloud_type not in ['gcp','azure', 'baremetal', 'aws']:
            # Validate SE VRF information between controller, vnic DB & DP
            # commenting this line as multi vrf is not supported in aws
            self.failed_validations += self.__validate_se_vrf_and_route_fields()
        if cloud_type not in ['aws']:
            # Check whether the SE vrf_context matches the controller vrf_context
            # commenting this line as multi vrf is not supported in aws
            self.failed_validations += self.__validate_se_and_cntrlr_vrf_context()
        # Check whether the details match across runtime summary, runtime details
        # and serviceengine APIs
        self.failed_validations += self.__validate_runtime_details_and_se_fields()
        # Check if the fields from seagent match runtime/details
        self.failed_validations = self.failed_validations + self.__validate_runtime_details_and_seagent()
        if cloud_type not in ['gcp','azure', 'baremetal']:
            # Validate data across SE placement and controller APIs
            self.failed_validations += self.__validate_placement_and_se_fields()
        if cloud_type not in ['openstack']:
            # Validate data across SE graphdb and placement APIs
            self.failed_validations += self.__validate_placement_and_graphdb_vs()
        # Validate data across SE graphdb and controller APIs
        # Configuration consistency check
        self.failed_validations += self.__validate_graphdb_and_controller_fields_with_retry()
        if cloud_type not in ['openstack']:
            # Validate SE data across SE graphdb and SE placement APIs
            self.failed_validations += self.__validate_graphdb_and_placement_ses()
        # Validate count of SE VRF between VNIC DB and SE DP
        self.failed_validations += self.__validate_vnicdb_and_se_dp_vrf_count()
        # Validate list of vrfcontext matches between SE and VNIC DB with count and set of VRFs
        if cloud_type not in ['aws','gcp','azure', 'baremetal']:
            self.failed_validations = self.failed_validations + self.__validate_se_and_vnicdb_vrf_set_and_count()

        #Checking the network type for vnic
        if self.se_vnicdb_data:
            self.failed_validations += self.__validate_no_dhcp_vip_vnicdb()
        if self.failed_validations:
            error("There are some failed validations: %s" % "\n".join(self.failed_validations))
        else:
            logger.info("All validations passed")
        return True

    def __validate_no_dhcp_vip_vnicdb(self):

        output = []
        logger.info("vnicdb_data::")
        logger.info(self.se_vnicdb_data)
        vnic_data = self.se_vnicdb_data[0]['vnic']
        for vnic in vnic_data:
            if vnic['enabled'] == False or vnic['connected'] == False or \
                            vnic['avi_internal_network'] == True or vnic['vrf_ref'] == "":
                logger.info("Now checking the ip type for each network uuid")
                try:
                    network_type = vnic['nw']
                    for net in network_type:
                        if net['mode'] == "DHCP" or net['mode'] == "VIP":
                            output.append("Validation failed for vnic %s. Network type either DHCP "
                                          "or VIP for given vnic" % vnic['if_name'])
                except KeyError:
                    pass
        return output

    def __intf_ip_match_check(self, vnic1, vnic2, skip_vip=False):
        """
        This function compares two network entries from url1 and url2.
        url1: /api/serviceengine/<se-uuid>/interface (vnic1)
        url2: /api/serviceengine/<se-uuid> (vnic2)
        The address should be the same.
        """
        if not vnic1 and not vnic2:
            return True
        if not vnic1 or not vnic2:
            return False

        graphdb_vs = self.graphdb_data.get("virtualservice", None)
        graphdb_vs_list = graphdb_vs.get("obj", []) if graphdb_vs else []
        vs_se_list = []
        vip_set = set()
        snat_ip_list = []

        for each in graphdb_vs_list:
            vs_se_list = each["config"]["virtual_service_se"].get("se_list", [])
            vs = each["config"]["virtual_service_se"]["virtual_service"]
            for vip in vs.get("vip", []):
                ip_address = vip.get("ip_address", None)
                if not ip_address:
                    continue
                vip_set.add(ip_address["addr"])

        for each in vs_se_list:
            if each.get("snat_ip"):
                snat_ip_list.append(each.get("snat_ip")["addr"])
       
        try:
            for each in vnic1:
                ip = each["ip_addr"]
                if ip in snat_ip_list:
                    continue
                if skip_vip and ip in vip_set:
                    continue
                match_ip = next(
                    x for x in vnic2 if x["ip"]["ip_addr"]["addr"] == ip)

                if not match_ip:
                    return False
                if not (IPAddress(each["net_mask"]).netmask_bits() ==
                        match_ip["ip"]["mask"]):
                    return False

        except Exception as e:
            logger.warning("An exception has occurred: %s" % str(e))
            return False
        return True

    def __ip_match_check(self, vnic1, vnic2):
        """
        This function compares two network entries from url1 and url2.
        url1: /api/serviceengine/<se-uuid> (vnic1)
        url2: /api/serviceengine/<se-uuid>/vnicdb (vnic2)
        The mode, mask and address must be the same.
        """
        if not vnic1 and not vnic2:
            return True
        if not vnic1 or not vnic2:
            return False

        try:
            for each in vnic1:
                ip = each["ip"]["ip_addr"]["addr"]
                match_ip = next(
                    x for x in vnic2 if x["ip"]["ip_addr"]["addr"] == ip)

                if not match_ip:
                    return False
                elif not each["ip"]["mask"] == match_ip["ip"]["mask"]:
                    return False
                elif not each["mode"] == match_ip["mode"]:
                    return False
        except Exception as e:
            logger.warning("An exception occurred: %s" % str(e))
            return False
        return True

    def __validate_len_vnics(self):

        if not self.se_connected:
            return []

        if not ((len(self.mgmt_and_data_vnics) == len(self.vnicdb_vnics)) and
                (len(self.vnicdb_vnics) == self.se_vnicdb_data[0]["num_vnics"])):
            return [("validate_len_vnics: Validation for the number of vnics across "
                     "controller and SE agent vnic DB APIs failed. "
                     "Number of vnics in controller API: %s. "
                     "Number of vnics in SE vnicdb API: %s.") %
                    (str(len(self.mgmt_and_data_vnics)), str(len(self.vnicdb_vnics)))]
        return []

    def __validate_set_of_vnics(self):
        output = []

        if not self.se_connected:
            return []

        for each_vnic in self.mgmt_and_data_vnics:
            if not any(('mac_address' in x) and x['mac_address'] == each_vnic['mac_address']
                       for x in self.vnicdb_vnics):
                output.append(("validate_set_of_vnics: Validation for the set of vnics "
                               "across controller and SE agent vnic DB APIs failed. "
                               "Vnic with MAC address %s does not exist in %s.") %
                              (each_vnic['mac_address'], self.vnicdb_uri))
        return output

    def __validate_vnic_fields(self):
        output = []
        cloud_type = get_cloud_context_type()
        error_msg = ("validate_vnic_fields: Validation for the set of vnics across "
                     "controller and SE agent vnic DB APIs failed. ")

        if not self.se_connected:
            return []
        for each_vnic in self.mgmt_and_data_vnics:
            try:
                matching_vnic = next(
                    x for x in self.vnicdb_vnics
                    if x['mac_address'] == each_vnic['mac_address'])
            except StopIteration:
                logger.info("validate_vnic_fields: An exception has occurred. " +
                            "There is no matching vnic for vnic with mac address %s" %
                            each_vnic['mac_address'])
                output.append("validate_vnic_fields: There is no matching vnic " +
                              "for vnic with mac address %s" % each_vnic['mac_address'])
                continue
            
            if "network_ref" in each_vnic:
                network_uuid = get_uuid_from_ref(each_vnic["network_ref"])
            else:
                network_uuid = "Unknown"

            if not (each_vnic.get("dhcp_enabled", None) ==
                    matching_vnic.get("dhcp_enabled", None)):
                output.append(error_msg +
                              "dhcp_enabled fields for vnics do not match."
                              " vnic for controller : \n%s. \n\nvnic for SE : %s." %
                              (str(each_vnic), str(matching_vnic)))
            if not (each_vnic.get("is_mgmt", None) ==
                    matching_vnic.get("is_mgmt", None)):
                output.append(error_msg +
                              "is_mgmt fields for vnics do not match."
                              "Controller : %s. \n\nSE : %s. " %
                              (str(each_vnic), str(matching_vnic)))
            if not (each_vnic.get("mtu", None) ==
                    matching_vnic.get("mtu", None)):
                output.append(error_msg +
                              "mtu fields for vnics do not match."
                              "Controller : %s. \n\nSE : %s. " %
                              (str(each_vnic), str(matching_vnic)))
            if not network_uuid == matching_vnic.get("network_uuid", "Unknown"):
                output.append(error_msg +
                              "network_ref fields for vnics do not match."
                              "Controller : %s. \n\nSE : %s. " %
                              (str(each_vnic), str(matching_vnic)))
            if not (each_vnic.get("is_avi_internal_network", None) ==
                    matching_vnic.get("avi_internal_network", None)):
                output.append(error_msg +
                              "avi_internal_network fields for vnics do not match." 
                              "Controller : %s. \n\nSE : %s. " %
                              (str(each_vnic), str(matching_vnic)))
            if not (each_vnic.get("enabled", None) ==
                    matching_vnic.get("enabled", None)):
                output.append(error_msg +
                              "enabled fields for vnics do not match." 
                              "Controller : %s. \n\nSE : %s. " %
                              (str(each_vnic), str(matching_vnic)))
            if not (each_vnic.get("connected", None) ==
                    matching_vnic.get("connected", None)):
                output.append(error_msg +
                              "connected fields for vnics do not match." 
                              "Controller : %s. \n\nSE : %s. " %
                              (str(each_vnic), str(matching_vnic)))
            if not (self.__ip_match_check(each_vnic.get("vnic_networks", None),
                                          matching_vnic.get("nw", None))):
                output.append(error_msg +
                              "IP address fields for vnics do not match." 
                              "Controller : %s. \n\nSE : %s. " %
                              (str(each_vnic), str(matching_vnic)))
            cloud_type = get_cloud_context_type()
            if cloud_type not in ['aws']:
                if (not each_vnic.get("is_mgmt", False) and
                        not matching_vnic.get("is_mgmt", False)):
                    if not each_vnic.get("vrf_ref", None):
                        # Special case where vrf_ref is None or ''
                        if "seagent-default" not in matching_vnic.get("vrf_ref", None):
                            output.append((error_msg +
                                           "vrf_ref fields for vnics do not match "
                                           "Controller : %s. \n\nSE : %s. "
                                           "for this special case.") %
                                          (str(each_vnic), str(matching_vnic)))
                    elif not (each_vnic.get("vrf_ref") ==
                              matching_vnic.get("vrf_ref", None)):
                        output.append((error_msg +
                                       "vrf_ref fields for vnics do not match." 
                                       "Controller : %s. \n\nSE : %s. " %
                                       (str(each_vnic), str(matching_vnic))))
        return output

    def __validate_vnics_with_ips(self):
        output = []
        cloud_type = get_cloud_context_type()
        error_msg = ("validate_vnics_with_ips: Validation for the set of vnics "
                     "across SE datapath and controller APIs failed. ")

        if not self.se_connected:
            return []

        if not self.interface_vnics:
            return [("validate_vnics_with_ip: There are no vnics in the "
                     "SE datapath API.")]

        for each_vnic in self.interface_vnics:
            try:
                matching_data_vnic = next(
                    x for x in self.data_vnics_with_ips
                    if x['mac_address'] == each_vnic['mac_address'])
                matching_vnicdb_vnic = next(
                    x for x in self.vnicdb_vnics_with_ips
                    if x['mac_address'] == each_vnic['mac_address'])
            except StopIteration:
                logger.info(("validate_vnic_with_ips: An exception has occurred. "
                             "There is no matching vnic for vnic with mac address %s") %
                            each_vnic['mac_address'])
                output.append(("validate_vnic_with_ips: There is no matching vnic "
                               "for vnic with mac address : %s") % each_vnic['mac_address'])
                continue

            if not (each_vnic.get("vnic_mtu", None) ==
                    matching_data_vnic.get("mtu", None)):
                output.append(error_msg +
                              "mtu fields for vnics do not match." 
                              "Controller : %s. \n\nSE : %s. " %
                              (str(each_vnic), str(matching_data_vnic)))
            if not (matching_data_vnic.get("mtu", None) ==
                    matching_vnicdb_vnic.get("mtu", None)):
                output.append(error_msg +
                              "mtu fields for vnics do not match." 
                              "Controller : %s. \n\nSE : %s. " %
                              (str(matching_data_vnic), str(matching_vnicdb_vnic)))
            if not (matching_vnicdb_vnic.get("mtu", None) ==
                    each_vnic.get("vnic_mtu", None)):
                output.append(error_msg +
                              "mtu fields for vnics do not match." 
                              "Controller : %s. \n\nSE : %s. " %
                              (str(matching_vnicdb_vnic), str(each_vnic)))

            if cloud_type not in ['aws']:
                if not (each_vnic.get("vrf_id", None) ==
                        matching_vnicdb_vnic.get("vrf_id", None)):
                    output.append(error_msg +
                                  "vrf_id fields for vnics do not match." 
                                  "Controller : %s. \n\nSE : %s. " %
                                  (str(each_vnic), str(matching_vnicdb_vnic)))
                if not (each_vnic.get("vrf_ref", None) ==
                        matching_data_vnic.get("vrf_ref", None)):
                    output.append(error_msg +
                                  "vrf_ref fields for vnics do not match." 
                                  "Controller : %s. \n\nSE : %s. " %
                                  (str(each_vnic), str(matching_data_vnic)))
                if not (matching_data_vnic.get("vrf_ref", None) ==
                        matching_vnicdb_vnic.get("vrf_ref", None)):
                    output.append(error_msg +
                                  "vrf_ref fields for vnics do not match." 
                                  "Controller : %s. \n\nSE : %s. " %
                                  (str(matching_data_vnic), str(matching_vnicdb_vnic)))
                if not (matching_vnicdb_vnic.get("vrf_ref", None) ==
                        each_vnic.get("vrf_ref", None)):
                    output.append(error_msg +
                                  "vrf_ref fields for vnics do not match." 
                                  "Controller : %s. \n\nSE : %s. " %
                                  (str(matching_vnicdb_vnic), str(each_vnic)))
            if not self.__ip_match_check(matching_data_vnic.get("vnic_networks", None),
                                         matching_vnicdb_vnic.get("nw", None)):
                output.append(error_msg +
                              "IP data for vnics do not match." 
                              "Data1 : %s. \n\nData2 : %s. " %
                              (str(matching_data_vnic), str(matching_vnicdb_vnic)))
            if not self.__intf_ip_match_check(each_vnic.get("ip_info", None),
                                              matching_data_vnic.get("vnic_networks", None),
                                              skip_vip=True):
                output.append(error_msg +
                              "IP data for vnics do not match." 
                              "Data1 : %s. \n\nData2 : %s. " %
                              (str(each_vnic), str(matching_data_vnic)))
            if not self.__intf_ip_match_check(each_vnic.get("ip_info", None),
                                              matching_vnicdb_vnic.get("nw", None),
                                              skip_vip=False):
                output.append(error_msg +
                              "IP data for vnics do not match." 
                              "Data1 : %s. \n\nData2 : %s. " %
                              (str(each_vnic), str(matching_vnicdb_vnic)))
        return output
    
    def __validate_se_vrf_and_route_fields(self):
        output = []
        error_msg = ("validate_se_vrf_and_route_fields: Validation for the SE VRF "
                     "information between controller, vnic DB and DP failed. ")

        if not self.se_connected:
            return []

        """
            Support for snat_ip
        """

        graphdb_vs = self.graphdb_data.get("virtualservice", None)
        graphdb_vs_list = graphdb_vs.get("obj", []) if graphdb_vs else []
        vs_se_list = []
        snat_ip_list = []

        for each in graphdb_vs_list:
            vs_se_list = each["config"]["virtual_service_se"].get("se_list",
                                                                  [])
        for each in vs_se_list:
            if each.get("snat_ip"):
                snat_ip_list.append(each.get("snat_ip")["addr"])

        routes = self.route_data[0].get("route_entry", [])
        vnic_list = self.se_vnicdb_data[0].get("vnic", [])
        vnic_nw_list = []
        for x in vnic_list:
            if "nw" in x:
                vnic_nw_list = vnic_nw_list + x["nw"]
        vnicdb_route = []

        for each in self.se_vnicdb_data[0].get("vrf", []):
            if each["vrf_context"]["name"] != "seagent-default":
                if 'route' in each and each["route"] not in vnicdb_route:
                    vnicdb_route = vnicdb_route + (each["route"])

        if not routes:
            return ["Skipping SE VRF Validation."]

        if not vnicdb_route:
            return ["Skipping SE VRF Validation."]
        vip_list = []
        for x in vnic_nw_list:
            if x["mode"] == "VIP":
                vip_list.append(x["ip"]["ip_addr"]["addr"])

        for each_route in routes:
            if each_route["destination"] in snat_ip_list:
                continue
            try:
                matching_route = next(
                    x for x in vnicdb_route
                    if x["dst_ip"]["addr"] == each_route["destination"])
            except StopIteration:

                if not (each_route["destination"] in vip_list):
                    logger.info(("validate_se_vrf_and_route_fields: There is no "
                                 "matching route for route with destination : %s") % each_route["destination"])
                    output.append(("validate_se_vrf_and_route_fields: There is no "
                                   "matching route for route with destination : %s") % each_route["destination"])

                continue

            mask = each_route.get("netmask", None)

            prefix = get_cidr(mask)

            if not (IPAddress(each_route.get("netmask", None)).netmask_bits() ==
                    int(matching_route.get("mask", None))):
                if not (int(prefix) == int(matching_route.get("mask", None))):
                    output.append(error_msg +
                                  "Network masks do not match."
                                  "Controller  : %s. \n\nSE : %s." %
                                  (each_route.get("netmask", None),
                                   matching_route.get("mask", None)))
            if not (each_route.get("interface", None) ==
                    matching_route.get("if_name", None).strip("avi_")):
                output.append(error_msg +
                              "Interface names do not match."
                              "Controller : %s. \n\nSE : %s." %
                              (each_route.get("interface", None),
                               matching_route.get("if_name", None)))
            if not (each_route.get("vrf_id", None) ==
                    matching_route.get("vrf_id", None)):
                output.append(error_msg +
                              "vrf_id fields do not match."
                              "Controller : %s. \n\n SE : %s." %
                              (each_route.get("vrf_id", None),
                               matching_route.get("vrf_id", None)))
        return output

    def __validate_se_and_cntrlr_vrf_context(self):
        vnicdb_vrfcontext = []

        if not self.se_connected:
            return []

        for each in self.se_vnicdb_data[0]["vrf"]:
            if each["vrf_context"]["name"] != "seagent-default":
                vnicdb_vrfcontext.append(each["vrf_context"])

        for each_vrfcontext in vnicdb_vrfcontext:
            vrf_context_uuid = get_uuid_by_name('vrfcontext', each_vrfcontext["name"])
            status_code, vrf_context = get('vrfcontext/%s' % vrf_context_uuid)
            vrf_context.pop("_last_modified", None)
            vrf_context.pop("url", None)
            if each_vrfcontext != vrf_context:
                return [(
                    "validate_se_and_cntrlr_vrf_context: Validation for "
                    "SE VRF Context failed. SE vrf_context object"
                    "does not match the controller vrf_context object.")]
        return []

    def __validate_runtime_details_and_se_fields(self):
        output = []
        error_msg_rt_rt_det = ("validate_runtime_details_and_se_fields: %s fields do not "
                               "match across %s and %s APIs. "
                               "match across runtime and runtime/detail APIs. Runtime: \n%s. "
                               "\n\nRuntime details: \n%s.")
        error_msg_rt_det_se = ("validate_runtime_details_and_se_fields: %s fields do not "
                               "match across runtime/detail and serviceengine APIs. Runtime details: \n%s. "
                               "\n\nSE API: \n%s")
        error_msg_rt_se = ("validate_runtime_details_and_se_fields: %s fields do not "
                           "match across runtime and serviceengine APIs. Runtime: \n%s. \n\nSE API: \n%s")

        if not (self.runtime_data.get("inband_mgmt", None) ==
                self.runtime_details_data.get("inband_mgmt", None)):
            output.append(error_msg_rt_rt_det %
                          ("inband_mgmt",
                           self.runtime_data.get("inband_mgmt", None),
                           self.runtime_details_data.get("inband_mgmt", None)))
        if not (self.runtime_details_data.get("inband_mgmt", None) ==
                self.se_data.get("inband_mgmt", None)):
            output.append(error_msg_rt_det_se %
                          ("inband_mgmt",
                           self.runtime_details_data.get("inband_mgmt", None),
                           self.se_data.get("inband_mgmt", None)))
        if not (self.se_data.get("inband_mgmt", None) ==
                self.runtime_data.get("inband_mgmt", None)):
            output.append(error_msg_rt_se %
                          ("inband_mgmt",
                           self.runtime_data.get("inband_mgmt", None),
                           self.se_data.get("inband_mgmt", None)))
        if not (self.runtime_data.get("gateway_up", None) ==
                self.runtime_details_data.get("gateway_up", None)):
            output.append(error_msg_rt_rt_det %
                          ("gateway_up",
                           self.runtime_data.get("gateway_up", None),
                           self.runtime_details_data.get("gateway_up", None)))
        if not (self.runtime_details_data.get("gateway_up", None) ==
                self.se_data.get("gateway_up", None)):
            output.append(error_msg_rt_det_se %
                          ("gateway_up",
                           self.runtime_details_data.get("gateway_up", None),
                           self.se_data.get("gateway_up", None)))
        if not (self.runtime_data.get("gateway_up", None) ==
                self.se_data.get("gateway_up", None)):
            output.append(error_msg_rt_se %
                          ("gateway_up",
                           self.runtime_data.get("gateway_up", None),
                           self.se_data.get("gateway_up", None)))
        if not (self.runtime_data.get("self.se_connected", None) ==
                self.runtime_details_data.get("self.se_connected", None)):
            output.append(error_msg_rt_rt_det %
                          ("self.se_connected",
                           self.runtime_data.get("self.se_connected", None),
                           self.runtime_details_data.get("self.se_connected", None)))
        if not (self.runtime_details_data.get("self.se_connected", None) ==
                self.se_data.get("self.se_connected", None)):
            output.append(error_msg_rt_det_se %
                          ("self.se_connected",
                           self.runtime_details_data.get("self.se_connected", None),
                           self.se_data.get("self.se_connected", None)))
        if not (self.runtime_data.get("self.se_connected", None) ==
                self.se_data.get("self.se_connected", None)):
            output.append(error_msg_rt_se %
                          ("self.se_connected",
                           self.runtime_data.get("self.se_connected", None),
                           self.se_data.get("self.se_connected", None)))
        if not (self.runtime_data.get("at_curr_ver", None) ==
                self.runtime_details_data.get("at_curr_ver", None)):
            output.append(error_msg_rt_rt_det %
                          ("at_curr_ver",
                           self.runtime_data.get("at_curr_ver", None),
                           self.runtime_details_data.get("at_curr_ver", None)))
        if not (self.runtime_details_data.get("at_curr_ver", None) ==
                self.se_data.get("at_curr_ver", None)):
            output.append(error_msg_rt_det_se %
                          ("at_curr_ver",
                           self.runtime_details_data.get("at_curr_ver", None),
                           self.se_data.get("at_curr_ver", None)))
        if not (self.runtime_data.get("at_curr_ver", None) ==
                self.se_data.get("at_curr_ver", None)):
            output.append(error_msg_rt_se %
                          ("at_curr_ver",
                           self.runtime_data.get("at_curr_ver", None),
                           self.se_data.get("at_curr_ver", None)))
        if not (self.runtime_data["oper_status"].get("state", None) ==
                self.runtime_details_data["oper_status"].get("state", None)):
            output.append(error_msg_rt_rt_det %
                          ("oper_status.state",
                           self.runtime_data["oper_status"].get("state", None),
                           self.runtime_details_data["oper_status"].get("state", None)))
        if not (self.runtime_data["oper_status"].get("state", None) == self.oper_state):
            output.append(("validate_runtime_details_and_se_fields: "
                           "oper_status.state fields do not match the provided oper state. "
                           "Runtime : \n%s.\n\nProvided oper state : \n%s.") %
                          (self.runtime_data["oper_status"].get("state", None), self.oper_state))
        if not (self.runtime_details_data["oper_status"].get("state", None) ==
                self.oper_state):
            output.append(("validate_runtime_details_and_se_fields: "
                           "oper_status.state fields do not match the provided oper state. "
                           "Runtime details : \n%s.\n\nProvided oper state : \n%s.") %
                          (self.runtime_details_data["oper_status"].get("state", None),
                           self.oper_state))
        if not (self.runtime_data.get("version", None) ==
                self.runtime_details_data.get("version", None)):
            output.append(error_msg_rt_rt_det %
                          ("version",
                           self.runtime_data.get("version", None),
                           self.runtime_details_data.get("version", None)))
        if not (self.runtime_details_data.get("version", None) ==
                self.se_data.get("version", None)):
            output.append(error_msg_rt_det_se %
                          ("version",
                           self.runtime_details_data.get("version", None),
                           self.se_data.get("version", None)))
        if not (self.runtime_data.get("version", None) ==
                self.se_data.get("version", None)):
            output.append(error_msg_rt_se %
                          ("version",
                           self.runtime_data.get("version", None),
                           self.se_data.get("version", None)))
        if not (self.runtime_data.get("vinfra_discovered", False) ==
                self.runtime_details_data.get("vinfra_discovered", False)):
            output.append(error_msg_rt_rt_det %
                          ("vinfra_discovered",
                           self.runtime_data.get("vinfra_discovered", False),
                           self.runtime_details_data.get("vinfra_discovered", False)))
        if not (self.runtime_details_data.get("vinfra_discovered", False) ==
                self.se_data.get("vinfra_discovered", False)):
            output.append(error_msg_rt_det_se %
                          ("vinfra_discovered",
                           self.runtime_details_data.get("vinfra_discovered", False),
                           self.se_data.get("vinfra_discovered", False)))
        if not (self.runtime_data.get("vinfra_discovered", False) ==
                self.se_data.get("vinfra_discovered", False)):
            output.append(error_msg_rt_se %
                          ("vinfra_discovered",
                           self.runtime_data.get("vinfra_discovered", False),
                           self.se_data.get("vinfra_discovered", False)))
        if "counters" in self.runtime_details_data and "counters" in self.se_data:
            if not (self.runtime_details_data["counters"].get("se_down_cnt", 0) ==
                    self.se_data["counters"].get("se_down_cnt", 0)):
                output.append(("validate_runtime_details_and_se_fields: "
                               "counter.se_down_cnt fields do not match across runtime/details "
                               "and serviceengine APIs. Runtime details : \n%s.\n\nSE API : \n%s") %
                              (self.runtime_details_data["counters"].get("se_down_cnt", 0),
                               self.se_data["counters"].get("se_down_cnt", 0)))
            if not (self.runtime_details_data["counters"].get("reg_fail_cnt", 0) ==
                    self.se_data["counters"].get("reg_fail_cnt", 0)):
                output.append(("validate_runtime_details_and_se_fields: "
                               "countr.reg_fail_cnt fields do not match across runtime/details"
                               " and serviceengine APIs. Runtime details : \n%s.\n\nSE API : \n%s") %
                              (self.runtime_details_data["counters"].get("se_down_cnt", 0),
                               self.se_data["counters"].get("se_down_cnt", 0)))
            if not (self.runtime_details_data["counters"].get("se_up_cnt", 0) ==
                    self.se_data["counters"].get("se_up_cnt", 0)):
                output.append(("validate_runtime_details_and_se_fields: "
                               "counter.se_up_cnt fields do not match across runtime/details "
                               "and serviceengine APIs. Runtime details : \n%s.\n\nSE API : \n%s") %
                              (self.runtime_details_data["counters"].get("se_up_cnt", 0),
                               self.se_data["counters"].get("se_up_cnt", None)))
            if not (self.runtime_details_data["counters"].get("reg_cnt", 0) ==
                    self.se_data["counters"].get("reg_cnt", 0)):
                output.append(("validate_runtime_details_and_se_fields: "
                               "counter.reg_cnt fields do not match across runtime/details "
                               "and serviceengine APIs. Runtime details : \n%s.\n\nSE API : \n%s") %
                              (self.runtime_details_data["counters"].get("reg_cnt", 0),
                               self.se_data["counters"].get("reg_cnt", 0)))
        return output

    def __validate_runtime_details_and_seagent(self):
        output = []
        error_msg = ("validate_runtime_details_and_seagent: runtime/details.%s "
                     "does not match seagent.%s. runtime/details.%s: \n%s. "
                     "\n\nseagent.%s : \n%s")

        if not self.se_connected:
            return []

        if not (self.runtime_details_data.get("gateway_up", None) ==
                self.seagent_data[0].get("gw_monitor_status_up", None)):
            output.append(error_msg % ("gateway_up", "gw_monitor_status_up",
                                       "gateway_up", self.runtime_details_data.get("gateway_up", None),
                                       "gw_monitor_status_up",
                                       self.seagent_data[0].get("gw_monitor_status_up", None)))
        if "resources" in self.runtime_details_data:
            if not (self.runtime_details_data["resources"].get("memory", None) ==
                    self.seagent_data[0].get("mem_mb", None)):
                output.append(error_msg % ("resources.memory", "mem_mb",
                                           "resources.memory",
                                           self.runtime_details_data["resources"].get("memory", None),
                                           "mem_mb", self.seagent_data[0].get("mem_mb", None)))
            elif not (self.runtime_details_data["resources"].get("num_vcpus", None) ==
                      self.seagent_data[0].get("num_cpu", None)):
                output.append(("validate_runtime_details_and_seagent: runtime/"
                               "details.resources.num_vcpus does not match seagent.num_cpu. "
                               "runtime/details.resources.num_vcpus : %s. "
                               "seagent.num_cpu : %s.") %
                              (self.runtime_details_data["resources"].get("num_vcpus", None),
                               self.seagent_data[0].get("num_cpu", None)))
        else:
            output.append(("validate_runtime_details_and_seagent: "
                           "The resources field is missing in runtime/details."))
        return output

    def __validate_placement_and_se_fields(self):
        output = []
        error_msg = ("validate_placement_and_se_fields: Validation for the set of "
                     "vnics across controller and SE placement APIs failed. ")

        if self.se_data.get("inband_mgmt", None):
            # Placement API has both data and mgmt VNICs
            se_vnics = [self.se_data["mgmt_vnic"]] + self.se_data.get("data_vnics", [])
        else:
            se_vnics = self.se_data.get("data_vnics", [])

        placement_vnics = self.placement_data.get("vnics", [])
        mac_list = []
        for x in placement_vnics:
            mac_list.append(x['mac_addr'])

        # Validate if the same vnics are in both lists
        for each_vnic in se_vnics:
            if each_vnic['mac_address'] not in mac_list:
                output.append((error_msg +
                               "Vnic with MAC address %s does not exist in %s.") %
                              (each_vnic['mac_address'], self.vnicdb_uri))

        # Validate if the values of fields are equal for the vnics in both lists
        for each_vnic in se_vnics:
            # If SE is warm starting skip vnic checks
            if self.placement_data.get('warm_starting', False):
                break

            try:
                matching_vnic = next(
                    x for x in placement_vnics
                    if x['mac_addr'] == each_vnic['mac_address'])
            except StopIteration:
                logger.info(("validate_placement_and_se_fields: There is no "
                             "placement vnic with mac_address %s") % each_vnic['mac_address'])
                output.append(("validate_placement_and_se_fields: There is no "
                               "placement vnic with mac_address %s") % each_vnic['mac_address'])
                continue

            vrf_uuid = get_uuid_from_ref(each_vnic.get("vrf_ref", None))
            # If vrf_ref = None, vrf_uuid = None. But placement API value = ''
            vrf_uuid = '' if not vrf_uuid else vrf_uuid

            if not (matching_vnic.get("is_avi_internal_network", None) ==
                    each_vnic.get("is_avi_internal_network", None)):
                output.append(error_msg +
                              "is_avi_internal_network fields do not match for "
                              "vnics. Controller : %s.\n\n SE : %s." % (matching_vnic, each_vnic))
            if not (matching_vnic.get("linux_name", None) ==
                    each_vnic.get("linux_name", None)):
                output.append(error_msg +
                              "linux_name fields do not match for vnics."
                              "Controller : %s. \n\nSE : %s." %
                              (matching_vnic, each_vnic))
            if not (matching_vnic.get("enabled", None) ==
                    each_vnic.get("enabled", None)):
                output.append(error_msg +
                              "enabled fields do not match for vnics." 
                              "Field1 :%s. \n\nSE : %s." %
                              (matching_vnic, each_vnic))
            if not (matching_vnic.get("connected", None) ==
                    each_vnic.get("connected", None)):
                output.append(error_msg +
                              "connected fields do not match for vnics. " 
                              "Controller : %s.\n\nSE : %s." %
                              (matching_vnic, each_vnic))
            if not (matching_vnic.get("vrf_uuid", None) == vrf_uuid):
                output.append(error_msg +
                              "vrf_uuid fields do not match for vnics. " 
                              "Controller : %s.\n\nSE : %s." %
                              (matching_vnic, each_vnic))

        # Validate fields in placement and SE data
        error_msg = ("validate_placement_and_se_fields: Validation for fields "
                     "across controller and SE placement APIs failed. ")
        if "resources" in self.se_data:
            if not (self.se_data["resources"].get("memory", None) ==
                    self.placement_data.get("memory", None)):
                output.append((error_msg + "resources.memory and memory fields do "
                                           "not match. Controller API: \n%s.\n\n SE Placement API: \n%s.") %
                              (self.se_data["resources"].get("memory", None),
                               self.placement_data.get("memory", None)))
            if not (self.se_data["resources"].get("disk", None) ==
                    self.placement_data.get("disk_gb", None)):
                output.append((error_msg + "resources.disk and disk_gb fields do "
                                           "not match. Controller API: \n%s. \n\nSE Placement API: \n%s.") %
                              (self.se_data["resources"].get("disk", None),
                               self.placement_data.get("disk_gb", None)))
            if not (self.se_data["resources"].get("num_vcpus", None) ==
                    self.placement_data.get("vcpus", None)):
                output.append((error_msg + "resources.num_vcpus and vcpus fields do "
                                           "not match. Controller API: \n%s. \n\nSE Placement API: \n%s.") %
                              (self.se_data["resources"].get("num_vcpus", None),
                               self.placement_data.get("vcpus", None)))
        else:
            output.append("Resources fields is missing in the controller API data.")

        if self.placement_data.get("hypervisor", None) == "VMWARE_ESX":
            pass
        elif not (self.se_data.get("hypervisor", None) ==
                  self.placement_data.get("hypervisor", None)):
            output.append((error_msg + "Hypervisor fields do not match. "
                                       "Controller API: \n%s. \n\nSE Placement API: \n%s.") %
                          (self.se_data.get("hypervisor", None),
                           self.placement_data.get("hypervisor", None)))
        if not (self.se_data.get("gateway_up", False) ==
                self.placement_data.get("gateway_up", False)):
            output.append((error_msg + "gateway_up fields do not match. "
                                       "Controller API: \n%s. \n\nSE Placement API: \n%s.") %
                          (self.se_data.get("gateway_up", False),
                           self.placement_data.get("gateway_up", False)))
        if not (self.se_data.get("at_curr_ver", False) ==
                self.placement_data.get("at_curr_ver", False)):
            output.append((error_msg + "at_curr_ver fields do not match. "
                                       "Controller API: \n%s. \n\nSE Placement API: \n%s.") %
                          (self.se_data.get("at_curr_ver", False),
                           self.placement_data.get("at_curr_ver", False)))
        if not (self.se_data.get("version", None) ==
                self.placement_data.get("version", None)):
            output.append((error_msg + "version fields do not match. "
                                       "Controller API: \n%s. \n\nSE Placement API: \n%s.") %
                          (self.se_data.get("version", None),
                           self.placement_data.get("version", None)))
        if not (self.se_data.get("se_group_ref", None) ==
                self.placement_data.get("se_group_ref", None)):
            output.append((error_msg + "se_group_ref fields do not match. "
                                       "Controller API: \n%s. \n\nSE Placement API: \n%s.") %
                          (self.se_data.get("se_group_ref", None),
                           self.placement_data.get("se_group_ref", None)))

        # Validate SE placement ips, ip_mac_addr and ip_masks against SE data_vnics
        placement_ips = self.placement_data.get("ips", [])
        placement_ip_mac_addr = self.placement_data.get("ip_mac_addr", [])
        placement_ip_masks = self.placement_data.get("ip_masks", [])
        self.data_vnics_with_ips = [x for x in self.se_data.get("data_vnics", [])
                                    if "vnic_networks" in x]

        for i in range(0, len(placement_ips)):
            # If SE is warm starting skip vnic ip checks
            if self.placement_data.get('warm_starting', False):
                break

            try:
                matching_vnic = next(
                    x for x in self.data_vnics_with_ips
                    if x["mac_address"] == placement_ip_mac_addr[i])
            except StopIteration:
                logger.info(("validate_placement_and_se_fields: There is no data "
                             "vnic with mac_address %s.") % placement_ip_mac_addr[i])
                output.append(("validate_placement_and_se_fields: There is no data "
                               "vnic with mac_address : %s.") % placement_ip_mac_addr[i])
                continue

            try:
                vnic_match = next(x for x in matching_vnic["vnic_networks"]
                                  if x["ip"]["ip_addr"]["addr"] == placement_ips[i]["addr"])
            except StopIteration:
                logger.info(("validate_placement_and_se_fields: There is no vnic IP "
                             "with matching IP %s.") % placement_ips[i]["addr"])
                output.append(("validate_placement_and_se_fields: There is no vnic IP "
                               "with matching IP : %s.") % placement_ips[i]["addr"])
                continue

            if not (placement_ip_masks[i] == vnic_match["ip"]["mask"]):
                output.append((error_msg +
                               "IP netmask fields do not match for vnics with MAC address : %s")
                              % placement_ip_mac_addr[i])
        return output

    def __validate_placement_and_graphdb_vs(self):
        output = []
        error_msg = ("validate_placement_and_graphdb_vs: Validation of SE "
                     "Placement and GraphDB APIs failed. ")

        if not self.se_connected:
            return []

        placement_vs_list = self.placement_data.get("resources_consumed", [])
        graphdb_vs = self.graphdb_data.get("virtualservice", None)
        graphdb_vs_num_obj = graphdb_vs.get("num_obj", 0) if graphdb_vs else 0
        graphdb_vs_num_obj_active = graphdb_vs.get("num_obj_active", 0) if graphdb_vs else 0
        graphdb_vs_list = graphdb_vs.get("obj", []) if graphdb_vs else []

        east_west_vs_list = []

        for each in graphdb_vs_list:
            if each.get("config")["virtual_service_se"]["virtual_service"]["east_west_placement"]:
                east_west_vs_list.append(each)
        east_west_vs_count = len(east_west_vs_list)
        placement_vs_count = len(placement_vs_list)

        if east_west_vs_count:
            placement_vs_count += east_west_vs_count

        # Validate that the lengths are the same
        if east_west_vs_count == 0:
            if not (placement_vs_count == graphdb_vs_num_obj ==
                        graphdb_vs_num_obj_active == len(graphdb_vs_list)):
                output.append((error_msg + "The lengths of placement.resources_"
                                           "consumed (%s), graphdb.virtualservice.num_obj (%s), graphdb."
                                           "virtualservice.obj (%s) and graphdb.virtualservice.num_obj_"
                                           "active (%s) are different.") % (str(placement_vs_count), graphdb_vs_num_obj,
                                                                            graphdb_vs_num_obj_active,
                                                                            str(len(graphdb_vs_list))))
                output.append(("validate_placement_and_graphdb_vs: The rest of "
                               "the checks will be skipped."))
                return output

        matching_vs = []
        # Validate that the sets of VSes match exactly
        for each_vs in placement_vs_list:
            uuid = get_uuid_from_ref(each_vs.get("consumer_ref", None))
            status_code, vs_data = get('virtualservice', uuid=uuid)
            if vs_data.get('east_west_placement', None):
                continue
            try:
                for each in graphdb_vs_list:
                    if not each.get("config")["virtual_service_se"]["virtual_service"]["east_west_placement"]:
                        if each.get("config")["virtual_service_se"]["uuid"] == uuid:
                            matching_vs.append(each)
            except StopIteration:
                logger.info(("validate_placement_and_graphdb_vs: There is no "
                             "matching VS with uuid %s.") % uuid)
                output.append(("validate_placement_and_graphdb_vs: There is no "
                               "matching VS with uuid : %s.") % uuid)
                continue

            if not matching_vs:
                output.append((error_msg + "There is not a matching virtualservice "
                                           "with uuid : %s in graphdb.virtualservice.obj.") % uuid)
        return output


    def __validate_graphdb_and_controller_fields_with_retry(self):
        output = []
        out, res = self.__validate_graphdb_and_controller_fields()
        if out == "not connected":
            return []
        if not res:
            for itr in range(3):
                status_code8, temp_graphdb_data = get(self.graphdb_uri)
                self.graphdb_data = temp_graphdb_data[0] if self.se_connected else []
                out, res = self.__validate_graphdb_and_controller_fields()
                if res:
                    output = []
                    break
                output += out
        return output

    def __validate_graphdb_and_controller_fields(self):
        output = []

        if not self.se_connected:
            return "not connected", False

        for each_key in self.graphdb_data.keys():
            if type(self.graphdb_data.get(each_key)) == dict:
                key_val = self.graphdb_data.get(each_key)
                obj_list = key_val.get("obj", [])

                for each_obj in obj_list:
                    if not each_obj["status"] == "SYSERR_SEAGENT_OBJ_ACTIVE":
                        output.append(("validate_graphdb_and_controller_fields: "
                                       "Status in %s is : \n%s. \n\nReason : \n%s.") %
                                      (each_key, each_obj["status"], each_obj["reason"]))

                    obj_key = each_obj["config"].keys()[0]
                    obj_uuid = each_obj["config"][obj_key]["uuid"]
                    if obj_key == "virtual_service_se":
                        # Special case
                        obj_data = each_obj["config"][obj_key]["virtual_service"]
                    else:
                        obj_data = each_obj["config"][obj_key]

                    output, res = self.__compare_controller_and_graphdb_data(
                        obj_uuid, obj_data, each_key)
                    if not res:
                        return output, False

        return output, True

    def __compare_controller_and_graphdb_data(self, uuid, data, obj_type):
        output = []
        code, obj_controller_data = get("%s/%s" % (obj_type, uuid))
        error_msg = ("validate_graphdb_and_controller_fields: Validation of SE "
                     "GraphDB and %s API failed. ")
        skip_fields = ['vip']

        for each in data.keys():
            if each not in obj_controller_data.keys():
                output.append((error_msg +
                               "The field %s is missing in the controller API.") %
                              (obj_type, each))
            else:
                if each in skip_fields:
                    continue
                #currently this works for one level of un-ordered list, may need to enhance in future for multiple levels
                elif not obj_controller_data[each] == data[each]:
                    if isinstance(data[each], list) and isinstance(obj_controller_data[each], list):
                        for data_item in data[each]:
                            if data_item in obj_controller_data[each]:
                                continue
                            else:
                                output.append((error_msg + "The values for %s do not match. "
                                               "SE graphdb.%s API: \n%s.\n\nController API: \n%s.") %
                                  (obj_type, obj_type, obj_type, data[each], obj_controller_data[each]))
                                return output, False
                    else:
                        output.append((error_msg + "The values for %s do not match. "
                                                "SE graphdb. %s API : \n%s. \n\nController API : \n%s.") %
                                  (obj_type, obj_type, obj_type, data[each], obj_controller_data[each]))
                        return output, False

        return output, True

    def __validate_graphdb_and_placement_ses(self):
        output = []
        error_msg = ("validate_graphdb_and_placement_ses: Validation of SE GraphDB"
                     "and Placement APIs failed. ")

        if not self.se_connected:
            return []
        placement_se_list = self.placement_data.get("resources_consumed", [])
        graph_vs = self.graphdb_data.get("virtualservice")
        vs_data = graph_vs.get("obj", []) if graph_vs else []
        #vs_se_list = []
        for x in vs_data:
            #vs_se_list = x["config"]["virtual_service_se"].get("se_list", [])
            uuid = x["config"]["virtual_service_se"]["uuid"]
            logger.debug("eastwest: %s" %
                         x["config"]["virtual_service_se"]["virtual_service"].get("east_west_placement", False))
            if x["config"]["virtual_service_se"]["virtual_service"].get("east_west_placement", False):
                logger.debug("%s east_west, ignore" % uuid)
                continue
            vs_se_list = x["config"]["virtual_service_se"].get("se_list", [])
            placement_se = None
            graphdb_se = None
            for each_se in vs_se_list:
                for v in placement_se_list:
                    if v["res_ref"] == each_se["se_ref"]:
                        if get_uuid_from_ref(v["consumer_ref"]) == uuid:
                            placement_se = v
                            graphdb_se = each_se
                            break
                if placement_se:
                    break
            if not placement_se:
                output.append(("validate_graphdb_and_placement_ses: Placement Resources API is missing SE entry %s for "
                               " VS %s") % (self.se_uuid, uuid))
            else:
                if not graphdb_se["is_primary"] == placement_se["is_primary"]:
                    output.append((error_msg + "The is_primary fields do not match. "
                                               "GraphDB : \n%s. \n\nPlacement : \n%s.") %
                                  (graphdb_se["is_primary"], placement_se["is_primary"]))
                if not graphdb_se["is_standby"] == placement_se["is_stby"]:
                    output.append((error_msg + "The is_standby fields do not match. "
                                               "GraphDB : \n%s. \n\nPlacement : \n%s.") %
                                  (graphdb_se["is_standby"], placement_se["is_stby"]))
                if "vip_intf_list" in graphdb_se and "vip_intf_list" in placement_se:
                    if not (graphdb_se["vip_intf_list"][0].get("vip_intf_ip", None) ==
                                placement_se["vip_intf_list"][0].get("vip_intf_ip", None)):
                        output.append((error_msg +
                                       "The vip_intf_list.vip_intf_ip "
                                       "fields do not match. GraphDB : \n%s. \n\nPlacement : \n%s.") %
                                      (graphdb_se["vip_intf_list"][0].get("vip_intf_ip", None),
                                       placement_se["vip_intf_list"][0].get("vip_intf_ip", None)))
                    if not (graphdb_se["vip_intf_list"][0].get("vip_intf_mac", None) ==
                                placement_se["vip_intf_list"][0].get("vip_intf_mac", None)):
                        output.append((error_msg +
                                       "The vip_intf_list.vip_intf_mac "
                                       "fields do not match. GraphDB : \n%s. \n\nPlacement : \n%s.") %
                                      (graphdb_se["vip_intf_list"][0].get("vip_intf_mac", None),
                                       placement_se["vip_intf_list"][0].get("vip_intf_mac", None)))
                    if not (graphdb_se["vip_intf_list"][0].get("is_portchannel", False) ==
                                placement_se["vip_intf_list"][0].get("is_portchannel", False)):
                        output.append((error_msg +
                                       "The vip_intf_list.is_portchannel "
                                       "fields do not match. GraphDB : \n%s. \n\nPlacement : \n%s.") %
                                      (graphdb_se["vip_intf_list"][0].get("is_portchannel", False),
                                       placement_se["vip_intf_list"][0].get("is_portchannel", False)))                    
        
        return output

    def __validate_vnicdb_and_se_dp_vrf_count(self):
        output = []
        error_msg = ("validate_vnicdb_and_se_dp_vrf_count: Validate count"
                     " of SE VRF between VNIC DB and SE DP failed. ")
        vnicdb_vrfcontext = []

        if not self.se_connected:
            return []

        for each in self.se_vnicdb_data[0]["vrf"]:
            if each["vrf_context"]["name"] != "seagent-default":
                vnicdb_vrfcontext.append(each["vrf_context"])

        vnicdb_vrfcontext_count=len(vnicdb_vrfcontext) # Taking count of vrfcontext in vnicdb api
        
        for each in self.mallocstats_data[0]["mallocstat_entry"]:
            if each["malloc_type_name"] == "SE_MTYPE_OS_RSVD_NS_HELPER":
                se_dp_count = each["malloc_type_cnt"]

        if not vnicdb_vrfcontext_count == se_dp_count:
            output.append((error_msg + "VRFs count do not match between vnicdb and se_dp."
            " \nCount of vrfs in VNICDB: [%s] \nCount of vrfs in SE_DP: [%s]") % (vnicdb_vrfcontext_count, se_dp_count))

        return output

    def __validate_se_and_vnicdb_vrf_set_and_count(self):
        output = []
        error_msg = ("validate_se_and_vnicdb_vrf_set_and_count: Validate list of vrfcontext"
                     " matches between SE and VNIC DB with count and set of VRFs failed. ")
        vnicdb_vrfcontext = []

        if not self.se_connected:
            return []

        for each in self.se_vnicdb_data[0]["vrf"]:
            if each["vrf_context"]["name"] != "seagent-default":
                vnicdb_vrfcontext.append(each["vrf_context"])

        vnicdb_vrfcontext_count = len(vnicdb_vrfcontext) # Taking count of vrfcontext in vnicdb api

        vrf_uuid_vnicdb=[]  #catching the uuids for vrfcontexts in vnicdb

        for each in vnicdb_vrfcontext:
            vrf_uuid_vnicdb.append(each["uuid"])

        vrf_uuids=[]         #catching vrf_refs' uuids from the serviceengine data_vnics

        for each in self.se_data.get("data_vnics", []):
            # Skip checking vrf_ref = None, ''
            if each.get('vrf_ref', None):
                vrf_uuids.append(get_uuid_from_ref(each["vrf_ref"]))

        vrf_uuids=list(set(vrf_uuids))  #removing the duplicate vrf_refs' uuids which has been fetched from the data_vnics in serviceengine api
        vrf_uuids_count = len(vrf_uuids) #Taking count of vrfcontext vrf_refs uuids in serviceengine api

        if not vnicdb_vrfcontext_count == vrf_uuids_count:
            output.append((error_msg + "VRFs count do not match between vnicdb and serviceengine."
                                       " \nCount of vrfs in VNICDB: [%s] \nCount of vrfs in Serviceengine: [%s]") %
                          (vnicdb_vrfcontext_count, vrf_uuids_count))

        if not (set(vrf_uuid_vnicdb) == set(vrf_uuids) and len(vrf_uuid_vnicdb) == len(vrf_uuids)):
            output.append((error_msg + "VRFs contexts do not match between vnicdb and serviceengine."
                                       " \nvrfs in VNICDB: [%s] \nvrfs in Serviceengine: [%s]") %
                          (vrf_uuid_vnicdb, vrf_uuids))

        return output
    # Copied from PR #13605

    def __get_se_state(self, se_uuid, expected_se_state):
        self.se_data = get_se_runtime_summary(se_uuid=se_uuid)
        if self.se_data["oper_status"]['state'] == expected_se_state:
            return True
        return False

    def __wait_for_expected_se_state(self, se_uuid, expected_se_state):
        
        no_of_retrys = self.timeout / 10

        @aretry(retry=no_of_retrys, delay=10, period=5)
        def aretry_fun():
            if not self.__get_se_state(se_uuid, expected_se_state):
                error('SE not in expected state after retry timeout of ')
        aretry_fun()


def se_check(se_uuid, oper_state, timeout=100):
    se_obj = SEWellnessCheck(se_uuid, oper_state, timeout)
    se_obj.se_check()


def all_se_is_well(se_group='Default-Group'):
    se_list = get_se_list_in_group(se_group)
    if not se_list:
        error("No SE found in se_group[%s]" % se_group)
        return
    logger.debug("SE list in se_group[%s] is: %s" % (se_group, str(se_list)))
    for se_uuid in se_list:
        se_check(se_uuid, 'OPER_UP')
    return True
