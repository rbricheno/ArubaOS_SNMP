from pysnmp.hlapi import *
from threading import Thread

debug = False
mini_debug = False

OID_wlsxSwitchListEntry = '1.3.6.1.4.1.14823.2.2.1.1.1.6.1'      # list of controllers managed by this master
OID_wlanAPUpTime        = '1.3.6.1.4.1.14823.2.2.1.5.2.1.4.1.12' # uptimes of the APs on this controller
OID_wlanAPRadioType     = '1.3.6.1.4.1.14823.2.2.1.5.2.1.5.1.2'  # MAC addresses of radios from a pre-AOS 6.4 controller
OID_wlanAPBssidPhyType  = '1.3.6.1.4.1.14823.2.2.1.5.2.1.7.1.5'  # MAC addresses of radios from an AOS 6.4+ controller
OID_wlanAPESSID         = '1.3.6.1.4.1.14823.2.2.1.5.2.1.7.1.2'  # list of ESSIDs on this controller and their MAC addresses
OID_staUserName         = '1.3.6.1.4.1.14823.2.2.1.1.2.2.1.3'    # user names of connected users on this controller
OID_staUserRole         = '1.3.6.1.4.1.14823.2.2.1.1.2.2.1.4'    # user roles of connected users on this controller

class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class SnmpError(Error):
    """An error which occurs during SNMP communication"""
    pass


class SnmpController():
    def __init__(self, version, host_ip=None, community=None, user=None, authkey=None, privkey=None):
        self.version = version
        self.host_ip = host_ip
        if host_ip is None:
            raise SnmpError
        self.community = community
        self.user = user
        self.authkey = authkey
        self.privkey = privkey
        if version == 'v2c':
            if self.community is None:
                raise SnmpError
        elif version == 'v3':
            if self.user is None or self.authkey is None or self.privkey is None:
                raise SnmpError
        else:
            raise SnmpError

    def get_results(self, oid):
        if self.version == 'v2c':
            return self.v2c_get_results(oid)
        elif self.version == 'v3':
            return self.v3_get_results(oid)
        else:
            raise SnmpError

    def v2c_get_results(self, oid):
        the_command = nextCmd(
            SnmpEngine(),
            CommunityData(self.community),
            UdpTransportTarget((self.host_ip, 161), timeout=10),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False)
        results = []

        for error_indication, error_status, error_index, var_binds in the_command:
            results.append(var_binds[0])
        try:
            if error_indication:
                if 'timeout' in str(error_indication):
                    if debug or mini_debug:
                        print(error_indication)
                else:
                    if debug or mini_debug:
                        print(error_indication)
                        print(error_status)
                        print(error_index)
                        print(var_binds)
                    raise SnmpError()
        except UnboundLocalError:
            pass
        return results

    def v3_get_results(self, oid):
        the_command = nextCmd(
            SnmpEngine(),
            UsmUserData(self.user, self.authkey, self.privkey,
                authProtocol=usmHMACSHAAuthProtocol,
                privProtocol=usmAesCfb128Protocol),
            UdpTransportTarget((self.host_ip, 161), timeout=10),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False)
        results = []
        for error_indication, error_status, error_index, var_binds in the_command:
            results.append(var_binds[0])
        try:
            if error_indication:
                if 'timeout' in str(error_indication):
                    if debug or mini_debug:
                        print(error_indication)
                else:
                    if debug or mini_debug:
                        print(error_indication)
                        print(error_status)
                        print(error_index)
                        print(var_binds)
                    raise SnmpError()
        except UnboundLocalError:
            pass
        return results

def update_controllers_list_with_results(controllers_list, results):
    for name, val in results:
        name_str=str(name)
        parts = name_str.split(".")
        found_controller = parts[-4] + "." + parts[-3] + "." + parts[-2] + "." + parts[-1]
        controllers_list.append(found_controller)
    return controllers_list


def get_all_controllers_snmp(snmp_master_controllers):
    controllers_list = []
    for snmp_controller in snmp_master_controllers:
        controllers_list.append(snmp_controller.host_ip)
        results = snmp_controller.get_results(OID_wlsxSwitchListEntry)
        controllers_list = update_controllers_list_with_results(controllers_list, results)
    return controllers_list


class Uptimes(Thread):

    def __init__(self, snmp_controller):
        self.snmp_controller = snmp_controller
        self.aps = {}
        super(Uptimes, self).__init__()

    def run(self):
        if debug:
            print("Polling " + str(self.snmp_controller.host_ip) + " for aps")
        results = self.snmp_controller.get_results(OID_wlanAPUpTime)
        if debug:
            if not results:
                print("No results for " + str(self.snmp_controller.host_ip) + "!")
        for name, val in results:
            name_str = str(name)
            parts = name_str.split(".")
            mac = get_mac_from_parts(parts, -6)
            self.aps[mac] = val

def get_mac_from_parts(parts, initial_offset):
    return hex(int(parts[initial_offset])).split('x')[1].zfill(2) + ":" + \
                hex(int(parts[initial_offset + 1])).split('x')[1].zfill(2) + ":" + \
                hex(int(parts[initial_offset + 2])).split('x')[1].zfill(2) + ":" + \
                hex(int(parts[initial_offset + 3])).split('x')[1].zfill(2) + ":" + \
                hex(int(parts[initial_offset + 4])).split('x')[1].zfill(2) + ":" + \
                hex(int(parts[initial_offset + 5])).split('x')[1].zfill(2)


def multiget(snmp_controllers_list, get_class):
    if debug:
        print("Begin SNMP AP poll for " + get_class.__name__)
    aps = {}

    the_threads = []

    for snmp_controller in snmp_controllers_list:
        a_thread = get_class(snmp_controller)
        the_threads.append(a_thread)

    for a_thread in the_threads:
        a_thread.start()

    for a_thread in the_threads:
        a_thread.join()

    for a_thread in the_threads:
        for mac, val in a_thread.aps.items():
            aps[mac] = val

    return aps


def multiget_aps_uptime(snmp_controllers_list):
    get_class = Uptimes
    if debug:
        print("Begin SNMP AP poll for " + get_class.__name__)
    aps = {}

    the_threads = []

    for snmp_controller in snmp_controllers_list:
        a_thread = get_class(snmp_controller)
        the_threads.append(a_thread)

    for a_thread in the_threads:
        a_thread.start()

    for a_thread in the_threads:
        a_thread.join()

    for a_thread in the_threads:
        for mac, val in a_thread.aps.items():
            # Here we have to handle the fact that the AP may have been on several controllers.
            # We simply prefer the highest value of uptime.
            try:
                if aps[mac] < val:
                    aps[mac] = val
            except KeyError:
                aps[mac] = val

    return aps


class Radios(Thread):

    def __init__(self, snmp_controller):
        self.snmp_controller = snmp_controller
        self.aps = {}
        super(Radios, self).__init__()

    def run(self):
        if debug:
            print("Polling " + str(self.snmp_controller.host_ip) + " for radio types")
        results = self.snmp_controller.get_results(OID_wlanAPRadioType)
        if not results:
            results = self.snmp_controller.get_results(OID_wlanAPBssidPhyType)
        if debug:
            if not results:
                print("No radio results for " + str(self.snmp_controller.host_ip) + "!")
        for name, val in results:
            name_str = str(name)
            parts = name_str.split(".")
            ap_mac = get_mac_from_parts(parts, -7)
            if ap_mac not in self.aps:
                self.aps[ap_mac] = {}
            radio = int(parts[-1])
            if radio not in self.aps[ap_mac]:
                self.aps[ap_mac][radio] = {}
            self.aps[ap_mac][radio]['type'] = str(val)
            self.aps[ap_mac][radio]['essids'] = []

        if debug:
            print("Polling " + str(self.snmp_controller.host_ip) + " for essids")
        results = self.snmp_controller.get_results(OID_wlanAPESSID)

        if debug:
            if not results:
                print("No ESSID results for " + str(self.snmp_controller.host_ip) + "!")

        for name, val in results:
            name_str = str(name)
            parts = name_str.split(".")
            ap_mac = get_mac_from_parts(parts, -13)
            if ap_mac not in self.aps:
                self.aps[ap_mac] = {}
            radio = int(parts[-7])
            if radio not in self.aps[ap_mac]:
                self.aps[ap_mac][radio] = {}
            radio_mac = get_mac_from_parts(parts, -6)
            if 'essids' not in self.aps[ap_mac][radio]:
                self.aps[ap_mac][radio]['essids'] = []
            self.aps[ap_mac][radio]['essids'].append({'mac': radio_mac, 'essid': str(val)})


class Stations(Thread):

    def __init__(self, snmp_controller):
        self.snmp_controller = snmp_controller
        self.aps = {}
        super(Stations, self).__init__()

    def run(self):
        if debug:
            print("Polling " + str(self.snmp_controller.host_ip) + " for usernames")
        results = self.snmp_controller.get_results(OID_staUserName)
        if debug:
            if not results:
                print("No username results for " + str(self.snmp_controller.host_ip) + "!")

        for name, val in results:
            name_str = str(name)
            parts = name_str.split(".")
            ap_mac = get_mac_from_parts(parts, -6)
            if ap_mac not in self.aps:
                self.aps[ap_mac] = {}
            sta_mac = get_mac_from_parts(parts, -12)
            if sta_mac not in self.aps[ap_mac]:
                self.aps[ap_mac][sta_mac] = {}
            self.aps[ap_mac][sta_mac]['name'] = str(val)

        if debug:
            print("Polling " + str(self.snmp_controller.host_ip) + " for user roles")
        results = self.snmp_controller.get_results(OID_staUserRole)
        if debug:
            if not results:
                print("No userrole results for " + str(self.snmp_controller.host_ip) + "!")

        for name, val in results:
            name_str = str(name)
            parts = name_str.split(".")
            ap_mac = get_mac_from_parts(parts, -6)
            if ap_mac not in self.aps:
                self.aps[ap_mac] = {}
            sta_mac = get_mac_from_parts(parts, -12)
            if sta_mac not in self.aps[ap_mac]:
                self.aps[ap_mac][sta_mac] = {}
            self.aps[ap_mac][sta_mac]['role'] = str(val)
