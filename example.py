import sys

from smtplib import (
    SMTPSenderRefused,
    SMTPRecipientsRefused,
    SMTPDataError,
    SMTPHeloError
)

from aruba_snmp import *

from includes.lapwing_config import LapwingConfig
config = LapwingConfig()


# ...

master_controllers_8 = config.master_controllers_8
snmp_v3_user = config.snmp_v3_user
snmp_v3_authkey = config.snmp_v3_authkey
snmp_v3_privkey = config.snmp_v3_privkey

snmp_master_controllers_8 = []
for host_ip in master_controllers_8:
    snmp_master_controllers_8.append(SnmpController('v3', host_ip=host_ip, user=snmp_v3_user, authkey=snmp_v3_authkey, privkey=snmp_v3_privkey))

try:
    all_controllers_8 = get_all_controllers_snmp(snmp_master_controllers_8)
except SnmpError:
    sys.exit("Could not get AOS 8 controllers from " + str(master_controllers_8[0]))

snmp_controllers = []
for host_ip in all_controllers_8:
    snmp_controllers.append(SnmpController('v3', host_ip=host_ip, user=snmp_v3_user, authkey=snmp_v3_authkey, privkey=snmp_v3_privkey))

try:
    aps_result = multiget_aps_uptime(snmp_controllers)
except SnmpError:
    sys.exit("Could not get APs from controller" )
	
radios_result = multiget(snmp_controllers, Radios)
stations_result = multiget(snmp_controllers, Stations)

# ...
