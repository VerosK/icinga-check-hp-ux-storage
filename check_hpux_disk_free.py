#!/usr/bin/env python3
#
# Check HP UX disk usage with SNMP agent.
# This is an Icinga check
#
# (C) Věroš Kaplan, 2019
# License: Apache 2
#
# requirements: pysnmp>4.1
#

import argparse
import sys
try:
    from pysnmp.hlapi import *
except ImportError:
    print("Unable to import pysnmp. Make sure pysnmp is newer than 4.4")
    raise
import json

# mib sources
# http://www.mibdepot.com/cgi-bin/getmib3.cgi?r=hp&f=hp-unix.mib&v=v1&t=txt
#
MOUNT_NAME_OID = '1.3.6.1.4.1.11.2.3.1.2.2.1.10'
TOTAL_BLOCKS_OID = '1.3.6.1.4.1.11.2.3.1.2.2.1.5'
FREE_BLOCKS_OID = '1.3.6.1.4.1.11.2.3.1.2.2.1.6'
BLOCK_SIZE_OID = '1.3.6.1.4.1.11.2.3.1.2.2.1.7'
CONVERTS = dict(
    mount_name=dict(oid=MOUNT_NAME_OID,
                    convertor=str, type=OctetString),
    block_size=dict(oid=BLOCK_SIZE_OID,
                    convertor=int, type=Integer32),
    free_blocks=dict(oid=FREE_BLOCKS_OID,
                     convertor=int, type=Integer32),
    total_blocks=dict(oid=TOTAL_BLOCKS_OID,
                      convertor=int, type=Integer32),
)

class HpUxCollector:
    @staticmethod
    def get_convertor(oid_str):
        for field, convert in CONVERTS.items():
            if oid_str.startswith(convert['oid']):
                return field, convert
        raise KeyError(oid_str)

    @staticmethod
    def get_filesystem_metrics(host_address, community='public'):
        filesystems = {}
        for (errorIndication,             errorStatus,            errorIndex,
             varBinds) in nextCmd(SnmpEngine(),
                                  CommunityData(community, mpModel=0),
                                  UdpTransportTarget((host_address, 161)),
                                  ContextData(),
                                  ObjectType(ObjectIdentity(MOUNT_NAME_OID)),
                                  ObjectType(ObjectIdentity(TOTAL_BLOCKS_OID)),
                                  ObjectType(ObjectIdentity(FREE_BLOCKS_OID)),
                                  ObjectType(ObjectIdentity(BLOCK_SIZE_OID)),
                                  lexicographicMode=False):

            if errorIndication:
                raise IOError('during snmpNext', errorIndication)
                break
            elif errorStatus:
                print('%s at %s' % (errorStatus.prettyPrint(),
                                    errorIndex and varBinds[int(errorIndex) - 1][
                                        0] or '?'))
                raise IOError('during snmpNext')
                break
            else:
                line = {}
                for varBind in varBinds:
                    string_oid = str(varBind[0].getOid())
                    field_name, conversion = HpUxCollector.get_convertor(string_oid)
                    snmp_value = varBind[1]
                    assert type(snmp_value) is conversion['type'], type(snmp_value)
                    python_value = conversion['convertor'](snmp_value)
                    line[field_name] = python_value
                filesystem_name = line['mount_name']
                filesystems[filesystem_name] = line
        return filesystems



def humanize_bytes(bytes, precision=1):
    abbrevs = (
        (1 << 50, 'PB'),
        (1 << 40, 'TB'),
        (1 << 30, 'GB'),
        (1 << 20, 'MB'),
        (1 << 10, 'kB'),
        (1, 'bytes')
    )
    if bytes == 1:
        return '1 byte'
    for factor, suffix in abbrevs:
        if bytes >= factor:
            break
    return '%.*f %s' % (precision, bytes / factor, suffix)

def main():
    parser = argparse.ArgumentParser('Check disk on HP-UX from SNMP')
    parser.add_argument('--host', '-H', required=True)
    parser.add_argument('--community', '-C', default='public')
    parser.add_argument('--disk', '-d', required=True, default='/')
    parser.add_argument('--critical-percentage-free', '-c', type=int)
    parser.add_argument('--critical-bytes-free', type=int)
    parser.add_argument('--warning-percentage-free', '-w', type=int)
    parser.add_argument('--warning-bytes-free', type=int)
    parser.add_argument('--verbose', action='store_true', default=False)
    args = parser.parse_args()

    all_disks_metrics = HpUxCollector.get_filesystem_metrics(
        host_address=args.host, community=args.community)
    if args.verbose:
        print("Metrics received")
        print(json.dumps(all_disks_metrics, indent=2))
    try:
        disk_metrics = all_disks_metrics[args.disk]
    except KeyError:
        print("Unable to check disk {}".format(args.disk))
        return 3

    disk_free = disk_metrics['free_blocks'] * disk_metrics['block_size']
    disk_size = disk_metrics['total_blocks'] * disk_metrics['block_size']
    percent_free = int(disk_free / disk_size * 100)

    retv, state = 0, ''
    perf_warn, perf_crit = '', ''

    if args.warning_bytes_free:
        perf_warn = disk_size - args.warning_bytes_free
        if disk_free < args.warning_bytes_free:
            retv, state = 1, 'WARNING - '
    if args.warning_percentage_free:
        perf_warn = disk_size - int(
            disk_size * args.warning_percentage_free / 100)
        if percent_free < args.warning_percentage_free:
            retv, state = 1, 'WARNING - '
    if args.critical_bytes_free:
        perf_crit = disk_size - args.critical_bytes_free
        if disk_free < args.critical_bytes_free:
            retv, state = 2, 'CRITICAL - '
    if args.critical_percentage_free:
        perf_crit = disk_size - int(
            disk_size * args.critical_percentage_free / 100)
        if percent_free < args.critical_percentage_free:
            retv, state = 2, 'CRITICAL - '

    perfdata = '{}={}B;{};{};0;{}'.format(args.disk, (disk_size - disk_free),
                                          perf_warn, perf_crit, disk_size)
    print('{}{} free of {} ({}%)|{}'.format(
        state, humanize_bytes(disk_free), humanize_bytes(disk_size),
        percent_free, perfdata))
    raise SystemExit(retv)

    if perfdata:
        print('%s - %s | %s' % (status, msg, perfdata))
    else:
        print('%s - %s' % (status, msg))

    return retval


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as e:
        print('Error - %s' % str(e))
        sys.exit(3)
