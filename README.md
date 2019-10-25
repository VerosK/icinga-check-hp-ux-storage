# check hpux disk free

This Nagios/Icinga plugin checks disk free space from HP-UX machines with SNMP.

It uses old proprietary HP MIB. 

# Example usage

    ./check_hpux_disk_free.py \
        -H hpux01.internal -C public --disk / \
        --critical-percentage-free 80 \
        --warning-percentage-free 70

## Requirements: 

  * enabled SNMP agent on the target host

  * Python with pysnmp on local machine

