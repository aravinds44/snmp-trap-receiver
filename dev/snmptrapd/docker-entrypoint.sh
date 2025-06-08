#!/bin/sh

# Substitute environment variables in the template using sed
sed -e "s|\${SNMP_ENGINE}|${SNMP_ENGINE}|g" \
    -e "s|\${SNMP_USER}|${SNMP_USER}|g" \
    -e "s|\${SNMP_AUTH_PASS}|${SNMP_AUTH_PASS}|g" \
    -e "s|\${SNMP_PRIV_PASS}|${SNMP_PRIV_PASS}|g" \
    /etc/snmp/snmptrapd.conf.template > /etc/snmp/snmptrapd.conf

# Start snmptrapd with the generated config
exec snmptrapd -f -Lo -p /tmp/snmptrapd.pid
