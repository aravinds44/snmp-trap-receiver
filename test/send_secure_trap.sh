#!/bin/bash
# Send encrypted SNMPv3 trap with SHA authentication and AES encryption

docker-compose exec trap-generator bash -c \
  "apt-get update && apt-get install -y snmp && \
  snmptrap -v 3 -n '' -e 0x0123456789 -l authPriv \
  -u trapuser -a SHA -A 'authpass123' -x AES -X 'privpass123' \
  snmptrapd:162 '' 1.3.6.1.4.1.8072.2.3.0.1 1.3.6.1.4.1.8072.2.3.2.1 i 123456"