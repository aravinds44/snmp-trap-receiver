#!/bin/bash
# Send test trap to the snmptrapd container
docker-compose exec trap-generator bash -c \
  "apt-get update && apt-get install -y snmp && \
  snmptrap -v 2c -c public snmptrapd '' 1.3.6.1.4.1.8072.2.3.0.1 1.3.6.1.4.1.8072.2.3.2.1 i 123456"