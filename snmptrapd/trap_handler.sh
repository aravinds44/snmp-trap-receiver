#!/bin/bash

# Trap handler script for snmptrapd
# This script receives trap data from snmptrapd and writes it to a file
# for processing by the trap-processor service

LOG_FILE="/var/log/snmp/traps.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Create log entry with timestamp and all trap data
{
    echo "TRAP_START:$TIMESTAMP"
    echo "HOST:$1"
    echo "IP:$2"
    shift 2

    # Process remaining arguments (OIDs and values)
    while [ $# -gt 0 ]; do
        echo "OID:$1"
        shift
        if [ $# -gt 0 ]; then
            echo "VALUE:$1"
            shift
        fi
    done

    echo "TRAP_END"
    echo "---"
} >> "$LOG_FILE"

# Ensure the trap processor can read the log
chmod 644 "$LOG_FILE"

exit 0