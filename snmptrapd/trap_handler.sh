#!/bin/bash

LOG_FILE="/var/log/snmp/traps.log"
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')

# Create log directory if it doesn't exist
mkdir -p "$(dirname "$LOG_FILE")"

# Read all STDIN data into variables
HOST=""
IP=""
TRANSPORT=""
declare -a OIDS=()
declare -a VALUES=()

{
    echo "TRAP_START:$TIMESTAMP"

    # Process STDIN line by line
    line_count=0
    while IFS= read -r line || [ -n "$line" ]; do
        line_count=$((line_count + 1))

        case $line_count in
            1)
                # First line is hostname
                HOST="$line"
                echo "HOST:$HOST"
                ;;
            2)
                # Second line is transport info (UDP: [IP]:port->[IP]:port)
                TRANSPORT="$line"
                # Extract source IP from transport line
                IP=$(echo "$line" | sed -n 's/.*\[\([^]]*\)\]:[0-9]*->.*/\1/p')
                echo "IP:$IP"
                echo "TRANSPORT:$TRANSPORT"
                ;;
            *)
                # Remaining lines are OID value pairs
                if [[ "$line" =~ ^([^[:space:]]+)[[:space:]]+(.+)$ ]]; then
                    oid="${BASH_REMATCH[1]}"
                    value="${BASH_REMATCH[2]}"
                    echo "OID:$oid"
                    echo "VALUE:$value"
                    OIDS+=("$oid")
                    VALUES+=("$value")
                else
                    echo "UNPARSED_LINE:$line"
                fi
                ;;
        esac
    done

    # Summary information
    echo "TOTAL_LINES_PROCESSED:$line_count"
    echo "TOTAL_OIDS:${#OIDS[@]}"

    # Process specific OIDs we care about
    for i in "${!OIDS[@]}"; do
        case "${OIDS[$i]}" in
            "SNMPv2-MIB::snmpTrapOID.0")
                echo "TRAP_TYPE:${VALUES[$i]}"
                ;;
            "DISMAN-EVENT-MIB::sysUpTimeInstance")
                echo "UPTIME:${VALUES[$i]}"
                ;;
            "NET-SNMP-EXAMPLES-MIB::netSnmpExampleHeartbeatRate")
                echo "HEARTBEAT_RATE:${VALUES[$i]}"
                ;;
        esac
    done

    echo "TRAP_END"
    echo "---"
} >> "$LOG_FILE"

# Set proper permissions
chmod 644 "$LOG_FILE"
exit 0

#TODO: Receiving traps twice when tri