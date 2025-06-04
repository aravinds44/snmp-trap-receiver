#!/bin/bash

# SNMP Trap Handler - Production Ready
# Description: Processes SNMP traps and logs them in structured format
# Usage: Called by snmptrapd as trap handler

set -euo pipefail

# Configuration
LOG_FILE="/var/log/snmp/traps.log"
ERROR_LOG="/var/log/snmp/trap_errors.log"
MAX_LOG_SIZE="100M"
SYSLOG_FACILITY="local0"
SYSLOG_PRIORITY="info"

# Ensure log directory exists with proper permissions
log_dir="$(dirname "$LOG_FILE")"
if [[ ! -d "$log_dir" ]]; then
    mkdir -p "$log_dir"
    chmod 755 "$log_dir"
fi

# Function to log errors
log_error() {
    local msg="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') ERROR: $msg" >> "$ERROR_LOG"
    logger -p "$SYSLOG_FACILITY.$SYSLOG_PRIORITY" -t "snmp-trap-handler" "ERROR: $msg"
}

# Function to rotate log if it gets too large
rotate_log_if_needed() {
    if [[ -f "$LOG_FILE" ]]; then
        local size=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        local max_bytes=$((100 * 1024 * 1024))  # 100MB in bytes

        if [[ $size -gt $max_bytes ]]; then
            mv "$LOG_FILE" "${LOG_FILE}.$(date +%Y%m%d_%H%M%S)"
            touch "$LOG_FILE"
            chmod 644 "$LOG_FILE"
        fi
    fi
}

# Function to escape JSON values
escape_json() {
    local str="$1"
    # Remove trailing newlines and whitespace, then escape JSON special characters
    str=$(echo "$str" | sed 's/[[:space:]]*$//')
    # Escape backslashes, quotes, newlines, tabs, and other control characters
    printf '%s' "$str" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g; s/\r/\\r/g; s/\t/\\t/g'
}

# Function to determine trap severity based on OID
get_trap_severity() {
    local trap_oid="$1"
    case "$trap_oid" in
        *".1.3.6.1.6.3.1.1.5.1"|*"coldStart") echo "warning" ;;
        *".1.3.6.1.6.3.1.1.5.2"|*"warmStart") echo "info" ;;
        *".1.3.6.1.6.3.1.1.5.3"|*"linkDown") echo "error" ;;
        *".1.3.6.1.6.3.1.1.5.4"|*"linkUp") echo "info" ;;
        *".1.3.6.1.6.3.1.1.5.5"|*"authenticationFailure") echo "critical" ;;
        *".1.3.6.1.6.3.1.1.5.6"|*"egpNeighborLoss") echo "warning" ;;
        *) echo "info" ;;
    esac
}

# Main processing function
process_trap() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local iso_timestamp=$(date -u '+%Y-%m-%dT%H:%M:%S.%3NZ')

    # Initialize variables
    local host=""
    local source_ip=""
    local transport=""
    local trap_oid=""
    local trap_name=""
    local uptime=""
    local severity="info"
    local line_count=0

    # Arrays for OID-value pairs
    declare -a oids=()
    declare -a values=()
    declare -a varbinds=()

    # Process input line by line
    while IFS= read -r line || [[ -n "$line" ]]; do
        ((line_count++))

        # Remove trailing whitespace/newlines from each line
        line=$(echo "$line" | sed 's/[[:space:]]*$//')

        case $line_count in
            1)
                host="$line"
                ;;
            2)
                transport="$line"
                # Extract source IP from transport info
                if [[ "$line" =~ UDP:\ \[([^]]+)\]:[0-9]+-\> ]]; then
                    source_ip="${BASH_REMATCH[1]}"
                elif [[ "$line" =~ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ]]; then
                    source_ip="${BASH_REMATCH[1]}"
                fi
                ;;
            *)
                # Parse OID-value pairs
                if [[ "$line" =~ ^([^[:space:]]+)[[:space:]]+(.+)$ ]]; then
                    local oid="${BASH_REMATCH[1]}"
                    local value="${BASH_REMATCH[2]}"

                    # Clean up the value by removing trailing whitespace
                    value=$(echo "$value" | sed 's/[[:space:]]*$//')

                    oids+=("$oid")
                    values+=("$value")

                    # Create JSON varbind object
                    local escaped_oid=$(escape_json "$oid")
                    local escaped_value=$(escape_json "$value")
                    varbinds+=("{\"oid\":\"$escaped_oid\",\"value\":\"$escaped_value\"}")

                    # Extract specific trap information
                    case "$oid" in
                        "SNMPv2-MIB::snmpTrapOID.0"|".1.3.6.1.6.3.1.1.4.1.0")
                            trap_oid="$value"
                            severity=$(get_trap_severity "$value")
                            # Extract trap name from OID
                            trap_name=$(echo "$value" | sed 's/.*:://; s/\.0$//')
                            ;;
                        "DISMAN-EVENT-MIB::sysUpTimeInstance"|".1.3.6.1.2.1.1.3.0")
                            uptime="$value"
                            ;;
                    esac
                fi
                ;;
        esac
    done

    # Create JSON log entry
    local varbinds_json=""
    if [[ ${#varbinds[@]} -gt 0 ]]; then
        IFS=','
        varbinds_json="[${varbinds[*]}]"
        unset IFS
    else
        varbinds_json="[]"
    fi

    # Structured log entry in JSON format
    cat << EOF >> "$LOG_FILE"
{
  "timestamp": "$iso_timestamp",
  "level": "INFO",
  "message": "SNMP trap received",
  "trap": {
    "host": "$(escape_json "$host")",
    "source_ip": "$(escape_json "$source_ip")",
    "transport": "$(escape_json "$transport")",
    "oid": "$(escape_json "$trap_oid")",
    "name": "$(escape_json "$trap_name")",
    "severity": "$severity",
    "uptime": "$(escape_json "$uptime")",
    "varbind_count": ${#oids[@]}
  },
  "varbinds": $varbinds_json,
  "metadata": {
    "handler_version": "2.0",
    "processed_lines": $line_count
  }
}
EOF

    # Also send to syslog for integration with log management systems
    logger -p "$SYSLOG_FACILITY.$SYSLOG_PRIORITY" -t "snmp-trap" \
        "host=$host src_ip=$source_ip trap=$trap_name severity=$severity oid_count=${#oids[@]}"
}

# Main execution
main() {
    # Rotate log if needed
    rotate_log_if_needed

    # Process the trap
    if ! process_trap; then
        log_error "Failed to process SNMP trap"
        exit 1
    fi

    # Set proper permissions
    chmod 644 "$LOG_FILE" 2>/dev/null || true

    exit 0
}

# Execute main function
main "$@"