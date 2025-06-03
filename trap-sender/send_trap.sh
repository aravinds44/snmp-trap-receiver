#!/bin/bash

# SNMPv3 Trap Sender Script
# Usage: ./send_trap.sh [trap_type]

TRAPD_HOST=${TRAPD_HOST:-snmptrapd}
SNMP_USER=${SNMP_USER:-snmpv3user}
SNMP_AUTH_PASS=${SNMP_AUTH_PASS:-authpassword123}
SNMP_PRIV_PASS=${SNMP_PRIV_PASS:-privpassword123}

# Function to send a basic SNMPv3 trap
send_trap() {
    local trap_oid=$1
    local description=$2
    local extra_varbinds=$3
    
    echo "Sending $description trap to $TRAPD_HOST..."
    
    snmptrap -v3 \
        -u "$SNMP_USER" \
        -l authPriv \
        -a SHA \
        -A "$SNMP_AUTH_PASS" \
        -x AES \
        -X "$SNMP_PRIV_PASS" \
        "$TRAPD_HOST":162 \
        '' \
        "$trap_oid" \
        1.3.6.1.2.1.1.3.0 t 12345 \
        $extra_varbinds
        
    if [ $? -eq 0 ]; then
        echo "Successfully sent $description trap"
    else
        echo "Failed to send $description trap"
    fi
}

# Function to send interface down trap
send_linkdown_trap() {
    send_trap "1.3.6.1.6.3.1.1.5.3" "Link Down" \
        "1.3.6.1.2.1.2.2.1.1.1 i 1 1.3.6.1.2.1.2.2.1.2.1 s \"eth0\" 1.3.6.1.2.1.2.2.1.8.1 i 2"
}

# Function to send interface up trap
send_linkup_trap() {
    send_trap "1.3.6.1.6.3.1.1.5.4" "Link Up" \
        "1.3.6.1.2.1.2.2.1.1.1 i 1 1.3.6.1.2.1.2.2.1.2.1 s \"eth0\" 1.3.6.1.2.1.2.2.1.8.1 i 1"
}

# Function to send cold start trap
send_coldstart_trap() {
    send_trap "1.3.6.1.6.3.1.1.5.1" "Cold Start" \
        "1.3.6.1.2.1.1.1.0 s \"Test SNMP Agent\" 1.3.6.1.2.1.1.5.0 s \"test-device\""
}

# Function to send custom enterprise trap
send_custom_trap() {
    send_trap "1.3.6.1.4.1.12345.1.1" "Custom Enterprise Trap" \
        "1.3.6.1.4.1.12345.1.2.1 s \"Custom alert message\" 1.3.6.1.4.1.12345.1.2.2 i 75"
}

# Function to send authentication failure trap
send_auth_failure_trap() {
    send_trap "1.3.6.1.6.3.1.1.5.5" "Authentication Failure" \
        "1.3.6.1.2.1.1.1.0 s \"Authentication failed from unknown source\""
}

# Main script logic
case "${1:-linkdown}" in
    "linkdown"|"down")
        send_linkdown_trap
        ;;
    "linkup"|"up")
        send_linkup_trap
        ;;
    "coldstart"|"start")
        send_coldstart_trap
        ;;
    "custom")
        send_custom_trap
        ;;
    "auth"|"authfail")
        send_auth_failure_trap
        ;;
    "all")
        echo "Sending all trap types..."
        send_coldstart_trap
        sleep 2
        send_linkdown_trap
        sleep 2
        send_linkup_trap
        sleep 2
        send_custom_trap
        sleep 2
        send_auth_failure_trap
        ;;
    "test"|"loop")
        echo "Starting continuous test mode (Ctrl+C to stop)..."
        while true; do
            send_linkdown_trap
            sleep 10
            send_linkup_trap
            sleep 10
            send_custom_trap
            sleep 20
        done
        ;;
    *)
        echo "Usage: $0 [linkdown|linkup|coldstart|custom|auth|all|test]"
        echo ""
        echo "Available trap types:"
        echo "  linkdown  - Send interface down trap"
        echo "  linkup    - Send interface up trap"
        echo "  coldstart - Send cold start trap"
        echo "  custom    - Send custom enterprise trap"
        echo "  auth      - Send authentication failure trap"
        echo "  all       - Send all trap types in sequence"
        echo "  test      - Continuous test mode"
        exit 1
        ;;
esac

## MIB Files

### mibs/SNMPv2-MIB.txt