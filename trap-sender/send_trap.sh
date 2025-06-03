#!/bin/bash
# SNMPv3 Trap Sender Script
# Usage: ./send_trap.sh [trap_type]

TRAPD_HOST=${TRAPD_HOST:-snmptrapd}
SNMP_USER=${SNMP_USER:-snmpv3user}
SNMP_AUTH_PASS=${SNMP_AUTH_PASS:-authpassword123}
SNMP_PRIV_PASS=${SNMP_PRIV_PASS:-privpassword123}
ENGINE_ID="0x8000000001020304"

# Function to send a basic SNMPv3 trap
send_trap() {
    local trap_oid=$1
    local description=$2
    shift 2
    local extra_varbinds=("$@")

    echo "Sending $description trap to $TRAPD_HOST..."

    # Build the snmptrap command with proper variable bindings
    local cmd=(
        snmptrap -v 3
        -e "$ENGINE_ID"
        -u "$SNMP_USER"
        -l authPriv
        -a SHA
        -A "$SNMP_AUTH_PASS"
        -x AES
        -X "$SNMP_PRIV_PASS"
        "$TRAPD_HOST":162
        ''
        "$trap_oid"
        1.3.6.1.2.1.1.3.0 t 12345
    )

    # Add extra variable bindings
    for varbind in "${extra_varbinds[@]}"; do
        cmd+=("$varbind")
    done

    # Execute the command
    "${cmd[@]}"

    if [ $? -eq 0 ]; then
        echo "Successfully sent $description trap"
    else
        echo "Failed to send $description trap"
    fi
}

# Trap definitions
send_linkdown_trap() {
    send_trap "1.3.6.1.6.3.1.1.5.3" "Link Down" \
        "1.3.6.1.2.1.2.2.1.1.1" "i" "1" \
        "1.3.6.1.2.1.2.2.1.2.1" "s" "eth0" \
        "1.3.6.1.2.1.2.2.1.8.1" "i" "2"
}

send_linkup_trap() {
    send_trap "1.3.6.1.6.3.1.1.5.4" "Link Up" \
        "1.3.6.1.2.1.2.2.1.1.1" "i" "1" \
        "1.3.6.1.2.1.2.2.1.2.1" "s" "eth0" \
        "1.3.6.1.2.1.2.2.1.8.1" "i" "1"
}

send_coldstart_trap() {
    send_trap "1.3.6.1.6.3.1.1.5.1" "Cold Start" \
        "1.3.6.1.2.1.1.1.0" "s" "Test SNMP Agent" \
        "1.3.6.1.2.1.1.5.0" "s" "test-device"
}

send_custom_trap() {
    send_trap "1.3.6.1.4.1.12345.2.1" "Custom Enterprise Trap" \
        "1.3.6.1.4.1.12345.1.1.1" "s" "Custom alert message" \
        "1.3.6.1.4.1.12345.1.1.2" "i" "75"
}

send_auth_failure_trap() {
    send_trap "1.3.6.1.6.3.1.1.5.5" "Authentication Failure" \
        "1.3.6.1.2.1.1.1.0" "s" "Authentication failed from unknown source"
}

# Main logic
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
        echo "  linkdown/down    - Interface link down trap"
        echo "  linkup/up        - Interface link up trap"
        echo "  coldstart/start  - System cold start trap"
        echo "  custom           - Custom enterprise trap"
        echo "  auth/authfail    - Authentication failure trap"
        echo "  all              - Send all trap types"
        echo "  test/loop        - Continuous testing mode"
        exit 1
        ;;
esac