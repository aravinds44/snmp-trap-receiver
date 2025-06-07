#!/bin/bash
set -e

# Docker entrypoint script for SNMP Trap Handler
echo "Starting SNMP Trap Handler Container..."

# Function to log messages
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1"
}

# Function to wait for Redis
wait_for_redis() {
    local max_attempts=30
    local attempt=1

    log "Waiting for Redis at ${REDIS_HOST}:${REDIS_PORT}..."

    while [ $attempt -le $max_attempts ]; do
        if python3 -c "import redis; r=redis.Redis(host='${REDIS_HOST}', port=${REDIS_PORT}, db=${REDIS_DB}, password='${REDIS_PASSWORD}', socket_timeout=2); r.ping()" 2>/dev/null; then
            log "Redis is ready!"
            return 0
        fi

        log "Attempt $attempt/$max_attempts: Redis not ready, waiting 2 seconds..."
        sleep 2
        attempt=$((attempt + 1))
    done

    log "WARNING: Redis not available after $max_attempts attempts. Continuing with fallback mode..."
    return 1
}

# Function to test trap handler
test_trap_handler() {
    log "Testing trap handler script..."
    if python3 /usr/local/bin/trap_handler.py --help 2>/dev/null || echo "test" | python3 /usr/local/bin/trap_handler.py 2>/dev/null; then
        log "Trap handler script is working"
        return 0
    else
        log "ERROR: Trap handler script test failed"
        return 1
    fi
}

# Function to create log files if they don't exist
setup_logging() {
    log "Setting up logging directories and files..."

    # Ensure log files exist and have proper permissions
    touch /var/log/snmp/traps.log \
          /var/log/snmp/trap_errors.log \
          /var/log/snmp/traps_fallback.log

    # Set permissions (files should be writable by snmp user)
    chmod 644 /var/log/snmp/*.log

    log "Logging setup complete"
}

# Function to validate configuration
validate_config() {
    log "Validating configuration..."

    # Check if snmptrapd.conf exists
    if [ ! -f /etc/snmp/snmptrapd.conf ]; then
        log "ERROR: /etc/snmp/snmptrapd.conf not found"
        exit 1
    fi

    # Check if trap handler exists and is executable
    if [ ! -x /usr/local/bin/trap_handler.py ]; then
        log "ERROR: trap_handler.py not found or not executable"
        exit 1
    fi

    log "Configuration validation complete"
}

# Function to display environment info
show_environment() {
    log "Environment Information:"
    log "  Redis Host: ${REDIS_HOST}"
    log "  Redis Port: ${REDIS_PORT}"
    log "  Redis DB: ${REDIS_DB}"
    log "  Trap List Key: ${REDIS_TRAP_LIST_KEY}"
    log "  Max List Length: ${REDIS_MAX_LIST_LENGTH}"
    log "  Timezone: ${TZ}"
    log "  Python Version: $(python3 --version)"
    log "  Redis Client Version: $(python3 -c 'import redis; print(redis.__version__)' 2>/dev/null || echo 'Not available')"
}

# Function to cleanup on exit
cleanup() {
    log "Shutting down gracefully..."
    # Kill snmptrapd if it's running
    if [ -f /tmp/snmptrapd.pid ]; then
        local pid=$(cat /tmp/snmptrapd.pid)
        if kill -0 "$pid" 2>/dev/null; then
            log "Stopping snmptrapd (PID: $pid)..."
            kill -TERM "$pid"
            # Wait for graceful shutdown
            for i in {1..10}; do
                if ! kill -0 "$pid" 2>/dev/null; then
                    break
                fi
                sleep 1
            done
            # Force kill if still running
            if kill -0 "$pid" 2>/dev/null; then
                log "Force killing snmptrapd..."
                kill -KILL "$pid"
            fi
        fi
        rm -f /tmp/snmptrapd.pid
    fi
    log "Cleanup complete"
}

# Set up signal handlers
trap cleanup SIGTERM SIGINT

# Main execution
main() {
    show_environment
    validate_config
    setup_logging

    # Wait for Redis (optional, continues with fallback if Redis is not available)
    wait_for_redis || log "Continuing without Redis connectivity check..."

    # Test trap handler
    if ! test_trap_handler; then
        log "WARNING: Trap handler test failed, but continuing..."
    fi

    log "Starting snmptrapd with command: $@"

    # Execute the main command
    exec "$@"
}

# Handle special cases
case "$1" in
    snmptrapd)
        main "$@"
        ;;
    bash|sh)
        # Allow shell access for debugging
        exec "$@"
        ;;
    --help|help)
        echo "SNMP Trap Handler Container"
        echo "Usage: docker run [options] <image> [command]"
        echo ""
        echo "Commands:"
        echo "  snmptrapd [options]  - Start SNMP trap daemon (default)"
        echo "  bash                 - Start interactive shell"
        echo "  --help               - Show this help"
        echo ""
        echo "Environment Variables:"
        echo "  REDIS_HOST          - Redis hostname (default: redis)"
        echo "  REDIS_PORT          - Redis port (default: 6379)"
        echo "  REDIS_DB            - Redis database number (default: 0)"
        echo "  REDIS_PASSWORD      - Redis password (optional)"
        echo "  TZ                  - Timezone (default: UTC)"
        ;;
    *)
        # Execute any other command directly
        exec "$@"
        ;;
esac