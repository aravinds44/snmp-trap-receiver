FROM alpine:3.18

# Install net-snmp tools
RUN apk add --no-cache \
    net-snmp-tools \
    bash \
    curl \
    && rm -rf /var/cache/apk/*

# Create snmp user and group
RUN addgroup -g 1001 snmp && \
    adduser -D -u 1001 -G snmp snmp

# Create SNMP config dir and fix permissions
RUN mkdir -p /var/lib/net-snmp && \
    chown -R snmp:snmp /var/lib/net-snmp && \
    chmod -R 755 /var/lib/net-snmp

# Copy test script
COPY send_trap.sh /usr/local/bin/send_trap.sh
RUN chmod +x /usr/local/bin/send_trap.sh

# Switch to non-root user
#USER snmp

# Keep container running for testing
CMD ["tail", "-f", "/dev/null"]
