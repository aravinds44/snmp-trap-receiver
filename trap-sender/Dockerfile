FROM alpine:3.18

# Install net-snmp tools
RUN apk add --no-cache \
    net-snmp-tools \
    bash \
    curl \
    && rm -rf /var/cache/apk/*

RUN mkdir -p /var/lib/net-snmp && \
    chown snmp:snmp /var/lib/net-snmp && \
    chmod 755 /var/lib/net-snmp


# Create snmp user
RUN addgroup -g 1001 snmp && \
    adduser -D -u 1001 -G snmp snmp

# Copy test scripts
COPY send_trap.sh /usr/local/bin/send_trap.sh

# Make scripts executable
RUN chmod +x /usr/local/bin/send_trap.sh

# Switch to snmp user
USER snmp

# Keep container running for testing
CMD ["tail", "-f", "/dev/null"]