FROM alpine:3.18

# Install net-snmp and dependencies
RUN apk add --no-cache \
    net-snmp \
    net-snmp-tools \
    bash \
    curl \
    && rm -rf /var/cache/apk/*

# Create snmp user and directories
RUN addgroup -g 1001 snmp && \
    adduser -D -u 1001 -G snmp snmp && \
    mkdir -p /var/lib/snmp /var/log/snmp /etc/snmp && \
    chown -R snmp:snmp /var/lib/snmp /var/log/snmp /etc/snmp

# Copy configuration and scripts
COPY snmptrapd.conf /etc/snmp/snmptrapd.conf
COPY trap_handler.sh /usr/local/bin/trap_handler.sh

# Make scripts executable
RUN chmod +x /usr/local/bin/trap_handler.sh

# Create log file
RUN touch /var/log/snmp/snmptrapd.log && \
    chown snmp:snmp /var/log/snmp/snmptrapd.log

# Switch to snmp user
USER snmp

# Expose SNMP trap port
EXPOSE 162/udp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep snmptrapd || exit 1

# Start snmptrapd
CMD ["snmptrapd", "-f", "-Lo", "-c", "/etc/snmp/snmptrapd.conf"]