FROM alpine:3.18

# Install net-snmp and dependencies
RUN apk update && apk add net-snmp net-snmp-tools bash

RUN mkdir -p /var/log/snmp /etc/snmp && touch /var/log/snmp/traps.log && \
    chmod 777 /var/log/snmp /var/log/snmp/traps.log


# Copy configuration and scripts
COPY snmptrapd.conf /etc/snmp/snmptrapd.conf
COPY trap_handler.sh /usr/local/bin/trap_handler.sh

# Make scripts executable
RUN chmod +x /usr/local/bin/trap_handler.sh

# Expose SNMP trap port
EXPOSE 162/udp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep snmptrapd || exit 1

# Start snmptrapd
CMD ["snmptrapd", "-f", "-Lo", "-c", "/etc/snmp/snmptrapd.conf"]