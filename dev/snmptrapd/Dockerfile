FROM alpine:3.18

# Install system dependencies
RUN apk update && apk add --no-cache \
    net-snmp \
    net-snmp-tools \
    python3 \
    py3-pip \
    bash \
    curl \
    tzdata \
    gcc \
    musl-dev \
    python3-dev \
    librdkafka-dev \
    rsyslog \
    && rm -rf /var/cache/apk/*

# Configure rsyslog
RUN mkdir -p /var/run/rsyslog && \
    touch /var/log/messages && \
    chmod 666 /var/log/messages && \
    echo '$ModLoad imuxsock' > /etc/rsyslog.conf && \
    echo '$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat' >> /etc/rsyslog.conf && \
    echo '$template TraditionalFormat,"%timegenerated% %HOSTNAME% %syslogtag%%msg%"' >> /etc/rsyslog.conf && \
    echo '*.info;mail.none;authpriv.none;cron.none -/var/log/messages' >> /etc/rsyslog.conf && \
    echo '$IncludeConfig /etc/rsyslog.d/*.conf' >> /etc/rsyslog.conf

# Symlink python
RUN ln -sf python3 /usr/bin/python

# Copy requirements first
COPY requirements.txt /tmp/requirements.txt

# Install Python dependencies
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    rm -rf /root/.cache/pip /tmp/requirements.txt

# Remove build dependencies
RUN apk del gcc musl-dev python3-dev

# Create log directory
RUN mkdir -p /var/log/snmp /etc/snmp /usr/local/bin && \
    touch /var/log/snmp/traps.log \
          /var/log/snmp/trap_errors.log \
          /var/log/snmp/traps_fallback.log && \
    chmod 755 /var/log/snmp && \
    chmod 644 /var/log/snmp/*.log

# Copy configs and scripts
COPY snmptrapd.conf /etc/snmp/snmptrapd.conf
COPY trap_handler.py /usr/local/bin/trap_handler.py
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Make executable
RUN chmod +x /usr/local/bin/trap_handler.py /usr/local/bin/docker-entrypoint.sh

# Create non-root user
RUN addgroup -g 1001 snmp && \
    adduser -D -u 1001 -G snmp -h /home/snmp -s /bin/bash snmp

# Set ownership
RUN chown -R snmp:snmp /var/log/snmp /etc/snmp

# Set timezone
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Kafka-specific environment
ENV KAFKA_BROKER=kafka:9092 \
    KAFKA_TOPIC=snmp.traps \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Expose SNMP trap port
EXPOSE 162/udp

# Health check (optional Kafka ping)
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD pgrep snmptrapd > /dev/null && \
      python3 -c "from kafka import KafkaProducer; KafkaProducer(bootstrap_servers='${KAFKA_BROKER}')" || exit 1

WORKDIR /home/snmp

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

CMD ["sh", "-c", "rsyslogd -n & exec snmptrapd -f -Lo -p /tmp/snmptrapd.pid"]
