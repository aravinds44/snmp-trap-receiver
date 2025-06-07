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
    postgresql-dev \
    rsyslog \
    && rm -rf /var/cache/apk/*

# Configure rsyslog
RUN apk add --no-cache rsyslog && \
    mkdir -p /var/run/rsyslog && \
    touch /var/log/messages && \
    chmod 666 /var/log/messages && \
    echo '$ModLoad imuxsock' > /etc/rsyslog.conf && \
#    echo '$ModLoad imklog' >> /etc/rsyslog.conf && \
    echo '$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat' >> /etc/rsyslog.conf && \
    echo '$template TraditionalFormat,"%timegenerated% %HOSTNAME% %syslogtag%%msg%"' >> /etc/rsyslog.conf && \
    echo '*.info;mail.none;authpriv.none;cron.none -/var/log/messages' >> /etc/rsyslog.conf && \
    echo '$IncludeConfig /etc/rsyslog.d/*.conf' >> /etc/rsyslog.conf

# Create symlink for python (some scripts may expect 'python' command)
RUN ln -sf python3 /usr/bin/python

# Copy requirements first for better Docker layer caching
COPY requirements.txt /tmp/requirements.txt

# Install Python dependencies
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    rm -rf /root/.cache/pip /tmp/requirements.txt

# Remove build dependencies to reduce image size
RUN apk del gcc musl-dev python3-dev postgresql-dev

# Create necessary directories with proper permissions
RUN mkdir -p /var/log/snmp /etc/snmp /usr/local/bin && \
    touch /var/log/snmp/traps.log \
          /var/log/snmp/trap_errors.log \
          /var/log/snmp/traps_fallback.log && \
    chmod 755 /var/log/snmp && \
    chmod 644 /var/log/snmp/*.log

# Copy configuration and scripts
COPY snmptrapd.conf /etc/snmp/snmptrapd.conf
COPY trap_handler.py /usr/local/bin/trap_handler.py
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Make scripts executable
RUN chmod +x /usr/local/bin/trap_handler.py /usr/local/bin/docker-entrypoint.sh

# Create non-root user for security
RUN addgroup -g 1001 snmp && \
    adduser -D -u 1001 -G snmp -h /home/snmp -s /bin/bash snmp

# Set proper ownership for snmp user
RUN chown -R snmp:snmp /var/log/snmp /etc/snmp

# Set timezone (can be overridden with environment variable)
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Environment variables for the trap handler
ENV REDIS_HOST=redis \
    REDIS_PORT=6379 \
    REDIS_DB=0 \
    REDIS_SOCKET_TIMEOUT=5 \
    REDIS_TRAP_LIST_KEY=snmp:traps \
    REDIS_TRAP_HASH_PREFIX=snmp:trap: \
    REDIS_STATS_KEY=snmp:stats \
    REDIS_MAX_LIST_LENGTH=10000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Expose SNMP trap port
EXPOSE 162/udp

# Health check with improved logic
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep snmptrapd > /dev/null && \
        python3 -c "import redis; r=redis.Redis(host='${REDIS_HOST}', port=${REDIS_PORT}, db=${REDIS_DB}, socket_timeout=2); r.ping()" || exit 1

# Working directory
WORKDIR /home/snmp

# Use entrypoint script for better startup handling
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command
CMD ["sh", "-c", "rsyslogd -n & exec snmptrapd -f -Lo -p /tmp/snmptrapd.pid"]