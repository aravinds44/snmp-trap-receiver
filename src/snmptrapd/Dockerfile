FROM alpine:3.18

# Install system dependencies
RUN apk update && apk add --no-cache \
    net-snmp \
    net-snmp-tools \
    python3 \
    py3-pip \
    bash \
    tzdata \
    gcc \
    musl-dev \
    python3-dev \
    librdkafka-dev \
    && rm -rf /var/cache/apk/*

# Symlink python
RUN ln -sf python3 /usr/bin/python

# Copy requirements first
COPY requirements.txt /tmp/requirements.txt

# Install Python dependencies (including kafka-python)
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r /tmp/requirements.txt && \
    rm -rf /root/.cache/pip /tmp/requirements.txt

# Create log directory and set permissions
RUN mkdir -p /var/log/snmp && \
    touch /var/log/snmp/kafka_trap_fallback.log && \
    chmod 755 /var/log/snmp && \
    chmod 644 /var/log/snmp/kafka_trap_fallback.log

# Copy configs and scripts
COPY snmptrapd.conf /etc/snmp/snmptrapd.conf.template
COPY trap_handler.py /usr/local/bin/trap_handler.py
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Make scripts executable
RUN chmod +x /usr/local/bin/trap_handler.py /usr/local/bin/docker-entrypoint.sh

# Create non-root user for security
RUN addgroup -g 1001 snmp && \
    adduser -D -u 1001 -G snmp -h /home/snmp -s /bin/bash snmp

# Set ownership for logs and configs
RUN chown -R snmp:snmp /var/log/snmp /etc/snmp

# Set timezone environment variable and configure timezone
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Kafka environment variables
ENV KAFKA_BROKER=kafka:9092 \
    KAFKA_TOPIC=snmp_traps \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Expose SNMP trap UDP port
EXPOSE 162/udp

WORKDIR /home/snmp

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

