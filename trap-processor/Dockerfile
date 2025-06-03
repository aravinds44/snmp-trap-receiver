FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libsnmp-dev \
    libpq-dev \
    snmp \
    snmp-mibs-downloader \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/* || \
    (apt-get update && apt-get install -y \
    gcc \
    libsnmp-dev \
    libpq-dev \
    snmp \
    wget \
    curl \
    && rm -rf /var/lib/apt/lists/*)

# Create app user
RUN useradd -m -u 1001 appuser

# Set working directory
WORKDIR /app

# Create MIB directories and set permissions
RUN mkdir -p /usr/share/snmp/mibs /app/mibs /custom-mibs /app/logs /var/log/snmp && \
    chmod 755 /usr/share/snmp/mibs /app/mibs /custom-mibs /var/log/snmp

# Download essential MIBs manually if snmp-mibs-downloader is not available
RUN wget -q -O /usr/share/snmp/mibs/SNMPv2-SMI.txt \
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMPv2-SMI.txt" || true && \
    wget -q -O /usr/share/snmp/mibs/SNMPv2-TC.txt \
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMPv2-TC.txt" || true && \
    wget -q -O /usr/share/snmp/mibs/SNMPv2-MIB.txt \
    "https://raw.githubusercontent.com/net-snmp/net-snmp/master/mibs/SNMPv2-MIB.txt" || true

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY trap_processor.py .
COPY config.py .

# Set proper permissions
RUN chown -R appuser:appuser /app && \
    chmod +x /app/trap_processor.py

# Switch to app user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import psycopg2; psycopg2.connect(host='${DB_HOST}', database='${DB_NAME}', user='${DB_USER}', password='${DB_PASSWORD}')" || exit 1

# Start the trap processor
CMD ["python", "trap_processor.py"]