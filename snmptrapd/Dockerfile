FROM python:3.9-slim

RUN apt-get update && \
    apt-get install -y snmp snmptrapd libsnmp-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN pip install psycopg2-binary pysnmp pycryptodomex && \
    chmod +x /app/trap_handler.py

# Configure snmptrapd
RUN mv /app/snmptrapd.conf /etc/snmp/snmptrapd.conf && \
    echo "createUser -e 0x0123456789 trapuser SHA \"authpass123\" AES \"privpass123\"" >> /var/lib/snmp/snmpd.conf

EXPOSE 162/udp

CMD ["sh", "-c", "snmptrapd -f -Lo -c /etc/snmp/snmptrapd.conf"]