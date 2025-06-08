#!/usr/bin/env python3

import sys
import json
from kafka import KafkaProducer
from datetime import datetime, timezone
from decouple import config

KAFKA_BROKER = config('KAFKA_BROKER')
KAFKA_TOPIC = config('KAFKA_TOPIC')

def read_trap():
    """Reads SNMP trap lines from stdin and structures basic JSON"""
    lines = [line.strip() for line in sys.stdin if line.strip()]
    if len(lines) < 2:
        return None

    host = lines[0]
    transport = lines[1]
    oid_lines = lines[2:]

    trap_data = {
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "host": host,
        "transport": transport,
        "oids": oid_lines
    }
    return trap_data

def main():
    trap = read_trap()
    if not trap:
        sys.exit(1)

    try:
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BROKER,
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            batch_size=32*1024,
            linger_ms=50
        )
        producer.send(KAFKA_TOPIC, trap)
    except Exception as e:
        # Log to fallback file
        with open("/var/log/snmp/kafka_trap_fallback.log", "a") as f:
            f.write(json.dumps(trap) + "\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
