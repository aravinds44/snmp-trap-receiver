#!/usr/bin/env python3

import sys
import json
import logging
import time  # Added missing import
from datetime import datetime, timezone
from typing import Dict, Optional

from confluent_kafka import Consumer, KafkaError, KafkaException
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError


def _setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/app/logs/trap_processor.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)


class TrapProcessor:
    def __init__(self):
        self.logger = _setup_logging()
        self.kafka_config = {
            'bootstrap.servers': 'kafka:9092',
            'group.id': 'snmp-trap-processor',
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': False,
            'session.timeout.ms': 10000,
            'socket.timeout.ms': 10000,
            'client.id': 'snmp-trap-processor-1',  # Added client identification
            'metadata.max.age.ms': 30000,  # Refresh metadata every 30s
            'reconnect.backoff.max.ms': 10000  # Max delay between reconnects
        }
        self.db_config = {
            'host': 'snmp-psql',
            'port': 5432,
            'database': 'snmptraps',
            'user': 'snmpuser',
            'password': 'snmppass123'
        }
        self.consumer = None
        self.db_engine = None
        self._initialize_components()

    def _initialize_components(self):
        """Initialize Kafka consumer and database connection with retries"""
        max_retries = 5
        retry_delay = 5

        # Initialize Kafka consumer with better error handling
        for attempt in range(max_retries):
            try:
                self.consumer = Consumer(self.kafka_config)

                # Verify Kafka connectivity and topic existence
                metadata = self.consumer.list_topics(timeout=10)
                if 'snmp_traps' not in metadata.topics:
                    self.logger.error("Topic 'snmp_traps' does not exist in Kafka")
                    raise KafkaException(KafkaError.UNKNOWN_TOPIC_OR_PART)

                self.consumer.subscribe(['snmp_traps'])
                self.logger.info("Kafka consumer initialized successfully")
                break
            except KafkaException as e:
                self.logger.warning(f"Kafka initialization attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    self.logger.error("Failed to initialize Kafka consumer after maximum retries")
                    raise
                time.sleep(retry_delay * (attempt + 1))
            except Exception as e:
                self.logger.error(f"Unexpected error initializing Kafka consumer: {e}")
                raise

        # Initialize database connection
        for attempt in range(max_retries):
            try:
                self.db_engine = create_engine(
                    f"postgresql://{self.db_config['user']}:{self.db_config['password']}@"
                    f"{self.db_config['host']}:{self.db_config['port']}/{self.db_config['database']}",
                    pool_pre_ping=True,  # Test connections before use
                    pool_recycle=3600  # Recycle connections after 1 hour
                )
                # Test connection with a simple query
                with self.db_engine.connect() as conn:
                    conn.execute(text("SELECT 1"))
                self.logger.info("Database connection established successfully")
                break
            except Exception as e:
                self.logger.warning(f"Database connection attempt {attempt + 1} failed: {e}")
                if attempt == max_retries - 1:
                    self.logger.error("Failed to connect to database after maximum retries")
                    raise
                time.sleep(retry_delay * (attempt + 1))

    def _parse_trap(self, trap_json: Dict) -> Optional[Dict]:
        """Parse the raw trap JSON into structured data for database insertion"""
        try:
            # Extract source IP from transport string
            transport = trap_json.get('transport', '')
            source_ip = '127.0.0.1'  # default
            if '->' in transport:
                source_part = transport.split('->')[0]
                if '[' in source_part and ']' in source_part:
                    source_ip = source_part.split('[')[1].split(']')[0].split(':')[0]

            # Extract trap OID from oids list
            trap_oid = ''
            trap_name = ''
            for oid in trap_json.get('oids', []):
                if 'snmpTrapOID.0' in oid:
                    trap_oid = oid.split()[-1]
                    trap_name = trap_oid.split('::')[-1] if '::' in trap_oid else trap_oid
                    break

            # Parse timestamp
            try:
                timestamp = datetime.fromisoformat(trap_json['timestamp'].replace('Z', '+00:00'))
            except (KeyError, ValueError):
                timestamp = datetime.now(timezone.utc)

            # Extract severity if present in oids
            severity = 'info'
            for oid in trap_json.get('oids', []):
                if 'Severity' in oid:
                    severity = oid.split()[-1].lower()
                    break

            # Extract uptime if present
            uptime = ''
            for oid in trap_json.get('oids', []):
                if 'sysUpTime' in oid:
                    uptime = oid.split()[-1]
                    break

            # Prepare variable bindings
            varbinds = []
            for oid in trap_json.get('oids', []):
                if 'snmpTrapOID.0' not in oid and 'sysUpTime' not in oid:
                    parts = oid.split()
                    oid_part = parts[0]
                    value = ' '.join(parts[1:]) if len(parts) > 1 else ''
                    varbinds.append({
                        'oid': oid_part,
                        'value': value,
                        'resolved_name': oid_part.split('::')[-1] if '::' in oid_part else oid_part
                    })

            return {
                'timestamp': timestamp,
                'hostname': trap_json.get('host', ''),
                'source_ip': source_ip,
                'trap_oid': trap_oid,
                'trap_name': trap_name,
                'severity': severity,
                'uptime': uptime,
                'transport': transport,
                'variable_bindings': varbinds,
                'raw_data': trap_json
            }
        except Exception as e:
            self.logger.error(f"Error parsing trap: {e}")
            return None

    def _store_trap(self, trap_data: Dict):
        """Store the parsed trap data in PostgreSQL"""
        try:
            with self.db_engine.begin() as conn:
                query = text("""
                    INSERT INTO snmp_traps (
                        timestamp, hostname, source_ip, trap_oid, trap_name,
                        severity, uptime, transport, variable_bindings, raw_data
                    ) VALUES (
                        :timestamp, :hostname, :source_ip, :trap_oid, :trap_name,
                        :severity, :uptime, :transport, :variable_bindings, :raw_data
                    )
                """)
                conn.execute(query, {
                    'timestamp': trap_data['timestamp'],
                    'hostname': trap_data['hostname'],
                    'source_ip': trap_data['source_ip'],
                    'trap_oid': trap_data['trap_oid'],
                    'trap_name': trap_data['trap_name'],
                    'severity': trap_data['severity'],
                    'uptime': trap_data['uptime'],
                    'transport': trap_data['transport'],
                    'variable_bindings': json.dumps(trap_data['variable_bindings']),
                    'raw_data': json.dumps(trap_data['raw_data'])
                })
                self.logger.info(f"Stored trap: {trap_data['trap_name']} from {trap_data['source_ip']}")
        except SQLAlchemyError as e:
            self.logger.error(f"Database error storing trap: {e}")
            # Fallback to file if database fails
            with open('/app/logs/failed_traps.log', 'a') as f:
                f.write(json.dumps(trap_data) + '\n')

    def process_traps(self):
        """Main processing loop"""
        self.logger.info("Starting trap processing loop")
        try:
            while True:
                msg = self.consumer.poll(1.0)
                if msg is None:
                    continue

                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    self.logger.error(f"Kafka error: {msg.error()}")
                    continue

                try:
                    trap_json = json.loads(msg.value().decode('utf-8'))
                    self.logger.debug(f"Received trap: {trap_json}")
                    parsed_trap = self._parse_trap(trap_json)
                    if parsed_trap:
                        self._store_trap(parsed_trap)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Invalid JSON in message: {e}")
                except Exception as e:
                    self.logger.error(f"Error processing message: {e}")
        except KeyboardInterrupt:
            self.logger.info("Shutting down gracefully...")
        finally:
            self.consumer.close()
            self.db_engine.dispose()
            self.logger.info("Processor shutdown complete")

if __name__ == '__main__':
    try:
        processor = TrapProcessor()
        processor.process_traps()
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)