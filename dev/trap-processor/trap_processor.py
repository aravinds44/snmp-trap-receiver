#!/usr/bin/env python3

import sys
import json
import logging
import time
from datetime import datetime, timezone
from typing import Dict, Optional

from confluent_kafka import Consumer, KafkaError, KafkaException
from confluent_kafka.admin import AdminClient, NewTopic
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
from config import Config


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
        self.config = Config()
        self.kafka_config = {
            'bootstrap.servers': self.config.KAFKA_BROKER,
            'group.id': 'snmp-trap-processor',
            'auto.offset.reset': 'earliest',
            'enable.auto.commit': False,
            'session.timeout.ms': 10000,
            'socket.timeout.ms': 10000,
            'client.id': 'snmp-trap-processor-1',
            'metadata.max.age.ms': 30000,
            'reconnect.backoff.max.ms': 10000
        }
        self.db_config = {
            'host': self.config.DB_HOST,
            'port': self.config.DB_PORT,
            'database': self.config.DB_NAME,
            'user': self.config.DB_USER,
            'password': self.config.DB_PASSWORD
        }
        self.consumer = None
        self.db_engine = None
        self.admin_client = AdminClient({'bootstrap.servers': self.kafka_config['bootstrap.servers']})
        self._initialize_components()

    def _initialize_components(self):
        """Initialize Kafka consumer and database connection with retries"""
        max_retries = 5
        retry_delay = 5

        # Initialize Kafka components
        self._initialize_kafka(max_retries, retry_delay)

        # Initialize database connection
        self._initialize_database(max_retries, retry_delay)

    def _initialize_kafka(self, max_retries, retry_delay):
        """Initialize Kafka consumer with topic creation if needed"""
        for attempt in range(max_retries):
            try:
                # First check if topic exists or create it
                if not self._kafka_topic_exists('snmp_traps'):
                    self.logger.warning("Topic 'snmp_traps' not found - attempting to create")
                    self._create_kafka_topic('snmp_traps', num_partitions=1, replication_factor=1)
                    self.logger.info("Topic 'snmp_traps' created successfully")

                # Now initialize consumer
                self.consumer = Consumer(self.kafka_config)
                self.consumer.subscribe([self.config.KAFKA_TOPIC])
                self.logger.info("Kafka consumer initialized and subscribed to 'snmp_traps'")
                return True

            except KafkaException as e:
                self.logger.warning(f"Kafka initialization attempt {attempt + 1} failed: {str(e)}")
                if attempt == max_retries - 1:
                    self.logger.error("Max retries reached for Kafka initialization")
                    raise
                time.sleep(retry_delay * (attempt + 1))
            except Exception as e:
                self.logger.error(f"Unexpected error during Kafka initialization: {str(e)}")
                raise

    def _kafka_topic_exists(self, topic_name):
        """Check if topic exists in Kafka"""
        try:
            metadata = self.admin_client.list_topics(timeout=10)
            return topic_name in metadata.topics
        except Exception as e:
            self.logger.error(f"Error checking topic existence: {str(e)}")
            raise

    def _create_kafka_topic(self, topic_name, num_partitions, replication_factor):
        """Create a new Kafka topic"""
        try:
            topic = NewTopic(
                topic_name,
                num_partitions=num_partitions,
                replication_factor=replication_factor,
                config={
                    'retention.ms': '604800000'  # 7 days retention
                }
            )

            futures = self.admin_client.create_topics([topic], operation_timeout=30)

            for topic_name, future in futures.items():
                try:
                    future.result()  # Wait for topic creation
                    self.logger.info(f"Topic '{topic_name}' creation successful")
                except Exception as e:
                    self.logger.error(f"Failed to create topic '{topic_name}': {str(e)}")
                    raise
        except Exception as e:
            self.logger.error(f"Error creating topic: {str(e)}")
            raise

    def _initialize_database(self, max_retries, retry_delay):
        """Initialize database connection with retries"""
        for attempt in range(max_retries):
            try:
                self.db_engine = create_engine(
                    f"postgresql://{self.db_config['user']}:{self.db_config['password']}@"
                    f"{self.db_config['host']}:{self.db_config['port']}/{self.db_config['database']}",
                    pool_pre_ping=True,
                    pool_recycle=3600
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
        """Parse the raw trap JSON into structured and flattened data for database insertion."""
        try:
            # Extract source IP from transport string
            transport = trap_json.get('transport', '')
            source_ip = '127.0.0.1'
            if '->' in transport:
                source_part = transport.split('->')[0]
                if '[' in source_part and ']' in source_part:
                    source_ip = source_part.split('[')[1].split(']')[0].split(':')[0]

            # Extract trap OID and name
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

            # Extract uptime
            uptime = ''
            for oid in trap_json.get('oids', []):
                if 'sysUpTime' in oid:
                    uptime = oid.split()[-1]
                    break

            # Initialize flattened values
            alarm_server = None
            alarm_number = None
            severity = 'info'
            alarm_text = None
            alarm_instance = None

            # Extract variable bindings
            varbinds = []
            for oid in trap_json.get('oids', []):
                if 'snmpTrapOID.0' in oid or 'sysUpTime' in oid:
                    continue

                parts = oid.split()
                oid_part = parts[0]
                value = ' '.join(parts[1:]) if len(parts) > 1 else ''
                resolved_name = oid_part.split('::')[-1] if '::' in oid_part else oid_part
                resolved_lower = resolved_name.lower()

                # Substring match to populate flattened fields
                if 'alarmseverity' in resolved_lower:
                    severity = value.lower()
                elif 'alarmnumber' in resolved_lower:
                    alarm_number = value
                elif 'alarmtext' in resolved_lower:
                    alarm_text = value
                elif 'dsrserverhostname' in resolved_lower:
                    alarm_server = value
                elif 'dsralarminstance' in resolved_lower:
                    alarm_instance = value


                varbinds.append({
                    'oid': oid_part,
                    'value': value,
                    'resolved_name': resolved_name
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
                'raw_data': trap_json,
                'alarm_server': alarm_server,
                'alarm_instance':alarm_instance,
                'alarm_number': alarm_number,
                'alarm_text': alarm_text
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
                        severity, uptime, transport,
                        alarm_server, alarm_instance, alarm_number, alarm_text,
                        variable_bindings, raw_data
                    ) VALUES (
                        :timestamp, :hostname, :source_ip, :trap_oid, :trap_name,
                        :severity, :uptime, :transport,
                        :alarm_server, :alarm_instance, :alarm_number, :alarm_text,
                        :variable_bindings, :raw_data
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
                    'alarm_server': trap_data.get('alarm_server'),
                    'alarm_instance': trap_data.get('alarm_instance'),
                    'alarm_number': trap_data.get('alarm_number'),
                    'alarm_text': trap_data.get('alarm_text'),
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
            if self.consumer:
                self.consumer.close()
            if self.db_engine:
                self.db_engine.dispose()
            self.logger.info("Processor shutdown complete")


if __name__ == '__main__':
    try:
        processor = TrapProcessor()
        processor.process_traps()
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)
