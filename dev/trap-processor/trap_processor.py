#!/usr/bin/env python3

import os
import sys
import time
import logging
import json
import redis
from datetime import datetime
from typing import Dict, List, Optional
from psycopg2.extras import RealDictCursor
from sqlalchemy import create_engine, text

from config import Config


class TrapProcessor:
    def __init__(self):
        self.last_processed_key = None
        self.trap_hash_prefix = None
        self.trap_list_key = None
        self.redis_client = None
        self.engine = None
        self.logger = None
        self.config = Config()
        self.setup_logging()
        self.setup_database()
        self.setup_redis()

    def setup_logging(self):
        """Configure logging for the application."""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=getattr(logging, self.config.LOG_LEVEL),
            format=log_format,
            handlers=[
                logging.FileHandler(self.config.APP_LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("Trap processor initialized")

    def setup_database(self):
        """Initialize database connection."""
        try:
            self.engine = create_engine(self.config.DATABASE_URL)
            self.logger.info("Database connection established")
        except Exception as e:
            self.logger.error(f"Failed to connect to database: {e}")
            sys.exit(1)

    def setup_redis(self):
        """Initialize Redis connection."""
        try:
            self.redis_client = redis.Redis(
                host=self.config.REDIS_HOST,
                port=self.config.REDIS_PORT,
                db=self.config.REDIS_DB,
                password=self.config.REDIS_PASSWORD,
                socket_timeout=self.config.REDIS_SOCKET_TIMEOUT,
                decode_responses=False  # We want bytes for raw data
            )
            # Test connection
            self.redis_client.ping()
            self.logger.info("Redis connection established")

            # Redis keys configuration
            self.trap_list_key = self.config.REDIS_TRAP_LIST_KEY
            self.trap_hash_prefix = self.config.REDIS_TRAP_HASH_PREFIX
            self.last_processed_key = "snmp:processor:last_processed"

        except Exception as e:
            self.logger.error(f"Failed to connect to Redis: {e}")
            sys.exit(1)

    def get_traps_from_redis(self) -> List[Dict]:
        """Retrieve new traps from Redis."""
        traps = []
        try:
            # Get all trap IDs from the list
            trap_ids = self.redis_client.lrange(self.trap_list_key, 0, -1)

            # Get the last processed ID to only get new traps
            last_processed = self.redis_client.get(self.last_processed_key)
            if last_processed:
                last_processed = last_processed.decode('utf-8')
                try:
                    # Find the position of the last processed ID
                    idx = trap_ids.index(last_processed.encode('utf-8'))
                    trap_ids = trap_ids[:idx]  # Only get newer traps
                except ValueError:
                    pass  # Last processed not found, process all

            if not trap_ids:
                return traps

            # Process traps from newest to oldest
            for trap_id_bytes in reversed(trap_ids):
                trap_id = trap_id_bytes.decode('utf-8')
                trap_key = f"{self.trap_hash_prefix}{trap_id}"

                # Get trap data from hash
                trap_data = self.redis_client.hget(trap_key, 'data')
                if not trap_data:
                    continue

                try:
                    trap = json.loads(trap_data.decode('utf-8'))
                    traps.append(trap)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Error decoding trap JSON {trap_id}: {e}")
                    continue

            # Update last processed ID
            if trap_ids:
                self.redis_client.set(self.last_processed_key, trap_ids[0])

            return traps

        except Exception as e:
            self.logger.error(f"Error retrieving traps from Redis: {e}")
            return []

    def parse_trap_entry(self, json_data: Dict) -> Optional[Dict]:
        """Parse a JSON-formatted trap entry into our standard format."""
        try:
            trap_data = {
                'timestamp': json_data.get('timestamp', datetime.now().isoformat()),
                'hostname': json_data.get('trap', {}).get('host', 'unknown'),
                'source_ip': json_data.get('trap', {}).get('source_ip', 'unknown'),
                'trap_oid': json_data.get('trap', {}).get('oid', ''),
                'trap_name': json_data.get('trap', {}).get('name', ''),
                'severity': json_data.get('trap', {}).get('severity', 'info'),
                'uptime': json_data.get('trap', {}).get('uptime', ''),
                'transport': json_data.get('trap', {}).get('transport', ''),
                'raw_data': json.dumps(json_data)
            }

            # Process variable bindings
            variable_bindings = []
            for vb in json_data.get('varbinds', []):
                variable_bindings.append({
                    'oid': vb.get('oid', ''),
                    'value': vb.get('value', ''),
                    'resolved_name': vb.get('oid', ''),  # Already resolved in the input
                    'description': ''  # Could be enhanced with MIB lookup
                })

            trap_data['variable_bindings'] = variable_bindings

            return trap_data

        except Exception as e:
            self.logger.error(f"Error parsing trap entry: {e}")
            return None

    def store_trap(self, trap_data: Dict):
        """Store trap data in PostgreSQL database."""
        try:
            # Handle timestamp parsing with timezone support
            timestamp_str = trap_data.get('timestamp', datetime.now().isoformat())

            # Remove 'Z' if present and convert to datetime
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str[:-1] + '+00:00'

            try:
                timestamp = datetime.fromisoformat(timestamp_str)
            except ValueError:
                # Fallback to current time if parsing fails
                timestamp = datetime.now()
                self.logger.warning(f"Failed to parse timestamp {timestamp_str}, using current time")

            with self.engine.connect() as conn:
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
                    'timestamp': timestamp,
                    'hostname': trap_data.get('hostname', 'unknown'),
                    'source_ip': trap_data.get('source_ip', 'unknown'),
                    'trap_oid': trap_data.get('trap_oid', ''),
                    'trap_name': trap_data.get('trap_name', ''),
                    'severity': trap_data.get('severity', 'info'),
                    'uptime': trap_data.get('uptime', ''),
                    'transport': trap_data.get('transport', ''),
                    'variable_bindings': json.dumps(trap_data.get('variable_bindings', [])),
                    'raw_data': trap_data.get('raw_data', '{}')
                })
                conn.commit()

                self.logger.info(f"Stored trap from {trap_data.get('source_ip')} - {trap_data.get('trap_name')}")

        except Exception as e:
            self.logger.error(f"Failed to store trap: {e}")

    def process_traps(self):
        """Process new traps from Redis."""
        traps = self.get_traps_from_redis()
        if not traps:
            self.logger.debug("No new traps found in Redis")
            return

        self.logger.info(f"Processing {len(traps)} new traps")
        for trap in traps:
            trap_data = self.parse_trap_entry(trap)
            if trap_data:
                self.store_trap(trap_data)


def main():
    """Main application entry point."""
    processor = TrapProcessor()
    processor.logger.info("SNMP Trap Processor started - monitoring Redis for traps")

    try:
        while True:
            processor.process_traps()
            time.sleep(10)  # Check every 10 seconds

    except KeyboardInterrupt:
        processor.logger.info("Shutting down trap processor")


if __name__ == "__main__":
    main()
