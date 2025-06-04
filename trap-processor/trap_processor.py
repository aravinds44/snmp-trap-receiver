#!/usr/bin/env python3

import os
import sys
import time
import logging
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

import psycopg2
from psycopg2.extras import RealDictCursor
from sqlalchemy import create_engine, text
from easysnmp import Session
from easysnmp.exceptions import EasySNMPError

from config import Config

class TrapProcessor:
    def __init__(self):
        self.config = Config()
        self.setup_logging()
        self.setup_database()
        self.setup_mibs()

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

    def setup_mibs(self):
        """Initialize MIB loading."""
        self.mib_cache = {}
        self.load_mibs()

    def load_mibs(self):
        """Load MIB files for OID resolution."""
        try:
            # Add custom MIB path to environment
            if not os.path.exists(self.config.MIB_PATH):
                self.logger.error(f"MIB path does not exist: {self.config.MIB_PATH}")
                sys.exit(1)
            else:
                self.logger.info(f"MIB path exists at {self.config.MIB_PATH}")

            os.environ['MIBS'] = f"+{self.config.MIB_PATH}"
            os.environ['MIBDIRS'] = f"+{self.config.MIB_PATH}"

            self.logger.info(f"Loading MIBs from {self.config.MIB_PATH}")

            # Load standard MIBs
            for mib in self.config.MIB_SOURCES:
                try:
                    self.mib_cache[mib] = True
                    self.logger.debug(f"Loaded MIB: {mib}")
                except Exception as e:
                    self.logger.warning(f"Could not load MIB {mib}: {e}")

        except Exception as e:
            self.logger.error(f"Failed to initialize MIBs: {e}")

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
                    'timestamp': datetime.fromisoformat(trap_data.get('timestamp', datetime.now().isoformat())),
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

    def process_trap_log(self):
        """Process the trap log file for new entries."""
        trap_log_path = Path(self.config.TRAP_LOG_FILE)

        if not trap_log_path.exists():
            self.logger.warning(f"Trap log file not found: {trap_log_path}")
            return

        if not hasattr(self, 'last_position'):
            self.last_position = 0

        try:
            with open(trap_log_path, 'r') as f:
                f.seek(self.last_position)
                content = f.read()
                self.last_position = f.tell()

            if content.strip():
                # Split content into individual JSON objects (each starting with { and ending with })
                entries = []
                buffer = ""
                in_json = False
                brace_count = 0

                for char in content:
                    if char == '{':
                        if not in_json:
                            in_json = True
                            buffer = char
                        else:
                            buffer += char
                        brace_count += 1
                    elif char == '}':
                        if in_json:
                            buffer += char
                            brace_count -= 1
                            if brace_count == 0:
                                try:
                                    entries.append(json.loads(buffer))
                                    buffer = ""
                                    in_json = False
                                except json.JSONDecodeError as e:
                                    self.logger.error(f"Error decoding JSON: {e}")
                                    buffer = ""
                                    in_json = False
                                    brace_count = 0
                    elif in_json:
                        buffer += char

                for entry in entries:
                    if isinstance(entry, dict):
                        trap_data = self.parse_trap_entry(entry)
                        if trap_data:
                            self.store_trap(trap_data)

        except Exception as e:
            self.logger.error(f"Error processing trap log: {e}")

class TrapLogHandler(FileSystemEventHandler):
    """File system event handler for trap log monitoring."""

    def __init__(self, processor):
        self.processor = processor

    def on_modified(self, event):
        if event.src_path == self.processor.config.TRAP_LOG_FILE:
            self.processor.process_trap_log()

def main():
    """Main application entry point."""
    processor = TrapProcessor()

    # Setup file monitoring
    event_handler = TrapLogHandler(processor)
    observer = Observer()
    observer.schedule(event_handler, os.path.dirname(processor.config.TRAP_LOG_FILE), recursive=False)
    observer.start()

    processor.logger.info("SNMP Trap Processor started - monitoring trap log")

    try:
        while True:
            # Process any existing log entries
            processor.process_trap_log()
            time.sleep(10)  # Check every 10 seconds

    except KeyboardInterrupt:
        processor.logger.info("Shutting down trap processor")
        observer.stop()

    observer.join()

if __name__ == "__main__":
    main()