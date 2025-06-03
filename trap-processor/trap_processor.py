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

    def resolve_oid(self, oid: str) -> Tuple[str, str]:
        """
        Resolve OID to human-readable name.
        Returns tuple of (resolved_name, description)
        """
        try:
            # Try to resolve using easysnmp
            session = Session(hostname='localhost', community='public', version=2)

            # Remove leading dot if present
            clean_oid = oid.lstrip('.')

            # Try to get symbolic name
            try:
                # This is a simplified approach - in production you might want
                # to use more sophisticated MIB parsing
                if clean_oid.startswith('1.3.6.1.2.1.1.3.0'):
                    return ('sysUpTime.0', 'System uptime')
                elif clean_oid.startswith('1.3.6.1.6.3.1.1.4.1.0'):
                    return ('snmpTrapOID.0', 'SNMP trap OID')
                elif clean_oid.startswith('1.3.6.1.2.1.2.2.1.1'):
                    return ('ifIndex', 'Interface index')
                elif clean_oid.startswith('1.3.6.1.2.1.2.2.1.2'):
                    return ('ifDescr', 'Interface description')
                elif clean_oid.startswith('1.3.6.1.2.1.2.2.1.8'):
                    return ('ifOperStatus', 'Interface operational status')
                else:
                    # Try to map common enterprise OIDs
                    return self.resolve_enterprise_oid(clean_oid)

            except Exception as e:
                self.logger.debug(f"Could not resolve OID {oid}: {e}")
                return (oid, 'Unknown OID')

        except Exception as e:
            self.logger.warning(f"Error resolving OID {oid}: {e}")
            return (oid, 'Resolution failed')

    def resolve_enterprise_oid(self, oid: str) -> Tuple[str, str]:
        """Resolve enterprise-specific OIDs."""
        enterprise_mappings = {
            '1.3.6.1.4.1.9': 'cisco',
            '1.3.6.1.4.1.2021': 'net-snmp',
            '1.3.6.1.4.1.8072': 'net-snmp-agent',
            '1.3.6.1.4.1.2636': 'juniper',
            '1.3.6.1.4.1.11': 'hp',
        }

        for prefix, vendor in enterprise_mappings.items():
            if oid.startswith(prefix):
                return (f"{vendor}.{oid[len(prefix)+1:]}", f"{vendor} enterprise OID")

        return (oid, 'Enterprise OID')

    def parse_trap_entry(self, lines: List[str]) -> Optional[Dict]:
        """Parse a single trap entry from log lines."""
        trap_data = {}
        variable_bindings = []

        for line in lines:
            line = line.strip()
            if line.startswith('TRAP_START:'):
                trap_data['timestamp'] = line.split(':', 1)[1]
            elif line.startswith('HOST:'):
                trap_data['hostname'] = line.split(':', 1)[1]
            elif line.startswith('IP:'):
                trap_data['source_ip'] = line.split(':', 1)[1]
            elif line.startswith('OID:'):
                current_oid = line.split(':', 1)[1]
            elif line.startswith('VALUE:'):
                current_value = line.split(':', 1)[1]
                if 'current_oid' in locals():
                    resolved_name, description = self.resolve_oid(current_oid)
                    variable_bindings.append({
                        'oid': current_oid,
                        'resolved_name': resolved_name,
                        'value': current_value,
                        'description': description
                    })

        if variable_bindings:
            trap_data['variable_bindings'] = variable_bindings
            # Set trap OID from the first binding (usually snmpTrapOID)
            trap_data['trap_oid'] = variable_bindings[0]['oid']
            trap_data['trap_name'] = variable_bindings[0]['resolved_name']

        return trap_data if trap_data else None

    def store_trap(self, trap_data: Dict):
        """Store trap data in PostgreSQL database."""
        try:
            with self.engine.connect() as conn:
                query = text("""
                    INSERT INTO snmp_traps (
                        timestamp, hostname, source_ip, trap_oid, trap_name,
                        variable_bindings, raw_data
                    ) VALUES (
                        :timestamp, :hostname, :source_ip, :trap_oid, :trap_name,
                        :variable_bindings, :raw_data
                    )
                """)

                conn.execute(query, {
                    'timestamp': datetime.fromisoformat(trap_data.get('timestamp', datetime.now().isoformat())),
                    'hostname': trap_data.get('hostname', 'unknown'),
                    'source_ip': trap_data.get('source_ip', 'unknown'),
                    'trap_oid': trap_data.get('trap_oid', ''),
                    'trap_name': trap_data.get('trap_name', ''),
                    'variable_bindings': json.dumps(trap_data.get('variable_bindings', [])),
                    'raw_data': json.dumps(trap_data)
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
                # Split into individual trap entries
                entries = content.split('---\n')

                for entry in entries:
                    if entry.strip():
                        lines = entry.strip().split('\n')
                        if len(lines) > 1:  # Valid trap entry
                            trap_data = self.parse_trap_entry(lines)
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
