#!/usr/bin/env python3

"""
SNMP Trap Handler - Redis Integration
Description: Processes SNMP traps and stores them in Redis
Usage: Called by snmptrapd as trap handler
"""

import sys
import os
import json
import re
import logging
import logging.handlers
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import redis
from redis.exceptions import ConnectionError, TimeoutError, RedisError


class SNMPTrapHandler:
    """Handles SNMP trap processing and Redis storage."""

    def __init__(self):
        """Initialize the trap handler with configuration."""
        # Redis configuration
        self.redis_host = os.getenv('REDIS_HOST', 'localhost')
        self.redis_port = int(os.getenv('REDIS_PORT', 6379))
        self.redis_db = int(os.getenv('REDIS_DB', 0))
        self.redis_password = os.getenv('REDIS_PASSWORD', None)
        self.redis_socket_timeout = int(os.getenv('REDIS_SOCKET_TIMEOUT', 5))

        # Redis keys configuration
        self.trap_list_key = os.getenv('REDIS_TRAP_LIST_KEY', 'snmp:traps')
        self.trap_hash_prefix = os.getenv('REDIS_TRAP_HASH_PREFIX', 'snmp:trap:')
        self.stats_key = os.getenv('REDIS_STATS_KEY', 'snmp:stats')
        self.max_list_length = int(os.getenv('REDIS_MAX_LIST_LENGTH', 10000))

        # Fallback logging configuration
        self.error_log = "/var/log/snmp/trap_errors.log"
        self.fallback_log = "/var/log/snmp/traps_fallback.log"

        # Redis connection
        self.redis_client = None

        # Setup logging
        self._setup_logging()

        # Initialize Redis connection
        self._initialize_redis()

        # Ensure log directory exists for fallback
        self._ensure_log_directory()

    def _setup_logging(self):
        """Configure logging for errors and syslog."""
        # Setup error logging
        self.error_logger = logging.getLogger('snmp_trap_errors')
        self.error_logger.setLevel(logging.ERROR)

        # Create formatter
        formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

        # File handler for errors
        try:
            error_handler = logging.FileHandler(self.error_log)
            error_handler.setFormatter(formatter)
            self.error_logger.addHandler(error_handler)
        except Exception as e:
            # Fallback to console if file logging fails
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.error_logger.addHandler(console_handler)
            self.error_logger.error(f"Failed to setup file logging: {e}")

        # Setup syslog - with better fallback handling
        self.syslog_logger = logging.getLogger('snmp_trap_syslog')
        self.syslog_logger.setLevel(logging.INFO)

        # Try syslog first, then fallback to console
        syslog_available = False
        try:
            syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
            syslog_formatter = logging.Formatter('snmp-trap-handler: %(message)s')
            syslog_handler.setFormatter(syslog_formatter)
            self.syslog_logger.addHandler(syslog_handler)
            syslog_available = True
        except Exception as e:
            self.error_logger.error(f"Syslog unavailable: {e}")

        # Always add console handler as fallback
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter('%(message)s'))
        self.syslog_logger.addHandler(console_handler)

        if not syslog_available:
            self.syslog_logger.info("Syslog unavailable, using console logging")

    def _initialize_redis(self):
        """Initialize Redis connection with retry logic."""
        try:
            self.redis_client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                password=self.redis_password,
                socket_timeout=self.redis_socket_timeout,
                socket_connect_timeout=self.redis_socket_timeout,
                decode_responses=True,
                retry_on_timeout=True,
                health_check_interval=30
            )

            # Test connection
            self.redis_client.ping()
            self.log_info("Redis connection established successfully")

        except Exception as e:
            self.log_error(f"Failed to initialize Redis connection: {e}")
            self.redis_client = None

    def _ensure_log_directory(self):
        """Ensure log directory exists with proper permissions."""
        log_dir = Path(self.error_log).parent
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(log_dir, 0o755)
        except OSError as e:
            print(f"Warning: Failed to create log directory: {e}", file=sys.stderr)

    def log_error(self, message: str):
        """Log error message to both error log and syslog."""
        self.error_logger.error(message)
        self.syslog_logger.error(f"ERROR: {message}")

    def log_info(self, message: str):
        """Log info message to syslog."""
        self.syslog_logger.info(message)

    def fallback_to_file(self, trap_data: dict):
        """Fallback to file logging when Redis is unavailable."""
        try:
            with open(self.fallback_log, 'a', encoding='utf-8') as f:
                json.dump(trap_data, f, ensure_ascii=False, separators=(',', ':'))
                f.write('\n')

            # Set proper permissions
            try:
                os.chmod(self.fallback_log, 0o644)
            except OSError:
                pass

        except Exception as e:
            self.log_error(f"Failed to write to fallback log: {e}")

    def get_trap_severity(self, trap_oid: str, eagle_severity: str) -> str:
        """Determine trap severity based on OID and EagleXgDsrAlarmSeverity."""
        if eagle_severity:
            severity_map = {
                '1': 'critical',
                '2': 'major',
                '3': 'minor',
                '4': 'info',
                '5': 'clear',
                'critical': 'critical',
                'major': 'major',
                'minor': 'minor',
                'info': 'info',
                'clear': 'clear'
            }
            return severity_map.get(eagle_severity.lower(), 'info')

        return 'info'

    def parse_transport_info(self, transport_line: str) -> str:
        """Extract source IP from transport information."""
        # Pattern for UDP: [IP]:port->
        udp_pattern = r'UDP:\s*\[([^\]]+)\]:\d+->'
        match = re.search(udp_pattern, transport_line)
        if match:
            return match.group(1)

        # Pattern for simple IP address
        ip_pattern = r'(\d+\.\d+\.\d+\.\d+)'
        match = re.search(ip_pattern, transport_line)
        if match:
            return match.group(1)

        return ""

    def parse_oid_value_line(self, line: str) -> Optional[Tuple[str, str]]:
        """Parse OID-value pair from input line."""
        # Split on first whitespace sequence
        parts = line.split(None, 1)
        if len(parts) == 2:
            oid = parts[0].strip()
            value = parts[1].rstrip()  # Remove trailing whitespace only
            return oid, value
        return None

    def store_trap_in_redis(self, trap_data: dict) -> bool:
        """Store trap data in Redis."""
        if not self.redis_client:
            return False

        try:
            # Generate unique trap ID
            trap_id = f"{trap_data['timestamp']}_{trap_data['trap']['host']}_{id(trap_data)}"
            trap_key = f"{self.trap_hash_prefix}{trap_id}"

            # Use Redis pipeline for atomic operations
            pipe = self.redis_client.pipeline()

            # Store trap data as hash
            pipe.hset(trap_key, mapping={
                'data': json.dumps(trap_data, separators=(',', ':')),
                'timestamp': trap_data['timestamp'],
                'host': trap_data['trap']['host'],
                'source_ip': trap_data['trap']['source_ip'],
                'severity': trap_data['trap']['severity'],
                'trap_oid': trap_data['trap']['oid'],
                'trap_name': trap_data['trap']['name']
            })

            # Set expiration (30 days)
            pipe.expire(trap_key, 30 * 24 * 60 * 60)

            # Add to trap list (most recent first)
            pipe.lpush(self.trap_list_key, trap_id)

            # Trim list to max length
            pipe.ltrim(self.trap_list_key, 0, self.max_list_length - 1)

            # Update statistics
            current_time = datetime.now(timezone.utc)
            stats_data = {
                'total_traps': 1,
                f"severity_{trap_data['trap']['severity']}": 1,
                f"host_{trap_data['trap']['host']}": 1
            }
            # Set the timestamp separately (not with HINCRBY)
            pipe.hset(self.stats_key, 'last_trap_time', trap_data['timestamp'])

            for key, value in stats_data.items():
                pipe.hincrby(self.stats_key, key, value)

            # Execute pipeline
            pipe.execute()

            return True

        except (ConnectionError, TimeoutError) as e:
            self.log_error(f"Redis connection error: {e}")
            # Try to reconnect
            self._initialize_redis()
            return False

        except RedisError as e:
            self.log_error(f"Redis operation error: {e}")
            return False

        except Exception as e:
            self.log_error(f"Unexpected error storing trap in Redis: {e}")
            return False

    def process_trap(self) -> bool:
        """Process SNMP trap from stdin."""
        try:
            # Read all input lines
            lines = []
            for line in sys.stdin:
                lines.append(line.rstrip('\n\r'))

            if not lines:
                self.log_error("No input received")
                return False

            # Initialize variables
            host = ""
            source_ip = ""
            transport = ""
            trap_oid = ""
            trap_name = ""
            uptime = ""
            severity = "info"
            eagle_severity = ""

            oids = []
            values = []
            varbinds = []

            # Process input lines
            for line_num, line in enumerate(lines, 1):
                if line_num == 1:
                    host = line
                elif line_num == 2:
                    transport = line
                    source_ip = self.parse_transport_info(line)
                else:
                    # Parse OID-value pairs
                    oid_value = self.parse_oid_value_line(line)
                    if oid_value:
                        oid, value = oid_value
                        oids.append(oid)
                        values.append(value)

                        # Create varbind object
                        varbind = {
                            "oid": oid,
                            "value": value
                        }
                        varbinds.append(varbind)

                        # Extract specific trap information
                        if oid in ["SNMPv2-MIB::snmpTrapOID.0", ".1.3.6.1.6.3.1.1.4.1.0"]:
                            trap_oid = value
                            # Extract trap name by removing namespace and trailing .0
                            trap_name = re.sub(r'.*::', '', value)
                            trap_name = re.sub(r'\.0$', '', trap_name)
                        elif oid in ["DISMAN-EVENT-MIB::sysUpTimeInstance", ".1.3.6.1.2.1.1.3.0"]:
                            uptime = value
                        elif "eaglexgdsralarmseverity" in oid.lower():
                            eagle_severity = value

            # Determine severity
            severity = self.get_trap_severity(trap_oid, eagle_severity)

            # Create structured trap data
            timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

            trap_data = {
                "timestamp": timestamp,
                "level": "INFO",
                "message": "SNMP trap received",
                "trap": {
                    "host": host,
                    "source_ip": source_ip,
                    "transport": transport,
                    "oid": trap_oid,
                    "name": trap_name,
                    "severity": severity,
                    "uptime": uptime,
                    "varbind_count": len(oids)
                },
                "varbinds": varbinds,
                "metadata": {
                    "handler_version": "2.0",
                    "processed_lines": len(lines)
                }
            }

            # Try to store in Redis
            if not self.store_trap_in_redis(trap_data):
                # Fallback to file logging
                self.fallback_to_file(trap_data)
                self.log_error("Stored trap in fallback file due to Redis unavailability")

            # Send to syslog
            syslog_message = (
                f"host={host} src_ip={source_ip} trap={trap_name} "
                f"severity={severity} oid_count={len(oids)}"
            )
            self.syslog_logger.info(syslog_message)

            return True

        except Exception as e:
            self.log_error(f"Failed to process SNMP trap: {e}")
            return False

    def run(self):
        """Main execution method."""
        try:
            # Process the trap
            if not self.process_trap():
                self.log_error("Failed to process SNMP trap")
                return 1

            return 0

        except Exception as e:
            self.log_error(f"Unexpected error in main execution: {e}")
            return 1


def main():
    """Main entry point."""
    handler = SNMPTrapHandler()
    exit_code = handler.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

#TODO: benchmark testing to avoid trap loss