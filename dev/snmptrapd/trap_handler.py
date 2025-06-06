#!/usr/bin/env python3

"""
SNMP Trap Handler - Production Ready
Description: Processes SNMP traps and logs them in structured format
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


class SNMPTrapHandler:
    """Handles SNMP trap processing and logging."""

    def __init__(self):
        """Initialize the trap handler with configuration."""
        self.log_file = "/var/log/snmp/traps.log"
        self.error_log = "/var/log/snmp/trap_errors.log"
        self.max_log_size = 100 * 1024 * 1024  # 100MB in bytes
        self.syslog_facility = logging.handlers.SysLogHandler.LOG_LOCAL0
        self.syslog_priority = logging.INFO

        # Setup logging
        self._setup_logging()

        # Ensure log directory exists
        self._ensure_log_directory()

    def _setup_logging(self):
        """Configure logging for errors and syslog."""
        # Setup error logging
        self.error_logger = logging.getLogger('snmp_trap_errors')
        self.error_logger.setLevel(logging.ERROR)

        error_handler = logging.FileHandler(self.error_log)
        error_formatter = logging.Formatter('%(asctime)s ERROR: %(message)s')
        error_handler.setFormatter(error_formatter)
        self.error_logger.addHandler(error_handler)

        # Setup syslog
        self.syslog_logger = logging.getLogger('snmp_trap_syslog')
        self.syslog_logger.setLevel(logging.INFO)

        try:
            syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')
            syslog_formatter = logging.Formatter('snmp-trap-handler: %(message)s')
            syslog_handler.setFormatter(syslog_formatter)
            self.syslog_logger.addHandler(syslog_handler)
        except Exception as e:
            # Fallback to console if syslog is not available
            console_handler = logging.StreamHandler()
            self.syslog_logger.addHandler(console_handler)

    def _ensure_log_directory(self):
        """Ensure log directory exists with proper permissions."""
        log_dir = Path(self.log_file).parent
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(log_dir, 0o755)
        except OSError as e:
            self.log_error(f"Failed to create log directory: {e}")
            raise

    def log_error(self, message: str):
        """Log error message to both error log and syslog."""
        self.error_logger.error(message)
        self.syslog_logger.error(f"ERROR: {message}")

    def rotate_log_if_needed(self):
        """Rotate log file if it exceeds maximum size."""
        try:
            if os.path.exists(self.log_file):
                file_size = os.path.getsize(self.log_file)
                if file_size > self.max_log_size:
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    backup_file = f"{self.log_file}.{timestamp}"
                    os.rename(self.log_file, backup_file)

                    # Create new log file with proper permissions
                    Path(self.log_file).touch()
                    os.chmod(self.log_file, 0o644)
        except OSError as e:
            self.log_error(f"Failed to rotate log file: {e}")

    def escape_json_string(self, value: str) -> str:
        """Escape string for JSON output."""
        if not isinstance(value, str):
            value = str(value)

        # Remove trailing whitespace
        value = value.rstrip()

        # Use json.dumps to properly escape the string, then remove the surrounding quotes
        return json.dumps(value)[1:-1]

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
                        # elif oid in ["EAGLEXGDSR-MIB::eagleXgDsrAlarmSeverity", ".1.3.6.1.4.1.323.5.3.28.1.1.3.5.1.7"]:
                        elif "eagleXgDsrAlarmSeverity" in oid:
                            eagle_severity = value
                            print(f"Eagle Sev: {value}")

            # Determine severity
            severity = self.get_trap_severity(trap_oid, eagle_severity)

            # Create structured log entry
            timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

            log_entry = {
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

            # Write to log file
            with open(self.log_file, 'a', encoding='utf-8') as f:
                json.dump(log_entry, f, ensure_ascii=False, separators=(',', ':'))
                f.write('\n')

            # Set proper permissions
            try:
                os.chmod(self.log_file, 0o644)
            except OSError:
                pass  # Ignore permission errors

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
            # Rotate log if needed
            self.rotate_log_if_needed()

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