#!/usr/bin/env python3

import sys
import re
import json
import psycopg2
import os
from datetime import datetime
from pysnmp.hlapi import *

def parse_trap(trap_data):
    """Parse raw SNMP trap data into structured format"""
    result = {
        'source_ip': None,
        'oid': None,
        'var_binds': {},
        'raw_message': trap_data,
        'security_level': 'none',
        'is_encrypted': False
    }

    # Extract source IP
    ip_match = re.search(r'\[.*?\] ([\d\.:]+)', trap_data.split('\n')[0])
    if ip_match:
        result['source_ip'] = ip_match.group(1)

    # Extract OID
    oid_match = re.search(r'SNMPv2-SMI::([^\s]+)', trap_data)
    if oid_match:
        result['oid'] = oid_match.group(1)

    # Extract variable bindings
    for line in trap_data.split('\n'):
        if '=' in line:
            var, val = line.split('=', 1)
            var = var.strip()
            val = val.strip()
            result['var_binds'][var] = val

    # Check for security parameters
    if 'usmSecurityParameters' in trap_data:
        result['security_level'] = 'authPriv' if 'priv' in trap_data.lower() else 'authNoPriv'
        result['is_encrypted'] = 'priv' in trap_data.lower()

    return result

def store_trap(trap_info):
    """Store trap information in PostgreSQL"""
    try:
        conn = psycopg2.connect(
            dbname=os.getenv('POSTGRES_DB'),
            user=os.getenv('POSTGRES_USER'),
            password=os.getenv('POSTGRES_PASSWORD'),
            host=os.getenv('POSTGRES_HOST')
        )
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO traps (
                source_ip, oid, var_binds, raw_message, 
                security_level, is_encrypted
            ) VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            trap_info['source_ip'],
            trap_info['oid'],
            json.dumps(trap_info['var_binds']),
            trap_info['raw_message'],
            trap_info['security_level'],
            trap_info['is_encrypted']
        ))

        conn.commit()
    except Exception as e:
        print(f"Database error: {e}", file=sys.stderr)
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    trap_data = sys.stdin.read()
    trap_info = parse_trap(trap_data)
    store_trap(trap_info)