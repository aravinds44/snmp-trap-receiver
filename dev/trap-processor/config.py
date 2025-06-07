import os
from decouple import config

class Config:
    # Database configuration
    DB_HOST = config('DB_HOST', default='localhost')
    DB_PORT = config('DB_PORT', default=5432, cast=int)
    DB_NAME = config('DB_NAME', default='snmptraps')
    DB_USER = config('DB_USER', default='snmpuser')
    DB_PASSWORD = config('DB_PASSWORD', default='snmppass')

    REDIS_HOST = config('REDIS_HOST', default='localhost')
    REDIS_PORT = config('REDIS_PORT', default=6379, cast=int)
    REDIS_DB = config('REDIS_DB', default=0, cast=int)
    REDIS_PASSWORD = config('REDIS_PASSWORD', default=None)
    REDIS_SOCKET_TIMEOUT = config('REDIS_SOCKET_TIMEOUT', default=5, cast=int)
    REDIS_TRAP_LIST_KEY = config('REDIS_TRAP_LIST_KEY', default='snmp:traps')
    REDIS_TRAP_HASH_PREFIX = config('REDIS_TRAP_HASH_PREFIX', default='snmp:trap:')

    # Application configuration
    LOG_LEVEL = config('LOG_LEVEL', default='INFO')
    TRAP_LOG_FILE = '/app/logs/traps.log'
    APP_LOG_FILE = '/app/processor.log'

    # Database URL
    DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"