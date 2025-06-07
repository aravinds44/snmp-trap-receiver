import os
from decouple import config

class Config:
    # Database configuration
    DB_HOST = config('DB_HOST', default='localhost')
    DB_PORT = config('DB_PORT', default=5432, cast=int)
    DB_NAME = config('DB_NAME', default='snmptraps')
    DB_USER = config('DB_USER', default='snmpuser')
    DB_PASSWORD = config('DB_PASSWORD', default='snmppass')

    KAFKA_BROKER = os.getenv('KAFKA_BROKER', 'kafka:9092')
    KAFKA_TOPIC = os.getenv('KAFKA_TOPIC', 'snmp_traps')
    KAFKA_CONSUMER_GROUP = os.getenv('KAFKA_CONSUMER_GROUP', 'trap_processor_group')

    # Application configuration
    LOG_LEVEL = config('LOG_LEVEL', default='INFO')
    TRAP_LOG_FILE = '/app/logs/traps.log'
    APP_LOG_FILE = '/app/processor.log'

    # Database URL
    DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"