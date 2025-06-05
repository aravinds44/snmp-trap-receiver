-- Initialize SNMP traps database schema

-- Create database if it doesn't exist (handled by docker-entrypoint)
-- CREATE DATABASE IF NOT EXISTS snmptraps;

-- ALTER USER snmpuser PASSWORD 'snmppass';
-- Create schema for SNMP traps
CREATE SCHEMA IF NOT EXISTS snmp;

-- Create main traps table
CREATE TABLE IF NOT EXISTS snmp_traps (
                                          id BIGSERIAL PRIMARY KEY,
                                          timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    hostname VARCHAR(255),
    source_ip INET NOT NULL,
    trap_oid VARCHAR(255) NOT NULL,
    trap_name VARCHAR(255),
    variable_bindings JSONB,
    raw_data JSONB,
    severity VARCHAR(50) DEFAULT 'info',
    uptime VARCHAR(50),  -- Added for new JSON format
    transport VARCHAR(255),  -- Added for new JSON format
    acknowledged BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
    );

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_snmp_traps_timestamp ON snmp_traps(timestamp);
CREATE INDEX IF NOT EXISTS idx_snmp_traps_source_ip ON snmp_traps(source_ip);
CREATE INDEX IF NOT EXISTS idx_snmp_traps_trap_oid ON snmp_traps(trap_oid);
CREATE INDEX IF NOT EXISTS idx_snmp_traps_trap_name ON snmp_traps(trap_name);
CREATE INDEX IF NOT EXISTS idx_snmp_traps_severity ON snmp_traps(severity);
CREATE INDEX IF NOT EXISTS idx_snmp_traps_acknowledged ON snmp_traps(acknowledged);
CREATE INDEX IF NOT EXISTS idx_snmp_traps_uptime ON snmp_traps(uptime);
CREATE INDEX IF NOT EXISTS idx_snmp_traps_transport ON snmp_traps(transport);

-- Create GIN index for JSONB columns for better JSON query performance
CREATE INDEX IF NOT EXISTS idx_snmp_traps_variable_bindings_gin ON snmp_traps USING GIN(variable_bindings);
CREATE INDEX IF NOT EXISTS idx_snmp_traps_raw_data_gin ON snmp_traps USING GIN(raw_data);

-- Create trap statistics table
CREATE TABLE IF NOT EXISTS snmp_trap_stats (
                                               id SERIAL PRIMARY KEY,
                                               date DATE NOT NULL DEFAULT CURRENT_DATE,
                                               trap_oid VARCHAR(255) NOT NULL,
    trap_name VARCHAR(255),
    source_ip INET NOT NULL,
    severity VARCHAR(50),
    count INTEGER DEFAULT 1,
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(date, trap_oid, source_ip)
    );


-- Create index for trap statistics
CREATE INDEX IF NOT EXISTS idx_snmp_trap_stats_date ON snmp_trap_stats(date);
CREATE INDEX IF NOT EXISTS idx_snmp_trap_stats_trap_oid ON snmp_trap_stats(trap_oid);
CREATE INDEX IF NOT EXISTS idx_snmp_trap_stats_source_ip ON snmp_trap_stats(source_ip);

-- Create function to update trap statistics
CREATE OR REPLACE FUNCTION update_trap_stats()
RETURNS TRIGGER AS $$
BEGIN
INSERT INTO snmp_trap_stats (date, trap_oid, trap_name, source_ip, severity, count, first_seen, last_seen)
VALUES (CURRENT_DATE, NEW.trap_oid, NEW.trap_name, NEW.source_ip, NEW.severity, 1, NEW.timestamp, NEW.timestamp)
    ON CONFLICT (date, trap_oid, source_ip)
    DO UPDATE SET
               count = snmp_trap_stats.count + 1,
               last_seen = NEW.timestamp,
               trap_name = COALESCE(NEW.trap_name, snmp_trap_stats.trap_name),
               severity = COALESCE(NEW.severity, snmp_trap_stats.severity);

RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to automatically update statistics
CREATE TRIGGER trigger_update_trap_stats
    AFTER INSERT ON snmp_traps
    FOR EACH ROW
    EXECUTE FUNCTION update_trap_stats();

-- Create function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to automatically update updated_at
CREATE TRIGGER trigger_update_snmp_traps_updated_at
    BEFORE UPDATE ON snmp_traps
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Grant permissions (adjust as needed for production)
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO snmpuser;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO snmpuser;
GRANT ALL PRIVILEGES ON SCHEMA snmp TO snmpuser;

-- Create views for common queries
CREATE OR REPLACE VIEW recent_traps AS
SELECT
    id,
    timestamp,
    hostname,
    source_ip,
    trap_name,
    trap_oid,
    variable_bindings->0->>'value' AS first_binding_value,
    severity,
    uptime,
    transport,
    acknowledged
FROM snmp_traps
WHERE timestamp >= NOW() - INTERVAL '24 hours'
ORDER BY timestamp DESC;

CREATE OR REPLACE VIEW trap_summary AS
SELECT
    trap_name,
    trap_oid,
    severity,
    COUNT(*) as total_count,
    COUNT(DISTINCT source_ip) as unique_sources,
    MAX(timestamp) as last_seen,
    MIN(timestamp) as first_seen
FROM snmp_traps
GROUP BY trap_name, trap_oid, severity
ORDER BY total_count DESC;

-- Set up table partitioning for better performance with large datasets
-- This creates monthly partitions for the traps table
-- Uncomment if you expect high volume of traps

-- CREATE TABLE snmp_traps_template (LIKE snmp_traps INCLUDING ALL);
-- ALTER TABLE snmp_traps RENAME TO snmp_traps_old;
-- CREATE TABLE snmp_traps (LIKE snmp_traps_template INCLUDING ALL) PARTITION BY RANGE (timestamp);

-- Create initial partition for current month
-- CREATE TABLE snmp_traps_y2025m01 PARTITION OF snmp_traps
-- FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');