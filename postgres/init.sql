CREATE TABLE traps (
                       id SERIAL PRIMARY KEY,
                       received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                       source_ip VARCHAR(45),
                       oid VARCHAR(256),
                       var_binds JSONB,
                       raw_message TEXT,
                       security_level VARCHAR(20),
                       is_encrypted BOOLEAN DEFAULT FALSE
);