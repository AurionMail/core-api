
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    wkd_hash VARCHAR(32) UNIQUE,
    token_version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_users_wkd_hash ON users(wkd_hash);

CREATE TABLE IF NOT EXISTS user_vault (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    format VARCHAR(64) NOT NULL DEFAULT 'openpgp-plugin-backup',
    version INT NOT NULL DEFAULT 7,
    keys JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS user_message_cache (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    message_id VARCHAR(64) NOT NULL,
    encrypted_payload TEXT NOT NULL,
    iv VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    PRIMARY KEY (user_id, message_id)
);

CREATE INDEX IF NOT EXISTS idx_message_cache_user_id ON user_message_cache(user_id);