-- Migration: Add Multi-Company Support
-- Date: 2025-01-21
-- Description: Adds Company table and company_id foreign keys to users and items

-- Create Company table
CREATE TABLE IF NOT EXISTS company (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL,
    subdomain VARCHAR(50) UNIQUE,
    logo_url VARCHAR(256),
    primary_color VARCHAR(7) DEFAULT '#0d6efd',
    address VARCHAR(256),
    phone VARCHAR(50),
    email VARCHAR(120),
    website VARCHAR(256),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    max_users INTEGER,
    max_items INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Add indexes
CREATE INDEX IF NOT EXISTS idx_company_name ON company(name);
CREATE INDEX IF NOT EXISTS idx_company_subdomain ON company(subdomain);
CREATE INDEX IF NOT EXISTS idx_company_is_active ON company(is_active);

-- Add company_id to user table
ALTER TABLE "user" ADD COLUMN IF NOT EXISTS company_id INTEGER REFERENCES company(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_user_company_id ON "user"(company_id);

-- Add company_id to item table
ALTER TABLE item ADD COLUMN IF NOT EXISTS company_id INTEGER REFERENCES company(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_item_company_id ON item(company_id);

-- Create default company for existing data (optional)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM company WHERE name = 'Default Organization') THEN
        INSERT INTO company (name, subdomain, is_active, created_at, updated_at)
        VALUES ('Default Organization', NULL, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
    END IF;
END $$;
