-- Initialize tansucloud database and roles (dev)
-- NOTE: Dev-only: passwords are hard-coded to match .env. Do NOT use in production.

CREATE DATABASE tansucloud;

-- Create required roles with fixed passwords (align with .env)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_user') THEN
    CREATE ROLE app_user LOGIN PASSWORD 'app_user_password';
  ELSE
    ALTER ROLE app_user WITH PASSWORD 'app_user_password';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pgbouncer') THEN
    CREATE ROLE pgbouncer LOGIN PASSWORD 'pgbouncerpass';
  ELSE
    ALTER ROLE pgbouncer WITH PASSWORD 'pgbouncerpass';
  END IF;
END $$;

GRANT CONNECT ON DATABASE tansucloud TO app_user;

-- Switch to tansucloud DB so grants apply to its public schema
\connect tansucloud

GRANT USAGE, CREATE ON SCHEMA public TO app_user;
