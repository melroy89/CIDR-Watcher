-- schema.sql
-- Creates the minimal DB schema for CIDR Watcher daemon.

-- 1) database creation (optional)
CREATE DATABASE IF NOT EXISTS auditdb CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE auditdb;

-- 2) audit_ips: records hits per IP (supports IPv4 + IPv6)
CREATE TABLE IF NOT EXISTS audit_ips (
    ip VARCHAR(45) PRIMARY KEY,
    hits INT UNSIGNED NOT NULL DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_seen TIMESTAMP NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 3) audit_state: single-row table storing last processed Influx timestamp (unix nanoseconds)
CREATE TABLE IF NOT EXISTS audit_state (
    id INT PRIMARY KEY,
    last_processed BIGINT UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- seed initial state row if missing
INSERT INTO audit_state (id, last_processed)
SELECT 1, 0
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM audit_state WHERE id = 1);
-- end of schema.sql
