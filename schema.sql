-- schema.sql
-- Creates the minimal DB schema for CIDR Watcher daemon.

-- 1) database creation (optional)
CREATE DATABASE IF NOT EXISTS audit CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE audit;

-- 2) audit_ips: records hits per IP (supports IPv4 + IPv6)
CREATE TABLE IF NOT EXISTS audit_ips (
    ip VARCHAR(45) PRIMARY KEY,
    cidr VARCHAR(50) NULL,
    hits INT UNSIGNED NOT NULL DEFAULT 1,
    last_user_agent VARCHAR(512) NULL,
    last_body_sent_bytes BIGINT UNSIGNED NULL,
    last_domainname VARCHAR(255) NULL,
    last_http_method VARCHAR(10) NULL,
    last_referrer VARCHAR(2048) NULL,
    last_response_status_code INT NULL,
    last_path VARCHAR(2048) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 3) Indexes for table audit_ips
ALTER TABLE `audit_ips`
  ADD KEY `cidr` (`cidr`),
  ADD KEY `hits` (`hits`),
  ADD KEY `created_at` (`created_at`),
  ADD KEY `updated_at` (`updated_at`);
COMMIT;

-- 4) audit_state: single-row table storing last processed Influx timestamp (unix nanoseconds)
CREATE TABLE IF NOT EXISTS audit_state (
    id INT PRIMARY KEY,
    last_processed_timestamp BIGINT UNSIGNED NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- 5) seed initial state row if missing
INSERT INTO audit_state (id, last_processed_timestamp)
SELECT 1, 0
FROM DUAL
WHERE NOT EXISTS (SELECT 1 FROM audit_state WHERE id = 1);
-- end of schema.sql
