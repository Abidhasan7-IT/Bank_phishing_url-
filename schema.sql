-- Database schema for "ENSURING SECURE ONLINE BANKING FROM PHISHING"
-- Compatible with MySQL / phpMyAdmin

CREATE DATABASE IF NOT EXISTS phishing_guard;
USE phishing_guard;

-- Optional users table for future authentication/authorization
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Known malicious URLs (seed with threat intel feeds if available)
CREATE TABLE IF NOT EXISTS phishing_urls (
  id INT AUTO_INCREMENT PRIMARY KEY,
  url VARCHAR(2048) NOT NULL UNIQUE,
  source VARCHAR(255) DEFAULT 'manual',
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Whitelist of verified Malaysian commercial bank domains
CREATE TABLE IF NOT EXISTS bank_whitelist (
  id INT AUTO_INCREMENT PRIMARY KEY,
  bank_name VARCHAR(255) NOT NULL,
  domain VARCHAR(255) NOT NULL UNIQUE,
  added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Seed whitelisted bank domains
INSERT IGNORE INTO bank_whitelist (bank_name, domain) VALUES
  ('Maybank', 'maybank2u.com.my'),
  ('CIMB Bank', 'cimb.com.my'),
  ('Public Bank', 'pbebank.com'),
  ('RHB Bank', 'rhbgroup.com'),
  ('Hong Leong Bank', 'hlb.com.my'),
  ('AmBank', 'ambank.com.my'),
  ('Bank Islam Malaysia', 'bankislam.com.my'),
  ('Alliance Bank', 'alliancebank.com.my'),
  ('Standard Chartered Malaysia', 'sc.com'),
  ('HSBC Malaysia', 'hsbc.com.my'),
  ('OCBC Malaysia', 'ocbc.com.my'),
  ('United Overseas Bank', 'uob.com.my'),
  ('Bank Rakyat', 'bankrakyat.com.my'),
  ('Affin Bank', 'affinbank.com.my'),
  ('Bank Muamalat', 'muamalat.com.my');

-- History of checked URLs and their signals
CREATE TABLE IF NOT EXISTS checked_urls (
  id INT AUTO_INCREMENT PRIMARY KEY,
  url VARCHAR(2048) NOT NULL,
  https_status TINYINT(1) NOT NULL,              -- 1 if HTTPS reachable, 0 otherwise
  domain_age INT NULL,                           -- age in days
  external_api_result VARCHAR(64) DEFAULT 'unknown',
  risk_score INT NOT NULL,
  final_status ENUM('safe', 'phishing') NOT NULL,
  checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_url (url),
  INDEX idx_checked_at (checked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;


-- Example user (replace hash in production)
-- INSERT INTO users (email, password_hash) VALUES
-- ('admin@example.com', '<bcrypt_hash_here>');

-- INSERT INTO users (email, password_hash) VALUES
-- ('admin@gmail.com', 'admin123');
