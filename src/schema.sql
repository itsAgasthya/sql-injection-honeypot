-- Create the honeypot database
CREATE DATABASE IF NOT EXISTS honeypot_db;
USE honeypot_db;

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_honeypot BOOLEAN DEFAULT FALSE
);

-- Create products table (honeytokens)
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2),
    category VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_honeypot BOOLEAN DEFAULT FALSE
);

-- Create attack_logs table
CREATE TABLE IF NOT EXISTS attack_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45) NOT NULL,
    request_method VARCHAR(10),
    request_path TEXT CHARACTER SET utf8mb4,
    request_data MEDIUMTEXT CHARACTER SET utf8mb4,
    type VARCHAR(100),
    attack_type VARCHAR(100),
    attack_details MEDIUMTEXT CHARACTER SET utf8mb4,
    risk_score FLOAT,
    user_agent TEXT CHARACTER SET utf8mb4,
    headers MEDIUMTEXT CHARACTER SET utf8mb4,
    response_code INT,
    is_malicious BOOLEAN
) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create ml_features table
CREATE TABLE IF NOT EXISTS ml_features (
    id INT AUTO_INCREMENT PRIMARY KEY,
    attack_log_id INT,
    feature_vector TEXT,
    prediction_score FLOAT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attack_log_id) REFERENCES attack_logs(id)
);

-- Insert sample honeytokens
INSERT INTO products (name, description, price, category, is_honeypot) VALUES
('Admin Console', 'Internal administrative dashboard', 999.99, 'admin', TRUE),
('User Database', 'Complete user database backup', 1499.99, 'data', TRUE),
('Payment Gateway', 'Payment processing system', 2999.99, 'finance', TRUE);

-- Create honeypot user if not exists
CREATE USER IF NOT EXISTS 'honeypot'@'localhost' IDENTIFIED BY 'honeypot';
GRANT ALL PRIVILEGES ON honeypot_db.* TO 'honeypot'@'localhost';
FLUSH PRIVILEGES; 