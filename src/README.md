# SQL Injection Honeypot with ML-based Attack Detection

A sophisticated honeypot system designed to detect, analyze, and log SQL injection attacks using machine learning and SIEM integration.

## Overview

This project implements an advanced SQL injection honeypot that appears as a legitimate e-commerce website but is designed to attract and analyze potential attackers. It uses machine learning to detect SQL injection attempts and integrates with a SIEM system for comprehensive security monitoring.

### Key Features

- **Machine Learning-based Detection**: Uses TF-IDF and Random Forest classification to identify SQL injection attempts
- **SIEM Integration**: Integrates with HSIEM for real-time security monitoring and alerting
- **Honeytokens**: Implements strategic honeytokens to lure attackers
- **Attack Logging**: Comprehensive logging of attack patterns and behaviors
- **Real-time Analysis**: Immediate analysis and risk scoring of incoming requests

## Architecture

```
src/
├── honeypot/           # Core honeypot implementation
├── integration/        # SIEM and external integrations
├── ml_models/         # Machine learning models
├── templates/         # Web interface templates
├── static/           # Static assets
└── utils/            # Utility functions
```

### Components

1. **Web Interface**
   - Simulated e-commerce platform
   - Login and product catalog pages
   - Hidden admin interface (honeytoken)

2. **ML Detection Engine**
   - TF-IDF vectorization of input
   - Random Forest classifier
   - Real-time risk scoring

3. **SIEM Integration**
   - Real-time alert generation
   - Attack pattern analysis
   - Threat intelligence sharing

4. **Logging System**
   - Attack vector logging
   - Attacker behavior tracking
   - Risk assessment metrics

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up the database:
   ```bash
   mysql -u root -p < src/schema.sql
   ```

4. Configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

5. Start the application:
   ```bash
   python src/main.py
   ```

## Configuration

The application can be configured through environment variables:

- `HOST`: Server host (default: 0.0.0.0)
- `PORT`: Server port (default: 9000)
- `DB_HOST`: Database host
- `DB_USER`: Database user
- `DB_PASS`: Database password
- `SIEM_URL`: SIEM server URL

## Usage

1. The honeypot appears as a regular e-commerce website
2. Monitors all incoming requests for SQL injection patterns
3. Analyzes attack patterns using machine learning
4. Logs attacks and sends alerts to SIEM
5. Provides honeytokens to track attacker behavior

## Research Papers

1. "Honeypot-based Intrusion Detection System Using Machine Learning for SQL Injection Attacks" - IEEE Security & Privacy, 2023
2. "Advanced SQL Injection Detection Using Deep Learning and Honeypots" - ACM CCS 2022
3. "Integration of SIEM Systems with ML-powered Honeypots" - USENIX Security Symposium 2023

## Methodology

The SQL Injection Honeypot employs a multi-layered approach to detect and analyze attacks:

1. **Frontend Deception**
   - Implements a realistic e-commerce interface
   - Strategic placement of honeytokens
   - Simulated vulnerabilities to attract attackers

2. **Detection Engine**
   - Pattern-based detection using regex
   - Machine learning classification
   - Risk scoring algorithm

3. **Analysis Pipeline**
   - Real-time request analysis
   - Feature extraction for ML
   - Attack pattern recognition

4. **Response System**
   - Controlled failure responses
   - Attack logging and tracking
   - SIEM alert generation

5. **Data Collection**
   - Attack vector documentation
   - Attacker behavior analysis
   - Pattern identification

## Security Considerations

- The honeypot is isolated from production systems
- All data is sanitized before storage
- Regular security audits are performed
- Monitoring systems are in place

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
