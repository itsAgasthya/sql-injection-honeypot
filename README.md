# SQL Injection Honeypot with HSIEM

A sophisticated honeypot system designed to detect, analyze, and monitor SQL injection attacks in real-time. The system includes a Honeypot Security Information and Event Management (HSIEM) dashboard for visual analysis of attack patterns and risk assessment.

## Features

- **Real-time Attack Detection**: Monitors and identifies SQL injection attempts as they occur
- **Risk Scoring System**: Assigns severity scores to attacks based on multiple factors
- **HSIEM Dashboard**: Visual interface for monitoring attacks and analyzing patterns
- **Comprehensive Logging**: Multiple logging mechanisms for thorough attack analysis
- **Attack Classification**: Categorizes attacks by type and severity
- **Honeytokens**: Includes fake sensitive data to attract and track malicious activity

## Architecture

- **Web Application**: Flask-based honeypot target
- **HSIEM Component**: Real-time monitoring and analysis dashboard
- **Database**: MySQL/MariaDB for storing attack logs and honeytokens
- **Logging System**: Multi-level logging with file and database handlers

## Prerequisites

- Python 3.8+
- MySQL/MariaDB
- Web browser (Chrome/Firefox recommended)
- Basic understanding of SQL and web security

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/sql-injection-honeypot.git
   cd sql-injection-honeypot
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Set up the database:
   ```bash
   sudo mysql < src/schema.sql
   ```

5. Start the application:
   ```bash
   PYTHONPATH=. python src/main.py
   ```

## Usage

1. Access the web interface:
   - Main application: `http://localhost:9000`
   - HSIEM Dashboard: `http://localhost:9000/hsiem`

2. Follow the tutorial:
   - See `tutorial.md` for detailed attack scenarios and analysis
   - Learn how to use both browser and command-line testing methods

## Security Considerations

- This is a honeypot system designed for educational and research purposes
- Do not deploy in production environments
- Use in isolated testing environments only
- Follow responsible disclosure practices if discovering new vulnerabilities

## Project Structure

```
sql-injection-honeypot/
├── src/
│   ├── honeypot/         # Honeypot application code
│   ├── hsiem/            # HSIEM dashboard components
│   ├── ml/               # Machine learning components
│   ├── schema.sql        # Database schema
│   └── main.py          # Application entry point
├── logs/                 # Application logs
├── hsiem_logs/          # HSIEM specific logs
├── requirements.txt     # Python dependencies
├── tutorial.md         # Usage tutorial
└── README.md          # This file
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Thanks to all contributors
- Inspired by real-world security research
- Built for educational purposes 