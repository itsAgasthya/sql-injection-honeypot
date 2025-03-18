# SQL Injection Honeypot Presentation Script

## Pre-Presentation Setup (5 minutes before)

1. Start the honeypot application:
```bash
PYTHONPATH=. python src/main.py
```

2. Open two browser windows:
   - Window 1: HSIEM Dashboard (http://localhost:9000/hsiem)
   - Window 2: Terminal for demonstrations

3. Clear existing logs:
```bash
> logs/honeypot.log
rm hsiem_logs/*
mysql -u honeypot -phoneypot -e "TRUNCATE TABLE honeypot_db.attack_logs;"
```

## Introduction (2 minutes)

"Good [morning/afternoon]. Today I'll be presenting a SQL Injection Honeypot with integrated HSIEM capabilities. This system combines advanced attack detection with comprehensive forensic analysis."

### Key Points:
- Purpose: Detect, analyze, and document SQL injection attacks
- Real-time monitoring and analysis
- Comprehensive logging and forensics
- Machine learning integration

## System Architecture (3 minutes)

"Let me walk you through the system architecture..."

1. Show architecture diagram
2. Highlight key components:
   - Web application honeypot
   - Attack detection engine
   - HSIEM integration
   - ML-based classification
   - Logging system

## Live Demonstration

### For Forensics Judge (15 minutes)

#### 1. Evidence Collection (4 minutes)
"Let me demonstrate our comprehensive evidence collection system..."

```bash
# Show real-time logging
tail -f logs/honeypot.log

# Show HSIEM logs
ls -l hsiem_logs/

# Demonstrate database logging
mysql -u honeypot -phoneypot -e "DESCRIBE honeypot_db.attack_logs;"
```

#### 2. Attack Chain Analysis (4 minutes)
"Now, I'll show you how we track attack evolution..."

1. Execute a series of attacks:
```bash
# LOW severity
curl "http://localhost:9000/api/products?category=test'--"

# MEDIUM severity
curl -X POST http://localhost:9000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin' OR '1'='1&password=anything"

# HIGH severity
curl "http://localhost:9000/api/products?category=1%27%20UNION%20SELECT%20NULL%2CNULL%2CNULL%2CNULL%2CNULL%20--"
```

2. Show the attack chain:
```bash
mysql -u honeypot -phoneypot -e "SELECT timestamp, type, risk_score, attack_details FROM honeypot_db.attack_logs WHERE source_ip='127.0.0.1' ORDER BY timestamp ASC;"
```

#### 3. Timeline Analysis (4 minutes)
"Let's analyze the attack timeline and pattern evolution..."

```bash
# Show hourly attack distribution
mysql -u honeypot -phoneypot -e "SELECT DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00') as hour, COUNT(*) as attacks, AVG(risk_score) as avg_risk FROM honeypot_db.attack_logs GROUP BY hour ORDER BY hour DESC;"

# Show pattern evolution
mysql -u honeypot -phoneypot -e "SELECT attack_type, COUNT(*) as count, AVG(risk_score) as avg_risk FROM honeypot_db.attack_logs GROUP BY attack_type ORDER BY avg_risk DESC;"
```

#### 4. Investigation Tools (3 minutes)
"These are our investigation and analysis tools..."

1. Show HSIEM Dashboard features:
   - Risk trend visualization
   - Attack pattern analysis
   - Source IP tracking
   - Event correlation

### For VAPT Judge (15 minutes)

#### 1. Attack Detection Capabilities (5 minutes)
"Let me demonstrate our attack detection capabilities..."

1. Show basic detection:
```bash
# Comment injection
curl "http://localhost:9000/api/products?category=test'--"
```

2. Show advanced detection:
```bash
# Blind SQL injection
curl "http://localhost:9000/api/products?category=1' AND IF(SUBSTRING(DATABASE(),1,1)='h',SLEEP(2),0) --"

# Error-based injection
curl "http://localhost:9000/api/products?category=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e)) --"
```

#### 2. Pattern Recognition (5 minutes)
"Our pattern recognition system uses both signature-based and ML-based detection..."

1. Show pattern matching:
   - Regular expressions
   - SQL query analysis
   - Context-aware detection

2. Demonstrate ML integration:
   - Feature extraction
   - Risk score calculation
   - Pattern learning

#### 3. Defense Mechanisms (5 minutes)
"Let's look at our defense and response mechanisms..."

1. Show real-time monitoring:
   - Attack detection
   - Risk scoring
   - Alert generation

2. Demonstrate deception techniques:
   - Honeytokens
   - False data
   - Response manipulation

## Q&A Preparation

### For Forensics Judge
- Evidence integrity preservation
- Chain of custody
- Timeline reconstruction
- Pattern correlation
- Data extraction capabilities

### For VAPT Judge
- False positive rates
- Detection coverage
- Evasion technique handling
- Response mechanisms
- Integration capabilities

## Conclusion (2 minutes)

"To summarize, this system provides:
1. Comprehensive attack detection
2. Detailed forensic analysis
3. Real-time monitoring
4. Machine learning integration
5. Extensive logging and reporting

Thank you for your attention. I'm happy to answer any questions."

## Emergency Backup Demos

If primary demos fail:

1. Show pre-recorded attack sequences
2. Use cached log files
3. Present static dashboard screenshots
4. Use backup database with sample data

## Technical Requirements

1. System Requirements:
   - Linux/Unix environment
   - Python 3.8+
   - MariaDB/MySQL
   - Modern web browser

2. Network Requirements:
   - Port 9000 available
   - Local network access
   - Database connectivity

3. Backup Materials:
   - Screenshots
   - Sample logs
   - Pre-recorded demos
   - Architecture diagrams 