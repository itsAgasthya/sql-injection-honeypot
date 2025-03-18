# SQL Injection Honeypot Tutorial

This tutorial explains how to use and test the SQL Injection Honeypot with HSIEM integration.

## Basic Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up the database:
```bash
mysql -u root -p < src/schema.sql
```

3. Configure environment variables:
```bash
cp .env.example .env
# Edit .env with your settings
```

4. Start the application:
```bash
PYTHONPATH=. python src/main.py
```

## Testing Attack Detection

The honeypot uses a sophisticated risk scoring system (0.0 to 1.0) with four severity levels:
- LOW (0.0 - 0.39): Basic probing attempts
- MEDIUM (0.4 - 0.59): Suspicious SQL patterns
- HIGH (0.6 - 0.79): Clear SQL injection attempts
- CRITICAL (0.8 - 1.0): Advanced SQL injection attacks

### Live Demo Instructions

For a live demonstration, you can use the web interface to perform attacks:

#### 1. LOW Severity Attacks (Risk Score < 0.4)
Browser-based testing:
1. Go to `http://localhost:9000/products`
2. In the category search box, try:
   - Enter: `test'--`
   - Enter: `test"`
   - Enter: `test#`

Expected Risk Score: ~0.36

#### 2. MEDIUM Severity Attacks (Risk Score 0.4 - 0.59)
Browser-based testing:
1. Go to `http://localhost:9000/login`
2. In the login form:
   - Username: `admin' OR '1'='1`
   - Password: `anything`

Expected Risk Score: ~0.40

#### 3. HIGH Severity Attacks (Risk Score 0.6 - 0.79)
Browser-based testing:
1. Go to `http://localhost:9000/products`
2. In the category search box, enter:
   ```sql
   1' UNION SELECT NULL,NULL,NULL,NULL,NULL --
   ```

Expected Risk Score: ~0.53

#### 4. CRITICAL Severity Attacks (Risk Score 0.8 - 1.0)
Browser-based testing:
1. Go to `http://localhost:9000/products`
2. In the category search box, enter:
   ```sql
   1' UNION ALL SELECT NULL,NULL,NULL,table_name,NULL FROM information_schema.tables; DROP TABLE users; --
   ```

Expected Risk Score: ~0.70

### Command-Line Testing

For automated testing using curl:

#### 1. LOW Severity Attacks
```bash
# Test suspicious characters
curl "http://localhost:9000/api/products?category=test--"
```

#### 2. MEDIUM Severity Attacks
```bash
# Basic OR condition
curl -X POST http://localhost:9000/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin' OR '1'='1&password=anything"
```

#### 3. HIGH Severity Attacks
```bash
# UNION-based injection
curl "http://localhost:9000/api/products?category=1' UNION SELECT NULL,NULL,NULL,NULL,NULL --"
```

#### 4. CRITICAL Severity Attacks
```bash
# Information schema access with destructive operation
curl "http://localhost:9000/api/products?category=1' UNION ALL SELECT NULL,NULL,NULL,table_name,NULL FROM information_schema.tables; DROP TABLE users; --"
```

## Monitoring Attacks

1. View HSIEM Dashboard:
```
http://localhost:9000/hsiem
```

2. Check application logs:
```bash
tail -f honeypot.log
```

3. Query attack logs from database:
```sql
mysql -u honeypot -p honeypot_db -e "SELECT timestamp, source_ip, attack_type, risk_score, request_data FROM attack_logs ORDER BY timestamp DESC LIMIT 10;"
```

## Understanding Risk Scores

The risk scoring system considers multiple factors:
1. SQL injection pattern complexity (weighted at 70%)
   - Information schema access: 0.4 base score
   - Destructive operations (DROP/DELETE): 0.35 base score
   - UNION-based injection: 0.3 base score
   - Data modification (INSERT/UPDATE): 0.3 base score
   - Basic boolean-based: 0.2 base score
   - Comment injection: 0.15 base score

2. Pattern combinations
   - Multiple patterns: +0.1 for each additional pattern

3. ML model prediction (weighted at 30%)
   - Contributes additional risk assessment based on training data

## HSIEM Features

The HSIEM dashboard provides:
1. Real-time attack monitoring
2. Risk score distribution
3. Attack trend analysis
4. System vulnerability assessment
5. Security recommendations

## Best Practices

1. Monitor the HSIEM dashboard regularly
2. Review high and critical severity attacks immediately
3. Analyze attack patterns in the trend graphs
4. Implement recommended security measures
5. Keep the honeypot system isolated from production

## Troubleshooting

If you encounter issues:
1. Check the honeypot.log file
2. Verify database connectivity
3. Ensure all required ports are open
4. Review system resource usage
5. Check SIEM integration status

## Recent Test Results

Recent attack detection test results:
1. LOW Severity (Comment Injection):
   - Risk Score: 0.36
   - Attack Type: SQL_INJECTION_PRODUCTS

2. MEDIUM Severity (Boolean-based):
   - Risk Score: 0.398
   - Attack Type: SQL_INJECTION_LOGIN

3. HIGH Severity (UNION-based):
   - Risk Score: 0.532
   - Attack Type: SQL_INJECTION_PRODUCTS

4. CRITICAL Severity (Information Schema):
   - Risk Score: 0.703
   - Attack Type: SQL_INJECTION_PRODUCTS
