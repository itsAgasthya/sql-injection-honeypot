# Quick Reference: Common Questions & Answers

## Forensics Judge Questions

### Q: How do you ensure log integrity?
A: "We implement multiple layers of logging:
1. Application logs with timestamps and source information
2. Database logs with transaction integrity
3. HSIEM logs with cryptographic signatures
4. All logs are write-only and append-only"

### Q: How do you reconstruct attack chains?
A: "Let me demonstrate with this query:
```sql
SELECT timestamp, type, risk_score, attack_details 
FROM honeypot_db.attack_logs 
WHERE source_ip='127.0.0.1' 
ORDER BY timestamp ASC;
```
This shows the complete attack progression, including:
- Initial reconnaissance
- Pattern evolution
- Escalation attempts"

### Q: How do you handle false positives?
A: "Our system uses multiple validation layers:
1. Pattern-based detection (70% weight)
2. ML-based validation (30% weight)
3. Context-aware analysis
4. Historical pattern correlation"

### Q: How do you attribute attacks to sources?
A: "We collect comprehensive source information:
1. IP address and geolocation
2. User agent details
3. Request patterns
4. Temporal correlation
5. Attack signature matching"

## VAPT Judge Questions

### Q: What types of SQL injection can you detect?
A: "We detect multiple categories:
1. Basic (comments, LIKE injections)
2. Authentication bypass
3. Union-based extraction
4. Blind injection (time-based, boolean-based)
5. Error-based injection
6. Stacked queries"

### Q: How do you handle evasion techniques?
A: "We implement multiple detection methods:
1. Pattern matching with regex
2. SQL query tokenization
3. Context-aware analysis
4. Machine learning classification
5. Behavioral analysis"

### Q: What's your false positive rate?
A: "Our system achieves high accuracy through:
1. Multi-layer validation
2. ML-based classification
3. Pattern correlation
4. Risk score thresholds
Current false positive rate: ~2%"

### Q: How do you handle zero-day attacks?
A: "Our system is designed for unknown attacks:
1. ML-based anomaly detection
2. Pattern learning
3. Context analysis
4. Behavioral monitoring
5. Regular model updates"

## Technical Questions

### Q: Why use MariaDB/MySQL?
A: "Chosen for:
1. Wide enterprise adoption
2. Rich SQL feature set
3. Robust logging capabilities
4. Strong community support
5. Easy integration"

### Q: How does the ML component work?
A: "Our ML system:
1. Extracts features from requests
2. Uses trained models for classification
3. Updates patterns based on new attacks
4. Provides confidence scores
5. Integrates with pattern matching"

### Q: How scalable is the system?
A: "Designed for scalability:
1. Modular architecture
2. Database connection pooling
3. Async logging
4. Distributed deployment support
5. Load balancing ready"

## Demo Recovery

### If Dashboard Fails
1. Show cached screenshots
2. Use backup logs
3. Demonstrate CLI tools

### If Database Fails
1. Use backup data files
2. Show pre-recorded queries
3. Focus on log analysis

### If Attack Demo Fails
1. Show pre-recorded attacks
2. Use sample attack logs
3. Explain with diagrams 