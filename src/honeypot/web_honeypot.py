import os
import re
import json
import logging
import sqlparse
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template, redirect, session, send_file
from sqlalchemy import create_engine, text
import numpy as np
from ..ml_models.attack_classifier import SQLInjectionClassifier
from ..integration.hsiem.hsiem import HSIEMIntegration
from ..data_collector.data_collector import DataCollector
from ..vulnerability_assessment.vulnerability_assessment import VulnerabilityAssessment
import matplotlib.pyplot as plt
import io
import time
import threading

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='honeypot.log'
)
logger = logging.getLogger(__name__)

class SQLInjectionHoneypot:
    def __init__(self):
        self.app = Flask(__name__, 
                        template_folder='../templates',
                        static_folder='../static')
        self.app.secret_key = os.urandom(24)
        
        # Initialize database connection with proper settings
        self.db = create_engine(
            'mariadb+mysqldb://honeypot:honeypot@localhost/honeypot_db',
            pool_size=5,
            max_overflow=10,
            pool_timeout=30,
            pool_recycle=1800  # Recycle connections after 30 minutes
        )
        
        # Test database connection
        try:
            with self.db.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info("Database connection successful")
        except Exception as e:
            logger.error(f"Database connection failed: {str(e)}", exc_info=True)
            raise
        
        # Initialize ML model
        self.classifier = SQLInjectionClassifier()
        
        # Initialize HSIEM integration
        self.hsiem = HSIEMIntegration()
        
        # Initialize data collector and assessment
        self.collector = DataCollector()
        
        # Setup routes
        self.setup_routes()
        
        # SQL injection patterns
        self.sql_patterns = [
            r'(\bUNION\b.*\bSELECT\b|\bOR\b.*\b1\b.*=.*\b1\b|\bAND\b.*\b1\b.*=.*\b1\b)',
            r'(-{2}|\/\*|\*\/|#)',
            r'(\bDROP\b.*\bTABLE\b|\bDELETE\b.*\bFROM\b)',
            r'(\bINSERT\b.*\bINTO\b|\bUPDATE\b.*\bSET\b)',
            r'(\bSELECT\b.*\bFROM\b.*\bINFORMATION_SCHEMA\b)'
        ]
        
        # Initialize risk history
        self.initialize_risk_history()
        
        # Start system monitoring
        self.start_monitoring()
    
    def initialize_risk_history(self):
        """Initialize risk history file with default data if it doesn't exist"""
        try:
            history_file = "risk_history.json"
            if not os.path.exists(history_file):
                # Create initial history with some default data points
                initial_history = []
                current_time = datetime.now()
                
                # Add some initial data points
                for i in range(5):
                    initial_history.append({
                        "timestamp": (current_time - timedelta(minutes=i*5)).isoformat(),
                        "risk_score": 0.2  # Start with low risk
                    })
                
                with open(history_file, "w") as f:
                    json.dump(initial_history, f, indent=2)
                    
            logger.info("Risk history initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing risk history: {str(e)}", exc_info=True)
    
    def setup_routes(self):
        """Setup Flask routes"""
        self.app.route('/')(self.index)
        self.app.route('/login', methods=['GET', 'POST'])(self.login)
        self.app.route('/products')(self.products)
        self.app.route('/api/products')(self.api_products)
        self.app.route('/admin')(self.admin)
        # Add HSIEM routes
        self.app.route('/hsiem')(self.hsiem_dashboard)
        self.app.route('/api/hsiem/events')(self.get_hsiem_events)
        self.app.route('/api/hsiem/events/<event_id>')(self.get_hsiem_event_details)
        self.app.route('/api/hsiem/system')(self.get_system_status)
        self.app.route('/api/hsiem/assessment')(self.get_system_assessment)
        self.app.route('/api/hsiem/graph')(self.get_risk_graph)
        self.app.route('/api/hsiem/trend')(self.get_risk_trend)
    
    def detect_sql_injection(self, input_data):
        """Detect potential SQL injection attempts"""
        if not input_data:
            return False, 0.0
            
        # Convert input to string if it's not already
        if isinstance(input_data, (dict, list)):
            input_data = json.dumps(input_data)
        
        # Pattern weights based on complexity and potential impact
        pattern_weights = {
            r'(\bUNION\b.*\bSELECT\b)': 0.3,  # UNION-based injection
            r'(\bINFORMATION_SCHEMA\b)': 0.4,  # Information schema access
            r'(\bDROP\b.*\bTABLE\b|\bDELETE\b.*\bFROM\b)': 0.35,  # Destructive operations
            r'(\bINSERT\b.*\bINTO\b|\bUPDATE\b.*\bSET\b)': 0.3,  # Data modification
            r'(\bOR\b.*\b1\b.*=.*\b1\b|\bAND\b.*\b1\b.*=.*\b1\b)': 0.2,  # Basic boolean-based
            r'(-{2}|\/\*|\*\/|#)': 0.15  # Basic comment injection
        }
        
        # Calculate base risk score from patterns
        risk_score = 0.0
        matched_patterns = []
        for pattern, weight in pattern_weights.items():
            if re.search(pattern, input_data, re.IGNORECASE):
                matched_patterns.append(pattern)
                risk_score = max(risk_score, weight)
        
        # Add complexity bonus for multiple patterns
        if len(matched_patterns) > 1:
            risk_score += 0.1 * (len(matched_patterns) - 1)
        
        # Use ML model for additional detection
        ml_score = self.classifier.predict_risk(input_data)
        
        # Combine pattern-based and ML scores with weighted average
        final_score = (0.7 * risk_score) + (0.3 * float(ml_score))
        
        # Normalize final score to 0-1 range
        final_score = min(1.0, max(0.0, final_score))
        
        return final_score > 0.3, final_score
        
    def log_attack(self, request_obj, attack_type, risk_score):
        """Log detected attacks"""
        try:
            # Map attack types to more descriptive names
            attack_type_mapping = {
                'SQL_INJECTION_LOGIN': 'Authentication Bypass Attempt',
                'SQL_INJECTION_PRODUCTS': 'Data Extraction Attempt'
            }

            # Get attack details based on the input
            attack_details = self._get_attack_details(request_obj, attack_type)
            
            # Safely get request data
            if request_obj.method == 'POST':
                request_data = {k: v for k, v in request_obj.form.items()}
            else:
                request_data = {k: v for k, v in request_obj.args.items()}
            
            log_data = {
                'source_ip': request_obj.remote_addr,
                'request_method': request_obj.method,
                'request_path': request_obj.path,
                'request_data': json.dumps(request_data),
                'type': attack_type_mapping.get(attack_type, attack_type),
                'attack_type': attack_type,
                'attack_details': attack_details,
                'risk_score': risk_score,
                'user_agent': request_obj.user_agent.string,
                'headers': json.dumps(dict(request_obj.headers)),
                'response_code': 200,
                'is_malicious': True
            }
            
            # Log to database using transaction
            query = text("""
                INSERT INTO attack_logs 
                (source_ip, request_method, request_path, request_data, 
                type, attack_type, attack_details, risk_score, user_agent, 
                headers, response_code, is_malicious)
                VALUES 
                (:source_ip, :request_method, :request_path, :request_data,
                :type, :attack_type, :attack_details, :risk_score, :user_agent, 
                :headers, :response_code, :is_malicious)
            """)
            
            with self.db.begin() as conn:
                conn.execute(query, log_data)
                
            # Send to HSIEM
            self.hsiem.send_event('sql_injection_attempt', log_data)
            
            logger.info(f"Attack logged: {log_data['source_ip']} - {log_data['type']} - Risk Score: {risk_score}")
            
        except Exception as e:
            logger.error(f"Error logging attack: {str(e)}", exc_info=True)
            # Try to log to file if database fails
            try:
                with open('attack_logs.txt', 'a') as f:
                    f.write(f"{datetime.now().isoformat()} - {request_obj.remote_addr} - {attack_type} - {risk_score}\n")
            except Exception as e2:
                logger.error(f"Failed to write to backup log file: {str(e2)}", exc_info=True)

    def _get_attack_details(self, request_obj, attack_type):
        """Get detailed information about the attack based on the request"""
        details = {}
        
        if attack_type == 'SQL_INJECTION_LOGIN':
            # For login attacks, capture the attempted username
            username = request_obj.form.get('username', '')
            details = {
                'attempted_username': username,
                'injection_point': 'login_form',
                'target': 'authentication'
            }
        elif attack_type == 'SQL_INJECTION_PRODUCTS':
            # For product attacks, capture the category parameter
            category = request_obj.args.get('category', '')
            details = {
                'injection_value': category,
                'injection_point': 'category_parameter',
                'target': 'product_query'
            }
        
        return json.dumps(details)
    
    def index(self):
        """Home page route"""
        return render_template('index.html')
    
    def login(self):
        """Login route"""
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            # Check for SQL injection
            is_attack, risk_score = self.detect_sql_injection(request.form)
            if is_attack:
                self.log_attack(request, 'SQL_INJECTION_LOGIN', risk_score)
                return jsonify({'error': 'Invalid credentials'}), 401
            
            # Simulate login (always fail for honeypot)
            return jsonify({'error': 'Invalid credentials'}), 401
            
        return render_template('login.html')
    
    def products(self):
        """Products page route"""
        return render_template('products.html')
    
    def api_products(self):
        """Products API route"""
        try:
            category = request.args.get('category', '')
            
            # Check for SQL injection
            is_attack, risk_score = self.detect_sql_injection(request.args)
            if is_attack:
                self.log_attack(request, 'SQL_INJECTION_PRODUCTS', risk_score)
                return jsonify([])
            
            # Return honeytokens
            query = text("""
                SELECT id, name, description, price, category 
                FROM products 
                WHERE is_honeypot = TRUE
                AND (:category = '' OR category = :category)
            """)
            
            with self.db.connect() as conn:
                result = conn.execute(query, {'category': category})
                products = [dict(row) for row in result]
                
            return jsonify(products)
            
        except Exception as e:
            logger.error(f"Error in products API: {str(e)}", exc_info=True)
            return jsonify({'error': 'Internal server error'}), 500
    
    def admin(self):
        """Admin page route (honeypot)"""
        if not session.get('logged_in'):
            return redirect('/login')
        return render_template('admin.html')
    
    def hsiem_dashboard(self):
        """HSIEM Dashboard route"""
        try:
            # Get events from database
            with self.db.connect() as conn:
                # Get recent events
                events_query = text("""
                    SELECT * FROM attack_logs 
                    ORDER BY timestamp DESC 
                    LIMIT 10
                """)
                events = [dict(row) for row in conn.execute(events_query)]
                
                # Get statistics
                stats_query = text("""
                    SELECT 
                        SUM(CASE WHEN risk_score >= 0.8 THEN 1 ELSE 0 END) as critical,
                        SUM(CASE WHEN risk_score >= 0.6 AND risk_score < 0.8 THEN 1 ELSE 0 END) as high,
                        SUM(CASE WHEN risk_score >= 0.4 AND risk_score < 0.6 THEN 1 ELSE 0 END) as medium,
                        SUM(CASE WHEN risk_score < 0.4 THEN 1 ELSE 0 END) as low
                    FROM attack_logs
                    WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                """)
                stats = dict(conn.execute(stats_query).fetchone())
                
            # Process events for display
            for event in events:
                event['severity'] = self._calculate_severity(event['risk_score'])
                
            return render_template('hsiem.html', events=events, stats=stats)
            
        except Exception as e:
            logger.error(f"Error in HSIEM dashboard: {str(e)}", exc_info=True)
            return render_template('hsiem.html', events=[], stats={'critical': 0, 'high': 0, 'medium': 0, 'low': 0})

    def get_hsiem_events(self):
        """API endpoint for HSIEM events"""
        try:
            with self.db.connect() as conn:
                # Get recent events
                events_query = text("""
                    SELECT * FROM attack_logs 
                    ORDER BY timestamp DESC 
                    LIMIT 10
                """)
                events = [dict(row) for row in conn.execute(events_query)]
                
                # Get statistics
                stats_query = text("""
                    SELECT 
                        SUM(CASE WHEN risk_score >= 0.8 THEN 1 ELSE 0 END) as critical,
                        SUM(CASE WHEN risk_score >= 0.6 AND risk_score < 0.8 THEN 1 ELSE 0 END) as high,
                        SUM(CASE WHEN risk_score >= 0.4 AND risk_score < 0.6 THEN 1 ELSE 0 END) as medium,
                        SUM(CASE WHEN risk_score < 0.4 THEN 1 ELSE 0 END) as low
                    FROM attack_logs
                    WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
                """)
                stats = dict(conn.execute(stats_query).fetchone())
                
            # Process events
            for event in events:
                event['severity'] = self._calculate_severity(event['risk_score'])
                event['timestamp'] = event['timestamp'].isoformat()
                
            return jsonify({'events': events, 'stats': stats})
            
        except Exception as e:
            logger.error(f"Error fetching HSIEM events: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    def get_hsiem_event_details(self, event_id):
        """API endpoint for HSIEM event details"""
        try:
            with self.db.connect() as conn:
                query = text("SELECT * FROM attack_logs WHERE id = :id")
                result = conn.execute(query, {'id': event_id}).fetchone()
                
                if result is None:
                    return jsonify({'error': 'Event not found'}), 404
                    
                event = dict(result)
                event['severity'] = self._calculate_severity(event['risk_score'])
                event['timestamp'] = event['timestamp'].isoformat()
                
                return jsonify(event)
                
        except Exception as e:
            logger.error(f"Error fetching HSIEM event details: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    def _calculate_severity(self, risk_score):
        """Calculate severity level based on risk score"""
        if risk_score >= 0.8:
            return 'CRITICAL'
        elif risk_score >= 0.6:
            return 'HIGH'
        elif risk_score >= 0.4:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def start_monitoring(self):
        """Start system monitoring thread"""
        def monitor():
            while True:
                try:
                    # Collect system data
                    system_data = self.collector.collect_all()
                    
                    # Perform vulnerability assessment
                    assessment = VulnerabilityAssessment(system_data)
                    report = assessment.get_report()
                    
                    # Save to risk history
                    self.save_risk_history(report)
                    
                    # Sleep for 5 minutes
                    time.sleep(300)
                except Exception as e:
                    logger.error(f"Error in monitoring thread: {str(e)}", exc_info=True)
                    time.sleep(60)  # Sleep for 1 minute on error
        
        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()

    def save_risk_history(self, report):
        """Save risk assessment report to history"""
        try:
            history_file = "risk_history.json"
            if os.path.exists(history_file):
                with open(history_file, "r") as f:
                    history = json.load(f)
            else:
                history = []
            
            # Keep last 100 reports
            history = (history + [report])[-100:]
            
            with open(history_file, "w") as f:
                json.dump(history, f, indent=2)
            
        except Exception as e:
            logger.error(f"Error saving risk history: {str(e)}", exc_info=True)

    def get_system_status(self):
        """API endpoint for current system status"""
        try:
            system_data = self.collector.collect_all()
            return jsonify(system_data)
        except Exception as e:
            logger.error(f"Error getting system status: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    def get_system_assessment(self):
        """API endpoint for system vulnerability assessment"""
        try:
            system_data = self.collector.collect_all()
            assessment = VulnerabilityAssessment(system_data)
            report = assessment.get_report()
            return jsonify(report)
        except Exception as e:
            logger.error(f"Error getting system assessment: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    def get_risk_graph(self):
        """API endpoint for risk component graph"""
        try:
            system_data = self.collector.collect_all()
            assessment = VulnerabilityAssessment(system_data)
            report = assessment.get_report()
            
            # Create graph using matplotlib
            plt.figure(figsize=(10, 6))
            components = ['Process', 'Network', 'Signatures', 'Registry', 'Nmap', 'Events']
            values = [
                len(report['details'].get('suspicious_processes', [])),
                len(report['details'].get('open_ports', [])),
                len(report['details'].get('failed_digital_signatures', [])),
                len(report['details'].get('unknown_startup_items', [])),
                len(report['details'].get('nmap_vulnerabilities', [])),
                len(report['details'].get('event_log_flags', {}).get('windows', []))
            ]
            
            plt.bar(components, values)
            plt.title('Risk Components Analysis')
            plt.xticks(rotation=45)
            
            # Save to bytes
            img = io.BytesIO()
            plt.savefig(img, format='png', bbox_inches='tight')
            img.seek(0)
            
            return send_file(img, mimetype='image/png')
            
        except Exception as e:
            logger.error(f"Error generating risk graph: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    def get_risk_trend(self):
        """API endpoint for risk trend graph"""
        try:
            # Get attack logs from the last hour
            with self.db.connect() as conn:
                query = text("""
                    SELECT timestamp, risk_score 
                    FROM attack_logs 
                    WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
                    ORDER BY timestamp ASC
                """)
                results = conn.execute(query).fetchall()
                
                if not results:
                    # If no recent attacks, use risk history
                    with open("risk_history.json", "r") as f:
                        history = json.load(f)
                        timestamps = [datetime.fromisoformat(entry['timestamp']) for entry in history]
                        scores = [float(entry['risk_score']) for entry in history]
                else:
                    # Use attack logs
                    timestamps = [row[0] for row in results]
                    scores = [float(row[1]) for row in results]
            
            # Create trend graph
            plt.figure(figsize=(10, 6))
            plt.plot(timestamps, scores, marker='o', linestyle='-', color='darkorange')
            plt.title('Attack Risk Score Trend')
            plt.xlabel('Time')
            plt.ylabel('Risk Score')
            plt.grid(True)
            
            # Rotate x-axis labels for better readability
            plt.xticks(rotation=45)
            
            # Add severity level bands
            plt.axhspan(0, 0.4, alpha=0.2, color='green', label='LOW')
            plt.axhspan(0.4, 0.6, alpha=0.2, color='yellow', label='MEDIUM')
            plt.axhspan(0.6, 0.8, alpha=0.2, color='orange', label='HIGH')
            plt.axhspan(0.8, 1.0, alpha=0.2, color='red', label='CRITICAL')
            
            plt.legend()
            
            # Adjust layout to prevent label cutoff
            plt.tight_layout()
            
            # Save to bytes
            img = io.BytesIO()
            plt.savefig(img, format='png')
            img.seek(0)
            plt.close()
            
            return send_file(img, mimetype='image/png')
            
        except Exception as e:
            logger.error(f"Error generating risk trend: {str(e)}", exc_info=True)
            return jsonify({'error': str(e)}), 500
    
    def start(self, host: str = '0.0.0.0', port: int = 9000):
        """Start the honeypot server"""
        logger.info(f"Starting SQL injection honeypot on {host}:{port}")
        self.app.run(host=host, port=port) 