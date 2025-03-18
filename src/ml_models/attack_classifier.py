import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
import re

class SQLInjectionClassifier:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            analyzer='char'
        )
        
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        self.model_path = os.path.join(os.path.dirname(__file__), 'sqli_model.joblib')
        self.vectorizer_path = os.path.join(os.path.dirname(__file__), 'sqli_vectorizer.joblib')
        
        # Load or train the model
        if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
            self.load_model()
        else:
            self.train_model()
    
    def preprocess_text(self, text):
        """Preprocess input text"""
        if isinstance(text, (dict, list)):
            text = str(text)
        
        # Convert to lowercase
        text = text.lower()
        
        # Remove extra whitespace
        text = re.sub(r'\s+', ' ', text)
        
        return text
    
    def extract_features(self, text):
        """Extract features from text"""
        features = {
            'length': len(text),
            'space_count': text.count(' '),
            'quote_count': text.count("'") + text.count('"'),
            'semicolon_count': text.count(';'),
            'comment_count': text.count('--') + text.count('/*'),
            'union_count': text.lower().count('union'),
            'select_count': text.lower().count('select'),
            'or_count': text.lower().count(' or '),
            'and_count': text.lower().count(' and '),
            'equal_count': text.count('='),
        }
        return features
    
    def train_model(self):
        """Train the model with sample data"""
        # Sample training data (you should replace this with real data)
        benign_queries = [
            "SELECT * FROM users WHERE id = 1",
            "SELECT name, price FROM products WHERE category = 'electronics'",
            "INSERT INTO orders (user_id, product_id) VALUES (1, 2)",
            "UPDATE users SET name = 'John' WHERE id = 1",
            "DELETE FROM cart WHERE user_id = 1"
        ]
        
        malicious_queries = [
            "SELECT * FROM users WHERE id = 1 OR 1=1",
            "SELECT * FROM users WHERE username = '' OR '1'='1'",
            "SELECT * FROM users WHERE id = 1; DROP TABLE users;",
            "SELECT * FROM users UNION SELECT * FROM admin",
            "' OR '1'='1' --",
            "admin' --",
            "1'; DROP TABLE users; --",
            "1' UNION SELECT username, password FROM users --",
            "1' OR '1' = '1",
            "' OR 1=1 #",
            "' OR 'x'='x",
            "1' AND 1=(SELECT COUNT(*) FROM tabname); --"
        ]
        
        # Prepare training data
        X = benign_queries + malicious_queries
        y = [0] * len(benign_queries) + [1] * len(malicious_queries)
        
        # Preprocess and extract features
        X_processed = [self.preprocess_text(x) for x in X]
        
        # Transform text data
        X_tfidf = self.vectorizer.fit_transform(X_processed)
        
        # Train the model
        self.classifier.fit(X_tfidf, y)
        
        # Save the model
        joblib.dump(self.classifier, self.model_path)
        joblib.dump(self.vectorizer, self.vectorizer_path)
    
    def load_model(self):
        """Load the trained model"""
        self.classifier = joblib.load(self.model_path)
        self.vectorizer = joblib.load(self.vectorizer_path)
    
    def predict_risk(self, input_data):
        """Predict risk score for input data"""
        try:
            # Preprocess input
            processed_input = self.preprocess_text(input_data)
            
            # Transform input
            X_tfidf = self.vectorizer.transform([processed_input])
            
            # Get prediction probability
            risk_score = self.classifier.predict_proba(X_tfidf)[0][1]
            
            return risk_score
            
        except Exception as e:
            print(f"Error in prediction: {str(e)}")
            return 0.0  # Return 0 risk score on error 