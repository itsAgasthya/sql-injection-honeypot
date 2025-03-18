"""
HSIEM (Honeypot Security Information and Event Management) Integration Module
"""

import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
import os

logger = logging.getLogger(__name__)

class HSIEMIntegration:
    """
    Integration class for sending honeypot events to SIEM systems
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize HSIEM integration with optional configuration
        
        Args:
            config: Dictionary containing SIEM configuration parameters
        """
        self.config = config or {}
        # Enable by default for local logging
        self.enabled = True
        self.siem_url = self.config.get('url', 'local')
        self.api_key = self.config.get('api_key', '')
        
        # Ensure log directory exists
        self.log_dir = 'hsiem_logs'
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        
        logger.info(f"HSIEM Integration initialized. Enabled: {self.enabled}")
        
    def send_event(self, event_type: str, event_data: Dict[str, Any]) -> bool:
        """
        Send an event to the configured SIEM system
        
        Args:
            event_type: Type of the event (e.g., 'sql_injection_attempt')
            event_data: Dictionary containing event details
            
        Returns:
            bool: True if event was sent successfully, False otherwise
        """
        try:
            event = {
                'timestamp': datetime.utcnow().isoformat(),
                'type': event_type,
                'source': 'sql_injection_honeypot',
                'severity': self._calculate_severity(event_data.get('risk_score', 0.0)),
                'data': event_data
            }
            
            # Log to HSIEM log file
            log_file = os.path.join(self.log_dir, f"hsiem_{datetime.now().strftime('%Y%m%d')}.log")
            with open(log_file, 'a') as f:
                f.write(json.dumps(event) + '\n')
            
            # Log summary to main log
            logger.info(
                "SIEM Event Details:\n"
                f"Type: {event_type}\n"
                f"Timestamp: {event['timestamp']}\n"
                f"Source IP: {event_data.get('source_ip')}\n"
                f"Risk Score: {event_data.get('risk_score')}\n"
                f"Severity: {event['severity']}"
            )
            return True
            
        except Exception as e:
            logger.error(f"Failed to send event to SIEM: {str(e)}", exc_info=True)
            return False
            
    def _calculate_severity(self, risk_score: float) -> str:
        """
        Calculate severity level based on standardized risk score ranges
        
        Risk Score Ranges:
        - CRITICAL (0.7-1.0): Schema enumeration, destructive attempts
        - HIGH (0.5-0.7): Data extraction attempts
        - MEDIUM (0.3-0.5): Authentication bypass attempts
        - LOW (0.0-0.3): Basic patterns, no data extraction
        """
        if risk_score >= 0.7:
            return 'CRITICAL'
        elif risk_score >= 0.5:
            return 'HIGH'
        elif risk_score >= 0.3:
            return 'MEDIUM'
        else:
            return 'LOW' 