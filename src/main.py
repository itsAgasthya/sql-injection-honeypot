#!/usr/bin/env python3
"""
Main entry point for the SQL Injection Honeypot with HSIEM Integration.
"""

import argparse
import logging
import sys
from typing import Optional
import os
from dotenv import load_dotenv
from src.honeypot.web_honeypot import SQLInjectionHoneypot

def setup_logging():
    """Setup logging with proper permissions and rotation"""
    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, mode=0o755)
    
    log_file = os.path.join(log_dir, 'honeypot.log')
    
    # Configure logging with more detailed format
    logging.basicConfig(
        level=logging.DEBUG,  # Set to DEBUG for more detailed logs
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s\n%(pathname)s:%(lineno)d\n',
        handlers=[
            logging.FileHandler(log_file, mode='a'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set file permissions
    try:
        os.chmod(log_file, 0o644)
    except Exception as e:
        print(f"Warning: Could not set log file permissions: {str(e)}")
    
    return logging.getLogger(__name__)

def main():
    try:
        # Setup logging first
        logger = setup_logging()
        
        # Load environment variables
        load_dotenv()
        
        # Get host and port from environment variables, with fallback to 9000
        host = os.getenv('HOST', '0.0.0.0')
        port = int(os.getenv('PORT', '9000'))
        
        # Initialize and start the honeypot
        honeypot = SQLInjectionHoneypot()
        # Enable debug mode and more verbose error handling
        honeypot.app.debug = True
        honeypot.app.config['PROPAGATE_EXCEPTIONS'] = True
        honeypot.start(host=host, port=port)
        
    except Exception as e:
        logger.error(f"Failed to start honeypot: {str(e)}", exc_info=True)
        raise

if __name__ == '__main__':
    main()
