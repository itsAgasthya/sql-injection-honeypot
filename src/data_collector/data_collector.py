"""
Data collection module for system monitoring and analysis
"""

import os
import psutil
import platform
import subprocess
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class DataCollector:
    """Collects system data for monitoring and analysis"""
    
    def __init__(self):
        """Initialize the data collector"""
        self.data = {}
        
    def collect_processes(self):
        """Collect information about running processes"""
        try:
            process_list = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent']):
                try:
                    process_list.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            self.data['processes'] = process_list
            return process_list
        except Exception as e:
            logger.error(f"Error collecting process data: {str(e)}", exc_info=True)
            return []

    def collect_network(self):
        """Collect network connection information"""
        try:
            connections = []
            for conn in psutil.net_connections():
                try:
                    conn_info = {
                        "fd": conn.fd,
                        "family": str(conn.family),
                        "type": str(conn.type),
                        "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "status": conn.status
                    }
                    connections.append(conn_info)
                except Exception:
                    continue
            self.data['network_connections'] = connections
            return connections
        except Exception as e:
            logger.error(f"Error collecting network data: {str(e)}", exc_info=True)
            return []

    def collect_system_info(self):
        """Collect general system information"""
        try:
            self.data['system'] = {
                'platform': platform.system(),
                'platform_release': platform.release(),
                'platform_version': platform.version(),
                'architecture': platform.machine(),
                'processor': platform.processor(),
                'hostname': platform.node()
            }
            
            # Memory information
            memory = psutil.virtual_memory()
            self.data['memory'] = {
                'total': memory.total,
                'available': memory.available,
                'percent': memory.percent,
                'used': memory.used,
                'free': memory.free
            }
            
            # CPU information
            self.data['cpu'] = {
                'physical_cores': psutil.cpu_count(logical=False),
                'total_cores': psutil.cpu_count(logical=True),
                'cpu_freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {},
                'cpu_percent': psutil.cpu_percent(interval=1, percpu=True)
            }
            
            # Disk information
            disk = psutil.disk_usage('/')
            self.data['disk'] = {
                'total': disk.total,
                'used': disk.used,
                'free': disk.free,
                'percent': disk.percent
            }
            
            return self.data['system']
        except Exception as e:
            logger.error(f"Error collecting system info: {str(e)}", exc_info=True)
            return {}

    def collect_logs(self):
        """Collect relevant system logs"""
        try:
            logs = {}
            
            # For Linux systems
            if platform.system() == "Linux":
                log_files = [
                    '/var/log/auth.log',
                    '/var/log/syslog',
                    '/var/log/messages'
                ]
                
                for log_file in log_files:
                    if os.path.exists(log_file):
                        try:
                            with open(log_file, 'r') as f:
                                logs[os.path.basename(log_file)] = f.readlines()[-100:]  # Last 100 lines
                        except Exception as e:
                            logger.warning(f"Could not read log file {log_file}: {str(e)}")
            
            self.data['logs'] = logs
            return logs
        except Exception as e:
            logger.error(f"Error collecting logs: {str(e)}", exc_info=True)
            return {}

    def collect_all(self):
        """Collect all available system data"""
        try:
            # Collect all data
            self.collect_processes()
            self.collect_network()
            self.collect_system_info()
            self.collect_logs()
            
            # Add timestamp
            self.data['timestamp'] = datetime.now().isoformat()
            
            return self.data
        except Exception as e:
            logger.error(f"Error in collect_all: {str(e)}", exc_info=True)
            return {
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            } 