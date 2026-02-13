"""
Logging Module
Provides structured logging for audit trail and debugging
"""
import logging
import json
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

class SecurityLogger:
    def __init__(self, log_file='scan.log'):
        self.log_file = log_file
        self.logger = logging.getLogger('CloudPentest')
        self.logger.setLevel(logging.INFO)
        
        # File handler
        fh = logging.FileHandler(log_file)
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(fh)
        
        self.scan_start = None
        self.findings_count = 0
    
    def start_scan(self, provider):
        self.scan_start = datetime.now()
        msg = f"Starting security scan for {provider}"
        self.logger.info(msg)
        print(f"{Fore.CYAN}[*] {msg}{Style.RESET_ALL}")
    
    def info(self, message):
        self.logger.info(message)
        print(f"{Fore.BLUE}[i] {message}{Style.RESET_ALL}")
    
    def success(self, message):
        self.logger.info(f"SUCCESS: {message}")
        print(f"{Fore.GREEN}[✓] {message}{Style.RESET_ALL}")
    
    def warning(self, message):
        self.logger.warning(message)
        print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")
    
    def error(self, message):
        self.logger.error(message)
        print(f"{Fore.RED}[✗] {message}{Style.RESET_ALL}")
    
    def finding(self, severity, resource, issue):
        self.findings_count += 1
        msg = f"{severity} - {resource}: {issue}"
        self.logger.warning(msg)
        
        color = {
            'CRITICAL': Fore.RED,
            'HIGH': Fore.MAGENTA,
            'MEDIUM': Fore.YELLOW,
            'LOW': Fore.CYAN
        }.get(severity, Fore.WHITE)
        
        print(f"{color}[{severity}] {resource}: {issue}{Style.RESET_ALL}")
    
    def end_scan(self):
        if self.scan_start:
            duration = (datetime.now() - self.scan_start).total_seconds()
            msg = f"Scan completed in {duration:.2f}s. Found {self.findings_count} issues."
            self.logger.info(msg)
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{msg}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
