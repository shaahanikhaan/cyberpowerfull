#!/usr/bin/env python3
# cyberpowerfull Custom Gap Tool 1: Port-Specific Service Fingerprinting
# English: Deep fingerprinting for non-standard ports beyond Nmap
# Roman Urdu: Non-standard ports ke liye gehra fingerprinting (Nmap se aage)

import socket
import json
import sys
from datetime import datetime

class PortFingerprint:
    def __init__(self, target, ports=None):
        # English: Initialize target and ports
        # Roman Urdu: Target aur ports initialize karein (Target aur ports initialize karein)
        self.target = target
        self.ports = ports or [8080, 8443, 8888, 9000, 9090, 9999]
        
        # English: Language support
        # Roman Urdu: Language support (Language support)
        self.language = "english"  # Default, can be changed
        self.strings = {
            'english': {
                'starting': 'Starting custom port fingerprinting for {}...',
                'scanning': 'Scanning port {}...',
                'found': 'Found service on port {}: {}',
                'completed': 'Fingerprinting completed.'
            },
            'roman_urdu': {
                'starting': 'Custom port fingerprinting shuru ho rahi hai {} ke liye...',
                'scanning': 'Port {} scan ho raha hai...',
                'found': 'Port {} par service mili: {}',
                'completed': 'Fingerprinting poori ho gayi.'
            }
        }
    
    def print_msg(self, key, *args):
        # English: Print message
        # Roman Urdu: Message print karein (Message print karein)
        msg = self.strings[self.language].get(key, key).format(*args)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    
    def fingerprint(self):
        # English: Perform fingerprinting
        # Roman Urdu: Fingerprinting karein (Fingerprinting karein)
        self.print_msg('starting', self.target)
        results = []
        
        for port in self.ports:
            self.print_msg('scanning', port)
            try:
                # English: Connect to port and grab banner
                # Roman Urdu: Port se connect karein aur banner pakdein (Port se connect karein aur banner pakdein)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target, port))
                
                if result == 0:
                    # English: Service found, try to grab banner
                    # Roman Urdu: Service mili, banner pakadne ki koshish karein (Service mili, banner pakadne ki koshish karein)
                    sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')[:100]
                    service = banner.strip() if banner else "Unknown Service (English) | Unknown Service (Roman Urdu)"
                    
                    self.print_msg('found', port, service)
                    results.append({
                        'port': port,
                        'service': service,
                        'status': 'open'
                    })
                sock.close()
            except Exception as e:
                pass  # English: Ignore connection errors | Roman Urdu: Connection errors ignore karein
        
        self.print_msg('completed')
        return results

# English: Main execution
# Roman Urdu: Main execution (Main execution)
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="cyberpowerfull Custom Gap Tool 1 - Port Fingerprinting")
    parser.add_argument("--target", required=True, help="English: Target IP/Host | Roman Urdu: Target IP/Host")
    parser.add_argument("--ports", nargs='+', type=int, help="English: Ports to scan | Roman Urdu: Scan karne wale ports")
    parser.add_argument("--language", choices=['english', 'roman_urdu'], default='english', help="English: Language | Roman Urdu: Language")
    
    args = parser.parse_args()
    
    fingerprinter = PortFingerprint(args.target, args.ports)
    fingerprinter.language = args.language
    
    results = fingerprinter.fingerprint()
    
    # English: Output results as JSON
    # Roman Urdu: Results ko JSON mein output karein (Results ko JSON mein output karein)
    output = {
        'timestamp': datetime.now().isoformat(),
        'target': args.target,
        'language': args.language,
        'results': results
    }
    print(json.dumps(output, indent=2))
