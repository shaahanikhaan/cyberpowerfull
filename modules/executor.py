#!/usr/bin/env python3
# cyberpowerfull Recon Module Executor
# English: Execute recon tools and handle modifications
# Roman Urdu: Recon tools chalayein aur modifications handle karein (Recon tools chalayein aur modifications handle karein)

import subprocess
import json
import yaml
import os
from datetime import datetime

class ReconExecutor:
    def __init__(self, config_path="config.yaml"):
        # English: Load configuration
        # Roman Urdu: Configuration load karein (Configuration load karein)
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.language = self.config.get('language', 'english')
        
        # English: Language strings
        # Roman Urdu: Language strings (Language strings)
        self.strings = {
            'english': {
                'executing': 'Executing recon tool: {}...',
                'modifying': 'Modifying tool: {}...',
                'completed': 'Execution completed.',
                'error': 'Error executing: {}'
            },
            'roman_urdu': {
                'executing': 'Recon tool chal raha hai: {}...',
                'modifying': 'Tool modify ho raha hai: {}...',
                'completed': 'Execution poora ho gaya.',
                'error': 'Execution mein ghalti: {}'
            }
        }
    
    def print_msg(self, key, *args):
        # English: Print message
        # Roman Urdu: Message print karein (Message print karein)
        msg = self.strings[self.language].get(key, key).format(*args)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    
    def execute_tool(self, tool_name, args, target=None):
        # English: Execute a tool with modifications
        # Roman Urdu: Tool ko modifications ke sath chalayein (Tool ko modifications ke sath chalayein)
        self.print_msg('executing', tool_name)
        
        # English: Apply modifications (e.g., custom flags, environment variables)
        # Roman Urdu: Modifications apply karein (e.g., custom flags, environment variables) (Modifications apply karein (e.g., custom flags, environment variables))
        self.print_msg('modifying', tool_name)
        
        # English: Construct command
        # Roman Urdu: Command banayein (Command banayein)
        cmd = [tool_name] + args
        if target:
            cmd.append(target)
        
        try:
            # English: Run command
            # Roman Urdu: Command chalayein (Command chalayein)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return {
                'tool': tool_name,
                'target': target,
                'output': result.stdout,
                'error': result.stderr,
                'status': 'success' if result.returncode == 0 else 'failed',
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'tool': tool_name,
                'target': target,
                'error': str(e),
                'status': 'error',
                'timestamp': datetime.now().isoformat()
            }
    
    def execute_all_recon(self, target, domain=None):
        # English: Execute all recon tools
        # Roman Urdu: Saare recon tools chalayein (Saare recon tools chalayein)
        self.print_msg('executing', 'All Recon Tools')
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'domain': domain,
            'language': self.language,
            'tools': {}
        }
        
        # English: Run Nmap (from config)
        # Roman Urdu: Nmap chalayein (config se) (Nmap chalayein (config se))
        nmap_args = self.config['recon']['nmap_args'].split()
        results['tools']['nmap'] = self.execute_tool('nmap', nmap_args, target)
        
        # English: Run Rustscan (from config)
        # Roman Urdu: Rustscan chalayein (config se) (Rustscan chalayein (config se))
        rustscan_args = self.config['recon']['rustscan_args'].split()
        results['tools']['rustscan'] = self.execute_tool('rustscan', rustscan_args, target)
        
        # English: Run Custom Gap Tools (personal tools)
        # Roman Urdu: Custom gap tools chalayein (personal tools) (Custom gap tools chalayein (personal tools))
        if self.config['recon']['custom_gaps_enabled']:
            # English: Gap 1: Port Fingerprint
            # Roman Urdu: Gap 1: Port Fingerprint (Gap 1: Port Fingerprint)
            gap1_cmd = ['python3', 'automation/recon/custom_gap_port_fingerprint.py', '--target', target]
            results['tools']['custom_gap_port_fingerprint'] = self.execute_tool('python3', gap1_cmd)
            
            # English: Gap 2: OSINT Cross-Reference (if domain provided)
            # Roman Urdu: Gap 2: OSINT Cross-Reference (agar domain diya gaya ho) (Gap 2: OSINT Cross-Reference (agar domain diya gaya ho))
            if domain:
                gap2_cmd = ['python3', 'automation/recon/custom_gap_osint_crossref.py', '--domain', domain]
                results['tools']['custom_gap_osint_crossref'] = self.execute_tool('python3', gap2_cmd)
        
        self.print_msg('completed')
        return results

# English: Main execution
# Roman Urdu: Main execution (Main execution)
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="cyberpowerfull Recon Executor")
    parser.add_argument("--target", required=True, help="English: Target IP/Host | Roman Urdu: Target IP/Host")
    parser.add_argument("--domain", help="English: Domain for subdomain enumeration | Roman Urdu: Subdomain ginne ke liye domain")
    parser.add_argument("--language", choices=['english', 'roman_urdu'], default='english', help="English: Language | Roman Urdu: Language")
    
    args = parser.parse_args()
    
    executor = ReconExecutor()
    executor.language = args.language
    
    results = executor.execute_all_recon(args.target, args.domain)
    print(json.dumps(results, indent=2))
