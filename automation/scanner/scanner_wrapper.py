#!/usr/bin/env python3
# cyberpowerfull Scanner Module - English & Roman Urdu
# English: POWERFULL vulnerability scanner (beyond known CVEs - deep research based)
# Roman Urdu: POWERFULL vulnerability scanner (pehle se maloom CVEs se aage - deep research based) (POWERFULL vulnerability scanner (pehle se maloom CVEs se aage - deep research based))

import subprocess
import json
import os
from datetime import datetime

# English: Try to import yaml, fallback to json for config if not available
# Roman Urdu: yaml import karne ki koshish karein, agar available nahi hai to config ke liye json fallback (yaml import karne ki koshish karein, agar available nahi hai to config ke liye json fallback)
try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

class ScannerWrapper:
    def __init__(self, config_path="config.yaml"):
        # English: Load configuration
        # Roman Urdu: Configuration load karein (Configuration load karein)
        self.config = {}
        if YAML_AVAILABLE and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                self.config = yaml.safe_load(f) or {}
        elif os.path.exists(config_path):
            # English: Fallback configuration
            # Roman Urdu: Fallback configuration (Fallback configuration)
            self.config = {
                'language': 'english',
                'output_format': 'json',
                'scanner': {
                    'cve_only': False,  # NEW: Not just known CVEs
                    'deep_research': True,  # NEW: Deep research-based discovery
                    'powerfull_tools': True,  # NEW: POWERFULL new vulnerability tools
                    'recon_first': True  # NEW: Recon phase first, then scanner
                }
            }
        else:
            # English: Default configuration
            # Roman Urdu: Default configuration (Default configuration)
            self.config = {
                'language': 'english',
                'output_format': 'json',
                'scanner': {
                    'cve_only': False,
                    'deep_research': True,
                    'powerfull_tools': True,
                    'recon_first': True
                }
            }
        
        self.language = self.config.get('language', 'english')
        self.output_format = self.config.get('output_format', 'json')
        
        # English: Language strings
        # Roman Urdu: Language strings (Language strings)
        self.strings = {
            'english': {
                'starting': 'Starting cyberpowerfull POWERFULL scanner (Recon phase first, then deep vulnerability discovery)...',
                'recon_phase': 'Phase 1: Reconnaissance (English/Roman Urdu)...',
                'scanner_phase': 'Phase 2: POWERFULL vulnerability scanner (beyond known CVEs)...',
                'deep_research': 'Executing deep research on CVE discovery methods (2026 AI-driven)...',
                'powerfull_tools': 'Running POWERFULL new vulnerability discovery tools...',
                'completed': 'POWERFULL scanner completed successfully. Novel vulnerabilities discovered beyond known CVEs.',
                'error': 'Error occurred: {}'
            },
            'roman_urdu': {
                'starting': 'cyberpowerfull POWERFULL scanner shuru ho raha hai (Recon phase pehle, phir deep vulnerability discovery)...',
                'recon_phase': 'Phase 1: Reconnaissance (English/Roman Urdu)...',
                'scanner_phase': 'Phase 2: POWERFULL vulnerability scanner (pehle se maloom CVEs se aage)...',
                'deep_research': 'CVE discovery methods par deep research execute ho rahi hai (2026 AI-driven)...',
                'powerfull_tools': 'POWERFULL nayi vulnerability discovery tools chal rahe hain...',
                'completed': 'POWERFULL scanner safaltapurvak poora ho gaya. Pehle se maloom CVEs se aage nayi vulnerabilities mili.',
                'error': 'Ghalti hui: {}'
            }
        }
    
    def print_msg(self, key):
        # English: Print message in selected language
        # Roman Urdu: Chuni hui language mein message print karein (Chuni hui language mein message print karein)
        msg = self.strings[self.language].get(key, key)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    
    def run_recon_phase(self, target, domain=None):
        # English: Phase 1: Reconnaissance (English/Roman Urdu)
        # Roman Urdu: Phase 1: Reconnaissance (English/Roman Urdu) (Phase 1: Reconnaissance (English/Roman Urdu))
        self.print_msg('recon_phase')
        
        # English: Call recon_wrapper.py for reconnaissance
        # Roman Urdu: Reconnaissance ke liye recon_wrapper.py call karein (Reconnaissance ke liye recon_wrapper.py call karein)
        recon_cmd = [
            'python3', 'automation/recon/recon_wrapper.py',
            '--target', target
        ]
        if domain:
            recon_cmd.extend(['--domain', domain])
        recon_cmd.extend(['--language', self.language, '--format', 'json'])
        
        try:
            recon_result = subprocess.run(recon_cmd, capture_output=True, text=True, timeout=300)
            # English: Extract only the JSON part (skip log lines)
            # Roman Urdu: Sirf JSON part extract karein (log lines skip karein) (Sirf JSON part extract karein (log lines skip karein))
            stdout_lines = recon_result.stdout.splitlines()
            json_lines = []
            in_json = False
            for line in stdout_lines:
                if line.startswith('{'):
                    in_json = True
                if in_json:
                    json_lines.append(line)
            json_str = '\n'.join(json_lines)
            
            if recon_result.returncode == 0 and json_str.strip():
                recon_data = json.loads(json_str)
                return {
                    'phase': 'recon',
                    'status': 'success',
                    'data': recon_data,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                return {
                    'phase': 'recon',
                    'status': 'failed',
                    'error': recon_result.stderr if recon_result.stderr else 'No JSON output found',
                    'timestamp': datetime.now().isoformat()
                }
        except Exception as e:
            return {
                'phase': 'recon',
                'status': 'error',
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
    
    def run_scanner_phase(self, target, domain=None):
        # English: Phase 2: POWERFULL vulnerability scanner (beyond known CVEs)
        # Roman Urdu: Phase 2: POWERFULL vulnerability scanner (pehle se maloom CVEs se aage) (Phase 2: POWERFULL vulnerability scanner (pehle se maloom CVEs se aage))
        self.print_msg('scanner_phase')
        
        results = []
        
        # English: Deep Research Phase (2026 AI-driven CVE discovery methods)
        # Roman Urdu: Deep Research Phase (2026 AI-driven CVE discovery methods) (Deep Research Phase (2026 AI-driven CVE discovery methods))
        if self.config['scanner'].get('deep_research', True):
            self.print_msg('deep_research')
            research_cmd = [
                'python3', 'automation/scanner/custom_gap_powerfull_vuln_discovery.py',
                '--target', target
            ]
            if domain:
                research_cmd.extend(['--domain', domain])
            research_cmd.extend(['--language', self.language])
            
            try:
                research_result = subprocess.run(research_cmd, capture_output=True, text=True, timeout=300)
                # English: Extract only the JSON part (skip log lines)
                # Roman Urdu: Sirf JSON part extract karein (log lines skip karein) (Sirf JSON part extract karein (log lines skip karein))
                stdout_lines = research_result.stdout.splitlines()
                json_lines = []
                in_json = False
                for line in stdout_lines:
                    if line.startswith('{'):
                        in_json = True
                    if in_json:
                        json_lines.append(line)
                json_str = '\n'.join(json_lines)
                
                if research_result.returncode == 0 and json_str.strip():
                    research_data = json.loads(json_str)
                    results.append({
                        'tool': 'cyberpowerfull_deep_research_discovery',
                        'target': target,
                        'domain': domain,
                        'description': 'English: Deep research-based new vulnerability discovery (beyond known CVEs) | Roman Urdu: Deep research-based nayi vulnerability discovery (pehle se maloom CVEs se aage)',
                        'results': research_data,
                        'status': 'success'
                    })
                else:
                    results.append({
                        'tool': 'cyberpowerfull_deep_research_discovery',
                        'target': target,
                        'error': research_result.stderr if research_result.stderr else 'No JSON output found',
                        'status': 'failed'
                    })
            except Exception as e:
                results.append({
                    'tool': 'cyberpowerfull_deep_research_discovery',
                    'target': target,
                    'error': str(e),
                    'status': 'error'
                })
        
        # English: POWERFULL New Vulnerability Tools Phase
        # Roman Urdu: POWERFULL Nayi Vulnerability Tools Phase (POWERFULL Nayi Vulnerability Tools Phase)
        if self.config['scanner'].get('powerfull_tools', True):
            self.print_msg('powerfull_tools')
            
            # English: Custom gap tools for new vulnerability discovery (beyond CVE databases)
            # Roman Urdu: Nayi vulnerability discovery ke liye custom gap tools (CVE databases se aage) (Nayi vulnerability discovery ke liye custom gap tools (CVE databases se aage))
            powerfull_tools = [
                ('behavioral_analyzer', 'automation/scanner/custom_gap_powerfull_vuln_discovery.py'),
                ('semantic_scanner', 'automation/scanner/custom_gap_powerfull_vuln_discovery.py'),
                ('ai_zero_day', 'automation/scanner/custom_gap_powerfull_vuln_discovery.py'),
                ('pattern_matcher', 'automation/scanner/custom_gap_powerfull_vuln_discovery.py')
            ]
            
            for tool_name, script_path in powerfull_tools:
                self.print_msg('powerfull_tools')
                cmd = [
                    'python3', script_path,
                    '--target', target
                ]
                if domain:
                    cmd.extend(['--domain', domain])
                cmd.extend(['--language', self.language])
                
                try:
                    tool_result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    # English: Extract only the JSON part (skip log lines)
                    # Roman Urdu: Sirf JSON part extract karein (log lines skip karein) (Sirf JSON part extract karein (log lines skip karein))
                    stdout_lines = tool_result.stdout.splitlines()
                    json_lines = []
                    in_json = False
                    for line in stdout_lines:
                        if line.startswith('{'):
                            in_json = True
                        if in_json:
                            json_lines.append(line)
                    json_str = '\n'.join(json_lines)
                    
                    if tool_result.returncode == 0 and json_str.strip():
                        tool_data = json.loads(json_str)
                        # Extract only the specific tool's results from the full discovery output
                        # English: Extract specific tool results | Roman Urdu: Specific tool results extract karein (Specific tool results extract karein)
                        tools_data = tool_data.get('tools', {})
                        specific_tool_data = tools_data.get(f'cyberpowerfull_{tool_name}', {
                            'tool': f'cyberpowerfull_{tool_name}',
                            'target': target,
                            'domain': domain,
                            'description': f'English: POWERFULL {tool_name} discovery (beyond known CVEs) | Roman Urdu: POWERFULL {tool_name} discovery (pehle se maloom CVEs se aage)',
                            'results': [],
                            'status': 'success',
                            'timestamp': datetime.now().isoformat()
                        })
                        results.append(specific_tool_data)
                    else:
                        results.append({
                            'tool': f'cyberpowerfull_{tool_name}',
                            'target': target,
                            'error': tool_result.stderr if tool_result.stderr else 'No JSON output found',
                            'status': 'failed'
                        })
                except Exception as e:
                    results.append({
                        'tool': f'cyberpowerfull_{tool_name}',
                        'target': target,
                        'error': str(e),
                        'status': 'error'
                    })
        
        return results
    
    def execute_all(self, target, domain=None):
        # English: Execute complete scanner (Recon phase first, then POWERFULL vulnerability discovery)
        # Roman Urdu: Complete scanner execute karein (Recon phase pehle, phir POWERFULL vulnerability discovery) (Complete scanner execute karein (Recon phase pehle, phir POWERFULL vulnerability discovery))
        self.print_msg('starting')
        
        results = {
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'domain': domain,
            'language': self.language,
            'phases': {}
        }
        
        # English: Phase 1: Reconnaissance (if enabled)
        # Roman Urdu: Phase 1: Reconnaissance (agar enabled ho) (Phase 1: Reconnaissance (agar enabled ho))
        if self.config['scanner'].get('recon_first', True):
            results['phases']['recon'] = self.run_recon_phase(target, domain)
        
        # English: Phase 2: POWERFULL vulnerability scanner (beyond known CVEs)
        # Roman Urdu: Phase 2: POWERFULL vulnerability scanner (pehle se maloom CVEs se aage) (Phase 2: POWERFULL vulnerability scanner (pehle se maloom CVEs se aage))
        results['phases']['scanner'] = self.run_scanner_phase(target, domain)
        
        self.print_msg('completed')
        
        # English: Return results in selected format
        # Roman Urdu: Chune hue format mein results wapas karein (Chune hue format mein results wapas karein)
        if self.output_format == 'json':
            return json.dumps(results, indent=2)
        elif self.output_format == 'markdown':
            return self._format_markdown(results)
        else:
            return str(results)
    
    def _format_markdown(self, results):
        # English: Format results as Markdown
        # Roman Urdu: Results ko Markdown mein format karein (Results ko Markdown mein format karein)
        md = f"# cyberpowerfull POWERFULL Scanner Report ({results['language']})\n"
        md += f"**Timestamp:** {results['timestamp']}\n"
        md += f"**Target:** {results['target']}\n"
        md += f"**Domain:** {results['domain']}\n\n"
        
        for phase, data in results['phases'].items():
            md += f"## Phase: {phase.upper()}\n"
            if data.get('status') == 'success':
                md += f"- **Status:** Success\n"
                if phase == 'recon':
                    md += f"- **Recon Data:** {json.dumps(data.get('data', {}))[:200]}...\n"
                elif phase == 'scanner':
                    for tool in data.get('results', []):
                        md += f"  - **Tool:** {tool.get('tool')}\n"
                        md += f"  - **Status:** {tool.get('status')}\n"
                        md += f"  - **Description:** {tool.get('description')}\n"
                        md += f"  - **Results:** {len(tool.get('results', {}).get('tools', [])) if 'discovery_tools' in tool.get('results', {}) else 'Available'}\n"
            else:
                md += f"- **Status:** Failed\n"
                md += f"- **Error:** {data.get('error', 'Unknown')[:200]}...\n"
            md += "\n"
        
        return md

# English: Main execution
# Roman Urdu: Main execution (Main execution)
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="cyberpowerfull POWERFULL Scanner (Recon + Deep Vulnerability Discovery) - English & Roman Urdu")
    parser.add_argument("--target", required=True, help="English: Target IP/Host | Roman Urdu: Target IP/Host")
    parser.add_argument("--domain", help="English: Domain | Roman Urdu: Domain")
    parser.add_argument("--language", choices=['english', 'roman_urdu'], default='english', help="English: Language | Roman Urdu: Language")
    parser.add_argument("--format", choices=['json', 'markdown', 'text'], default='json', help="English: Output format | Roman Urdu: Output format")
    
    args = parser.parse_args()
    
    # English: Override config language/format if provided
    # Roman Urdu: Agar diya gaya ho to config language/format badal dein (Agar diya gaya ho to config language/format badal dein)
    scanner = ScannerWrapper()
    scanner.language = args.language
    scanner.output_format = args.format
    
    output = scanner.execute_all(args.target, args.domain)
    print(output)
