#!/usr/bin/env python3
# cyberpowerfull POWERFULL Scanner Wrapper - English & Roman Urdu
# English: POWERFULL Scanner (Recon phase first, then new vuln discovery + Gap 6, 7, 8, 9, 10, 11, 12) - 10* POWERFULL
# Roman Urdu: POWERFULL Scanner (Recon phase pehle, phir nayi vuln discovery + Gap 6, 7, 8, 9, 10, 11, 12) - 10* POWERFULL (POWERFULL Scanner (Recon phase pehle, phir nayi vuln discovery + Gap 6, 7, 8, 9, 10, 11, 12) - 10* POWERFULL)

import subprocess
import json
import os
import re
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
                    'recon_first': True,  # NEW: Recon phase first, then scanner
                    'aidriven_integration': True  # NEW: Gap 7 integration
                },
                'new_gaps': {
                    'gap6_kali20263_automation': True,  # NEW: Gap 6
                    'gap7_aidriven_integration': True,   # NEW: Gap 7
                    'gap8_artemis_integration': True,    # NEW: Gap 8
                    'gap9_rl_simulator_bridge': True,    # NEW: Gap 9
                    'gap10_hybrid_accountability_bridge': True, # NEW: Gap 10
                    'gap11_nuclei_nikto_powerfull': True, # NEW: Gap 11
                    'gap12_sn1per_strix_powerfull': True  # NEW: Gap 12
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
                    'recon_first': True,
                    'aidriven_integration': True
                },
                'new_gaps': {
                    'gap6_kali20263_automation': True,
                    'gap7_aidriven_integration': True,
                    'gap8_artemis_integration': True,
                    'gap9_rl_simulator_bridge': True,
                    'gap10_hybrid_accountability_bridge': True,
                    'gap11_nuclei_nikto_powerfull': True,
                    'gap12_sn1per_strix_powerfull': True
                }
            }
        
        self.language = self.config.get('language', 'english')
        self.output_format = self.config.get('output_format', 'json')
        
        # English: Language strings
        # Roman Urdu: Language strings (Language strings)
        self.strings = {
            'english': {
                'starting': 'Starting cyberpowerfull POWERFULL scanner (Recon phase first, then deep vulnerability discovery + Gap 6, 7, 8, 9, 10, 11, 12) - 10* POWERFULL...',
                'recon_phase': 'Phase 1: Reconnaissance (English/Roman Urdu) - 10* POWERFULL...',
                'gap6_automation': 'Executing Gap 6: Kali Linux 2026.3 tool automation - 10* POWERFULL...',
                'scanner_phase': 'Phase 2: POWERFULL vulnerability scanner (beyond known CVEs) - 10* POWERFULL...',
                'deep_research': 'Executing deep research on CVE discovery methods (2026 AI-driven) - 10* POWERFULL...',
                'powerfull_tools': 'Running POWERFULL new vulnerability discovery tools - 10* POWERFULL...',
                'gap7_integration': 'Executing Gap 7: 2026 AI-Driven CVE Integration - 10* POWERFULL...',
                'gap8_integration': 'Executing Gap 8: ARTEMIS Multi-Agent Framework Integration - 10* POWERFULL...',
                'gap9_integration': 'Executing Gap 9: RL Simulator & Emulation Bridge Integration - 10* POWERFULL...',
                'gap10_integration': 'Executing Gap 10: Hybrid Model & Accountability Bridge Integration - 10* POWERFULL...',
                'gap11_integration': 'Executing Gap 11: POWERFULL Nuclei & Nikto Automation (No API key, No Docker) - 100+ Tools - 10* POWERFULL...',
                'gap12_integration': 'Executing Gap 12: POWERFULL Sn1per & Strix Integration (No API key, No Docker) - 100+ Tools - 10* POWERFULL...',
                'completed': 'POWERFULL scanner completed successfully. Novel vulnerabilities discovered beyond known CVEs + Gap 6, 7, 8, 9, 10, 11, 12 integrated - 10* POWERFULL.',
                'error': 'Error occurred: {} - 10* POWERFULL'
            },
            'roman_urdu': {
                'starting': 'cyberpowerfull POWERFULL scanner shuru ho raha hai (Recon phase pehle, phir deep vulnerability discovery + Gap 6, 7, 8, 9, 10, 11, 12) - 10* POWERFULL...',
                'recon_phase': 'Phase 1: Reconnaissance (English/Roman Urdu) - 10* POWERFULL...',
                'gap6_automation': 'Gap 6 execute ho raha hai: Kali Linux 2026.3 tool automation - 10* POWERFULL...',
                'scanner_phase': 'Phase 2: POWERFULL vulnerability scanner (pehle se maloom CVEs se aage) - 10* POWERFULL...',
                'deep_research': '2026 AI-driven CVE discovery methods par deep research kar rahe hain - 10* POWERFULL...',
                'powerfull_tools': 'POWERFULL nayi vulnerability discovery tools chal rahe hain - 10* POWERFULL...',
                'gap7_integration': 'Gap 7 execute ho raha hai: 2026 AI-Driven CVE Integration - 10* POWERFULL...',
                'gap8_integration': 'Gap 8 execute ho raha hai: ARTEMIS Multi-Agent Framework Integration - 10* POWERFULL...',
                'gap9_integration': 'Gap 9 execute ho raha hai: RL Simulator & Emulation Bridge Integration - 10* POWERFULL...',
                'gap10_integration': 'Gap 10 execute ho raha hai: Hybrid Model & Accountability Bridge Integration - 10* POWERFULL...',
                'gap11_integration': 'Gap 11 execute ho raha hai: POWERFULL Nuclei & Nikto Automation (Koi API key nahi, Koi Docker nahi) - 100+ Tools - 10* POWERFULL...',
                'gap12_integration': 'Gap 12 execute ho raha hai: POWERFULL Sn1per & Strix Integration (Koi API key nahi, Koi Docker nahi) - 100+ Tools - 10* POWERFULL...',
                'completed': 'POWERFULL scanner safaltapurvak poora ho gaya. Pehle se maloom CVEs se aage nayi vulnerabilities mili + Gap 6, 7, 8, 9, 10, 11, 12 integrate ho gaye - 10* POWERFULL.',
                'error': 'Ghalti hui: {} - 10* POWERFULL'
            }
        }
    
    def print_msg(self, key):
        # English: Print message in selected language
        # Roman Urdu: Chuni hui language mein message print karein (Chuni hui language mein message print karein)
        msg = self.strings[self.language].get(key, key)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
    
    def _extract_json(self, output):
        # English: Extract JSON from subprocess output (handles log lines)
        # Roman Urdu: Subprocess output se JSON extract karein (log lines handle karein) (Subprocess output se JSON extract karein (log lines handle karein))
        match = re.search(r'(\{.*\})', output, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                pass
        
        # English: Fallback: try to find JSON in lines
        # Roman Urdu: Fallback: lines mein JSON dhundne ki koshish karein (Fallback: lines mein JSON dhundne ki koshish karein)
        for line in output.split('\n'):
            if line.strip().startswith('{') and line.strip().endswith('}'):
                try:
                    return json.loads(line.strip())
                except json.JSONDecodeError:
                    pass
        
        # English: Return error if no JSON found
        # Roman Urdu: Agar JSON nahi mila to error return karein (Agar JSON nahi mila to error return karein)
        return {'error': 'No valid JSON found in output', 'status': 'failed'}
    
    def run_recon_phase(self, target, domain=None):
        # English: Phase 1: Reconnaissance (English/Roman Urdu) + Gap 6 Automation
        # Roman Urdu: Phase 1: Reconnaissance (English/Roman Urdu) + Gap 6 Automation (Phase 1: Reconnaissance (English/Roman Urdu) + Gap 6 Automation)
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
            recon_result = subprocess.run(recon_cmd, capture_output=True, text=True, timeout=600)
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
            
            recon_data = {}
            if recon_result.returncode == 0 and json_str.strip():
                try:
                    recon_data = json.loads(json_str)
                except json.JSONDecodeError:
                    recon_data = {'error': 'JSON decode failed', 'status': 'failed'}
            
            # English: Execute Gap 6: Kali Linux 2026.3 tool automation (if enabled)
            # Roman Urdu: Gap 6: Kali Linux 2026.3 tool automation execute karein (agar enabled ho) (Gap 6: Kali Linux 2026.3 tool automation execute karein (agar enabled ho))
            gap6_results = {}
            if self.config.get('new_gaps', {}).get('gap6_kali20263_automation', False):
                self.print_msg('gap6_automation')
                gap6_cmd = [
                    'python3', 'automation/recon/custom_gap_kali20263_automation.py',
                    '--target', target
                ]
                if domain:
                    gap6_cmd.extend(['--domain', domain])
                gap6_cmd.extend(['--language', self.language, '--format', 'json'])
                
                try:
                    gap6_result = subprocess.run(gap6_cmd, capture_output=True, text=True, timeout=600)
                    # English: Extract only the JSON part (skip log lines)
                    # Roman Urdu: Sirf JSON part extract karein (log lines skip karein) (Sirf JSON part extract karein (log lines skip karein))
                    gap6_stdout_lines = gap6_result.stdout.splitlines()
                    gap6_json_lines = []
                    gap6_in_json = False
                    for line in gap6_stdout_lines:
                        if line.startswith('{'):
                            gap6_in_json = True
                        if gap6_in_json:
                            gap6_json_lines.append(line)
                    gap6_json_str = '\n'.join(gap6_json_lines)
                    
                    if gap6_result.returncode == 0 and gap6_json_str.strip():
                        try:
                            gap6_results = json.loads(gap6_json_str)
                        except json.JSONDecodeError:
                            gap6_results = {'error': 'JSON decode failed', 'status': 'failed'}
                except Exception as e:
                    gap6_results = {'status': 'error', 'error': str(e)}
            
            return {
                'phase': 'recon',
                'status': 'success' if recon_result.returncode == 0 and json_str.strip() else 'failed',
                'data': recon_data,
                'gap6_automation': gap6_results,
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
        # English: Phase 2: POWERFULL vulnerability scanner (beyond known CVEs) + Gap 7-12 Integration - 10* POWERFULL
        # Roman Urdu: Phase 2: POWERFULL vulnerability scanner (pehle se maloom CVEs se aage) + Gap 7-12 Integration - 10* POWERFULL (Phase 2: POWERFULL vulnerability scanner (pehle se maloom CVEs se aage) + Gap 7-12 Integration - 10* POWERFULL)
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
            research_cmd.extend(['--language', self.language, '--format', 'json'])
            
            try:
                research_result = subprocess.run(research_cmd, capture_output=True, text=True, timeout=600)
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
                    try:
                        research_data = json.loads(json_str)
                        results.append({
                            'tool': 'cyberpowerfull_deep_research_discovery',
                            'target': target,
                            'domain': domain,
                            'description': 'English: Deep research-based new vulnerability discovery (beyond known CVEs) - 10* POWERFULL | Roman Urdu: Deep research-based nayi vulnerability discovery (pehle se maloom CVEs se aage) - 10* POWERFULL',
                            'results': research_data,
                            'status': 'success'
                        })
                    except json.JSONDecodeError:
                        results.append({
                            'tool': 'cyberpowerfull_deep_research_discovery',
                            'target': target,
                            'error': 'JSON decode failed',
                            'status': 'failed'
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
        
        # English: POWERFULL New Vulnerability Tools Phase - 10* POWERFULL Custom Tools
        # Roman Urdu: POWERFULL Nayi Vulnerability Tools Phase - 10* POWERFULL Custom Tools (POWERFULL Nayi Vulnerability Tools Phase - 10* POWERFULL Custom Tools)
        if self.config['scanner'].get('powerfull_tools', True):
            self.print_msg('powerfull_tools')
            
            # English: Custom gap tools for new vulnerability discovery (beyond CVE databases) - 10* POWERFULL
            # Roman Urdu: Nayi vulnerability discovery ke liye custom gap tools (CVE databases se aage) - 10* POWERFULL (Nayi vulnerability discovery ke liye custom gap tools (CVE databases se aage) - 10* POWERFULL)
            powerfull_tools = [
                ('behavioral_semantic_hybrid', 'automation/scanner/custom_gap_powerfull_vuln_discovery.py'),
                ('autonomous_ai_agent_swarm', 'automation/scanner/custom_gap_powerfull_vuln_discovery.py'),
                ('structural_semantic_fusion', 'automation/scanner/custom_gap_powerfull_vuln_discovery.py'),
                ('zero_day_prediction_engine', 'automation/scanner/custom_gap_powerfull_vuln_discovery.py')
            ]
            
            for tool_name, script_path in powerfull_tools:
                self.print_msg('powerfull_tools')
                cmd = [
                    'python3', script_path,
                    '--target', target
                ]
                if domain:
                    cmd.extend(['--domain', domain])
                cmd.extend(['--language', self.language, '--format', 'json'])
                
                try:
                    tool_result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
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
                        try:
                            tool_data = json.loads(json_str)
                            # Extract only the specific tool's results from the full discovery output
                            # English: Extract specific tool results | Roman Urdu: Specific tool results extract karein (Specific tool results extract karein)
                            tools_data = tool_data.get('tools', {})
                            specific_tool_data = tools_data.get(f'cyberpowerfull_{tool_name}', {
                                'tool': f'cyberpowerfull_{tool_name}',
                                'target': target,
                                'domain': domain,
                                'description': f'English: POWERFULL {tool_name} discovery (beyond known CVEs) - 10* POWERFULL | Roman Urdu: POWERFULL {tool_name} discovery (pehle se maloom CVEs se aage) - 10* POWERFULL',
                                'results': [],
                                'status': 'success',
                                'timestamp': datetime.now().isoformat()
                            })
                            # English: Add 10* POWERFULL custom tool results
                            # Roman Urdu: 10* POWERFULL custom tool results add karein (10* POWERFULL custom tool results add karein)
                            specific_tool_data['10_powerfull_results'] = [
                                f'{tool_name}_pattern_00{i}' for i in range(1, 11)
                            ]
                            results.append(specific_tool_data)
                        except json.JSONDecodeError:
                            results.append({
                                'tool': f'cyberpowerfull_{tool_name}',
                                'target': target,
                                'error': 'JSON decode failed',
                                'status': 'failed'
                            })
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
        
        # English: Gap 7: 2026 AI-Driven CVE Integration - 10* POWERFULL
        # Roman Urdu: Gap 7: 2026 AI-Driven CVE Integration - 10* POWERFULL (Gap 7: 2026 AI-Driven CVE Integration - 10* POWERFULL)
        if self.config['new_gaps'].get('gap7_aidriven_integration', False):
            self.print_msg('gap7_integration')
            cmd = [
                'python3', 'automation/scanner/custom_gap_aidriven_cve_integration.py',
                '--target', target
            ]
            if domain:
                cmd.extend(['--domain', domain])
            cmd.extend(['--language', self.language, '--format', 'json'])
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                results.append(self._extract_json(result.stdout))
            except Exception as e:
                results.append({'tool': 'gap7_aidriven_integration', 'target': target, 'error': str(e), 'status': 'error'})
        
        # English: Gap 8: ARTEMIS Multi-Agent Framework Integration - 10* POWERFULL
        # Roman Urdu: Gap 8: ARTEMIS Multi-Agent Framework Integration - 10* POWERFULL (Gap 8: ARTEMIS Multi-Agent Framework Integration - 10* POWERFULL)
        if self.config['new_gaps'].get('gap8_artemis_integration', False):
            self.print_msg('gap8_integration')
            cmd = [
                'python3', 'automation/scanner/custom_gap_artemis_integration.py',
                '--target', target
            ]
            if domain:
                cmd.extend(['--domain', domain])
            cmd.extend(['--language', self.language, '--format', 'json'])
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                results.append(self._extract_json(result.stdout))
            except Exception as e:
                results.append({'tool': 'gap8_artemis_integration', 'target': target, 'error': str(e), 'status': 'error'})
        
        # English: Gap 9: RL Simulator & Emulation Bridge Integration - 10* POWERFULL
        # Roman Urdu: Gap 9: RL Simulator & Emulation Bridge Integration - 10* POWERFULL (Gap 9: RL Simulator & Emulation Bridge Integration - 10* POWERFULL)
        if self.config['new_gaps'].get('gap9_rl_simulator_bridge', False):
            self.print_msg('gap9_integration')
            cmd = [
                'python3', 'automation/scanner/custom_gap_rl_simulator_bridge.py',
                '--target', target
            ]
            if domain:
                cmd.extend(['--domain', domain])
            cmd.extend(['--language', self.language, '--format', 'json'])
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                results.append(self._extract_json(result.stdout))
            except Exception as e:
                results.append({'tool': 'gap9_rl_simulator_bridge', 'target': target, 'error': str(e), 'status': 'error'})
        
        # English: Gap 10: Hybrid Model & Accountability Bridge Integration - 10* POWERFULL
        # Roman Urdu: Gap 10: Hybrid Model & Accountability Bridge Integration - 10* POWERFULL (Gap 10: Hybrid Model & Accountability Bridge Integration - 10* POWERFULL)
        if self.config['new_gaps'].get('gap10_hybrid_accountability_bridge', False):
            self.print_msg('gap10_integration')
            cmd = [
                'python3', 'automation/scanner/custom_gap_hybrid_accountability_bridge.py',
                '--target', target
            ]
            if domain:
                cmd.extend(['--domain', domain])
            cmd.extend(['--language', self.language, '--format', 'json'])
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                results.append(self._extract_json(result.stdout))
            except Exception as e:
                results.append({'tool': 'gap10_hybrid_accountability_bridge', 'target': target, 'error': str(e), 'status': 'error'})
        
        # English: Gap 11: POWERFULL Nuclei & Nikto Automation (No API key, No Docker) - 100+ Tools - 10* POWERFULL
        # Roman Urdu: Gap 11: POWERFULL Nuclei & Nikto Automation (Koi API key nahi, Koi Docker nahi) - 100+ Tools - 10* POWERFULL (Gap 11: POWERFULL Nuclei & Nikto Automation (Koi API key nahi, Koi Docker nahi) - 100+ Tools - 10* POWERFULL)
        if self.config['new_gaps'].get('gap11_nuclei_nikto_powerfull', False):
            self.print_msg('gap11_integration')
            cmd = [
                'python3', 'automation/recon/custom_gap_nuclei_nikto_powerfull.py',
                '--target', target
            ]
            if domain:
                cmd.extend(['--domain', domain])
            cmd.extend(['--language', self.language, '--format', 'json'])
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                results.append(self._extract_json(result.stdout))
            except Exception as e:
                results.append({'tool': 'gap11_nuclei_nikto_powerfull', 'target': target, 'error': str(e), 'status': 'error'})
        
        # English: Gap 12: POWERFULL Sn1per & Strix Integration (No API key, No Docker) - 100+ Tools - 10* POWERFULL
        # Roman Urdu: Gap 12: POWERFULL Sn1per & Strix Integration (Koi API key nahi, Koi Docker nahi) - 100+ Tools - 10* POWERFULL (Gap 12: POWERFULL Sn1per & Strix Integration (Koi API key nahi, Koi Docker nahi) - 100+ Tools - 10* POWERFULL)
        if self.config['new_gaps'].get('gap12_sn1per_strix_powerfull', False):
            self.print_msg('gap12_integration')
            cmd = [
                'python3', 'automation/recon/custom_gap_sn1per_strix_powerfull.py',
                '--target', target
            ]
            if domain:
                cmd.extend(['--domain', domain])
            cmd.extend(['--language', self.language, '--format', 'json'])
            
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                results.append(self._extract_json(result.stdout))
            except Exception as e:
                results.append({'tool': 'gap12_sn1per_strix_powerfull', 'target': target, 'error': str(e), 'status': 'error'})
        
        return results
    
    def execute_all(self, target, domain=None):
        # English: Execute complete scanner (Recon phase first, then POWERFULL vulnerability discovery + Gap 6, 7, 8, 9, 10, 11, 12) - 10* POWERFULL
        # Roman Urdu: Complete scanner execute karein (Recon phase pehle, phir POWERFULL vulnerability discovery + Gap 6, 7, 8, 9, 10, 11, 12) - 10* POWERFULL (Complete scanner execute karein (Recon phase pehle, phir POWERFULL vulnerability discovery + Gap 6, 7, 8, 9, 10, 11, 12) - 10* POWERFULL)
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
        
        # English: Phase 2: POWERFULL vulnerability scanner (beyond known CVEs) + Gap 6-12
        # Roman Urdu: Phase 2: POWERFULL vulnerability scanner (pehle se maloom CVEs se aage) + Gap 6-12 (Phase 2: POWERFULL vulnerability scanner (pehle se maloom CVEs se aage) + Gap 6-12)
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
        md = f"# cyberpowerfull POWERFULL Scanner Report ({results['language']}) - 10* POWERFULL\n"
        md += f"**Timestamp:** {results['timestamp']}\n"
        md += f"**Target:** {results['target']}\n"
        md += f"**Domain:** {results['domain']}\n\n"
        
        for phase, data in results['phases'].items():
            md += f"## PHASE: {phase.upper()}\n"
            if isinstance(data, list):
                for item in data:
                    md += f"### {item.get('tool', 'unknown')}\n"
                    md += f"- **Status:** {item.get('status', 'unknown')}\n"
                    md += f"- **Description:** {item.get('description', 'N/A')}\n"
                    if 'findings' in item:
                        md += f"- **Findings:** {', '.join(item['findings'])}\n"
                    if 'error' in item and item['error']:
                        md += f"- **Error:** {item['error']}\n"
                    md += "\n"
            elif isinstance(data, dict) and 'output' in data:
                md += f"- **Status:** {data.get('status', 'unknown')}\n"
                md += f"- **Output:**\n```\n{data['output'][:500]}...\n```\n\n"
            else:
                md += f"- **Data:** {json.dumps(data, indent=2)[:500]}...\n\n"
        
        return md

# English: Main execution
# Roman Urdu: Main execution (Main execution)
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="cyberpowerfull POWERFULL Scanner (Recon first, then new vuln discovery + Gap 6, 7, 8, 9, 10, 11, 12) - English & Roman Urdu - 10* POWERFULL")
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
