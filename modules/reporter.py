#!/usr/bin/env python3
# cyberpowerfull Recon Module Reporter
# English: Generate reports in English & Roman Urdu
# Roman Urdu: English aur Roman Urdu mein reports banayein (English aur Roman Urdu mein reports banayein)

import json
import yaml
import os
from datetime import datetime

class ReconReporter:
    def __init__(self, config_path="config.yaml"):
        # English: Load configuration
        # Roman Urdu: Configuration load karein (Configuration load karein)
        with open(config_path, 'r') as f:
            self.config = yaml.safe_load(f)
        
        self.language = self.config.get('language', 'english')
        self.output_format = self.config.get('output_format', 'json')
        
        # English: Language strings
        # Roman Urdu: Language strings (Language strings)
        self.strings = {
            'english': {
                'report_title': 'cyberpowerfull Recon Report',
                'timestamp': 'Timestamp:',
                'target': 'Target:',
                'domain': 'Domain:',
                'tools_summary': 'Tools Summary:',
                'custom_gaps': 'Custom Gap Results:',
                'nmap': 'Nmap Scan:',
                'rustscan': 'Rustscan:',
                'subdomains': 'Subdomains:',
                'error': 'Error generating report: {}'
            },
            'roman_urdu': {
                'report_title': 'cyberpowerfull Recon Report',
                'timestamp': 'Timestamp:',
                'target': 'Target:',
                'domain': 'Domain:',
                'tools_summary': 'Tools Summary:',
                'custom_gaps': 'Custom Gap Results:',
                'nmap': 'Nmap Scan:',
                'rustscan': 'Rustscan:',
                'subdomains': 'Subdomains:',
                'error': 'Report banane mein ghalti: {}'
            }
        }
    
    def generate_report(self, results_json):
        # English: Generate report from JSON results
        # Roman Urdu: JSON results se report banayein (JSON results se report banayein)
        try:
            results = json.loads(results_json)
            language = results.get('language', self.language)
            strings = self.strings[language]
            
            # English: Format report based on output format
            # Roman Urdu: Output format ke mutabiq report format karein (Output format ke mutabiq report format karein)
            if self.output_format == 'json':
                return json.dumps(results, indent=2)
            
            elif self.output_format == 'markdown':
                md = f"# {strings['report_title']}\n"
                md += f"**{strings['timestamp']}** {results.get('timestamp', datetime.now().isoformat())}\n"
                md += f"**{strings['target']}** {results.get('target', 'N/A')}\n"
                md += f"**{strings['domain']}** {results.get('domain', 'N/A')}\n\n"
                
                # English: Tools summary
                # Roman Urdu: Tools summary (Tools summary)
                md += f"## {strings['tools_summary']}\n"
                if 'tools' in results:
                    for tool, data in results['tools'].items():
                        md += f"### {tool.upper()}\n"
                        if isinstance(data, dict) and 'status' in data:
                            md += f"- **Status:** {data['status']}\n"
                            if 'output' in data and data['output']:
                                md += f"- **Output:**\n```\n{data['output'][:500]}...\n```\n"
                        elif isinstance(data, list):
                            for item in data:
                                md += f"- **Tool:** {item.get('tool', 'N/A')}\n"
                                md += f"- **Results:** {', '.join(item.get('subdomains', [])) if 'subdomains' in item else str(item)}\n"
                        md += "\n"
                
                # English: Custom gaps
                # Roman Urdu: Custom gaps (Custom gaps)
                if 'tools' in results and 'custom_gaps' in results['tools']:
                    md += f"## {strings['custom_gaps']}\n"
                    for gap in results['tools']['custom_gaps']:
                        md += f"### {gap.get('tool', 'N/A')}\n"
                        md += f"- **Description:** {gap.get('description', 'N/A')}\n"
                        md += f"- **Results:** {', '.join(gap.get('results', []))}\n\n"
                
                return md
            
            else:
                return str(results)
            
        except Exception as e:
            return self.strings[self.language]['error'].format(str(e))

# English: Main execution
# Roman Urdu: Main execution (Main execution)
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="cyberpowerfull Recon Reporter")
    parser.add_argument("--input", required=True, help="English: Input JSON file | Roman Urdu: Input JSON file")
    parser.add_argument("--output", help="English: Output file path | Roman Urdu: Output file path")
    parser.add_argument("--language", choices=['english', 'roman_urdu'], default='english', help="English: Language | Roman Urdu: Language")
    parser.add_argument("--format", choices=['json', 'markdown', 'text'], default='json', help="English: Output format | Roman Urdu: Output format")
    
    args = parser.parse_args()
    
    reporter = ReconReporter()
    reporter.language = args.language
    reporter.output_format = args.format
    
    with open(args.input, 'r') as f:
        results_json = f.read()
    
    report = reporter.generate_report(results_json)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Report saved to {args.output}")
    else:
        print(report)
