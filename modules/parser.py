# English: cyberpowerfull Recon Module Parser
# Roman Urdu: cyberpowerfull Recon Module Parser (cyberpowerfull Recon Module Parser)

import json
import yaml
import os

class ReconParser:
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
                'parsing': 'Parsing recon results...',
                'summary': 'Recon Summary:',
                'targets': 'Targets scanned:',
                'subdomains': 'Subdomains found:',
                'custom_gaps': 'Custom gap results:',
                'error': 'Error parsing: {}'
            },
            'roman_urdu': {
                'parsing': 'Recon results parse ho rahe hain...',
                'summary': 'Recon Summary:',
                'targets': 'Scan kiye gaye targets:',
                'subdomains': 'Mile hue subdomains:',
                'custom_gaps': 'Custom gap results:',
                'error': 'Parsing mein ghalti: {}'
            }
        }
    
    def parse_results(self, results_json):
        # English: Parse JSON results
        # Roman Urdu: JSON results parse karein (JSON results parse karein)
        try:
            results = json.loads(results_json)
            parsed = {
                'summary': self.strings[self.language]['summary'],
                'targets': [],
                'subdomains': [],
                'custom_gaps': [],
                'language': results.get('language', 'english')
            }
            
            # English: Extract targets from tools
            # Roman Urdu: Tools se targets extract karein (Tools se targets extract karein)
            if 'tools' in results:
                for tool, data in results['tools'].items():
                    if isinstance(data, dict) and 'target' in data:
                        parsed['targets'].append(data['target'])
                    
                    # English: Extract subdomains
                    # Roman Urdu: Subdomains extract karein (Subdomains extract karein)
                    if tool == 'subdomains' and isinstance(data, list):
                        for item in data:
                            parsed['subdomains'].extend(item.get('subdomains', []))
                    
                    # English: Extract custom gaps
                    # Roman Urdu: Custom gaps extract karein (Custom gaps extract karein)
                    if tool == 'custom_gaps' and isinstance(data, list):
                        parsed['custom_gaps'].extend(data)
            
            # English: Format summary
            # Roman Urdu: Summary format karein (Summary format karein)
            summary = f"{self.strings[self.language]['summary']}\n"
            summary += f"- {self.strings[self.language]['targets']}: {', '.join(parsed['targets'])}\n"
            summary += f"- {self.strings[self.language]['subdomains']}: {', '.join(parsed['subdomains'])}\n"
            summary += f"- {self.strings[self.language]['custom_gaps']}: {len(parsed['custom_gaps'])} results\n"
            
            parsed['summary_text'] = summary
            return parsed
            
        except Exception as e:
            return {'error': self.strings[self.language]['error'].format(str(e))}

# English: Main execution
# Roman Urdu: Main execution (Main execution)
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="cyberpowerfull Recon Parser")
    parser.add_argument("--input", required=True, help="English: Input JSON file | Roman Urdu: Input JSON file")
    parser.add_argument("--language", choices=['english', 'roman_urdu'], default='english', help="English: Language | Roman Urdu: Language")
    
    args = parser.parse_args()
    
    parser_obj = ReconParser()
    parser_obj.language = args.language
    
    with open(args.input, 'r') as f:
        results_json = f.read()
    
    parsed = parser_obj.parse_results(results_json)
    print(json.dumps(parsed, indent=2))
