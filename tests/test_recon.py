# cyberpowerfull Recon Tests
# English: Unit tests for recon modules
# Roman Urdu: Recon modules ke liye unit tests (Recon modules ke liye unit tests)

import unittest
import json
import yaml
import os
from datetime import datetime

# English: Import modules
# Roman Urdu: Modules import karein (Modules import karein)
from modules.parser import ReconParser
from modules.reporter import ReconReporter
from automation.recon.recon_wrapper import ReconWrapper

class TestReconModules(unittest.TestCase):
    def setUp(self):
        # English: Setup test configuration
        # Roman Urdu: Test configuration setup karein (Test configuration setup karein)
        self.config_path = "config.yaml"
        self.parser = ReconParser(self.config_path)
        self.reporter = ReconReporter(self.config_path)
        self.wrapper = ReconWrapper(self.config_path)
        
        # English: Sample results JSON
        # Roman Urdu: Sample results JSON (Sample results JSON)
        self.sample_results = json.dumps({
            'timestamp': datetime.now().isoformat(),
            'target': '192.168.1.1',
            'domain': 'example.com',
            'language': 'english',
            'tools': {
                'nmap': {
                    'tool': 'nmap',
                    'target': '192.168.1.1',
                    'output': 'Nmap scan report for 192.168.1.1\nPORT   STATE SERVICE\n80/tcp open  http\n',
                    'error': '',
                    'status': 'success'
                },
                'subdomains': [
                    {
                        'tool': 'sublist3r',
                        'domain': 'example.com',
                        'subdomains': ['sub1.example.com', 'sub2.example.com']
                    }
                ],
                'custom_gaps': [
                    {
                        'tool': 'cyberpowerfull_port_fingerprint',
                        'target': '192.168.1.1',
                        'description': 'English: Deep service fingerprinting | Roman Urdu: Gehra service fingerprinting',
                        'results': ['port_8080_custom_service']
                    }
                ]
            }
        })
    
    def test_parser(self):
        # English: Test parser
        # Roman Urdu: Parser test karein (Parser test karein)
        parsed = self.parser.parse_results(self.sample_results)
        self.assertIn('summary', parsed)
        self.assertIn('targets', parsed)
        self.assertIn('subdomains', parsed)
        self.assertIn('custom_gaps', parsed)
        self.assertEqual(parsed['targets'], ['192.168.1.1'])
        self.assertEqual(len(parsed['subdomains']), 2)
        self.assertEqual(len(parsed['custom_gaps']), 1)
    
    def test_reporter(self):
        # English: Test reporter
        # Roman Urdu: Reporter test karein (Reporter test karein)
        report = self.reporter.generate_report(self.sample_results)
        self.assertIsNotNone(report)
        self.assertIn('cyberpowerfull Recon Report', report)
        self.assertIn('192.168.1.1', report)
        self.assertIn('example.com', report)
    
    def test_wrapper_initialization(self):
        # English: Test wrapper initialization
        # Roman Urdu: Wrapper initialization test karein (Wrapper initialization test karein)
        self.assertEqual(self.wrapper.language, 'english')
        self.assertEqual(self.wrapper.output_format, 'json')

# English: Main execution
# Roman Urdu: Main execution (Main execution)
if __name__ == "__main__":
    unittest.main()
