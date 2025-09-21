import os
import ast
import json
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM

class CodeT5Analyzer:
    def __init__(self):
        # Define the cache directory for the model, as requested
        current_dir = os.path.dirname(os.path.abspath(__file__))
        cache_dir = os.path.join(current_dir, 'Codet5')
        os.makedirs(cache_dir, exist_ok=True)

        # Initialize standard CodeT5 model (will be replaced with fine-tuned version later)
        print(f"Loading standard CodeT5 model. It will be downloaded to: {cache_dir}")
        try:
            # Use cache_dir to specify the download and cache location
            self.tokenizer = AutoTokenizer.from_pretrained("Salesforce/codet5-base", cache_dir=cache_dir)
            self.model = AutoModelForSeq2SeqLM.from_pretrained("Salesforce/codet5-base", cache_dir=cache_dir)
        except Exception:
            # In environments without transformers, continue with no model loaded
            self.tokenizer = None
            self.model = None
        
        # Note: This is using the standard CodeT5 model for now
        # The fine-tuned model will be integrated in future updates
        
    def analyze(self, repo_path):
        """Analyze codebase for security vulnerabilities"""
        findings = []
        
        # Walk through all Python files
        for root, dirs, files in os.walk(repo_path):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    file_findings = self._analyze_file(file_path, repo_path)
                    findings.extend(file_findings)
        
        return findings
    
    def _analyze_file(self, file_path, repo_path):
        """Analyze individual file for vulnerabilities"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Parse AST
            tree = ast.parse(content)
            
            # Apply security rules
            findings.extend(self._check_sql_injection(content, file_path, repo_path))
            findings.extend(self._check_xss(content, file_path, repo_path))
            findings.extend(self._check_hardcoded_secrets(content, file_path, repo_path))
            
        except Exception as e:
            print(f"Error analyzing {file_path}: {str(e)}")
        
        return findings
    
    def _check_sql_injection(self, content, file_path, repo_path):
        """Check for potential SQL injection vulnerabilities"""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Simple pattern matching (you'd want more sophisticated analysis)
            if 'execute(' in line and '%s' in line:
                findings.append({
                    'shortform_keyword': 'SQLI-UNSAN-INPUT',
                    'file_path': os.path.relpath(file_path, repo_path),
                    'line_number': i,
                    'severity': 'HIGH',
                    'context_snippet': line.strip()
                })
        
        return findings
    
    def _check_xss(self, content, file_path, repo_path):
        """Check for potential XSS vulnerabilities"""
        findings = []
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            if 'render_template_string' in line and 'request.' in line:
                findings.append({
                    'shortform_keyword': 'XSS-UNESC-OUTPUT',
                    'file_path': os.path.relpath(file_path, repo_path),
                    'line_number': i,
                    'severity': 'MEDIUM',
                    'context_snippet': line.strip()
                })
        
        return findings
    
    def _check_hardcoded_secrets(self, content, file_path, repo_path):
        """Check for hardcoded secrets"""
        findings = []
        lines = content.split('\n')
        
        secret_patterns = ['password', 'api_key', 'secret_key', 'token']
        
        for i, line in enumerate(lines, 1):
            for pattern in secret_patterns:
                if pattern in line.lower() and '=' in line:
                    findings.append({
                        'shortform_keyword': 'HARDCODED-SECRET',
                        'file_path': os.path.relpath(file_path, repo_path),
                        'line_number': i,
                        'severity': 'CRITICAL',
                        'context_snippet': line.strip()
                    })
        
        return findings
