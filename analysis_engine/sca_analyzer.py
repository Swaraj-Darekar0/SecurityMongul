import os

class SCAAnalyzer:
    def __init__(self):
        pass
    
    def analyze(self, repo_path):
        """Perform a simple dependency scan (stub)"""
        findings = []
        # Look for requirements.txt or package.json and flag known patterns (stub)
        req_path = os.path.join(repo_path, 'requirements.txt')
        if os.path.exists(req_path):
            with open(req_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Simple heuristic: flag outdated packages placeholder
                if 'django' in content.lower():
                    findings.append({
                        'shortform_keyword': 'DEPENDENCY-DJANGO-OLD',
                        'file_path': os.path.relpath(req_path, repo_path),
                        'line_number': 0,
                        'severity': 'LOW',
                        'context_snippet': 'Potential outdated Django in requirements.txt'
                    })
        return findings
