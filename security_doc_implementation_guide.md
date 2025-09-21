### Week 1: Foundation Setup
- [ ] Set up project structure with PulledCode and templates folders
- [ ] Configure development environment
- [ ] Implement basic Flask application with template directory configuration
- [ ] Create GitHub service for repository cloning (with overwrite functionality)
- [ ]# Security Documentation Project - Implementation Guide

## Project Overview

This implementation guide provides a step-by-step approach to building a comprehensive security documentation system that analyzes GitHub repositories and generates professional security reports. The system uses a three-phase workflow: Input & Analysis, Data Processing & Storage, and Report Generation & Output.

## Architecture Overview

```
Frontend (React) → Backend (Flask) → Analysis Engine (CodeT5) → Knowledge Base → Report Generator (Gemini 2.5 Pro) → Document Formatter
```

## Technology Stack

- **Frontend**: React.js
- **Backend**: Python Flask
- **Analysis Engine**: CodeT5 (Fine-tuned)
- **Report Generation**: Google Gemini 2.5 Pro API
- **Database**: JSON files (lightweight approach)
- **Document Processing**: Python libraries (pandoc, python-docx)

## Project Structure

```
security-documentation-system/
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── utils/
│   ├── public/
│   └── package.json
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── routes/
│   │   ├── models/
│   │   ├── services/
│   │   └── utils/
│   ├── PulledCode/          # Local repository storage (overwritten each time)
│   ├── data/
│   │   ├── findings_dictionary.json
│   │   └── scanned_results/
│   ├── templates/           # Report templates for Gemini integration
│   │   ├── regulatory_compliance_template.md
│   │   ├── technical_operational_template.md
│   │   └── business_focused_template.md
│   ├── requirements.txt
│   └── run.py
├── analysis_engine/
│   ├── codet5_analyzer.py   # Using standard CodeT5 (fine-tuned version later)
│   ├── sca_analyzer.py
│   └── models/
└── docs/
    └── api_documentation/
```

## Implementation Phases

### Phase 1: Project Setup and Environment

#### 1.1 Initialize the Project Structure

```bash
# Create main project directory
mkdir security-documentation-system
cd security-documentation-system

# Create subdirectories
mkdir frontend backend analysis_engine docs
mkdir backend/PulledCode backend/data backend/data/scanned_results backend/templates
mkdir frontend/src frontend/src/components frontend/src/pages frontend/src/services
mkdir backend/app backend/app/routes backend/app/models backend/app/services backend/app/utils
mkdir analysis_engine/models docs/api_documentation
```

#### 1.2 Backend Environment Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install required packages
pip install flask flask-cors requests python-dotenv
pip install transformers torch
pip install pandas numpy
pip install python-docx pypandoc
pip install gitpython
pip install google-generativeai
pip freeze > requirements.txt
```

#### 1.3 Frontend Environment Setup

```bash
cd ../frontend
npx create-react-app .
npm install axios
npm install @mui/material @emotion/react @emotion/styled
npm install react-dropzone
```

### Phase 2: Backend Implementation

#### 2.1 Flask Application Setup

**backend/app/__init__.py**
```python
from flask import Flask
from flask_cors import CORS
import os

def create_app():
    app = Flask(__name__)
    CORS(app)
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
    app.config['PULLED_CODE_DIR'] = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'PulledCode')
    app.config['DATA_DIR'] = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data')
    app.config['TEMPLATES_DIR'] = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
    
    # Register blueprints
    from app.routes.main import main_bp
    app.register_blueprint(main_bp)
    
    return app
```

**backend/app/routes/main.py**
```python
from flask import Blueprint, request, jsonify, send_file
from app.services.github_service import GitHubService
from app.services.analysis_service import AnalysisService
from app.services.report_service import ReportService
import os

main_bp = Blueprint('main', __name__)

@main_bp.route('/api/analyze', methods=['POST'])
def analyze_repository():
    try:
        data = request.get_json()
        github_url = data.get('github_url')
        sector_hint = data.get('sector_hint', '')
        
        # Phase 1: Input & Analysis
        github_service = GitHubService()
        repo_path = github_service.clone_repository(github_url)
        
        # Phase 2: Data Processing & Storage
        analysis_service = AnalysisService()
        scan_results = analysis_service.analyze_codebase(repo_path, sector_hint)
        
        return jsonify({
            'status': 'success',
            'scan_id': scan_results['scan_id'],
            'message': 'Analysis completed successfully'
        })
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@main_bp.route('/api/generate-report', methods=['POST'])
def generate_report():
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        report_type = data.get('report_type')
        
        # Phase 3: Report Generation & Output
        report_service = ReportService()
        report_path = report_service.generate_report(scan_id, report_type)
        
        return send_file(report_path, as_attachment=True)
    
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
```

#### 2.2 GitHub Service Implementation

**backend/app/services/github_service.py**
```python
import git
import os
import shutil
from datetime import datetime
from flask import current_app

class GitHubService:
    def __init__(self):
        self.pulled_code_dir = current_app.config['PULLED_CODE_DIR']
        
    def clone_repository(self, github_url):
        """Clone GitHub repository to PulledCode directory (overwrites existing files)"""
        try:
            # Always clear and recreate PulledCode directory
            if os.path.exists(self.pulled_code_dir):
                shutil.rmtree(self.pulled_code_dir)
            os.makedirs(self.pulled_code_dir, exist_ok=True)
            
            # Clone repository
            repo_name = github_url.split('/')[-1].replace('.git', '')
            clone_path = os.path.join(self.pulled_code_dir, repo_name)
            
            print(f"Cloning {github_url} to {clone_path}")
            git.Repo.clone_from(github_url, clone_path)
            
            # Log the operation
            self._log_clone_operation(github_url, clone_path)
            
            return clone_path
            
        except Exception as e:
            raise Exception(f"Failed to clone repository: {str(e)}")
    
    def _log_clone_operation(self, github_url, clone_path):
        """Log clone operation for tracking"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'github_url': github_url,
            'local_path': clone_path,
            'status': 'success'
        }
        # You can implement logging to file or database here
        print(f"Repository cloned: {log_entry}")
    
    def get_repository_info(self, repo_path):
        """Extract basic repository information"""
        info = {}
        
        # Read README.md if exists
        readme_path = os.path.join(repo_path, 'README.md')
        if os.path.exists(readme_path):
            with open(readme_path, 'r', encoding='utf-8') as f:
                info['readme'] = f.read()
        
        # Get package files for dependency analysis
        package_files = ['requirements.txt', 'package.json', 'Pipfile', 'pom.xml']
        info['dependencies'] = {}
        
        for file in package_files:
            file_path = os.path.join(repo_path, file)
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    info['dependencies'][file] = f.read()
        
        return info
```

#### 2.3 Analysis Service Implementation

**backend/app/services/analysis_service.py**
```python
import os
import json
import uuid
from datetime import datetime
from flask import current_app
from analysis_engine.codet5_analyzer import CodeT5Analyzer
from analysis_engine.sca_analyzer import SCAAnalyzer

class AnalysisService:
    def __init__(self):
        self.data_dir = current_app.config['DATA_DIR']
        self.codet5_analyzer = CodeT5Analyzer()
        self.sca_analyzer = SCAAnalyzer()
        
    def analyze_codebase(self, repo_path, sector_hint):
        """Perform comprehensive security analysis"""
        try:
            # Generate unique scan ID
            scan_id = str(uuid.uuid4())
            
            # Perform CodeT5 analysis
            code_findings = self.codet5_analyzer.analyze(repo_path)
            
            # Perform SCA analysis
            dependency_findings = self.sca_analyzer.analyze(repo_path)
            
            # Combine findings
            all_findings = code_findings + dependency_findings
            
            # Enrich findings with knowledge base
            enriched_findings = self._enrich_findings(all_findings)
            
            # Create comprehensive JSON
            scan_results = {
                'scan_id': scan_id,
                'timestamp': datetime.now().isoformat(),
                'repository_path': repo_path,
                'sector_hint': sector_hint,
                'findings': enriched_findings,
                'summary': self._generate_summary(enriched_findings)
            }
            
            # Save results
            self._save_scan_results(scan_id, scan_results)
            
            return scan_results
            
        except Exception as e:
            raise Exception(f"Analysis failed: {str(e)}")
    
    def _enrich_findings(self, findings):
        """Enrich findings with knowledge base information"""
        # Load findings dictionary
        dict_path = os.path.join(self.data_dir, 'findings_dictionary.json')
        with open(dict_path, 'r') as f:
            findings_dict = json.load(f)
        
        enriched = []
        for finding in findings:
            keyword = finding.get('shortform_keyword')
            if keyword in findings_dict:
                # Merge finding with dictionary data
                enriched_finding = {**finding, **findings_dict[keyword]}
                enriched.append(enriched_finding)
            else:
                enriched.append(finding)
        
        return enriched
    
    def _generate_summary(self, findings):
        """Generate summary statistics"""
        severity_counts = {}
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_findings': len(findings),
            'severity_breakdown': severity_counts
        }
    
    def _save_scan_results(self, scan_id, results):
        """Save scan results to file"""
        results_path = os.path.join(self.data_dir, 'scanned_results', f'{scan_id}.json')
        with open(results_path, 'w') as f:
            json.dump(results, f, indent=2)
```

#### 2.4 Analysis Engine Components

**analysis_engine/codet5_analyzer.py**
```python
import os
import ast
import json
from transformers import AutoTokenizer, AutoModelForSeq2SeqLM

class CodeT5Analyzer:
    def __init__(self):
        # Initialize standard CodeT5 model (will be replaced with fine-tuned version later)
        print("Loading standard CodeT5 model (fine-tuned version will be integrated later)")
        self.tokenizer = AutoTokenizer.from_pretrained("Salesforce/codet5-base")
        self.model = AutoModelForSeq2SeqLM.from_pretrained("Salesforce/codet5-base")
        
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
```

#### 2.6 Report Service with Template Integration

**backend/app/services/report_service.py**
```python
import os
import json
import google.generativeai as genai
from flask import current_app
from docx import Document
from datetime import datetime

class ReportService:
    def __init__(self):
        self.data_dir = current_app.config['DATA_DIR']
        self.templates_dir = current_app.config['TEMPLATES_DIR']
        
        # Configure Gemini API
        genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
        self.model = genai.GenerativeModel('gemini-1.5-pro')
    
    def generate_report(self, scan_id, report_type):
        """Generate report using Gemini with appropriate template"""
        try:
            # Load scan results
            scan_results = self._load_scan_results(scan_id)
            
            # Load appropriate template
            template = self._load_template(report_type)
            
            # Generate report content using Gemini
            report_content = self._generate_with_gemini(scan_results, template, report_type)
            
            # Format and save report
            report_path = self._format_and_save_report(report_content, scan_id, report_type)
            
            return report_path
            
        except Exception as e:
            raise Exception(f"Report generation failed: {str(e)}")
    
    def _load_template(self, report_type):
        """Load template based on report type"""
        template_mapping = {
            'regulatory_compliance': 'regulatory_compliance_template.md',
            'technical_operational': 'technical_operational_template.md',
            'business_focused': 'business_focused_template.md'
        }
        
        template_file = template_mapping.get(report_type)
        if not template_file:
            raise ValueError(f"Unknown report type: {report_type}")
        
        template_path = os.path.join(self.templates_dir, template_file)
        
        if not os.path.exists(template_path):
            raise FileNotFoundError(f"Template not found: {template_path}")
        
        with open(template_path, 'r', encoding='utf-8') as f:
            return f.read()
    
    def _generate_with_gemini(self, scan_results, template, report_type):
        """Use Gemini to generate report content"""
        prompt = f"""
        You are a professional security report generator. Use the provided template and security scan data to create a comprehensive {report_type.replace('_', ' ')} report.

        TEMPLATE:
        {template}

        SECURITY SCAN DATA:
        {json.dumps(scan_results, indent=2)}

        Instructions:
        1. Follow the template structure exactly
        2. Replace placeholders with actual data from the scan results
        3. Write in professional, clear language
        4. Include specific findings with file paths and line numbers where applicable
        5. Provide actionable recommendations
        6. Ensure compliance mappings are accurate
        
        Generate the complete report:
        """
        
        response = self.model.generate_content(prompt)
        return response.text
    
    def _load_scan_results(self, scan_id):
        """Load scan results from storage"""
        results_path = os.path.join(self.data_dir, 'scanned_results', f'{scan_id}.json')
        
        if not os.path.exists(results_path):
            raise FileNotFoundError(f"Scan results not found for ID: {scan_id}")
        
        with open(results_path, 'r') as f:
            return json.load(f)
    
    def _format_and_save_report(self, content, scan_id, report_type):
        """Format report content and save as document"""
        # Create reports directory if it doesn't exist
        reports_dir = os.path.join(self.data_dir, 'generated_reports')
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{report_type}_{scan_id}_{timestamp}.docx"
        report_path = os.path.join(reports_dir, filename)
        
        # Create Word document
        doc = Document()
        
        # Add title
        title = doc.add_heading(f'Security {report_type.replace("_", " ").title()} Report', 0)
        
        # Split content into paragraphs and add to document
        paragraphs = content.split('\n\n')
        for paragraph in paragraphs:
            if paragraph.strip():
                if paragraph.startswith('#'):
                    # Handle headers
                    level = paragraph.count('#')
                    text = paragraph.strip('#').strip()
                    doc.add_heading(text, level)
                else:
                    doc.add_paragraph(paragraph.strip())
        
        # Save document
        doc.save(report_path)
        return report_path
```

#### 2.7 Template System Setup

Create the following template files in the `backend/templates/` directory:

**backend/templates/regulatory_compliance_template.md**
```markdown
# Security Compliance Report

## Executive Summary
[EXECUTIVE_SUMMARY_PLACEHOLDER]

## Compliance Overview
- **Assessment Date**: [DATE_PLACEHOLDER]
- **Repository**: [REPOSITORY_PLACEHOLDER]
- **Sector**: [SECTOR_PLACEHOLDER]

## Compliance Standards Assessment

### OWASP Top 10 Compliance
[OWASP_ASSESSMENT_PLACEHOLDER]

### PCI DSS Requirements
[PCI_DSS_ASSESSMENT_PLACEHOLDER]

### SOC 2 Controls
[SOC2_ASSESSMENT_PLACEHOLDER]

## Critical Findings
[CRITICAL_FINDINGS_PLACEHOLDER]

## High Priority Findings
[HIGH_PRIORITY_FINDINGS_PLACEHOLDER]

## Medium Priority Findings
[MEDIUM_PRIORITY_FINDINGS_PLACEHOLDER]

## Remediation Roadmap
[REMEDIATION_ROADMAP_PLACEHOLDER]

## Compliance Status Summary
[COMPLIANCE_STATUS_PLACEHOLDER]

## Next Steps and Recommendations
[NEXT_STEPS_PLACEHOLDER]
```

**backend/templates/technical_operational_template.md**
```markdown
# Technical Security Assessment Report

## Technical Summary
[TECHNICAL_SUMMARY_PLACEHOLDER]

## Vulnerability Analysis

### Code Security Issues
[CODE_SECURITY_PLACEHOLDER]

### Dependency Vulnerabilities
[DEPENDENCY_VULNERABILITIES_PLACEHOLDER]

### Architecture Security Review
[ARCHITECTURE_REVIEW_PLACEHOLDER]

## Detailed Technical Findings

### Critical Vulnerabilities
[CRITICAL_TECHNICAL_FINDINGS_PLACEHOLDER]

### High-Risk Issues
[HIGH_RISK_TECHNICAL_FINDINGS_PLACEHOLDER]

### Medium-Risk Issues
[MEDIUM_RISK_TECHNICAL_FINDINGS_PLACEHOLDER]

## Security Testing Results
[SECURITY_TESTING_RESULTS_PLACEHOLDER]

## Technical Recommendations
[TECHNICAL_RECOMMENDATIONS_PLACEHOLDER]

## Implementation Guidelines
[IMPLEMENTATION_GUIDELINES_PLACEHOLDER]

## Security Monitoring and Alerting
[MONITORING_RECOMMENDATIONS_PLACEHOLDER]
```

**backend/templates/business_focused_template.md**
```markdown
# Business Security Risk Assessment

## Business Impact Summary
[BUSINESS_IMPACT_SUMMARY_PLACEHOLDER]

## Risk Assessment Overview
- **Overall Risk Level**: [OVERALL_RISK_PLACEHOLDER]
- **Business Critical Issues**: [CRITICAL_COUNT_PLACEHOLDER]
- **Financial Impact**: [FINANCIAL_IMPACT_PLACEHOLDER]

## Business Risk Analysis

### Customer Data Protection
[CUSTOMER_DATA_PROTECTION_PLACEHOLDER]

### Operational Risks
[OPERATIONAL_RISKS_PLACEHOLDER]

### Compliance Risks
[COMPLIANCE_RISKS_PLACEHOLDER]

### Reputation Risks
[REPUTATION_RISKS_PLACEHOLDER]

## Priority Action Items

### Immediate Actions Required (0-30 days)
[IMMEDIATE_ACTIONS_PLACEHOLDER]

### Short-term Improvements (1-3 months)
[SHORT_TERM_ACTIONS_PLACEHOLDER]

### Long-term Strategic Initiatives (3-12 months)
[LONG_TERM_ACTIONS_PLACEHOLDER]

## Investment Recommendations
[INVESTMENT_RECOMMENDATIONS_PLACEHOLDER]

## Business Continuity Considerations
[BUSINESS_CONTINUITY_PLACEHOLDER]

## Return on Security Investment
[ROI_ANALYSIS_PLACEHOLDER]
```

**backend/data/findings_dictionary.json**
```json
{
  "SQLI-UNSAN-INPUT": {
    "title": "SQL Injection via Unsanitized Input",
    "description": "The application constructs SQL queries using unsanitized user input, which can allow attackers to manipulate query logic and access unauthorized data.",
    "remediation_steps": [
      "Use parameterized queries or prepared statements",
      "Implement input validation and sanitization",
      "Use ORM frameworks that handle parameterization",
      "Apply principle of least privilege for database access"
    ],
    "compliance_mappings": {
      "OWASP_TOP_10": "A03:2021 – Injection",
      "CWE": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
      "PCI_DSS": "Requirement 6.2.4",
      "SOC2": "CC6.1"
    }
  },
  "XSS-UNESC-OUTPUT": {
    "title": "Cross-Site Scripting (XSS) via Unescaped Output",
    "description": "User-controlled data is rendered in web pages without proper encoding, allowing attackers to inject malicious scripts.",
    "remediation_steps": [
      "Implement output encoding/escaping",
      "Use Content Security Policy (CSP)",
      "Validate and sanitize all input",
      "Use secure templating engines"
    ],
    "compliance_mappings": {
      "OWASP_TOP_10": "A03:2021 – Injection",
      "CWE": "CWE-79: Improper Neutralization of Input During Web Page Generation",
      "PCI_DSS": "Requirement 6.2.4"
    }
  },
  "HARDCODED-SECRET": {
    "title": "Hardcoded Credentials",
    "description": "Sensitive credentials are hardcoded in the source code, making them accessible to anyone with code access.",
    "remediation_steps": [
      "Use environment variables for sensitive data",
      "Implement secure credential management systems",
      "Use encrypted configuration files",
      "Implement proper access controls"
    ],
    "compliance_mappings": {
      "OWASP_TOP_10": "A07:2021 – Identification and Authentication Failures",
      "CWE": "CWE-798: Use of Hard-coded Credentials",
      "SOC2": "CC6.1"
    }
  }
}
```

### Phase 3: Frontend Implementation

#### 3.1 Main Components

**frontend/src/App.js**
```jsx
import React, { useState } from 'react';
import UploadForm from './components/UploadForm';
import ReportSelector from './components/ReportSelector';
import './App.css';

function App() {
  const [scanId, setScanId] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  return (
    <div className="App">
      <header className="App-header">
        <h1>Security Documentation System</h1>
        <p>Automated security analysis and professional report generation</p>
      </header>
      <main>
        {!scanId ? (
          <UploadForm 
            onScanComplete={setScanId}
            isAnalyzing={isAnalyzing}
            setIsAnalyzing={setIsAnalyzing}
          />
        ) : (
          <ReportSelector 
            scanId={scanId} 
            onNewScan={() => setScanId(null)}
          />
        )}
      </main>
    </div>
  );
}

export default App;
```

**frontend/src/components/UploadForm.js**
```jsx
import React, { useState } from 'react';
import axios from 'axios';

const UploadForm = ({ onScanComplete, isAnalyzing, setIsAnalyzing }) => {
  const [githubUrl, setGithubUrl] = useState('');
  const [sectorHint, setSectorHint] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsAnalyzing(true);

    try {
      console.log('Starting analysis for:', githubUrl);
      const response = await axios.post('http://localhost:5000/api/analyze', {
        github_url: githubUrl,
        sector_hint: sectorHint
      });

      if (response.data.status === 'success') {
        console.log('Analysis completed, scan ID:', response.data.scan_id);
        onScanComplete(response.data.scan_id);
      }
    } catch (error) {
      console.error('Analysis failed:', error);
      setError('Analysis failed. Please check the repository URL and try again.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="upload-form">
      <h2>Repository Security Analysis</h2>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="githubUrl">GitHub Repository URL:</label>
          <input
            id="githubUrl"
            type="url"
            value={githubUrl}
            onChange={(e) => setGithubUrl(e.target.value)}
            required
            placeholder="https://github.com/user/repository"
            disabled={isAnalyzing}
          />
          <small>Note: Each analysis will overwrite the previous repository in PulledCode folder</small>
        </div>
        
        <div className="form-group">
          <label htmlFor="sectorHint">Sector/Industry Hint:</label>
          <select
            id="sectorHint"
            value={sectorHint}
            onChange={(e) => setSectorHint(e.target.value)}
            disabled={isAnalyzing}
          >
            <option value="">Select sector (optional)</option>
            <option value="Trading Website">Trading Website</option>
            <option value="Healthcare">Healthcare</option>
            <option value="Financial Services">Financial Services</option>
            <option value="E-commerce">E-commerce</option>
            <option value="SaaS Platform">SaaS Platform</option>
            <option value="Government">Government</option>
          </select>
        </div>

        {error && <div className="error-message">{error}</div>}

        <button type="submit" disabled={isAnalyzing || !githubUrl}>
          {isAnalyzing ? 'Analyzing Repository...' : 'Start Security Analysis'}
        </button>
        
        {isAnalyzing && (
          <div className="analysis-status">
            <p>🔍 Cloning repository to PulledCode folder...</p>
            <p>🤖 Running CodeT5 security analysis (standard model)...</p>
            <p>📊 Processing findings with knowledge base...</p>
          </div>
        )}
      </form>
    </div>
  );
};

export default UploadForm;
```

**frontend/src/components/ReportSelector.js**
```jsx
import React, { useState } from 'react';
import axios from 'axios';

const ReportSelector = ({ scanId, onNewScan }) => {
  const [selectedReportType, setSelectedReportType] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState('');

  const reportTypes = [
    {
      value: 'regulatory_compliance',
      label: 'Regulatory and Compliance Report',
      description: 'OWASP, PCI DSS, SOC 2 compliance assessment'
    },
    {
      value: 'technical_operational',
      label: 'Technical and Operational Report',
      description: 'Detailed technical findings and implementation guidelines'
    },
    {
      value: 'business_focused',
      label: 'Business-Focused Report',
      description: 'Risk assessment and business impact analysis'
    }
  ];

  const handleGenerateReport = async () => {
    if (!selectedReportType) {
      setError('Please select a report type');
      return;
    }

    setError('');
    setIsGenerating(true);

    try {
      console.log('Generating report:', selectedReportType, 'for scan:', scanId);
      
      const response = await axios.post('http://localhost:5000/api/generate-report', {
        scan_id: scanId,
        report_type: selectedReportType
      }, {
        responseType: 'blob' // Important for file download
      });

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `${selectedReportType}_report_${scanId}.docx`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

      console.log('Report downloaded successfully');
    } catch (error) {
      console.error('Report generation failed:', error);
      setError('Report generation failed. Please try again.');
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="report-selector">
      <h2>✅ Analysis Complete!</h2>
      <p>Scan ID: <code>{scanId}</code></p>
      <p>Repository has been analyzed using standard CodeT5 model and stored in PulledCode folder.</p>
      
      <h3>Select Report Type</h3>
      <div className="report-options">
        {reportTypes.map((type) => (
          <div key={type.value} className="report-option">
            <label>
              <input
                type="radio"
                name="reportType"
                value={type.value}
                checked={selectedReportType === type.value}
                onChange={(e) => setSelectedReportType(e.target.value)}
                disabled={isGenerating}
              />
              <div className="report-info">
                <h4>{type.label}</h4>
                <p>{type.description}</p>
              </div>
            </label>
          </div>
        ))}
      </div>

      {error && <div className="error-message">{error}</div>}

      <div className="action-buttons">
        <button 
          onClick={handleGenerateReport}
          disabled={!selectedReportType || isGenerating}
          className="generate-btn"
        >
          {isGenerating ? 'Generating Report with Gemini...' : 'Generate Report'}
        </button>
        
        <button 
          onClick={onNewScan}
          disabled={isGenerating}
          className="new-scan-btn"
        >
          Start New Analysis
        </button>
      </div>

      {isGenerating && (
        <div className="generation-status">
          <p>🤖 Loading template from templates folder...</p>
          <p>🧠 Gemini 2.5 Pro processing scan results...</p>
          <p>📄 Formatting professional report...</p>
        </div>
      )}
    </div>
  );
};

export default ReportSelector;
```

### Phase 4: Deployment Setup

#### 4.1 Environment Configuration

**backend/.env**
```
SECRET_KEY=your-secret-key-here
GEMINI_API_KEY=your-gemini-api-key-here
GITHUB_TOKEN=your-github-token-optional
FLASK_ENV=development

# Directory configurations (automatically handled by Flask config)
# PULLED_CODE_DIR will be set to backend/PulledCode/
# TEMPLATES_DIR will be set to backend/templates/
```

#### 4.2 Run Scripts

**backend/run.py**
```python
from app import create_app
import os

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

## Implementation Timeline

### Week 1: Foundation Setup
- [ ] Set up project structure with PulledCode and templates folders
- [ ] Configure development environment
- [ ] Implement basic Flask application with template directory configuration
- [ ] Create GitHub service for repository cloning (with overwrite functionality)
- [ ] Set up basic template files in templates/ directory

### Week 2: Analysis Engine
- [ ] Implement standard CodeT5 analyzer (note: fine-tuned version comes later)
- [ ] Create SCA analyzer for dependency scanning
- [ ] Build findings dictionary and knowledge base
- [ ] Test PulledCode directory overwrite mechanism
- [ ] Verify analysis pipeline with sample repositories

### Week 3: Template System & Report Generation
- [ ] Complete all three report templates (regulatory, technical, business)
- [ ] Integrate Gemini 2.5 Pro API for report generation
- [ ] Implement template loading and selection logic
- [ ] Test template-based report generation
- [ ] Add error handling for missing templates

### Week 4: Frontend Development & Integration
- [ ] Create React components with enhanced UI
- [ ] Implement file upload and repository input functionality
- [ ] Build report selection interface with template descriptions
- [ ] Add progress indicators and status messages
- [ ] Test complete frontend-backend integration

### Week 5: Testing, Refinement & Documentation
- [ ] End-to-end testing with multiple repositories
- [ ] Performance optimization and error handling improvements
- [ ] Document PulledCode folder behavior and template system
- [ ] Prepare for future fine-tuned CodeT5 integration
- [ ] Create deployment documentation

## Next Steps

1. **Start with Phase 1** - Set up the basic project structure with PulledCode and templates directories
2. **Test PulledCode Overwrite** - Verify that the directory is properly cleared and overwritten with each new repository
3. **Create Basic Templates** - Start with simple template files that Gemini can use for report generation
4. **Implement Standard CodeT5** - Use the base CodeT5 model first, then plan for fine-tuned version integration
5. **Test Template Integration** - Ensure Gemini can properly load and use templates from the templates folder
6. **Iterate and Improve** - Build incrementally and test each component

## Important Notes

### PulledCode Directory Behavior
- The `PulledCode` directory will be **completely cleared** and **overwritten** with each new repository analysis
- This ensures a clean slate for each analysis and prevents file conflicts
- Previous repository files are permanently removed when a new analysis starts
- Consider implementing backup/archive functionality if needed in the future

### Template System
- Templates are stored in `backend/templates/` directory as separate markdown files
- Gemini will load the appropriate template based on user selection
- Templates use placeholder syntax that Gemini will replace with actual data
- Easy to modify templates without changing code - just edit the template files

### CodeT5 Integration
- Currently using **standard CodeT5 model** from Salesforce/codet5-base
- The system is designed to easily swap in a fine-tuned version later
- Analysis results structure will remain the same regardless of model version
- Fine-tuned model integration planned for future enhancement

### Scalability Considerations
- Ensure proper error handling for network requests and file operations
- Consider implementing rate limiting for API calls (both GitHub and Gemini)
- Add comprehensive logging throughout the system for debugging and monitoring
- Plan for concurrent analysis if multiple users expected
- Monitor disk space usage in PulledCode directory

### Security Best Practices
- Store API keys in environment variables
- Implement proper input validation for GitHub URLs
- Consider sandboxing the PulledCode directory
- Add authentication if deploying to production
- Implement rate limiting to prevent abuse

This implementation guide provides a solid foundation for building your security documentation system with the specified requirements. The system is designed to be robust, scalable, and easily extensible for future enhancements like the fine-tuned CodeT5 model integration.