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
            print("[AnalysisService] Starting analysis...")
            # Generate unique scan ID
            scan_id = str(uuid.uuid4())
            print(f"[AnalysisService] Generated Scan ID: {scan_id}")
            
            # Perform CodeT5 analysis
            print("[AnalysisService] Running CodeT5 analysis...")
            code_findings = self.codet5_analyzer.analyze(repo_path)
            print(f"[AnalysisService] CodeT5 found {len(code_findings)} findings.")
            
            # Perform SCA analysis
            print("[AnalysisService] Running SCA analysis...")
            dependency_findings = self.sca_analyzer.analyze(repo_path)
            print(f"[AnalysisService] SCA found {len(dependency_findings)} findings.")
            
            # Combine findings
            all_findings = code_findings + dependency_findings
            
            # Enrich findings with knowledge base
            print("[AnalysisService] Enriching findings...")
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
            print("[AnalysisService] Saving scan results...")
            self._save_scan_results(scan_id, scan_results)
            print("[AnalysisService] Analysis finished successfully.")
            return scan_results
            
        except Exception as e:
            print(f"[AnalysisService] ERROR: {e}")
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
