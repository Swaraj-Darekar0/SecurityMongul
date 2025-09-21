from flask import Blueprint, request, jsonify, send_file
from app.services.github_service import GitHubService
from app.services.analysis_service import AnalysisService
from app.services.report_service import ReportService
import os

main_bp = Blueprint('main', __name__)

@main_bp.route('/api/analyze', methods=['POST'])
def analyze_repository():
    try:
        print("[/api/analyze] Received request")
        data = request.get_json()
        github_url = data.get('github_url')
        sector_hint = data.get('sector_hint', '')
        print(f"[/api/analyze] GitHub URL: {github_url}, Sector: {sector_hint}")
        
        # Phase 1: Input & Analysis
        print("[/api/analyze] Phase 1: Cloning repository...")
        github_service = GitHubService()
        repo_path = github_service.clone_repository(github_url)
        print(f"[/api/analyze] Repository cloned to: {repo_path}")
        
        # Phase 2: Data Processing & Storage
        print("[/api/analyze] Phase 2: Starting codebase analysis...")
        analysis_service = AnalysisService()
        scan_results = analysis_service.analyze_codebase(repo_path, sector_hint)
        print(f"[/api/analyze] Analysis complete. Scan ID: {scan_results.get('scan_id')}")
        
        return jsonify({
            'status': 'success',
            'scan_id': scan_results['scan_id'],
            'message': 'Analysis completed successfully'
        })
    
    except Exception as e:
        print(f"[/api/analyze] ERROR: {e}")
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
