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
