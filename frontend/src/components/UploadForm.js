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
