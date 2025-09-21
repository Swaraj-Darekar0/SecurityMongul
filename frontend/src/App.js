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
