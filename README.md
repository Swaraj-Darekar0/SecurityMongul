# Security Documentation System

A comprehensive platform for automated security analysis of GitHub repositories and professional report generation.  
**Frontend:** React.js  
**Backend:** Python Flask

---

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/Swaraj-Darekar0/SecurityMongul.git
cd SecurityMongul
```

---

### 2. Backend Setup

```bash
cd backend
python -m venv venv
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
# source venv/bin/activate

pip install -r requirements.txt
```

- **Environment Variables:**  
  Create a `.env` file in the `backend` directory with the following (fill in your keys):

  ```
  SECRET_KEY=your-secret-key
  GEMINI_API_KEY=your-gemini-api-key
  FLASK_ENV=development
  ```

- **Run the Backend:**

  ```bash
  python run.py
  ```

  The backend will start at `http://localhost:5000`.

---

### 3. Frontend Setup

```bash
cd ../frontend
npm install
```

- **Run the Frontend:**

  ```bash
  npm start
  ```

  The frontend will start at `http://localhost:3000`.

---

## 🗂️ Project Structure

```
security-documentation-system/
├── frontend/         # React app
├── backend/          # Flask app
│   ├── PulledCode/   # Cloned repositories (overwritten per scan)
│   ├── templates/    # Report templates
│   ├── data/         # Findings and scan results
│   └── app/          # Flask modules
├── analysis_engine/  # Code analysis modules
└── docs/             # Documentation
```

---

## 📝 Usage

1. **Start both backend and frontend servers.**
2. **In the web UI:**
   - Enter a GitHub repository URL.
   - (Optional) Select a sector/industry.
   - Start analysis.
   - After analysis, select a report type and download the generated report.

---

## ⚠️ Notes

- Each new analysis **overwrites** the `PulledCode` directory.
- API keys (Gemini, etc.) must be set in your `.env` file.
- For Gemini integration, ensure your API key is valid and has access.

---

## 📚 Further Information

- See `security_doc_implementation_guide.md` for detailed architecture and implementation steps.
- Templates for reports are in `backend/templates/` and can be customized.

---

## 🛠️ Troubleshooting

- If you encounter issues with dependencies, ensure your Python and Node.js versions are up to date.
- For Windows users, use `venv\Scripts\activate` to activate the Python virtual environment.

---

## 📄 License

MIT License
