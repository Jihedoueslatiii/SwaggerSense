# 🚀 SwaggeSsense  API Tester  
AI-Powered API Scenario Generator & Testing UI

Nexus API Tester is an MVP tool that lets you:
- Load a Swagger/OpenAPI URL
- Discover and list API endpoints
- Generate test scenarios using 
- Display results and analytics in a modern dashboard

---

## 🧱 Project Architecture

📂 project-root
├── app.py # Flask backend with AI logic
├── index.html # Frontend UI (standalone page)
├── requirements.txt # Dependencies list
└── README.md # Documentation

yaml
Copy code

**Backend (Flask)**
- Fetches and parses OpenAPI docs
- Sends endpoint structure to ai
- Returns AI-generated scenario list to frontend

**Frontend**
- Single-page UI
- Endpoint selection sidebar
- Test display and statistics grid

---

## 🧰 Tech Stack

**Backend**
- Python 3.x
- Flask
- flask_cors
- requests
- Google Generative AI SDK 

**Frontend**
- HTML + Inline CSS + JavaScript (fetch)

---

## ⚙️ Installation & Setup

### 1️⃣ Clone the Project
```bash
git clone <your_repo_url>
cd <project_folder>
2️⃣ Install Python Libraries
bash
Copy code
pip install -r requirements.txt
3️⃣ Configure API Key
Add your ai  key (one method):

➡ Option A — Export environment variable:

bash
Copy code
export AI_API_KEY="your_key_here"
➡ Option B — Add directly in code (not recommended):

ini
Copy code
AI_API_KEY = "your_key"
4️⃣ Start the Backend Server
bash
Copy code
python app.py
Flask will run at:

arduino
Copy code
http://localhost:5000
5️⃣ Open the UI
Open index.html in your browser
(no framework/build needed)

▶️ Usage Guide
Start Flask server

Open index.html

Enter your API Swagger/OpenAPI URL
Ex:

bash
Copy code
http://localhost:8089/v3/api-docs
Load endpoints

Select any route

Click Execute Tests

View:

AI-generated test scenarios

Result status (pass/fail)

Response details & execution time

Security warnings

🤖 How AI Works
Gemini analyzes:

HTTP method

Request body schema

Params & constraints

Endpoint purpose

It generates:

Happy path tests

Validation tests

Negative/error cases

Security exploits (SQLi, XSS)

Edge cases (null/empty, wrong types)

📌 Features
✔ Extracts every endpoint automatically
✔ Uses swagger spec dynamically — no manual config
✔ Real-time scenario generation
✔ Visual dashboard
✔ Status counts (passed/failed/security)
✔ Auth token support
✔ Handles GET, POST, PUT, PATCH, DELETE

