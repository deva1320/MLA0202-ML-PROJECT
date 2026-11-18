# PhishGuard AI — Complete Deployment Guide (Vercel + Render)

This guide provides step-by-step instructions to deploy **PhishGuard AI** with:
- **Backend on Render:** FastAPI Python web service running Scikit-learn Decision Tree & Random Forest models.
- **Frontend on Vercel:** Modern, responsive React + Vite web dashboard.

---

## Architecture Diagram

```
+------------------------------------+           +------------------------------------+
|         Vercel (Frontend)          |           |          Render (Backend)          |
|   https://<your-app>.vercel.app    |  HTTP(S)  |  https://<your-api>.onrender.com   |
|                                    | --------> |                                    |
| - React 19 + Vite Dashboard        |    REST   | - FastAPI + Python 3.11            |
| - URL Safety Scanner UI            |    API    | - Decision Tree & Random Forest    |
| - 18-Feature Analysis Matrix       |           | - Canonical Feature Extractor      |
| - 6-Stage Process Demonstration    | <-------- | - Audit PDF Report Generator       |
| - Model Comparison Benchmark UI    |   JSON/   | - Scikit-learn Pipeline Inference  |
+------------------------------------+    PDF    +------------------------------------+
```

---

## Part 1: Deploy Backend to Render (Free Tier)

### Step 1: Sign in to Render
1. Go to [https://render.com](https://render.com) and sign in (using GitHub).

### Step 2: Create a New Web Service
1. Click the **New +** button in the dashboard and select **Web Service**.
2. Connect your GitHub repository: `deva1320/MLA0202-ML-PROJECT`.

### Step 3: Configure Service Settings
Fill in the configuration fields:

| Setting | Value |
|---|---|
| **Name** | `phishguard-api` (or your preferred name) |
| **Region** | Oregon (US West) or Frankfurt (EU) |
| **Branch** | `main` |
| **Root Directory** | *(Leave blank)* |
| **Runtime** | `Python 3` |
| **Build Command** | `pip install -r requirements.txt` |
| **Start Command** | `uvicorn backend.main:app --host 0.0.0.0 --port $PORT` |
| **Instance Type** | `Free` |

### Step 4: Environment Variables (Optional)
In the **Environment Variables** section, you can add:
- `PYTHON_VERSION`: `3.11.9`

### Step 5: Deploy
1. Click **Deploy Web Service**.
2. Wait 2-3 minutes for dependencies (`scikit-learn`, `fastapi`, `fpdf2`, etc.) to install and the service to launch.
3. Once the log says `Application startup complete`, copy your live backend URL (e.g. `https://phishguard-api.onrender.com`).
4. Test in your browser: `https://phishguard-api.onrender.com/api/health` &rarr; should return `{"status": "healthy"}`.
5. Interactive API Swagger docs are available at: `https://phishguard-api.onrender.com/docs`.

---

## Part 2: Deploy Frontend to Vercel (Free Tier)

### Step 1: Sign in to Vercel
1. Go to [https://vercel.com](https://vercel.com) and sign in with GitHub.

### Step 2: Import Project
1. In the Vercel dashboard, click **Add New...** &rarr; **Project**.
2. Select your repository: `deva1320/MLA0202-ML-PROJECT`.

### Step 3: Configure Project Settings
In the configuration screen:

| Setting | Value |
|---|---|
| **Framework Preset** | `Vite` |
| **Root Directory** | Click **Edit** and select **`frontend`** |
| **Build Command** | `npm run build` *(auto-detected)* |
| **Output Directory** | `dist` *(auto-detected)* |

### Step 4: Add Backend API Environment Variable
Under **Environment Variables**, add:
* **Key:** `VITE_API_URL`
* **Value:** `https://phishguard-api.onrender.com` *(Paste your Render backend URL from Part 1 without trailing slash)*

### Step 5: Deploy
1. Click **Deploy**.
2. Vercel will install npm packages and build the optimized production assets in ~30 seconds.
3. Click your live Vercel URL (e.g. `https://mla0202-ml-project.vercel.app` or `https://phishguard-ai.vercel.app`).

---

## Part 3: Verification & Live Testing

1. Open your live Vercel frontend URL in Google Chrome or Microsoft Edge.
2. The bottom of the sidebar will display: `Render API: Connected` (with a green dot).
3. Test a legitimate URL (e.g. `https://en.wikipedia.org/wiki/Phishing`):
   * Decision Tree: `Likely Legitimate`
   * Random Forest: `Likely Legitimate`
   * Verdict: `LIKELY LEGITIMATE`
4. Test a phishing lure (e.g. `http://192.168.1.105/webscr/login.php`):
   * Decision Tree: `Potential Phishing`
   * Random Forest: `Potential Phishing`
   * Verdict: `POTENTIAL PHISHING`
5. Click **Download Scan Report (PDF)** to verify instant generation of the cybersecurity PDF report.
6. Browse the remaining tabs:
   * **URL Analysis:** 18-feature cards and parsed RFC 3986 anatomy.
   * **Analysis Process:** 6-stage connected demonstration workflow.
   * **Model Comparison:** 63 held-out test benchmarks, confusion matrices, and RF Gini importances.
   * **About Project:** Architecture, CART vs. RF, and dataset provenance.

---

## Note on Render Free Tier Spin-Down
Render's free tier spins down web services after 15 minutes of inactivity. When visiting the site after an idle period, the first request may take 30-40 seconds to wake up the backend. Subsequent requests respond instantly in under 50ms.
