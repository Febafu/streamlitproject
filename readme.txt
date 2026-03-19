readme.txt -- Academy Project: Phishing URLs
=============================================

WHAT IT DOES
------------
Two-file Python pipeline that collects, processes, and analyses
phishing/malware URL data from URLhaus and ThreatFox, producing
4 findings with charts and an interactive Streamlit dashboard.

FILES
-----
  phishing_analysis.py  -- Main script: collect -> process -> analyse -> report
  streamlit_app.py      -- Interactive dashboard (ThreatScope Observatory)
  readme.txt            -- This file
  output/               -- Created automatically
    urlhaus_raw.csv, threatfox_raw.csv, combined.csv
    fig1-4 PNG charts
    summary_findings.txt

HOW TO RUN
----------
1. pip install requests pandas matplotlib plotly streamlit
2. python phishing_analysis.py
3. streamlit run streamlit_app.py  (opens at http://localhost:8501)

Note: If school network blocks APIs, synthetic data is used automatically.

DATA SOURCES
------------
URLhaus: CSV download + JSON API (no key needed)
ThreatFox: JSON API (no key needed)

FOUR FINDINGS
-------------
1. URL Status Distribution -- % still online vs taken down
2. TLD Distribution -- attacker TLD preferences
3. Temporal Activity -- burst detection, daily rates, hourly heatmap
4. Malware Families -- top threat tags, sunburst drill-down

BONUS FEATURES (dashboard only)
--------------------------------
URL Inspector, Risk Gauge, Treemap, Sunburst, Hourly Heatmap,
Cross-feed Overlap, Live Threat Ticker, Full filtering, CSV export

HOW TO DEPLOY
-------------
Option A (FREE, recommended): Streamlit Cloud
  1. Push to GitHub (include requirements.txt with: requests pandas plotly streamlit)
  2. Go to streamlit.io/cloud -> New App -> connect repo -> Deploy
  3. Live at https://YOURAPP.streamlit.app

Option B: ngrok (share localhost)
  1. streamlit run streamlit_app.py
  2. ngrok http 8501  -> share the https URL

Option C: Same network
  streamlit run streamlit_app.py --server.address 0.0.0.0
  Others access: http://YOUR_LOCAL_IP:8501

Option D: Replit
  Upload files, add requirements, run:
  streamlit run streamlit_app.py --server.port 8080

DEPENDENCIES
------------
Python >= 3.9
requests, pandas, matplotlib, plotly, streamlit
