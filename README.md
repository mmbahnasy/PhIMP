# AIMS Pharmacy Incident Management
AIMS Pharmacy Incident Management Platform

A simple pharmacy incident management portal for documenting medication incidents, tracking Continuous Quality Improvement (CQI) action plans, and preparing anonymized NIDR submissions.

This project is a work in progress and is not yet configured to submit live data to the National Incident Data Repository for Community Pharmacies (NIDR).

CQI action plans are saved in `action_plans/action_plans.json` and loaded when the action-plan management page is opened. This file is created when the first plan is saved and is excluded from Git because it contains local operational data.

Required libraries:
- Flask
- PyYAML
- Requests

To run the application:
1. Open a terminal in the project folder.
2. Install the dependencies: `pip install flask pyyaml requests`
3. Start the app: `python main.py`
4. Open http://127.0.0.1:5000 in a browser.
