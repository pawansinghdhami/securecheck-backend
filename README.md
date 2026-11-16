# SecureCheck Backend

SecureCheck Backend is the API layer for a cybersecurity audit platform designed to help businesses assess website security, identify weaknesses, and monitor improvements over time. Built with FastAPI, it validates domains, inspects HTTPS and header security, evaluates cookie protections, and stores scan history for reporting and comparison.

## What it does

- Handles user authentication and session management
- Validates and normalizes target domains before scanning
- Checks HTTPS configuration and redirect security
- Reviews security headers and cookie protections
- Runs vulnerability and risk scoring workflows for a target site
- Stores historical scan data and supports result comparison
- Exposes APIs for frontend dashboards and reporting tools

## Core features

- Signup and login with secure password hashing
- Session-based access control for authenticated users
- Domain reachability and security validation
- Security score generation and summary insights
- Scan history and comparison endpoints
- PostgreSQL-backed persistence with SQLAlchemy ORM

## Tech stack

- Python
- FastAPI
- SQLAlchemy
- PostgreSQL
- Pydantic

## Getting started

Create and activate a virtual environment, then install dependencies:

```bash
python -m venv venv
venv\Scripts\activate
pip install fastapi uvicorn sqlalchemy psycopg pydantic python-dotenv
```

Run the API locally:

```bash
uvicorn main:app --reload
```

The API will be available at:

```text
http://localhost:8000
```

## Useful endpoints

- `GET /health` — health check
- `POST /auth/signup` — create a user
- `POST /auth/login` — user login
- `POST /scan` — run a website security scan
- `GET /scans/{domain}` — view scan history for a domain
- `GET /scans/id/{scan_id}` — fetch a specific scan result
- `GET /scans/id/{scan_id}/compare` — compare scan results over time

## Project intent

SecureCheck aims to make website security assessments easier, more actionable, and more transparent for businesses that need to protect customer data and reduce digital risk.
