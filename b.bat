@echo off
echo 🐍 Starting BB84 QKD Backend...
cd backend
call venv\Scripts\activate
set PYTHONPATH=%CD%
python -m uvicorn app.main:socket_app --reload --host 0.0.0.0 --port 8000 --log-level info
