#!/bin/bash
echo "🐍 Starting BB84 QKD Backend..."
cd backend
source venv/bin/activate
export PYTHONPATH=$(pwd)
python3 -m uvicorn app.main:socket_app --reload --host 0.0.0.0 --port 8000 --log-level info
