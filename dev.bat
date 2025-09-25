@echo off
echo 🚀 Starting BB84 QKD Development Environment (Vite)...

echo 📡 Starting backend server...
start "BB84 Backend" cmd /k "cd backend && call venv\Scripts\activate && set PYTHONPATH=%CD% && python -m uvicorn app.main:socket_app --reload --host 0.0.0.0 --port 8000 --log-level info"

timeout /t 3 /nobreak >nul

echo ⚡ Starting Vite frontend...
start "BB84 Frontend" cmd /k "cd frontend && npm run dev"

echo ✅ Development environment running!
echo 🌐 Frontend: http://localhost:5173
echo 📡 Backend:  http://localhost:8000
echo 📖 API Docs: http://localhost:8000/docs
echo.
echo Press any key to stop all servers
pause >nul
