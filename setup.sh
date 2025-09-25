#!/bin/bash

# BB84 QKD System - Quick Setup for Existing Vite Project
echo "🚀 Setting up BB84 QKD System with existing Vite project..."

# Check if we're in the right place
if [ ! -d "frontend" ]; then
    echo "❌ Error: Please run this script from the directory containing your 'frontend' folder"
    exit 1
fi

# Create backend structure
echo "📁 Creating backend structure..."
mkdir -p backend/app/{models,services,routes,utils}
mkdir -p {docs,tests}

# Backend setup
echo "🐍 Setting up Python backend..."
cd backend

# Create __init__.py files
touch app/__init__.py
touch app/models/__init__.py  
touch app/services/__init__.py
touch app/routes/__init__.py
touch app/utils/__init__.py

# Create requirements.txt
cat > requirements.txt << 'EOF'
fastapi==0.104.1
uvicorn==0.24.0
python-socketio[asyncio_client]==5.9.0
qiskit==0.44.2
qiskit-aer==0.12.2
cryptography==41.0.7
python-multipart==0.0.6
pydantic==2.4.2
numpy==1.25.2
python-dotenv==1.0.0
EOF

# Create virtual environment and install dependencies
echo "📦 Creating Python virtual environment..."
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cd ..

# Frontend setup
echo "⚡ Setting up Vite frontend..."
cd frontend

# Install additional dependencies
echo "📦 Installing Node.js dependencies..."
npm install socket.io-client@4.7.2 axios@1.5.1 recharts@2.8.0 lucide-react@0.263.1 @headlessui/react@1.7.17

# Install Tailwind CSS
npm install -D tailwindcss@3.3.5 postcss@8.4.31 autoprefixer@10.4.16

# Initialize Tailwind if not already done
if [ ! -f "tailwind.config.js" ]; then
    npx tailwindcss init -p
fi

cd ..

# Create startup scripts
echo "📜 Creating startup scripts..."

cat > start-backend.sh << 'EOF'
#!/bin/bash
echo "🐍 Starting BB84 QKD Backend..."
cd backend
source venv/bin/activate
python -m uvicorn app.main:socket_app --reload --host 0.0.0.0 --port 8000
EOF

cat > start-frontend.sh << 'EOF'
#!/bin/bash
echo "⚡ Starting BB84 QKD Frontend (Vite)..."
cd frontend
npm run dev
EOF

chmod +x start-backend.sh start-frontend.sh

# Create the main development script
cat > dev.sh << 'EOF'
#!/bin/bash
echo "🚀 Starting BB84 QKD Development Environment (Vite)..."

cleanup() {
    echo "🛑 Shutting down..."
    kill $(jobs -p) 2>/dev/null
    exit 0
}
trap cleanup SIGINT SIGTERM

# Start backend
echo "📡 Starting backend server..."
cd backend
source venv/bin/activate
python -m uvicorn app.main:socket_app --reload --host 0.0.0.0 --port 8000 &
cd ..

sleep 3

# Start frontend
echo "⚡ Starting Vite frontend..."
cd frontend
npm run dev &
cd ..

echo "✅ Development environment running!"
echo "🌐 Frontend: http://localhost:3000"
echo "📡 Backend:  http://localhost:8000"
echo "📖 API Docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop all servers"

wait
EOF

chmod +x dev.sh

# Create environment file
cat > .env << 'EOF'
# Backend Configuration
BACKEND_HOST=localhost
BACKEND_PORT=8000
FRONTEND_URL=http://localhost:3000

# Security
SESSION_TIMEOUT_MINUTES=60
QBER_THRESHOLD=0.11

# Development
DEBUG=true
LOG_LEVEL=INFO
EOF

# Create .gitignore
cat > .gitignore << 'EOF'
# Python
venv/
__pycache__/
*.pyc
*.pyo
*.pyd
.env.local
.venv
env/
ENV/

# Node.js
node_modules/
npm-debug.log*
yarn-debug.log*
yarn-error.log*
.npm

# Vite
dist/
dist-ssr/
*.local

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Database
*.db
*.sqlite

# Temporary files
*.tmp
*.temp
.cache/
EOF

echo ""
echo "🎉 Setup complete!"
echo ""
echo "📋 Next Steps:"
echo "1. Copy all the component files to frontend/src/"
echo "2. Update your frontend/src files with the provided components"
echo "3. Update vite.config.ts, tailwind.config.js, and index.css"
echo "4. Run: ./dev.sh"
echo ""
echo "🔧 Manual Steps Needed:"
echo "1. Copy the React components to frontend/src/components/"
echo "2. Copy the services to frontend/src/services/"
echo "3. Copy the types to frontend/src/types/"
echo "4. Copy the backend code to backend/app/"
echo "5. Update your App.tsx with the provided code"
echo ""
echo "🚀 Then run: ./dev.sh to start both servers"
echo "🌐 Visit: http://localhost:3000"
