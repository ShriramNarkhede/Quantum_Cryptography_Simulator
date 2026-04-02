#!/bin/bash

# BB84 QKD System - PQC Installation Script
# This script installs Post-Quantum Cryptography dependencies

echo "🔐 BB84 QKD System - Installing Post-Quantum Cryptography..."

# Check if we're in the backend directory
if [ ! -f "requirements.txt" ]; then
    echo "❌ Error: Please run this script from the backend directory"
    exit 1
fi

# Check Python version
python_version=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
echo "🐍 Python version: $python_version"

# Install system dependencies (Ubuntu/Debian)
echo "📦 Installing system dependencies..."
if command -v apt-get &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y build-essential cmake libssl-dev libffi-dev
    echo "✅ System dependencies installed"
else
    echo "⚠️  Please install build-essential, cmake, libssl-dev, and libffi-dev manually"
fi

# Install Python dependencies
echo "📦 Installing Python PQC dependencies..."

# Try to install liboqs-python (primary PQC library)
echo "🔧 Installing liboqs-python..."
if pip3 install liboqs-python==0.8.0; then
    echo "✅ liboqs-python installed successfully"
    LIBOQS_INSTALLED=true
else
    echo "⚠️  liboqs-python installation failed, trying alternative..."
    LIBOQS_INSTALLED=false
fi

# Try to install pqcrypto (pure Python fallback)
echo "🔧 Installing pqcrypto..."
if pip3 install pqcrypto==0.20.1; then
    echo "✅ pqcrypto installed successfully"
    PQCRYPTO_INSTALLED=true
else
    echo "⚠️  pqcrypto installation failed"
    PQCRYPTO_INSTALLED=false
fi

# Install other requirements
echo "📦 Installing other requirements..."
pip3 install -r requirements.txt

# Test PQC installation
echo "🧪 Testing PQC installation..."
python3 -c "
try:
    import oqs
    print('✅ liboqs-python is working')
    LIBOQS_WORKING = True
except ImportError:
    print('❌ liboqs-python not working')
    LIBOQS_WORKING = False

try:
    import pqcrypto
    print('✅ pqcrypto is working')
    PQCRYPTO_WORKING = True
except ImportError:
    print('❌ pqcrypto not working')
    PQCRYPTO_WORKING = False

if LIBOQS_WORKING or PQCRYPTO_WORKING:
    print('🎉 PQC installation successful!')
else:
    print('⚠️  PQC libraries not working - will use demo mode')
"

echo ""
echo "🔐 PQC Installation Summary:"
echo "=========================="
if [ "$LIBOQS_INSTALLED" = true ]; then
    echo "✅ liboqs-python: Installed"
else
    echo "❌ liboqs-python: Failed"
fi

if [ "$PQCRYPTO_INSTALLED" = true ]; then
    echo "✅ pqcrypto: Installed"
else
    echo "❌ pqcrypto: Failed"
fi

echo ""
echo "🚀 Next steps:"
echo "1. Start the backend server: python3 -m uvicorn app.main:socket_app --reload"
echo "2. Start BB84 simulation with hybrid mode enabled"
echo "3. Check PQC status in the frontend interface"

if [ "$LIBOQS_INSTALLED" = false ] && [ "$PQCRYPTO_INSTALLED" = false ]; then
    echo ""
    echo "⚠️  Warning: No PQC libraries installed successfully."
    echo "   The system will run in demo mode with simulated PQC."
    echo "   For real PQC, please install liboqs-python manually:"
    echo "   https://github.com/open-quantum-safe/liboqs-python"
fi

echo ""
echo "🎯 PQC Features Available:"
echo "- Kyber512 KEM (Key Encapsulation Mechanism)"
echo "- Dilithium2 Digital Signatures"
echo "- Hybrid BB84 + PQC key derivation"
echo "- Real-time PQC key exchange"
echo "- PQC signature verification"

echo ""
echo "📚 Documentation:"
echo "- NIST PQC Standards: https://csrc.nist.gov/projects/post-quantum-cryptography"
echo "- liboqs: https://github.com/open-quantum-safe/liboqs"
echo "- Kyber: https://pq-crystals.org/kyber/"
echo "- Dilithium: https://pq-crystals.org/dilithium/"

echo ""
echo "✨ Installation complete!"











