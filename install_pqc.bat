@echo off
REM BB84 QKD System - PQC Installation Script for Windows
REM This script installs Post-Quantum Cryptography dependencies

echo 🔐 BB84 QKD System - Installing Post-Quantum Cryptography...

REM Check if we're in the backend directory
if not exist "backend\requirements.txt" (
    echo ❌ Error: Please run this script from the project root directory
    pause
    exit /b 1
)

REM Check Python version
python --version
if errorlevel 1 (
    echo ❌ Error: Python not found. Please install Python 3.8+
    pause
    exit /b 1
)

echo 🐍 Python found

REM Install Python dependencies
echo 📦 Installing Python PQC dependencies...

REM Try to install liboqs-python (primary PQC library)
echo 🔧 Installing liboqs-python...
pip install liboqs-python==0.8.0
if errorlevel 1 (
    echo ⚠️  liboqs-python installation failed, trying alternative...
    set LIBOQS_INSTALLED=false
) else (
    echo ✅ liboqs-python installed successfully
    set LIBOQS_INSTALLED=true
)

REM Try to install pqcrypto (pure Python fallback)
echo 🔧 Installing pqcrypto...
pip install pqcrypto==0.20.1
if errorlevel 1 (
    echo ⚠️  pqcrypto installation failed
    set PQCRYPTO_INSTALLED=false
) else (
    echo ✅ pqcrypto installed successfully
    set PQCRYPTO_INSTALLED=true
)

REM Install other requirements
echo 📦 Installing other requirements...
cd backend
pip install -r requirements.txt
cd ..

REM Test PQC installation
echo 🧪 Testing PQC installation...
python -c "try: import oqs; print('✅ liboqs-python is working'); LIBOQS_WORKING = True; except ImportError: print('❌ liboqs-python not working'); LIBOQS_WORKING = False; try: import pqcrypto; print('✅ pqcrypto is working'); PQCRYPTO_WORKING = True; except ImportError: print('❌ pqcrypto not working'); PQCRYPTO_WORKING = False; print('🎉 PQC installation successful!' if (LIBOQS_WORKING or PQCRYPTO_WORKING) else '⚠️  PQC libraries not working - will use demo mode')"

echo.
echo 🔐 PQC Installation Summary:
echo ==========================
if "%LIBOQS_INSTALLED%"=="true" (
    echo ✅ liboqs-python: Installed
) else (
    echo ❌ liboqs-python: Failed
)

if "%PQCRYPTO_INSTALLED%"=="true" (
    echo ✅ pqcrypto: Installed
) else (
    echo ❌ pqcrypto: Failed
)

echo.
echo 🚀 Next steps:
echo 1. Start the backend server: cd backend ^&^& python -m uvicorn app.main:socket_app --reload
echo 2. Start BB84 simulation with hybrid mode enabled
echo 3. Check PQC status in the frontend interface

if "%LIBOQS_INSTALLED%"=="false" if "%PQCRYPTO_INSTALLED%"=="false" (
    echo.
    echo ⚠️  Warning: No PQC libraries installed successfully.
    echo    The system will run in demo mode with simulated PQC.
    echo    For real PQC, please install liboqs-python manually:
    echo    https://github.com/open-quantum-safe/liboqs-python
)

echo.
echo 🎯 PQC Features Available:
echo - Kyber512 KEM (Key Encapsulation Mechanism)
echo - Dilithium2 Digital Signatures
echo - Hybrid BB84 + PQC key derivation
echo - Real-time PQC key exchange
echo - PQC signature verification

echo.
echo 📚 Documentation:
echo - NIST PQC Standards: https://csrc.nist.gov/projects/post-quantum-cryptography
echo - liboqs: https://github.com/open-quantum-safe/liboqs
echo - Kyber: https://pq-crystals.org/kyber/
echo - Dilithium: https://pq-crystals.org/dilithium/

echo.
echo ✨ Installation complete!
pause











