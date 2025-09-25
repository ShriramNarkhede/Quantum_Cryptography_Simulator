# BB84 Quantum Key Distribution (QKD) System

This project is a full-stack simulation and demonstration platform for the BB84 Quantum Key Distribution protocol. It allows users to experience quantum-secure key exchange, simulate eavesdropping attacks, and use the generated keys for secure chat—all through an interactive web interface.

## Project Overview

The BB84 QKD System provides a hands-on environment to learn, experiment, and visualize the principles of quantum cryptography. It consists of a Python backend (using FastAPI, Qiskit, and Socket.IO) and a modern React frontend (with Vite, Tailwind CSS, and real-time visualization). The system supports multiple user roles (Alice, Bob, Eve), session management, and real-time updates of the quantum key exchange process.

**Key Features:**
- Simulate the BB84 quantum key distribution protocol with adjustable parameters
- Visualize the quantum transmission, basis choices, sifting, and QBER (Quantum Bit Error Rate)
- Support for an eavesdropper (Eve) to demonstrate quantum attack detection
- Real-time secure chat using the established quantum key
- Multi-user session management (join as Alice, Bob, or Eve)
- Modern, responsive web interface with live progress and alerts

**Architecture:**
- **Backend:** Python FastAPI app with Qiskit for quantum simulation, Socket.IO for real-time events, and REST endpoints for session management
- **Frontend:** React (TypeScript) app using Vite, Tailwind CSS, and Socket.IO-client for real-time communication and visualization
- **Communication:** The frontend and backend communicate via REST (for setup) and Socket.IO (for real-time simulation and chat)

## Backend Technology Stack

- **FastAPI**: Provides the REST API endpoints for session management, health checks, and other backend services. It also serves as the main web server.
- **Socket.IO (python-socketio)**: Enables real-time, bidirectional communication between the backend and frontend. Used for live simulation progress, chat messages, and event notifications (e.g., Eve detection).
- **Qiskit**: Simulates the quantum circuits and operations required for the BB84 protocol, including qubit preparation, measurement, and quantum state manipulation.
- **Qiskit Aer**: Provides high-performance quantum circuit simulation for the BB84 protocol.
- **Cryptography**: Used for secure key handling and encryption of chat messages.
- **Pydantic**: For data validation and serialization of API models.
- **Uvicorn**: ASGI server to run the FastAPI application with high performance and async support.
- **NumPy, SciPy**: Used for numerical operations and data processing in the simulation.

## Frontend Technology Stack

- **React (TypeScript)**: The main framework for building the interactive user interface and managing application state.
- **Vite**: Provides fast development server and build tooling for the React app.
- **Tailwind CSS**: Utility-first CSS framework for rapid and responsive UI design.
- **Socket.IO-client**: Handles real-time communication with the backend for simulation progress, chat, and event updates.
- **Axios**: For making REST API calls to the backend (e.g., session creation, health checks).
- **Recharts**: Used for data visualization, such as plotting QBER and simulation progress.
- **Lucide-react**: Provides modern iconography for the UI.

## User Flow

1. **Session Creation**: A user creates a new QKD session via the frontend. The backend generates a unique session ID and manages session state.
2. **Joining a Session**: Users can join an existing session as Alice, Bob, or Eve. Each role has a specific function:
   - **Alice**: Initiates the BB84 protocol and prepares quantum bits.
   - **Bob**: Receives and measures the quantum bits.
   - **Eve**: (Optional) Acts as an eavesdropper to simulate attacks and test quantum security.
3. **Running the BB84 Simulation**: Once Alice and Bob are present, Alice can start the BB84 protocol. The backend simulates the quantum transmission, basis selection, sifting, and QBER calculation. If Eve is present, her attack is simulated in real time.
4. **Real-Time Visualization**: The frontend displays live progress of the protocol, including quantum state transmission, QBER, and detection of eavesdropping.
5. **Key Establishment**: If the QBER is below the threshold, a secure session key is established and shared between Alice and Bob.
6. **Secure Chat**: Users can use the established quantum key to send encrypted messages in real time. If Eve is detected, the session is terminated and users are alerted.

## Setup and Running the Project

### Prerequisites
- Python 3.10+
- Node.js (v18+ recommended) and npm

### Backend Setup
1. Navigate to the `backend` directory:
   ```sh
   cd backend
   ```
2. Create a virtual environment and activate it:
   - On Windows:
     ```sh
     python -m venv venv
     venv\Scripts\activate
     ```
   - On Linux/macOS:
     ```sh
     python3 -m venv venv
     source venv/bin/activate
     ```
3. Install Python dependencies:
   ```sh
   pip install -r requirements.txt
   ```
4. Start the backend server:
   ```sh
   uvicorn app.main:socket_app --reload --host 0.0.0.0 --port 8000
   ```

### Frontend Setup
1. Navigate to the `frontend` directory:
   ```sh
   cd frontend
   ```
2. Install Node.js dependencies:
   ```sh
   npm install
   ```
3. Start the frontend development server:
   ```sh
   npm run dev
   ```
   The app will be available at [http://localhost:5173](http://localhost:5173).

### Quick Start Scripts
- Use `start-backend.bat` or `start-backend.sh` to start the backend.
- Use `start-frontend.bat` or `start-frontend.sh` to start the frontend.

---
