# BB84-QKD System Architecture

## Architecture Overview
- Hybrid quantum/classical platform that pairs BB84 quantum key distribution with Kyber/Dilithium PQC to establish resilient session keys.
- Backend implemented with FastAPI + Socket.IO orchestrates simulations, cryptography, and real-time messaging.
- React/Vite frontend delivers visualization, chat, and monitoring dashboards over HTTPS and WebSockets.

## System Flow Diagram

```
                    ┌─────────────────────┐
                    │  System Startup     │
                    │  (Backend + Frontend)│
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Initialize Services │
                    │  - BB84 Engine      │
                    │  - Crypto Service   │
                    │  - PQC Service      │
                    │  - Eve Module       │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Frontend Connects  │
                    │  (WebSocket + REST) │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Create Session     │
                    │  (POST /sessions)   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Session State:     │
                    │      CREATED        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Users Join Session │
                    │  - Alice (Sender)   │
                    │  - Bob (Receiver)   │
                    │  - [Optional] Eve   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Session State:      │
                    │       ACTIVE        │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Start BB84 Protocol│
                    │  (User Initiated)   │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │  Session State:     │
                    │   BB84_RUNNING      │
                    └──────────┬──────────┘
                               │
                               ▼
        ┌──────────────────────────────────────┐
        │  BB84 Protocol Execution              │
        │  ┌────────────────────────────────┐  │
        │  │ 1. Alice generates bits/bases  │  │
        │  │ 2. Prepare quantum states |ψ⟩ │  │
        │  │ 3. [If Eve] Intercept & measure│  │
        │  │ 4. Bob measures qubits          │  │
        │  │ 5. Public basis comparison     │  │
        │  │ 6. Sifting (keep matching)     │  │
        │  │ 7. QBER calculation            │  │
        │  └────────────────────────────────┘  │
        └──────────┬───────────────────────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
        ▼                     ▼
┌───────────────┐    ┌───────────────┐
│ QBER ≤ 11%    │    │ QBER > 11%    │
│ (Secure)      │    │ (Compromised) │
└───────┬───────┘    └───────┬───────┘
        │                     │
        │                     ▼
        │            ┌─────────────────┐
        │            │ Session State:  │
        │            │  COMPROMISED    │
        │            └────────┬────────┘
        │                     │
        │                     ▼
        │            ┌─────────────────┐
        │            │ Terminate Session│
        │            │ Clear Keys      │
        │            └────────┬────────┘
        │                     │
        │                     ▼
        │            ┌─────────────────┐
        │            │ Session State:   │
        │            │   TERMINATED     │
        │            └─────────────────┘
        │
        ▼
┌───────────────────────┐
│ Privacy Amplification │
│ (SHA-256 hash)        │
└───────────┬───────────┘
            │
            ▼
┌───────────────────────┐
│ BB84 Key Derived      │
│ (32 bytes)            │
└───────────┬───────────┘
            │
            ▼
    ┌───────────────┐
    │ Hybrid Mode?  │
    └───┬───────┬───┘
    No  │       │ Yes
        │       │
        │       ▼
        │ ┌─────────────────────┐
        │ │ PQC Key Exchange    │
        │ │ (Kyber KEM)         │
        │ └──────────┬──────────┘
        │            │
        │            ▼
        │ ┌─────────────────────┐
        │ │ Combine Keys:       │
        │ │ BB84 || PQC         │
        │ └──────────┬──────────┘
        │            │
        └────────────┴──────────┐
                                 │
                                 ▼
                    ┌─────────────────────┐
                    │ HKDF Key Derivation  │
                    │ - key_stream_seed    │
                    │ - key_mac           │
                    │ - key_file          │
                    └──────────┬──────────┘
                               │
                               ▼
                    ┌─────────────────────┐
                    │ Session State:       │
                    │  KEY_ESTABLISHED     │
                    └──────────┬──────────┘
                               │
                               ▼
        ┌──────────────────────────────────────┐
        │  Secure Communication Phase          │
        │  ┌────────────────────────────────┐  │
        │  │ Message Encryption:             │  │
        │  │ - Derive OTP stream (seq_no)   │  │
        │  │ - XOR plaintext                │  │
        │  │ - Compute HMAC-SHA3            │  │
        │  │ - Broadcast via WebSocket      │  │
        │  │                                 │  │
        │  │ File Encryption:                │  │
        │  │ - XChaCha20-Poly1305           │  │
        │  │ - Random 24-byte nonce         │  │
        │  │ - AAD (session:seq:filename)   │  │
        │  │ - Upload via REST              │  │
        │  └────────────────────────────────┘  │
        └──────────┬───────────────────────────┘
                   │
                   ▼
        ┌───────────────────────┐
        │ Real-time Monitoring  │
        │ - QBER metrics        │
        │ - Key status          │
        │ - Message counts      │
        │ - Security alerts     │
        └──────────┬────────────┘
                   │
                   ▼
        ┌───────────────────────┐
        │ User Action or        │
        │ Security Threshold     │
        └──────────┬─────────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
        ▼                     ▼
┌───────────────┐    ┌───────────────┐
│ User Requests │    │ Auto-Terminate│
│ Termination   │    │ (High QBER,   │
│               │    │  Timeout, etc)│
└───────┬───────┘    └───────┬───────┘
        │                     │
        └──────────┬──────────┘
                   │
                   ▼
        ┌───────────────────────┐
        │ Secure Cleanup        │
        │ - Zeroize all keys    │
        │ - Clear message buffer│
        │ - Delete file cache   │
        │ - Persist audit logs  │
        └──────────┬─────────────┘
                   │
                   ▼
        ┌───────────────────────┐
        │ Session State:         │
        │    TERMINATED          │
        └───────────────────────┘
                   │
                   ▼
        ┌───────────────────────┐
        │ Broadcast Teardown     │
        │ Event to All Clients   │
        └───────────────────────┘
                   │
                   ▼
        ┌───────────────────────┐
        │ System Ready for       │
        │ Next Session           │
        └───────────────────────┘
```

## Detailed Architecture Diagram Description
Visualize the platform as a layered set of interconnected blocks:

- **Frontend Layer (React + Vite)** sits on the left. At the top is the `App Shell & Routing` block, which fans out to four feature blocks: `Session Manager`, `BB84 Simulator`, `Chat Interface`, and `File Transfer Panel`. Beneath these, a `Security Dashboard` block spans the width, consuming telemetry from all features. Along the base, two infrastructure blocks—`Socket.IO Client` and `REST Client`—anchor the frontend, with vertical arrows showing each feature relying on one or both communication channels.

- **Backend Edge (FastAPI + Socket.IO)** occupies the central column. Incoming HTTPS arrows from the `REST Client` land on an `ASGI Gateway` block, which connects to an `Auth Middleware` block before branching into three controller blocks: `Session Controller`, `Message Controller`, and `File Controller`. Parallel to these, incoming WebSocket arrows from the `Socket.IO Client` terminate at a `Socket.IO Namespaces` block that routes events to the same controllers as well as two additional ones: `BB84 Controller` and `Telemetry Controller`.

- **Service Layer** forms a column to the right of the controllers. Each controller points to a dedicated service: `Session Manager Service`, `BB84 Engine`, `PQC Service (Kyber/Dilithium)`, `Crypto Service (HKDF, OTP, AEAD)`, `Eve/Noise Module`, and `Metrics Aggregator`. Arrows illustrate how the Session Manager coordinates with the crypto, BB84, PQC, and metrics services, while the message and file controllers depend on the Crypto Service for encryption and authentication.

- **State & Integrations Layer** is the rightmost column. Here, horizontal arrows extend from the services into storage blocks: `In-memory Session Store`, `Encrypted Message Buffer`, `Encrypted File Cache`, and `Telemetry/Audit Log`. The `PQC Service` additionally connects downward to a `PQC Native Libraries` block representing external binaries installed with the project’s setup scripts.

- **Cross-layer Feedback Loops** are highlighted with dashed arrows: telemetry data flows from the Metrics Aggregator back through the Socket.IO server to the frontend dashboard; encrypted message acknowledgments propagate from the message buffer to the chat interface; file availability notifications move from the file cache to the file transfer panel.

Taken together, the diagram shows a left-to-right data flow (frontend → controllers → services → storage) with return paths for real-time updates, emphasizing the separation of concerns across presentation, orchestration, cryptographic services, and state management.

## Detailed Architecture Data

### Tier Summary
- **Presentation Tier** (`frontend/src`): React components render simulation controls (`SessionManager`, `BB84Simulator`), encrypted chat UI, file transfer workflows, and security dashboards. Context providers coordinate state from REST plus Socket.IO.
- **Edge/API Tier** (`backend/app/main.py`): FastAPI routes expose REST endpoints for session management and file uploads. Socket.IO namespaces stream event-driven updates (BB84 progress, message delivery, metrics).
- **Service Tier** (`backend/app/services`): Encapsulates pure services for BB84 simulation, PQC operations, crypto transformations, session orchestration, and Eve/noise modeling.
- **State & Persistence Tier** (`backend/app/models/session.py`): Maintains session metadata, participants, key material, encrypted message buffer, and file manifests in memory with hooks for persistence.
- **External Integrations**: PQC binaries (`install_pqc.*`) provide Kyber/Dilithium primitives; logging/telemetry surfaces to dashboards and optional external sinks.

### Backend Subsystems
- **Session Controller** (`SessionCtrl`): Coordinates lifecycle—creation, participant binding, BB84 start, QBER thresholds, termination. Delegates to `SessionSvc` for state mutation and to `CryptoSvc` for key derivations.
- **BB84 Controller & Engine** (`BB84Ctrl`, `bb84_engine.py`): Generates random bases/bits, simulates measurement outcomes, performs sifting, QBER evaluation, error correction, and privacy amplification; streams intermediate states to frontend.
- **PQC Controller & Service** (`PqCCtrl`, `pqc_service.py`): Manages Kyber key pair generation, encapsulation/decapsulation, and optional Dilithium signing for authenticity checks; returns PQC-derived secret to `CryptoSvc`.
- **Crypto Service** (`crypto_service.py`): Runs HKDF extract/expand, constructs OTP-style deterministic streams for chat, performs HMAC (SHA3) verification, handles XChaCha20-Poly1305 file encryption, and zeroizes secret material on teardown.
- **Messaging Pipeline** (`MessageCtrl`, `SessionSvc`): Validates sequencing, calls `CryptoSvc` encrypt/decrypt routines, stores ciphertext + metadata, emits delivery confirmations and failure alerts via Socket.IO.
- **File Pipeline** (`FileCtrl`): Accepts uploads, encrypts content server-side, persists metadata in `FileVault`, manages download authorization, and tracks per-file sequence numbers for replay protection.
- **Telemetry & Monitoring** (`MetricsCtrl`, `MetricsSvc`): Aggregates QBER trends, key derivation status, session health, Eve detections; pushes metrics to dashboards and logs.
- **Eve/Noise Module** (`eve_module.py`): Injects controllable interference to simulate eavesdropping; feeds metrics back into BB84 pipeline influencing QBER.

### Frontend Subsystems
- **Session Management UI** (`SessionManager.tsx`): Drives session creation, participant assignment, toggles PQC/Eve modules, and surfaces session state via context.
- **BB84 Visualization** (`BB84Simulator.tsx`): Animates qubit preparation, basis comparisons, sifting results, and QBER metrics in real time using Socket.IO event streams.
- **Chat & Messaging** (`ChatInterface.tsx`, `socketService.ts`): Derives per-message key stream segments in browser, encrypts outbound payloads, validates incoming HMACs, and renders message timeline with status indicators.
- **File Transfer Panel** (`FileUI` components): Integrates REST uploads/downloads with progress display, gating access based on session state and verifying AEAD authentication results.
- **Security Dashboards** (`SecurityDashboard.tsx`, `CryptoMonitor.tsx`, `StatusBar.tsx`): Consolidate telemetry (QBER graphs, key status, Eve detections, PQC status) and provide alerts when thresholds hit.
- **Service Layer** (`apiService.ts`, `cryptoService.ts`, `socketService.ts`): Wraps REST/Socket.IO interactions, handles JWT/session tokens if configured, and exposes hooks for components.

### Data & State Management
- **Session Store**: In-memory dictionary keyed by `session_id` containing participants, cryptographic material, message/file sequences, and audit trails; supports eventual persistence extension.
- **Message Buffer**: Stores encrypted message payloads with metadata (sequence, timestamp, MAC) enabling replay detection and history reviews.
- **File Vault**: Maintains metadata and encrypted blobs (nonce, ciphertext, tag) for file transfers; integrates with optional external storage.
- **Telemetry Logs**: Capture BB84 runs, QBER outcomes, PQC encapsulation events, and security alerts for audit/compliance.
- **Client State**: React Query or context-based caches maintain mirrored session state, auto-refreshed from Socket.IO.

### Security Architecture
- **Key Establishment**: BB84-derived key optionally concatenated with Kyber secret, fed into HKDF with `session_id` salt; results in independent keys for OTP stream, HMAC, and file AEAD.
- **Transport Security**: REST over HTTPS; Socket.IO leveraged over secure WebSockets (wss) with access tokens; payloads double-protected via HMAC.
- **Message Confidentiality & Integrity**: Deterministic OTP stream derived per sequence number, HMAC-SHA3 ensures authenticity and replay protection.
- **File Security**: XChaCha20-Poly1305 with rich AAD (session id, sequence, filename, timestamp) prevents tampering and substitution.
- **Key Lifecycle**: Keys held in memory only for active sessions; `CryptoSvc` zeroizes buffers on termination or high QBER abort.
- **Eavesdropping Detection**: Eve module induces disturbances; QBER thresholds trigger automated session aborts and notifications.

### Primary Interaction Flow
1. **Session Creation**: Frontend calls `POST /sessions`; backend instantiates session state, returns identifiers, and emits creation event via Socket.IO.
2. **Participant Join**: Users register roles; session controller validates and updates state; UI refreshes participants list in real time.
3. **BB84 Run**: User initiates simulation; backend iterates through preparation, measurement, sifting, and error estimation, emitting granular progress events.
4. **Hybrid Key Derivation**: PQC encapsulation (optional) executes; combined secret runs through HKDF; derived keys stored transiently in session state.
5. **Secure Messaging**: Frontend encrypts outbound messages with deterministic stream, attaches HMAC, and sends via Socket.IO; backend verifies, stores, and broadcasts to peers.
6. **Secure File Transfer**: Files uploaded through REST; backend performs AEAD encryption, stores metadata, and informs clients for download; clients verify tags before decrypting.
7. **Monitoring & Alerts**: Metrics services stream QBER, encryption status, and Eve detections to dashboards; alerts trigger UI highlighting or session termination.
8. **Session Termination**: On user request or security threshold breach, backend clears keys, persists audit logs, and broadcasts teardown events for client cleanup.

### Deployment & Scaling Considerations
- **Backend Runtime**: Deploy behind ASGI servers (Uvicorn/Gunicorn) with workers tuned for WebSocket throughput; enable SSL termination at ingress.
- **State Sharing**: To scale horizontally, back session store with Redis or database, and use Socket.IO adapter for multi-instance event broadcasting.
- **Frontend Build**: Vite build outputs static assets served via CDN or reverse proxy; ensure environment variables point to secure backend endpoints.
- **PQC Environment**: Install Kyber/Dilithium binaries via `install_pqc.bat`/`.sh`; validate CPU/AVX support; container images should bundle these dependencies.
- **Observability**: Integrate metrics with Prometheus/Grafana or cloud monitoring; log QBER anomalies and crypto errors for incident response.

### Extensibility Roadmap
- Abstract session repository to plug persistent databases or distributed caches.
- Swap simulated BB84 engine with hardware interface by implementing compatible service adapter.
- Add support for alternate PQC schemes by extending `pqc_service` with standardized interface.
- Introduce role-based access control (RBAC) layer in `AuthMiddleware` for enterprise deployments.
- Enhance dashboards with historical analytics by storing telemetry in time-series database.

### Related Documents
- `README_SYSTEM_COMPONENTS.md`: Deep dives into BB84, PQC, messaging, file encryption, session lifecycle.
- `README_CRYPTO.md`: Cryptographic primitives, HKDF usage, and best practices.
- `README_PQC.md`: Post-quantum cryptography installation, command references, and troubleshooting.

