# BB84 QKD System — Complete UI & Design Documentation

**App Name:** Cryptex (BB84 QKD Simulator)  
**Framework:** React 18 + TypeScript + Vite  
**Styling:** Tailwind CSS + Custom CSS (index.css)  
**Icons:** Lucide React  
**Charts:** Recharts  
**Date:** February 25, 2026  

---

## 1. Design System Overview

### Design Philosophy

The UI follows an **iOS-inspired glassmorphism** aesthetic — frosted-glass cards floating over rich gradient backgrounds with subtle grid overlays and animated particles. The entire interface feels like a futuristic "quantum laboratory" control panel.

### Typography

| Usage | Font | Weight |
|-------|------|--------|
| Body text | Inter | 400–700 |
| Monospace / Code / Keys | JetBrains Mono | 400–600 |

Both loaded from Google Fonts with `-apple-system` fallback.

### Color System

#### System Colors (iOS-inspired)

| Token | Hex | Usage |
|-------|-----|-------|
| `--system-blue` | #007AFF | Primary actions, links, info badges |
| `--system-red` | #FF3B30 | Eve, errors, security alerts |
| `--system-green` | #34C759 | Success, secure status, QBER safe |
| `--system-indigo` | #5856D6 | Bob identity color |
| `--system-orange` | #FF9500 | Warnings, disconnect alerts |
| `--system-cyan` | #32ADE6 | Alice identity color, quantum accents |
| `--system-gray` | #8E8E93 | Muted text, disabled states |

#### Semantic Aliases

| Alias | Maps To | Purpose |
|-------|---------|---------|
| `--alice` | `--system-cyan` | Alice's messages, chips, glows |
| `--bob` | `--system-indigo` | Bob's messages, chips, glows |
| `--eve` | `--system-red` | Eve's panels, attack warnings |
| `--success` | `--system-green` | Secure states, QBER OK |
| `--warning` | `--system-orange` | Connection lost, key rotation |
| `--info` | `--system-blue` | General info notifications |

### Theme Support

Two themes via `[data-theme='dark']` CSS attribute:

| Token | Light Mode | Dark Mode |
|-------|------------|-----------|
| `--bg-primary` | #F2F2F7 | #000000 |
| `--bg-secondary` | #FFFFFF | #1C1C1E |
| `--bg-tertiary` | #FFFFFF | #2C2C2E |
| `--text-primary` | #000000 | #FFFFFF |
| `--text-secondary` | #3C3C43 | rgba(235,235,245,0.6) |
| `--card-surface` | rgba(255,255,255,0.72) | rgba(30,30,30,0.65) |
| `--card-border` | rgba(255,255,255,0.4) | rgba(255,255,255,0.12) |

Toggled by `ThemeToggle` component, persisted in `ThemeContext`.

### Glass Materials

Four blur levels used throughout the app:

| Class | Blur | Saturation | Usage |
|-------|------|------------|-------|
| `.material-thin` | 10px | 180% | Subtle overlays |
| `.glass-card` (default) | 20px | 180% | All standard cards |
| `.material-thick` | 30px | 180% | Auth page, modals |
| Glass heavy | 50px | 180% | Reserved |

### Core CSS Classes

| Class | Purpose |
|-------|---------|
| `.glass-card` | Primary card container — frosted background, 24px radius, shadow, hover lift |
| `.glow-border` | Adds gradient pseudo-element glow behind card edges |
| `.glow-border.eve` | Red/orange glow variant for Eve-related panels |
| `.metric-label` | Small uppercase label (0.85rem, muted, tracking) |
| `.metric-value` | Large bold number display |
| `.session-chip` | Pill-shaped role badge (Alice/Bob/Eve colored) |
| `.copy-button` | Ghost-style button with cyan hover glow |
| `.quantum-button` | Rounded pill button with scale + glow hover |
| `.quantum-lab` | Full-page background with radial gradients and grid overlay |
| `.quantum-content` | Centered content container (max-width 1600px) |
| `.qubit-stream` | Animated quantum channel visualization |
| `.qubit-particle` | Glowing dot with pulsing animation |
| `.qber-ring` | Conic-gradient ring gauge for QBER display |
| `.secure-message` | Chat bubble (alice/bob/eve variants with role-colored glow) |
| `.drag-zone` | Dashed file drop area with drag-over highlight |
| `.collapsible-card` | Expandable section container |
| `.modal-overlay` | Fixed fullscreen backdrop with blur |

### Animations

| Animation | Effect | Duration |
|-----------|--------|----------|
| `particleFloat` | Translates particles upward and fades | 9–12s |
| `qubitFlow` | Sweeps gradient highlight across qubit stream | 4s |
| `particleBlink` | Scales qubit particles up/down with opacity | 2.2s |
| `typing` | Bounces dots for typing indicator | 1s |
| `shimmer` | Key progress bar shine effect | 2s |
| Respects `prefers-reduced-motion` | All animations reduced to 0.01s | — |

---

## 2. Page Layout & Responsive Behavior

### Breakpoints (via `useBreakpoint` hook)

| Name | Width | Behavior |
|------|-------|----------|
| Mobile | < 768px | Single column, stacked layout, bottom sheet navigation |
| Tablet | 768–1023px | Two-column grid, simplified sidebars |
| Desktop | ≥ 1024px | Full multi-column layout, all panels visible |

### Layout Structure

```
┌────────────────────────────────────────────────────┐
│                  HEADER BAR                         │
│  Logo "Cryptex" │ Status │ Session ID │ Theme │ Logout
├────────────────────────────────────────────────────┤
│                                                     │
│  ┌─ SessionControlPanel ───────────────────────┐   │  ← Desktop only
│  │ Session ID │ Status Pills │ Participants     │   │
│  └─────────────────────────────────────────────┘   │
│                                                     │
│  ┌─ BB84Simulator ──────────┐ ┌─ KeyStatusPanel ┐ │  ← 1.8fr : 1fr grid
│  │ Protocol controls        │ │ Key length, QBER│ │
│  │ Start BB84 / Hybrid mode │ │ Key preview     │ │
│  │ Qubit stream visual      │ │ Progress bar    │ │
│  └──────────────────────────┘ └─────────────────┘ │
│                                                     │
│  ┌─ ChatInterface ──────┐ ┌ FileTransfer ┐ ┌─────┐│  ← 1.4fr : 0.9fr : 0.9fr
│  │ Message bubbles      │ │ Drag & drop  │ │ Eve ││
│  │ Inline file download │ │ Transfer list│ │Panel││  (Eve role shows
│  │ Send input bar       │ │ Download btns│ │     ││   EveControlPanel
│  └──────────────────────┘ └──────────────┘ └─────┘│   instead)
│                                                     │
│  ┌─ Security Insights (Collapsible) ───────────┐  │
│  │ CryptoMonitor │ SecurityDashboard            │  │
│  └─────────────────────────────────────────────┘  │
│                                                     │
│  ┌─ Notifications Toast Stack (top-right) ─────┐  │
│  │ Auto-dismiss after 5s, max 10 visible        │  │
│  └─────────────────────────────────────────────┘  │
│                                                     │
│  ┌─ QBERAlertModal (fullscreen overlay) ───────┐  │
│  │ Shows when QBER exceeds 11% threshold        │  │
│  └─────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
```

---

## 3. User Flow

```
Auth Page → Create/Join Session → Run BB84 → Secure Chat & File Transfer
    │              │                    │              │
    ▼              ▼                    ▼              ▼
 AuthPage    SessionManager     BB84Simulator    ChatInterface
                                                 FileTransferModule
                                                 EveControlPanel (if Eve)
```

1. **Authentication** — Login/Signup via `AuthPage`
2. **Session** — Create new or join existing session as Alice/Bob/Eve via `SessionManager`
3. **BB84 Key Exchange** — Run protocol via `BB84Simulator`, monitor with `KeyStatusPanel`
4. **Communication** — Exchange encrypted messages (`ChatInterface`) and files (`FileTransferModule`)
5. **Eve (optional)** — Configure attacks via `EveControlPanel`
6. **Monitoring** — Live security view via `CryptoMonitor` and `SecurityDashboard`

---

## 4. Component Reference

### 4.1 AuthPage

| | |
|---|---|
| **File** | `components/AuthPage.tsx` (156 lines) |
| **Purpose** | Login / Signup form — the entry gate before any session access |
| **Visual** | Centered card with glassmorphic backdrop, tab switcher (Login / Sign Up) |

**Features:**
- Toggle between login and signup modes
- Username + password fields with show/hide toggle
- Confirm password field (signup only) with mismatch warning
- Loading state, inline error display
- Calls `apiService.login()` or `apiService.signup()`

---

### 4.2 SessionManager

| | |
|---|---|
| **File** | `components/SessionManager.tsx` (342 lines) |
| **Purpose** | Create new QKD sessions or join existing ones |
| **Visual** | Glass card with two main action areas |

**Features:**
- **Create Session** button — generates new session ID via API
- **Join Session** — paste session ID + select role (Alice/Bob/Eve)
- Role cards with color-coded identity chips (cyan/indigo/red)
- Server offline warning when backend unreachable
- Success/error feedback with icons (CheckCircle, AlertCircle)

---

### 4.3 BB84Simulator

| | |
|---|---|
| **File** | `components/BB84Simulator.tsx` (367 lines) |
| **Purpose** | Main BB84 protocol visualization and control panel |
| **Visual** | Large card with protocol stages, qubit stream animation, QBER ring gauge |

**Features:**
- **Start BB84** button (standard or hybrid mode toggle)
- **Retry Key Retrieval** button (when auto-retrieval fails)
- Protocol stage indicator: Preparation → Transmission → Sifting → QBER → Amplification → Complete
- Animated qubit stream visualization (`.qubit-stream` with `.qubit-particle` dots)
- Real-time QBER display via conic-gradient ring (`.qber-ring`)
- Progress percentage and stage labels
- Eve detection alert (red pulsing when QBER > 11%)
- QBER history line chart (Recharts)

**Props:** `progress`, `sessionKey`, `onStartBB84`, `onRetrySessionKey`, `userRole`, `eveDetected`, `cryptoInfo`, `qberHistory`

---

### 4.4 KeyStatusPanel

| | |
|---|---|
| **File** | `components/KeyStatusPanel.tsx` (136 lines) |
| **Purpose** | Displays key material status, QBER live reading, and key preview |
| **Visual** | Compact card with status badge, metrics grid, and blurred key stream |

**Features:**
- Status badge: Active (green) / Pending (gray) / Unsafe (red pulsing)
- Metrics grid: Key Length (bytes) + Live QBER (%)
- Key stream preview (hex bytes) — blurred by default, toggle reveal with eye icon
- Eve role sees "ENCRYPTED - NO ACCESS" instead of key data
- Progress bar with gradient shimmer during key generation

---

### 4.5 ChatInterface

| | |
|---|---|
| **File** | `components/ChatInterface.tsx` (372 lines) |
| **Purpose** | End-to-end encrypted messaging interface |
| **Visual** | Chat bubbles (role-colored), message input bar, file attachment |

**Features:**
- Role-colored message bubbles (`.secure-message.alice` / `.bob` / `.eve`)
- Each message shows encrypted ciphertext preview (truncated hex)
- "Decrypt" button on received messages (server-side decryption via Socket.IO)
- Lock/Unlock icon per message indicating encryption status
- File messages display inline with download buttons (decrypt or raw)
- Text input with Send button and file upload attachment
- Auto-scroll to bottom on new messages
- Disabled state when no session key or session compromised

---

### 4.6 FileTransferModule

| | |
|---|---|
| **File** | `components/FileTransferModule.tsx` (152 lines) |
| **Purpose** | Drag-and-drop encrypted file transfer |
| **Visual** | Dashed upload zone + recent transfers list |

**Features:**
- Drag-and-drop zone with hover highlight (`.drag-zone.drag-over`)
- Browse Files button fallback
- Upload progress bar (gradient cyan → blue → purple)
- Encryption indicator: "Encrypting with AES-256-GCM + One-Time Pad overlay"
- Recent transfers list with file icon, name, size, timestamp
- Per-file buttons: "Decrypt" download + "Raw" encrypted download

---

### 4.7 EveControlPanel

| | |
|---|---|
| **File** | `components/EveControlPanel.tsx` (214 lines) |
| **Purpose** | Configure and launch eavesdropper attack strategies (Eve role only) |
| **Visual** | Glass card with red glow border, attack type selector, parameter sliders |

**Features:**
- Attack type dropdown: Intercept-Resend / Depolarizing Noise / Qubit Loss
- Per-attack parameter controls:
  - Intercept: fraction slider (0–100%) + basis strategy (random/alice/fixed)
  - Depolarizing: noise probability slider
  - Qubit Loss: loss probability slider
- Start/Stop attack buttons with status indicator
- Attack info description per type
- Activity log of attack actions
- Expandable/collapsible advanced settings

---

### 4.8 CryptoMonitor

| | |
|---|---|
| **File** | `components/CryptoMonitor.tsx` (151 lines) |
| **Purpose** | Real-time cryptographic session metrics |
| **Visual** | Compact stats card with encryption status badge and key rotation indicator |

**Features:**
- Encryption status badge with icon (none / standard / hybrid)
- Metrics grid (2 columns):
  - Messages count, Files count, Key Usage (formatted bytes)
  - QBER (color-coded), Key Age (formatted time), Violations count
- Security recommendations list (truncated to 3)
- Key rotation status: "Current" (green ✓) or "Recommended" (orange clock)

---

### 4.9 SecurityDashboard

| | |
|---|---|
| **File** | `components/SecurityDashboard.tsx` (346 lines) |
| **Purpose** | Detailed security analytics with charts and health scores |
| **Visual** | Multi-section dashboard with line charts, pie charts, and violation log |

**Features:**
- **Session Health Score** — large percentage display, color-coded (green/orange/red)
- **Risk Level** badge (low/medium/high/critical)
- **QBER History Line Chart** (Recharts) — QBER line vs threshold reference line
- **Crypto Stats Pie Chart** — messages vs files distribution
- **Encryption Algorithms** used (listed with badges)
- **Security Violations Log** — severity-colored entries with timestamps
- **Health Recommendations** list

---

### 4.10 SessionControlPanel

| | |
|---|---|
| **File** | `components/SessionControlPanel.tsx` (145 lines) |
| **Purpose** | Session metadata bar — ID, connection/security status, participants |
| **Visual** | Wide horizontal card (desktop only) with status pills |

**Features:**
- Session ID display with copy-to-clipboard button
- Connection status pill: Connected (green) / Disconnected (orange) / Server Offline (red)
- Security status pill: Secure (green ⚡) / Compromised (red ⚠)
- High Contrast toggle button
- Active participants list with role badges and online indicators
  - Alice (cyan) / Bob (indigo) / Eve (red)

---

### 4.11 StatusBar

| | |
|---|---|
| **File** | `components/StatusBar.tsx` (163 lines) |
| **Purpose** | Compact status strip showing user role, session info, and protocol progress |
| **Visual** | Horizontal bar with role pill, session ID, participant count, progress bar |

**Features:**
- Current user role badge (color-coded pill)
- Session ID monospace display
- Online participant count
- BB84 progress bar with percentage
- Status text: Ready to Start → BB84 Running → Secure Channel → Session Compromised
- Eve detection warning banner (red alert box)
- BB84 detailed progress: stage, QBER, bits sifted, final key length

---

### 4.12 QBERAlertModal

| | |
|---|---|
| **File** | `components/QBERAlertModal.tsx` (108 lines) |
| **Purpose** | Fullscreen emergency modal when eavesdropping is detected |
| **Visual** | Centered modal with red glow, pulsing icon, and action buttons |

**Features:**
- Animated mount (scale + translate + backdrop blur)
- Pulsing AlertTriangle icon with red/orange gradient glow
- Title: "Security Breach Detected"
- Metrics grid: Current QBER vs Threshold (side by side)
- Two action buttons:
  - "Abort Protocol" (red gradient, primary)
  - "Analyze Threat" (secondary, opens SecurityDashboard)
- Close button (top right)

---

### 4.13 ThemeToggle

| | |
|---|---|
| **File** | `components/ThemeToggle.tsx` (33 lines) |
| **Purpose** | Light/Dark mode switch button |
| **Visual** | Pill with Moon/Sun icon, optional label |

**Features:**
- Reads from `ThemeContext`
- Compact mode (icon only) for mobile
- Full mode (icon + "Dark"/"Light" label) for desktop

---

### 4.14 CollapsibleSection

| | |
|---|---|
| **File** | `components/CollapsibleSection.tsx` (46 lines) |
| **Purpose** | Generic expandable/collapsible container |
| **Visual** | Card with clickable header and chevron indicator |

**Features:**
- Title + optional subtitle
- `defaultOpen` prop
- Chevron rotates 180° on toggle
- Used to wrap Security Insights section (CryptoMonitor + SecurityDashboard)

---

## 5. Services Layer

### 5.1 apiService (`services/apiService.ts` — 16.6KB)

HTTP client (Axios) for all REST API calls:
- `login()`, `signup()` — auth endpoints
- `checkServerHealth()` — health check
- `createSession()`, `joinSession()` — session management
- `startBB84Simulation()` — trigger BB84 protocol
- `getSessionKey()`, `getSessionSecurity()` — key and crypto info retrieval
- `sendEncryptedFile()`, `downloadEncryptedFile()`, `downloadRawEncryptedFile()` — file operations
- PQC endpoints: `getPQCInfo()`, `encapsulateKey()`, `signMessage()`, etc.
- JWT auth token management (localStorage)

### 5.2 socketService (`services/socketService.ts` — 6.3KB)

Socket.IO client for real-time bidirectional events:
- `connect()` / `disconnect()` — connection lifecycle
- `joinSession()` — join Socket.IO room
- `sendEncryptedMessage()` — send OTP-encrypted message
- `requestMessageDecryption()` — request server-side decryption
- `updateEveParams()` — send Eve attack configuration
- Event listeners: `onBB84Started`, `onBB84Progress`, `onBB84Complete`, `onBB84Error`, `onEncryptedMessageReceived`, `onMessageDecrypted`, `onEncryptedFileReceived`, `onEveStatusUpdate`, `onEveDetected`, `onUserJoined`, `onUserDisconnected`, `onSessionTerminated`, `onSecurityViolation`

### 5.3 cryptoService (`services/cryptoService.ts` — 15.4KB)

Client-side cryptographic utilities (libsodium):
- `setSessionKey()` / `getSessionKey()` — key management
- `updateCryptoInfo()` — cache server-reported encryption stats
- `addQBERDataPoint()` — track QBER history
- `cacheDecryptedContent()` / `getCachedDecryptedContent()` — decryption cache
- `getEncryptionStatus()` — returns icon, color, description based on current mode
- `getSessionHealthAssessment()` — computes health score and risk level
- `getSecurityRecommendations()` — generates advisory messages
- `clear()` — wipe all key material

---

## 6. Hooks

### useBreakpoint (`hooks/useBreakpoint.ts`)
Returns `{ isMobile, isTablet, isDesktop }` booleans based on window width.

### useMediaQuery (`hooks/useMediaQuery.ts`)
Generic media query hook — returns boolean match for any CSS media query string.

---

## 7. Type Definitions (`types/index.ts` — 9.2KB)

Key interfaces:

| Type | Purpose |
|------|---------|
| `User` | `user_id`, `role`, `connected`, `joined_at`, `last_activity` |
| `Session` | `session_id`, `participants`, `status`, `created_at` |
| `BB84Progress` | `stage`, `progress`, `qber`, `threshold`, `sifted_length`, `final_key_length`, ... |
| `SecureMessage` | `message_id`, `sender_id`, `message_type`, `encrypted_payload`, `decrypted_content` |
| `CryptoInfo` | `crypto_stats`, `qber`, `key_age_seconds`, `needs_key_rotation`, `security_violations` |
| `QBERDataPoint` | `timestamp`, `qber`, `threshold`, `stage` |
| `EveParams` | `attack_type`, `params` (fraction, strategy, probability) |
| `FileTransferInfo` | `message_id`, `filename`, `file_size`, `sender_id`, `download_ready` |
| `EncryptionStatus` | `status`, `icon`, `color`, `description` |
| `SessionHealthAssessment` | `score`, `risk_level`, `recommendations` |
| `SecurityViolation` | `timestamp`, `violation`, `severity`, `session_id` |
| `AppState` | Top-level state aggregating all of the above |

---

## 8. Notification System

Toast-style notifications appear in the top-right corner:

| Type | Color |
|------|-------|
| `success` | Green |
| `info` | Blue |
| `warning` | Orange |
| `error` | Red |

- Max 10 visible at once
- Auto-dismiss after 5 seconds
- Managed via `addNotification()` callback in `App.tsx`
- Used throughout the app for feedback on all operations

---

## 9. Accessibility

- `aria-expanded` on collapsible sections
- `aria-modal` and `role="alertdialog"` on QBERAlertModal
- `aria-label` on ThemeToggle button
- `prefers-reduced-motion` respected — all animations reduced
- High-contrast mode toggle (applies `high-contrast` class to body)
- Minimum 44px touch targets on interactive elements

---

*Created by Shriram Narkhede | Cryptex — BB84 QKD Simulator | 2026*
