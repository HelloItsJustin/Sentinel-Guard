# SentinelGuard IDE Guard

SentinelGuard IDE Guard brings the AI data firewall directly into VS Code.

## Features

- Scan selected text or the full active file.
- Send scans to the SentinelGuard backend as `source = IDE_GUARD`.
- Show a status bar health indicator for the local backend.
- Add VS Code diagnostics on risky scanned ranges.
- Open a rich scan report with:
  - decision, risk, incident ID, and issue chips
  - original and sanitized text
  - AI enforcement gateway action that blocks unsafe originals, re-checks sanitized payloads, and approves original content only when policy allows it
  - four policy-safe prompt variants: Guarded, Brief, Analyst, Support
  - one-click copy, insert, replace, and dashboard actions
- Configure backend URL, dashboard URL, user ID, timeouts, diagnostics, and report behavior.

## Commands

- `SentinelGuard: Scan Selection`
- `SentinelGuard: Scan Current File`
- `SentinelGuard: Open Last Report`
- `SentinelGuard: Copy Sanitized Output`
- `SentinelGuard: Send Last Scan Through AI Gateway`
- `SentinelGuard: Copy Last Safe Prompt`
- `SentinelGuard: Insert Last Safe Prompt`
- `SentinelGuard: Replace Selection with Sanitized Output`
- `SentinelGuard: Open Incident in Dashboard`
- `SentinelGuard: Check Backend Health`
- `SentinelGuard: Clear Diagnostics`

## Configuration

```json
{
  "sentinelguard.apiBaseUrl": "http://localhost:8000",
  "sentinelguard.frontendBaseUrl": "http://127.0.0.1:5173",
  "sentinelguard.userId": "vs-code-user",
  "sentinelguard.autoOpenReport": "onRisk",
  "sentinelguard.diagnosticsEnabled": true,
  "sentinelguard.showStatusBar": true
}
```

## Run In Development

1. Start the backend:

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

2. Open `ide-guard/vscode-extension` in VS Code.
3. Run `npm install`.
4. Press `F5` to start the Extension Development Host.
5. Select text and run `SentinelGuard: Scan Selection`.
