# Sensitive Guard AI DLP v2.0

A Manifest V3 Chrome extension that performs local browser-side sensitive-data checks before text is submitted to websites, with special handling for common AI destinations.

## Features
- AI-specific site recognition: ChatGPT, Claude, Gemini, Google AI Studio, Perplexity, Copilot, Poe, Grok, DeepSeek, Mistral, NotebookLM, Meta AI, Hugging Face.
- Local detection for API keys, access tokens, passwords, private keys, JWTs, PAN-like IDs, Aadhaar-like numbers, phone numbers, emails, card-like numbers, SQL/internal code patterns, and custom keywords.
- Block/warn modes.
- Allowlist and blocklist.
- Remove sensitive data & continue redaction.
- Popup dashboard with blocked/redacted counters.
- Settings page.
- Main-world fetch/XHR guard for known AI destinations.

## Platform limitation
This is not a complete network DLP proxy. Chrome extensions cannot universally inspect arbitrary encrypted HTTPS request bodies. WebSockets, service workers, custom encodings and extension-owned traffic may not be visible to the interception layer.

## Install
1. Extract the extension.
2. Open chrome://extensions.
3. Enable Developer mode.
4. Load unpacked and choose this folder.

## Privacy
Detection is performed locally in the browser. Event metadata is stored locally; matched sensitive text is not intentionally persisted.
