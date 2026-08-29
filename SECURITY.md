# Security policy

Veil Link is a security-oriented prototype and has not received an independent cryptographic audit.

Do not report vulnerabilities through public issues when disclosure would expose an active weakness. Use a private contact channel for security reports.

## In scope

- handshake authentication flaws
- key handling defects
- nonce or state reuse
- plaintext exposure
- fingerprint verification bypass
- malformed frame handling

## Out of scope

- compromised operating systems or endpoints
- traffic analysis and IP metadata
- denial of service against the TCP listener
- weaknesses in third-party cryptographic libraries outside this project's integration
