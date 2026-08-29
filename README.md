# Veil Link

Veil Link is a minimal peer-to-peer encrypted terminal channel for situations where message content must remain confidential even when network traffic is captured.

It uses the Noise Protocol Framework rather than a custom cryptographic design.

## Security profile

- `Noise_XX_25519_ChaChaPoly_BLAKE2s`
- X25519 ephemeral and static Diffie-Hellman keys
- ChaCha20-Poly1305 authenticated encryption
- BLAKE2s hashing
- forward secrecy from ephemeral session keys
- peer identity fingerprints with optional pinning
- private identity material zeroized when released
- no plaintext message logging
- no central message server

Veil Link protects message content in transit. It does not make endpoints invisible and it does not claim to prevent traffic analysis. An attacker that compromises either endpoint can read messages on that endpoint.

## Build

```bash
cargo build --release
```

## Create an identity

```bash
veil-link keygen --out alice.key
```

The identity file contains only the 32-byte private key. Its public key and fingerprint are derived locally at runtime. Protect the file like any other credential.

## Start a listener

```bash
veil-link listen --bind 0.0.0.0:9443 --key alice.key
```

## Connect

```bash
veil-link connect --addr 203.0.113.10:9443 --key bob.key
```

After the Noise XX handshake, each side prints the remote identity fingerprint. Verify that fingerprint through a separate trusted channel before treating the session as authenticated.

For repeat contacts, pin the expected identity:

```bash
veil-link connect \
  --addr 203.0.113.10:9443 \
  --key bob.key \
  --expect 7e52:1b0d:62b3:40cb:7cf1:5c69:913e:c623
```

A fingerprint mismatch terminates the session.

Type `/quit` to close the channel.

## Design constraints

Veil Link deliberately avoids account systems, message history, cloud persistence and recovery keys. The current implementation is a terminal transport prototype, not a replacement for an audited secure messenger.

See `docs/PROTOCOL.md` for the handshake and trust model.
