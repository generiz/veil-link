# Protocol notes

## Transport

Veil Link runs Noise over a TCP byte stream. TCP provides delivery and ordering only. Confidentiality, peer authentication and integrity come from the Noise session.

Each Noise handshake or transport message is wrapped in a four-byte big-endian length field. The length field is visible to the network and is not treated as secret metadata.

## Handshake

The protocol name is:

`Noise_XX_25519_ChaChaPoly_BLAKE2s`

The XX pattern is used because peers do not need to know each other's static public key before the first connection.

The handshake exchanges ephemeral keys first. Static identity keys are then encrypted under keys derived during the handshake. A passive observer does not learn the static identity keys from the wire.

## Identity verification

XX does not by itself decide whether a remote static key belongs to the intended person. Veil Link therefore derives a short BLAKE2s fingerprint from the remote static public key.

For first contact, compare the fingerprint over an independent trusted channel. For later sessions, pass the expected fingerprint with `--expect`. A mismatch terminates the connection.

Without fingerprint verification, an active man-in-the-middle can impersonate both endpoints during first contact.

## Forward secrecy

The session incorporates ephemeral X25519 keys. Recording a session and later obtaining a long-term static private key is not enough to reconstruct the old session keys.

This is session-level forward secrecy. Veil Link does not implement the Signal Double Ratchet and therefore does not claim per-message post-compromise security.

## Metadata

The current transport does not hide:

- source and destination IP addresses
- connection time and duration
- approximate encrypted message sizes
- traffic volume

Protecting those properties requires a separate anonymity or mix-network layer and is outside this project.
