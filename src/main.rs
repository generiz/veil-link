use anyhow::{anyhow, bail, Context, Result};
use blake2::{Blake2s256, Digest};
use clap::{Parser, Subcommand};
use snow::{Builder, HandshakeState, TransportState};
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const HANDSHAKE_BUFFER: usize = 65535;
const MESSAGE_LIMIT: usize = 32768;

#[derive(Parser)]
#[command(name = "veil-link", version, about = "Peer-to-peer encrypted terminal channel")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Keygen {
        #[arg(long, default_value = "veil-link.key")]
        out: PathBuf,
    },
    Listen {
        #[arg(long, default_value = "0.0.0.0:9443")]
        bind: String,
        #[arg(long, default_value = "veil-link.key")]
        key: PathBuf,
        #[arg(long)]
        expect: Option<String>,
    },
    Connect {
        #[arg(long)]
        addr: String,
        #[arg(long, default_value = "veil-link.key")]
        key: PathBuf,
        #[arg(long)]
        expect: Option<String>,
    },
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct Identity {
    private: [u8; 32],
    public: [u8; 32],
}

impl Identity {
    fn generate() -> Result<Self> {
        let secret = StaticSecret::random_from_rng(rand_core::OsRng);
        let public = PublicKey::from(&secret);
        Ok(Self {
            private: secret.to_bytes(),
            public: public.to_bytes(),
        })
    }

    fn load(path: &Path) -> Result<Self> {
        let data = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        if data.len() != 32 {
            bail!("identity file has invalid length");
        }
        let mut private = [0u8; 32];
        private.copy_from_slice(&data);
        let secret = StaticSecret::from(private);
        let public = PublicKey::from(&secret).to_bytes();
        Ok(Self { private, public })
    }

    fn save(&self, path: &Path) -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(path)
            .with_context(|| format!("cannot create {}", path.display()))?;
        file.write_all(&self.private)?;
        file.sync_all()?;
        Ok(())
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Keygen { out } => {
            let identity = Identity::generate()?;
            identity.save(&out)?;
            println!("identity: {}", fingerprint(&identity.public));
            println!("stored: {}", out.display());
            Ok(())
        }
        Command::Listen { bind, key, expect } => {
            let identity = Identity::load(&key)?;
            println!("identity: {}", fingerprint(&identity.public));
            let listener = TcpListener::bind(&bind).with_context(|| format!("cannot bind {bind}"))?;
            println!("listening: {bind}");
            let (mut stream, peer) = listener.accept()?;
            println!("peer: {peer}");
            let session = responder_handshake(&mut stream, &identity, expect.as_deref())?;
            run_session(stream, session)
        }
        Command::Connect { addr, key, expect } => {
            let identity = Identity::load(&key)?;
            println!("identity: {}", fingerprint(&identity.public));
            let mut stream = TcpStream::connect(&addr).with_context(|| format!("cannot connect to {addr}"))?;
            let session = initiator_handshake(&mut stream, &identity, expect.as_deref())?;
            run_session(stream, session)
        }
    }
}

fn initiator_handshake(stream: &mut TcpStream, identity: &Identity, expect: Option<&str>) -> Result<TransportState> {
    let mut noise = build_handshake(identity, true)?;
    let mut buf = vec![0u8; HANDSHAKE_BUFFER];

    let len = noise.write_message(&[], &mut buf)?;
    write_frame(stream, &buf[..len])?;

    let msg = read_frame(stream)?;
    noise.read_message(&msg, &mut buf)?;

    let len = noise.write_message(&[], &mut buf)?;
    write_frame(stream, &buf[..len])?;

    verify_remote(&noise, expect)?;
    Ok(noise.into_transport_mode()?)
}

fn responder_handshake(stream: &mut TcpStream, identity: &Identity, expect: Option<&str>) -> Result<TransportState> {
    let mut noise = build_handshake(identity, false)?;
    let mut buf = vec![0u8; HANDSHAKE_BUFFER];

    let msg = read_frame(stream)?;
    noise.read_message(&msg, &mut buf)?;

    let len = noise.write_message(&[], &mut buf)?;
    write_frame(stream, &buf[..len])?;

    let msg = read_frame(stream)?;
    noise.read_message(&msg, &mut buf)?;

    verify_remote(&noise, expect)?;
    Ok(noise.into_transport_mode()?)
}

fn build_handshake(identity: &Identity, initiator: bool) -> Result<HandshakeState> {
    let params = NOISE_PATTERN.parse()?;
    let builder = Builder::new(params).local_private_key(&identity.private);
    if initiator {
        Ok(builder.build_initiator()?)
    } else {
        Ok(builder.build_responder()?)
    }
}

fn verify_remote(noise: &HandshakeState, expect: Option<&str>) -> Result<()> {
    let remote = noise.get_remote_static().ok_or_else(|| anyhow!("remote identity unavailable"))?;
    let actual = fingerprint(remote);
    println!("remote fingerprint: {actual}");
    if let Some(expected) = expect {
        if normalize_fingerprint(expected) != normalize_fingerprint(&actual) {
            bail!("remote fingerprint mismatch");
        }
        println!("remote identity verified");
    } else {
        println!("identity not pinned; verify this fingerprint out of band before trusting the session");
    }
    Ok(())
}

fn run_session(stream: TcpStream, transport: TransportState) -> Result<()> {
    let state = Arc::new(Mutex::new(transport));
    let mut rx = stream.try_clone()?;
    let rx_state = Arc::clone(&state);

    let reader = thread::spawn(move || -> Result<()> {
        loop {
            let frame = match read_frame(&mut rx) {
                Ok(frame) => frame,
                Err(err) if is_disconnect(&err) => return Ok(()),
                Err(err) => return Err(err),
            };
            let mut plaintext = vec![0u8; frame.len()];
            let len = rx_state.lock().map_err(|_| anyhow!("session state poisoned"))?.read_message(&frame, &mut plaintext)?;
            println!("peer> {}", String::from_utf8_lossy(&plaintext[..len]));
        }
    });

    let stdin = io::stdin();
    let mut tx = stream;
    for line in stdin.lock().lines() {
        let line = line?;
        if line == "/quit" {
            break;
        }
        if line.len() > MESSAGE_LIMIT {
            eprintln!("message exceeds {MESSAGE_LIMIT} bytes");
            continue;
        }
        let mut ciphertext = vec![0u8; line.len() + 64];
        let len = state.lock().map_err(|_| anyhow!("session state poisoned"))?.write_message(line.as_bytes(), &mut ciphertext)?;
        write_frame(&mut tx, &ciphertext[..len])?;
    }

    let _ = tx.shutdown(Shutdown::Both);
    drop(tx);
    match reader.join() {
        Ok(result) => result,
        Err(_) => bail!("receiver thread terminated unexpectedly"),
    }
}

fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| anyhow!("frame too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len == 0 || len > HANDSHAKE_BUFFER {
        bail!("invalid frame length");
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

fn fingerprint(public_key: &[u8]) -> String {
    let digest = Blake2s256::digest(public_key);
    let encoded = hex::encode(digest);
    encoded
        .as_bytes()
        .chunks(4)
        .take(8)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join(":")
}

fn normalize_fingerprint(value: &str) -> String {
    value.chars().filter(|c| c.is_ascii_hexdigit()).flat_map(char::to_lowercase).collect()
}

fn is_disconnect(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .map(|io_err| matches!(io_err.kind(), io::ErrorKind::UnexpectedEof | io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe))
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noise_xx_roundtrip() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let mut initiator = build_handshake(&alice, true).unwrap();
        let mut responder = build_handshake(&bob, false).unwrap();
        let mut a = vec![0u8; HANDSHAKE_BUFFER];
        let mut b = vec![0u8; HANDSHAKE_BUFFER];

        let n = initiator.write_message(&[], &mut a).unwrap();
        responder.read_message(&a[..n], &mut b).unwrap();
        let n = responder.write_message(&[], &mut b).unwrap();
        initiator.read_message(&b[..n], &mut a).unwrap();
        let n = initiator.write_message(&[], &mut a).unwrap();
        responder.read_message(&a[..n], &mut b).unwrap();

        assert_eq!(initiator.get_remote_static().unwrap(), bob.public);
        assert_eq!(responder.get_remote_static().unwrap(), alice.public);

        let mut tx = initiator.into_transport_mode().unwrap();
        let mut rx = responder.into_transport_mode().unwrap();
        let plaintext = b"intercepted traffic should not reveal this";
        let n = tx.write_message(plaintext, &mut a).unwrap();
        let m = rx.read_message(&a[..n], &mut b).unwrap();
        assert_eq!(&b[..m], plaintext);
    }

    #[test]
    fn fingerprint_is_stable_and_normalized() {
        let key = [7u8; 32];
        let fp = fingerprint(&key);
        assert_eq!(normalize_fingerprint(&fp).len(), 32);
        assert_eq!(normalize_fingerprint(&fp.to_uppercase()), normalize_fingerprint(&fp));
    }
}
