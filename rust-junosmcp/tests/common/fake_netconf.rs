//! Loopback NETCONF-over-SSH responder for integration tests.
//!
//! Lets the real binary dial `127.0.0.1:<port>`, authenticate, open the
//! `netconf` subsystem, exchange `<hello>`s and run RPCs against a scripted
//! table, so lock / commit / rollback failure paths run end to end in CI with
//! no device. The binary verifies the host key exactly as in production: the
//! test writes [`FakeNetconf::known_hosts_line`] to a file and passes it with
//! `--known-hosts-file`. Any public key is accepted for auth.

use russh::keys::{Algorithm, PrivateKey, PublicKeyBase64, key::safe_rng, ssh_key::LineEnding};
use russh::server::{Auth, Config, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId};
use std::sync::{Arc, Mutex};

/// `<ok/>` reply body.
pub const OK: &str = "<ok/>";

/// An `<rpc-error>` reply body with the given message.
pub fn rpc_error(message: &str) -> String {
    format!(
        "<rpc-error><error-type>protocol</error-type><error-tag>operation-failed</error-tag>\
         <error-severity>error</error-severity><error-message>{message}</error-message></rpc-error>"
    )
}

/// Ordered `(substring of the request, reply body)` table; first match wins.
/// An unmatched RPC gets an `<rpc-error>` so a missing entry fails loudly.
pub type Script = Vec<(&'static str, String)>;

/// A running fake device. The accept loop dies with the test process.
pub struct FakeNetconf {
    pub port: u16,
    known_hosts_line: String,
    requests: Arc<Mutex<Vec<String>>>,
}

impl FakeNetconf {
    /// Bind 127.0.0.1:0 and serve `script` on a background thread.
    pub fn start(script: Script) -> Self {
        let host_key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
        let blob = host_key.public_key().public_key_base64();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut server = Fake {
            script: Arc::new(script),
            requests: requests.clone(),
        };
        let config = Arc::new(Config {
            keys: vec![host_key],
            auth_rejection_time: std::time::Duration::from_millis(1),
            ..Default::default()
        });
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async move {
                    let socket = tokio::net::TcpListener::from_std(listener).unwrap();
                    let _ = server.run_on_socket(config, &socket).await;
                });
        });
        Self {
            port,
            known_hosts_line: format!("[127.0.0.1]:{port} ssh-ed25519 {blob}\n"),
            requests,
        }
    }

    /// A known_hosts entry trusting this server's host key.
    pub fn known_hosts_line(&self) -> &str {
        &self.known_hosts_line
    }

    /// Every RPC received so far, as raw XML.
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }

    /// True if any received RPC contains `needle`.
    pub fn saw(&self, needle: &str) -> bool {
        self.requests().iter().any(|r| r.contains(needle))
    }
}

/// An OpenSSH-format ed25519 private key the client can really load.
pub fn client_key_pem() -> String {
    let key = PrivateKey::random(&mut safe_rng(), Algorithm::Ed25519).unwrap();
    key.to_openssh(LineEnding::LF).unwrap().to_string()
}

#[derive(Clone)]
struct Fake {
    script: Arc<Script>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl Server for Fake {
    type Handler = Conn;
    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Conn {
        Conn {
            fake: self.clone(),
            buf: Vec::new(),
            chunked: None,
        }
    }
}

struct Conn {
    fake: Fake,
    buf: Vec<u8>,
    /// `None` until the client's hello arrives; then whether 1.1 chunking was negotiated.
    chunked: Option<bool>,
}

const EOM: &str = "]]>]]>";
const HELLO: &str = r#"<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability><capability>urn:ietf:params:netconf:base:1.1</capability><capability>urn:ietf:params:netconf:capability:candidate:1.0</capability><capability>urn:ietf:params:netconf:capability:confirmed-commit:1.1</capability><capability>urn:ietf:params:netconf:capability:validate:1.1</capability></capabilities><session-id>1</session-id></hello>"#;

fn chunk(body: &str) -> String {
    format!("\n#{}\n{body}\n##\n", body.len())
}

impl Conn {
    /// Pop one complete message off the buffer, if there is one.
    fn next_message(&mut self) -> Option<String> {
        if self.chunked == Some(true) {
            let mut message = Vec::new();
            let mut pos = 0;
            loop {
                let rest = &self.buf[pos..];
                if rest.starts_with(b"\n##\n") {
                    self.buf.drain(..pos + 4);
                    return Some(String::from_utf8_lossy(&message).into_owned());
                }
                let header_end = rest.iter().skip(2).position(|&b| b == b'\n')? + 2;
                let len: usize = std::str::from_utf8(rest.get(2..header_end)?)
                    .ok()?
                    .parse()
                    .ok()?;
                let data = rest.get(header_end + 1..header_end + 1 + len)?;
                message.extend_from_slice(data);
                pos += header_end + 1 + len;
            }
        }
        let text = String::from_utf8_lossy(&self.buf).into_owned();
        let end = text.find(EOM)?;
        self.buf.drain(..end + EOM.len());
        Some(text[..end].to_string())
    }

    fn reply_for(&self, request: &str) -> String {
        self.fake.requests.lock().unwrap().push(request.to_string());
        let message_id = request
            .split("message-id=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap_or("1");
        let body = self
            .fake
            .script
            .iter()
            .find(|(needle, _)| request.contains(needle))
            .map(|(_, body)| body.clone())
            .unwrap_or_else(|| rpc_error("fake-netconf: unscripted rpc"));
        format!(
            "<rpc-reply message-id=\"{message_id}\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">{body}</rpc-reply>"
        )
    }
}

impl Handler for Conn {
    type Error = russh::Error;

    async fn auth_publickey(
        &mut self,
        _: &str,
        _: russh::server::VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name != "netconf" {
            return session.channel_failure(channel);
        }
        session.channel_success(channel)?;
        session.data(channel, format!("{HELLO}{EOM}").into_bytes())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.buf.extend_from_slice(data);
        while let Some(message) = self.next_message() {
            if self.chunked.is_none() {
                // The client's hello: 1.1 framing only if it offers 1.1 too.
                self.chunked = Some(message.contains("netconf:base:1.1"));
                continue;
            }
            let reply = self.reply_for(&message);
            let framed = if self.chunked == Some(true) {
                chunk(&reply)
            } else {
                format!("{reply}{EOM}")
            };
            session.data(channel, framed.into_bytes())?;
        }
        Ok(())
    }
}
