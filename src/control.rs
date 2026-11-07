use std::{
    ffi::OsString,
    io::{self, Write},
    os::unix::ffi::OsStringExt,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::{sleep, timeout},
};

use crate::{
    AnyError,
    quota::{Key, Ledger, Rule, State},
    reduced_ua,
};

const DEADLINE: Duration = Duration::from_secs(5);
const MAX_COMMAND: u64 = 128;

pub struct Address {
    name: OsString,
    uid: u32,
}

impl Address {
    pub fn new(instance: &str) -> Result<Self, AnyError> {
        if instance.is_empty()
            || instance.len() > 64
            || !instance
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err("--instance must be 1–64 letters, digits, hyphens, or underscores".into());
        }
        // geteuid has no arguments or memory safety preconditions.
        let uid = unsafe { libc::geteuid() };
        let name = OsString::from_vec(format!("\0blockade.{uid}.{instance}").into_bytes());
        Ok(Self { name, uid })
    }

    pub fn bind(&self) -> Result<UnixListener, AnyError> {
        UnixListener::bind(&self.name).map_err(|err| format!("bind control socket: {err}").into())
    }

    pub async fn serve(
        self,
        listener: UnixListener,
        ledger: Arc<Mutex<Ledger>>,
        state: Arc<State>,
    ) {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    eprintln!("control accept: {error}");
                    sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            if stream.peer_cred().is_ok_and(|peer| peer.uid() == self.uid) {
                let _ = respond(stream, &ledger, &state).await;
            }
        }
    }
}

pub async fn call(address: Address, request: &str) -> Result<(), AnyError> {
    let response = timeout(DEADLINE, async {
        let mut stream = UnixStream::connect(&address.name)
            .await
            .map_err(|err| format!("connect to blockade proxy: {err}"))?;
        if stream.peer_cred()?.uid() != address.uid {
            return Err("control socket is owned by a different user".into());
        }
        stream.write_all(request.as_bytes()).await?;
        stream.shutdown().await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        Ok::<_, AnyError>(response)
    })
    .await??;
    match response.split_first() {
        Some((b'+', text)) => io::stdout().write_all(text)?,
        Some((b'-', text)) => {
            return Err(String::from_utf8_lossy(text).trim_end().to_owned().into());
        }
        _ => return Err("invalid control response".into()),
    }
    Ok(())
}

async fn respond(
    mut stream: UnixStream,
    ledger: &Arc<Mutex<Ledger>>,
    state: &Arc<State>,
) -> io::Result<()> {
    let mut request = String::new();
    let mut bounded = (&mut stream).take(MAX_COMMAND);
    timeout(DEADLINE, bounded.read_to_string(&mut request)).await??;
    let result = if request.len() < MAX_COMMAND as usize {
        execute(&request, ledger, state).await
    } else {
        Err("control command is too long".into())
    };
    let (status, text) = match result {
        Ok(report) => (b"+", report),
        Err(error) => (b"-", error),
    };
    timeout(DEADLINE, async {
        stream.write_all(status).await?;
        stream.write_all(text.as_bytes()).await
    })
    .await?
}

async fn execute(
    request: &str,
    ledger: &Arc<Mutex<Ledger>>,
    state: &Arc<State>,
) -> Result<String, String> {
    match request.split_once(' ') {
        None if request == "stats" => Ok(ledger.lock().unwrap().report(false)),
        None if request == "list" => Ok(ledger.lock().unwrap().report(true)),
        Some(("unblock", pair)) => {
            let (network, ua) = pair
                .split_once(' ')
                .ok_or("unblock requires a network and UA")?;
            let network = network.parse()?;
            let ua = reduced_ua(ua.as_bytes());
            let message = format!("unblocked {network} {ua}\n");
            if !state
                .update_blocks(ledger, Some(Key(network, ua)))
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())?
            {
                return Err("no automatic block for that network and UA".into());
            }
            Ok(message)
        }
        Some((command @ ("allow" | "reject" | "clear"), ua)) => {
            let ua = reduced_ua(ua.as_bytes());
            let (rule, message) = match command {
                "allow" => (Some(Rule::Allow), "allowed"),
                "reject" => (Some(Rule::Deny), "rejected"),
                _ => (None, "cleared"),
            };
            let result = format!("{message} {ua}\n");
            let (ledger, state) = (Arc::clone(ledger), Arc::clone(state));
            tokio::task::spawn_blocking(move || state.change_rule(&ledger, ua, rule))
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())?;
            Ok(result)
        }
        _ => Err("invalid control command".into()),
    }
}
