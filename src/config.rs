use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use hyper::{Uri, body::Bytes, header::HeaderValue};

use crate::AnyError;

pub const USAGE: &str = "\
Usage: blockade proxy --upstream URL --asn-db FILE [OPTIONS]
       blockade stats|list [--instance NAME]
       blockade allow|reject|clear UA [--instance NAME]
       blockade unblock ASN_OR_IP UA [--instance NAME]

Proxy options:
  --listen ADDR             Listen IP and port [127.0.0.1:8080]
  --interval-secs N          Seconds per interval [86400]
  --window-intervals N      Intervals per window, including current [30]
  --max-requests N          Requests per key per window [1000]
  --max-bytes N             Upload plus download bytes per key [67108864]
  --trusted-proxy IP        Ingress allowed to set one X-Forwarded-For IP
  --garbage-file FILE       Serve this file instead of returning 403 for denylisted UAs
  --instance NAME           Management socket suffix [default]
  --state-dir DIR           State directory [./blockade-state for default instance]
  --checkpoint-secs N       Seconds between quota checkpoints [5]
  --empty-allowlist         Start without built-in rules on first run";

pub struct Config {
    pub upstream: Uri,
    pub host: HeaderValue,
    pub asn_db: PathBuf,
    pub listen: SocketAddr,
    pub trusted_proxy: Option<IpAddr>,
    pub garbage: Option<Bytes>,
    pub interval_secs: u64,
    pub intervals: u64,
    pub max_requests: u64,
    pub max_bytes: u64,
    pub state_dir: PathBuf,
    pub checkpoint: Duration,
    pub empty_allowlist: bool,
}

impl Config {
    pub fn parse(instance: &str, args: &[OsString]) -> Result<Self, AnyError> {
        let mut upstream: Option<Uri> = None;
        let mut asn_db = None;
        let mut listen = SocketAddr::from(([127, 0, 0, 1], 8080));
        let mut trusted_proxy = None;
        let mut garbage_file = None;
        let mut interval_secs = 86_400;
        let mut intervals = 30;
        let mut max_requests = 1000;
        let mut max_bytes = 64 * 1024 * 1024;
        let mut state_dir = if instance == "default" {
            PathBuf::from("blockade-state")
        } else {
            PathBuf::from(format!("blockade-{instance}-state"))
        };
        let mut checkpoint_secs = 5;
        let mut empty_allowlist = false;
        let mut args = args.iter();
        while let Some(flag) = args.next() {
            let flag = flag.to_str().ok_or("invalid option name")?;
            if flag == "--empty-allowlist" {
                empty_allowlist = true;
                continue;
            }
            let arg = args
                .next()
                .filter(|arg| !arg.as_encoded_bytes().starts_with(b"--"))
                .ok_or_else(|| format!("{flag} requires a value"))?;
            match flag {
                "--upstream" => upstream = Some(parse(flag, arg)?),
                "--asn-db" => asn_db = Some(PathBuf::from(arg)),
                "--listen" => listen = parse(flag, arg)?,
                "--trusted-proxy" => {
                    trusted_proxy = Some(parse::<IpAddr>(flag, arg)?.to_canonical())
                }
                "--garbage-file" => garbage_file = Some(PathBuf::from(arg)),
                "--interval-secs" => interval_secs = positive(flag, arg, u64::MAX)?,
                "--window-intervals" => intervals = positive(flag, arg, 60)?,
                "--max-requests" => max_requests = positive(flag, arg, u64::MAX)?,
                "--max-bytes" => max_bytes = positive(flag, arg, u64::MAX)?,
                "--state-dir" => state_dir = PathBuf::from(arg),
                "--checkpoint-secs" => checkpoint_secs = positive(flag, arg, 86_400)?,
                _ => return Err(format!("unknown option {flag}").into()),
            }
        }

        let upstream = upstream.ok_or("proxy requires --upstream")?;
        let authority = upstream.authority().ok_or("--upstream requires a host")?;
        let host = authority.host();
        if upstream.scheme_str() != Some("http")
            || upstream.path() != "/"
            || upstream.query().is_some()
            || authority.as_str().contains('@')
            || host.is_empty()
            || (host.len() != authority.as_str().len()
                && authority.port_u16().is_none_or(|port| port == 0))
        {
            return Err("--upstream must be an http://host[:port] origin".into());
        }
        let host = HeaderValue::from_str(authority.as_str())?;
        let asn_db = asn_db.ok_or("proxy requires --asn-db")?;
        let garbage = garbage_file.as_deref().map(read_garbage).transpose()?;
        Ok(Self {
            upstream,
            host,
            asn_db,
            listen,
            trusted_proxy,
            garbage,
            interval_secs,
            intervals,
            max_requests,
            max_bytes,
            state_dir,
            checkpoint: Duration::from_secs(checkpoint_secs),
            empty_allowlist,
        })
    }
}

fn read_garbage(path: &Path) -> Result<Bytes, AnyError> {
    const MAX_GARBAGE: u64 = 16 * 1024 * 1024;
    let file_error = |error| format!("garbage file {}: {error}", path.display());
    let metadata = fs::metadata(path).map_err(file_error)?;
    if !metadata.is_file() || metadata.len() > MAX_GARBAGE {
        return Err("--garbage-file requires a regular file of at most 16 MiB".into());
    }
    let mut data = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .map_err(file_error)?
        .take(MAX_GARBAGE + 1)
        .read_to_end(&mut data)
        .map_err(file_error)?;
    if data.len() as u64 > MAX_GARBAGE {
        return Err("--garbage-file requires a regular file of at most 16 MiB".into());
    }
    Ok(Bytes::from(data))
}

fn parse<T: FromStr>(flag: &str, value: &OsStr) -> Result<T, AnyError> {
    value
        .to_str()
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| format!("invalid value for {flag}: {}", value.to_string_lossy()).into())
}

fn positive(flag: &str, value: &OsStr, max: u64) -> Result<u64, AnyError> {
    let n = parse(flag, value)?;
    if (1..=max).contains(&n) {
        Ok(n)
    } else {
        Err(format!("{flag} must be in 1..={max}").into())
    }
}
