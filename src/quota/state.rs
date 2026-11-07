use std::{
    collections::BTreeMap,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, BufRead, BufReader, BufWriter, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use super::{Block, Bucket, Key, Ledger, MAX_KEYS, Rule, Window};

const RULES: &str = "rules.tsv";
const QUOTAS: &str = "quotas.tsv";
const BLOCKS: &str = "blocks.tsv";
const DEFAULT_ALLOWLIST: &[&str] = &[
    "curl",
    "wget",
    "httpie",
    "python-requests",
    "go-http-client",
    "mozilla",
    "okhttp",
];

pub struct State {
    path: PathBuf,
    directory: File,
    _lock: File,
    block_updates: tokio::sync::Mutex<()>,
    quota_writer: Mutex<()>,
}

impl State {
    pub fn open(path: PathBuf, ledger: &mut Ledger, empty_allowlist: bool) -> io::Result<Self> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&path)?;
        let directory = File::open(&path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path.join(".lock"))?;
        lock.try_lock()
            .map_err(|error| io::Error::other(format!("lock state directory: {error}")))?;
        let state = Self {
            path,
            directory,
            _lock: lock,
            block_updates: tokio::sync::Mutex::new(()),
            quota_writer: Mutex::new(()),
        };

        if let Some(file) = open_existing(&state.path.join(RULES), 2 * 1024 * 1024)? {
            for line in file.lines() {
                let line = line?;
                let (kind, ua) = line.split_once('\t').ok_or_else(bad_state)?;
                let rule = match kind {
                    "allowlist" => Rule::Allow,
                    "denylist" => Rule::Deny,
                    _ => return Err(bad_state()),
                };
                if !valid_ua(ua)
                    || ledger.rules.len() == MAX_KEYS
                    || ledger.rules.insert(ua.into(), rule).is_some()
                {
                    return Err(bad_state());
                }
            }
        } else {
            if !empty_allowlist {
                ledger.rules.extend(
                    DEFAULT_ALLOWLIST
                        .iter()
                        .map(|ua| (String::from(*ua), Rule::Allow)),
                );
            }
            state.write_rules(&ledger.rules)?;
        }
        let blocks = open_existing(&state.path.join(BLOCKS), 2 * 1024 * 1024)?;
        if let Some(file) = open_existing(&state.path.join(QUOTAS), 128 * 1024 * 1024)? {
            restore_quotas(file, ledger, blocks.is_none())?;
        }
        if let Some(file) = blocks {
            for line in file.lines() {
                let line = line?;
                let [reason, network, ua] = fields(&line)?;
                let reason = match reason {
                    "requests" => "requests",
                    "bytes" => "bytes",
                    _ => return Err(bad_state()),
                };
                if !valid_ua(ua) {
                    return Err(bad_state());
                }
                let key = Key(network.parse().map_err(|_| bad_state())?, ua.into());
                if ledger.keys.len() == MAX_KEYS && !ledger.keys.contains_key(&key) {
                    return Err(bad_state());
                }
                let window = ledger.keys.entry(key.into()).or_default();
                if window
                    .block
                    .replace(Block {
                        reason,
                        durable: true,
                    })
                    .is_some()
                {
                    return Err(bad_state());
                }
            }
        } else {
            let blocks = block_rows(ledger, None);
            state.write_blocks(&blocks)?;
            mark_committed(ledger, &blocks);
        }
        Ok(state)
    }

    pub fn change_rule(
        &self,
        ledger: &Mutex<Ledger>,
        ua: String,
        rule: Option<Rule>,
    ) -> io::Result<()> {
        let mut rules = ledger.lock().unwrap().rules.clone();
        let previous = match rule {
            Some(rule) => {
                if rules.len() == MAX_KEYS && !rules.contains_key(&ua) {
                    return Err(io::Error::other("UA rule table is full"));
                }
                rules.insert(ua, rule)
            }
            None => rules.remove(&ua),
        };
        if previous != rule {
            self.write_rules(&rules)?;
            ledger.lock().unwrap().rules = rules;
        }
        Ok(())
    }

    fn write_rules(&self, rules: &BTreeMap<String, Rule>) -> io::Result<()> {
        self.replace(RULES, |file| {
            for (ua, rule) in rules {
                writeln!(file, "{}\t{ua}", rule.name())?;
            }
            Ok(())
        })
    }

    pub fn checkpoint(&self, ledger: &Mutex<Ledger>) -> io::Result<()> {
        let _writer = self.quota_writer.lock().unwrap();
        let (interval_secs, tick, windows) = {
            let mut ledger = ledger.lock().unwrap();
            if !ledger.dirty {
                return Ok(());
            }
            let policy = ledger.policy;
            let tick = policy.tick();
            let windows = ledger
                .keys
                .iter_mut()
                .filter_map(|(key, window)| {
                    window.expire(policy, tick);
                    (!window.buckets.is_empty()).then(|| (key.as_ref().clone(), window.clone()))
                })
                .collect::<Vec<_>>();
            ledger.dirty = false;
            (policy.interval_secs, tick, windows)
        };
        let result = self.replace(QUOTAS, |file| {
            writeln!(file, "blockade-quotas-1\t{interval_secs}\t{tick}")?;
            for (key, window) in windows {
                writeln!(
                    file,
                    "K\t{}\t{}\t{}",
                    key.0,
                    key.1,
                    u8::from(window.block.is_some_and(|block| block.reason == "requests"))
                )?;
                for bucket in window.buckets {
                    writeln!(
                        file,
                        "B\t{}\t{}\t{}",
                        bucket.tick, bucket.requests, bucket.bytes
                    )?;
                }
            }
            Ok(())
        });
        if result.is_err() {
            ledger.lock().unwrap().dirty = true;
        }
        result
    }

    pub fn update_blocks(
        self: &Arc<Self>,
        ledger: &Arc<Mutex<Ledger>>,
        unblock: Option<Key>,
    ) -> tokio::task::JoinHandle<io::Result<bool>> {
        let (state, ledger) = (Arc::clone(self), Arc::clone(ledger));
        tokio::spawn(async move {
            let _guard = state.block_updates.lock().await;
            let writer = Arc::clone(&state);
            tokio::task::spawn_blocking(move || writer.commit_blocks(&ledger, unblock.as_ref()))
                .await
                .map_err(io::Error::other)?
        })
    }

    pub fn commit_blocks(&self, ledger: &Mutex<Ledger>, unblock: Option<&Key>) -> io::Result<bool> {
        let blocks = {
            let mut ledger = ledger.lock().unwrap();
            if let Some(key) = unblock {
                let Some(window) = ledger.keys.get_mut(key) else {
                    return Ok(false);
                };
                if window.block.is_none() {
                    return Ok(false);
                }
                *window = Window {
                    block: window.block,
                    ..Window::default()
                };
                ledger.dirty = true;
            } else if !ledger
                .keys
                .values()
                .any(|window| window.block.is_some_and(|block| !block.durable))
            {
                return Ok(false);
            }
            block_rows(&ledger, unblock)
        };
        // Checkpoint the reset before dropping the block, so a restart cannot
        // resurrect the quota that caused an acknowledged block removal.
        if unblock.is_some() {
            self.checkpoint(ledger)?;
        }
        self.write_blocks(&blocks)?;
        let mut ledger = ledger.lock().unwrap();
        if let Some(key) = unblock {
            ledger.keys.get_mut(key).unwrap().block = None;
        }
        mark_committed(&mut ledger, &blocks);
        Ok(true)
    }

    fn write_blocks(&self, blocks: &[(Key, &'static str)]) -> io::Result<()> {
        self.replace(BLOCKS, |file| {
            for (key, reason) in blocks {
                writeln!(file, "{reason}\t{}\t{}", key.0, key.1)?;
            }
            Ok(())
        })
    }

    fn replace(
        &self,
        name: &str,
        write: impl FnOnce(&mut BufWriter<File>) -> io::Result<()>,
    ) -> io::Result<()> {
        let temp = self.path.join(format!("{name}.tmp"));
        match fs::remove_file(&temp) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        let result = (|| {
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            let mut file = BufWriter::new(file);
            write(&mut file)?;
            file.flush()?;
            file.get_ref().sync_all()?;
            fs::rename(&temp, self.path.join(name))
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
            return result;
        }
        if let Err(error) = self.directory.sync_all() {
            eprintln!("sync state directory: {error}");
        }
        Ok(())
    }
}

fn block_rows(ledger: &Ledger, skip: Option<&Key>) -> Vec<(Key, &'static str)> {
    ledger
        .keys
        .iter()
        .filter_map(|(key, window)| {
            if skip == Some(key.as_ref()) {
                return None;
            }
            window
                .block
                .map(|block| (key.as_ref().clone(), block.reason))
        })
        .collect()
}

fn mark_committed(ledger: &mut Ledger, blocks: &[(Key, &'static str)]) {
    for (key, _) in blocks {
        ledger
            .keys
            .get_mut(key)
            .unwrap()
            .block
            .as_mut()
            .unwrap()
            .durable = true;
    }
}

fn open_existing(path: &Path, limit: u64) -> io::Result<Option<BufReader<File>>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(bad_state());
    }
    Ok(Some(BufReader::new(file)))
}

fn restore_quotas(file: impl BufRead, ledger: &mut Ledger, migrate_blocks: bool) -> io::Result<()> {
    let mut lines = file.lines();
    let header = lines.next().ok_or_else(bad_state)??;
    let ["blockade-quotas-1", interval_secs, saved_tick] = fields(&header)? else {
        return Err(bad_state());
    };
    let interval_secs: u64 = number(interval_secs)?;
    let saved_tick: u64 = number(saved_tick)?;
    if interval_secs != ledger.policy.interval_secs {
        eprintln!("state interval changed; starting with empty quota counters");
        return Ok(());
    }
    if saved_tick > ledger.policy.tick() {
        ledger.policy.epoch = Duration::from_secs(
            saved_tick
                .checked_mul(interval_secs)
                .ok_or_else(bad_state)?,
        );
        ledger.policy.start = Instant::now();
    }
    let tick = ledger.policy.tick();

    let mut entry: Option<(Key, Window, bool)> = None;
    for line in lines {
        let line = line?;
        match fields(&line)? {
            ["K", network, ua, blocked] => {
                restore_window(ledger, tick, entry.take(), migrate_blocks)?;
                if !valid_ua(ua) || !matches!(blocked, "0" | "1") {
                    return Err(bad_state());
                }
                let network = network.parse().map_err(|_| bad_state())?;
                entry = Some((Key(network, ua.into()), Window::default(), blocked == "1"));
            }
            ["B", bucket_tick, requests, bytes] => {
                let (_, window, _) = entry.as_mut().ok_or_else(bad_state)?;
                let bucket = Bucket {
                    tick: number(bucket_tick)?,
                    requests: u128::from(number::<u64>(requests)?),
                    bytes: u128::from(number::<u64>(bytes)?),
                };
                if bucket.tick > saved_tick
                    || window.buckets.len() == 60
                    || window
                        .buckets
                        .back()
                        .is_some_and(|previous| previous.tick >= bucket.tick)
                {
                    return Err(bad_state());
                }
                window.requests = window
                    .requests
                    .checked_add(bucket.requests)
                    .ok_or_else(bad_state)?;
                window.bytes = window
                    .bytes
                    .checked_add(bucket.bytes)
                    .ok_or_else(bad_state)?;
                window.buckets.push_back(bucket);
            }
            _ => return Err(bad_state()),
        }
    }
    restore_window(ledger, tick, entry, migrate_blocks)
}

fn restore_window(
    ledger: &mut Ledger,
    tick: u64,
    entry: Option<(Key, Window, bool)>,
    migrate_blocks: bool,
) -> io::Result<()> {
    if let Some((key, mut window, request_blocked)) = entry {
        window.expire(ledger.policy, tick);
        if migrate_blocks && ledger.rules.get(&key.1) != Some(&Rule::Allow) {
            let reason = window.reason(ledger.policy).or_else(|| {
                (request_blocked && window.requests == u128::from(ledger.policy.max_requests))
                    .then_some("requests")
            });
            window.block = reason.map(|reason| Block {
                reason,
                durable: false,
            });
        }
        if !window.buckets.is_empty()
            && (ledger.keys.len() == MAX_KEYS || ledger.keys.insert(key.into(), window).is_some())
        {
            return Err(bad_state());
        }
    }
    Ok(())
}

fn fields<const N: usize>(line: &str) -> io::Result<[&str; N]> {
    let mut parts = line.split('\t');
    let fields = std::array::from_fn(|_| parts.next().unwrap_or(""));
    if fields.contains(&"") || parts.next().is_some() {
        return Err(bad_state());
    }
    Ok(fields)
}

fn number<T: std::str::FromStr>(text: &str) -> io::Result<T> {
    text.parse().map_err(|_| bad_state())
}

fn valid_ua(ua: &str) -> bool {
    !ua.is_empty() && ua.len() <= 64 && ua.bytes().all(|byte| byte.is_ascii_graphic())
}

fn bad_state() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid blockade state file")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quota::Policy;

    #[test]
    fn restore_keeps_live_counts_and_request_block_after_downtime() {
        let mut ledger = Ledger::new(Policy {
            start: Instant::now(),
            epoch: Duration::from_secs(120),
            interval_secs: 10,
            intervals: 3,
            max_requests: 2,
            max_bytes: 20,
        });
        let checkpoint = b"blockade-quotas-1\t10\t11\nK\tAS123\tbot\t1\nB\t9\t1\t2\nB\t11\t2\t4\n";
        restore_quotas(checkpoint.as_slice(), &mut ledger, true).unwrap();
        assert!(
            ledger
                .report(false)
                .contains("AS123\tbot\t2\t4\trequests\n")
        );
    }
}
