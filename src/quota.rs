mod state;
pub use state::State;

use std::{
    collections::{BTreeMap, HashMap, VecDeque, hash_map::Entry},
    fmt::{self, Write},
    io,
    net::IpAddr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Network {
    Asn(u32),
    Ip(IpAddr),
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Asn(asn) => write!(f, "AS{asn}"),
            Self::Ip(ip) => ip.fmt(f),
        }
    }
}

impl FromStr for Network {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = "network must be an ASN (such as AS123) or IP address";
        let asn = value
            .strip_prefix("AS")
            .or_else(|| value.strip_prefix("as"));
        if let Some(asn) = asn {
            return asn.parse().map(Self::Asn).map_err(|_| invalid);
        }
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Ok(Self::Ip(ip.to_canonical()));
        }
        value.parse().map(Self::Asn).map_err(|_| invalid)
    }
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key(pub Network, pub String);

#[derive(Clone, Copy)]
pub struct Policy {
    pub start: Instant,
    pub epoch: Duration,
    pub interval_secs: u64,
    pub intervals: u64,
    pub max_requests: u64,
    pub max_bytes: u64,
}

impl Policy {
    fn tick(self) -> u64 {
        self.epoch.saturating_add(self.start.elapsed()).as_secs() / self.interval_secs
    }

    fn oldest(self, tick: u64) -> u64 {
        tick.saturating_sub(self.intervals - 1)
    }
}

pub struct Ledger {
    policy: Policy,
    keys: HashMap<Arc<Key>, Window>,
    rules: BTreeMap<String, Rule>,
    last_sweep: u64,
    dirty: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    Allow,
    Deny,
}

impl Rule {
    fn name(self) -> &'static str {
        match self {
            Self::Allow => "allowlist",
            Self::Deny => "denylist",
        }
    }
}

pub enum Denial {
    Quota,
    Pending,
    Manual,
}

impl Ledger {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            keys: HashMap::new(),
            rules: BTreeMap::new(),
            last_sweep: 0,
            dirty: true,
        }
    }

    fn admit(&mut self, key: Key) -> Result<Arc<Key>, Denial> {
        let rule = self.rules.get(&key.1).copied();
        if rule == Some(Rule::Deny) {
            return Err(Denial::Manual);
        }
        let tick = self.policy.tick();
        if tick != self.last_sweep {
            let oldest = self.policy.oldest(tick);
            self.keys.retain(|key, window| {
                window.block.is_some()
                    || Arc::strong_count(key) > 1
                    || window.buckets.back().is_some_and(|b| b.tick >= oldest)
            });
            self.last_sweep = tick;
        }

        let mut entry = match self.keys.entry(Arc::new(key)) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(entry) => entry.insert_entry(Window::default()),
        };
        let window = entry.get_mut();
        let admitted = window.admit(self.policy, tick, rule == Some(Rule::Allow));
        self.dirty |= admitted;
        if admitted {
            Ok(Arc::clone(entry.key()))
        } else {
            Err(window.block.unwrap().denial())
        }
    }

    pub fn report(&mut self, list: bool) -> String {
        let mut output = if list {
            String::from("NETWORK\tUA\tREASON\n")
        } else {
            String::from("NETWORK\tUA\tREQUESTS\tBYTES\tSTATE\n")
        };
        if list {
            for (ua, rule) in &self.rules {
                writeln!(output, "*\t{ua}\t{}", rule.name()).unwrap();
            }
        }

        let tick = self.policy.tick();
        let mut entries: Vec<_> = self.keys.iter_mut().collect();
        entries.sort_unstable_by_key(|(key, _)| *key);
        for (key, window) in entries {
            window.expire(self.policy, tick);
            let reason = window.block.map(|block| block.reason);
            let rule = self.rules.get(&key.1);
            if list {
                if let Some(reason) = reason {
                    writeln!(output, "{}\t{}\t{reason}", key.0, key.1).unwrap();
                }
            } else if !window.buckets.is_empty() || reason.is_some() {
                let state = reason.unwrap_or_else(|| rule.map_or("open", |rule| rule.name()));
                writeln!(
                    output,
                    "{}\t{}\t{}\t{}\t{state}",
                    key.0, key.1, window.requests, window.bytes
                )
                .unwrap();
            }
        }
        output
    }
}

#[derive(Clone)]
pub struct Meter {
    ledger: Arc<Mutex<Ledger>>,
    state: Arc<State>,
    key: Arc<Key>,
}

impl Meter {
    pub fn admit(
        ledger: &Arc<Mutex<Ledger>>,
        state: &Arc<State>,
        key: Key,
    ) -> Result<Self, Denial> {
        let key = ledger.lock().unwrap().admit(key)?;
        Ok(Self {
            ledger: Arc::clone(ledger),
            state: Arc::clone(state),
            key,
        })
    }

    pub fn transfer(&self, bytes: usize) -> Transfer {
        let mut ledger = self.ledger.lock().unwrap();
        let policy = ledger.policy;
        let rule = ledger.rules.get(&self.key.1).copied();
        if rule == Some(Rule::Deny) {
            return Transfer::Stop;
        }
        let passed = ledger.keys.get_mut(&self.key).unwrap().transfer(
            policy,
            policy.tick(),
            bytes,
            rule == Some(Rule::Allow),
        );
        ledger.dirty |= matches!(passed, Transfer::Pass | Transfer::Commit { forward: true });
        passed
    }

    pub fn denial(&self) -> Option<Denial> {
        let ledger = self.ledger.lock().unwrap();
        if ledger.rules.get(&self.key.1) == Some(&Rule::Deny) {
            return Some(Denial::Manual);
        }
        ledger.keys.get(&self.key).unwrap().block.map(Block::denial)
    }

    pub fn commit(&self) -> tokio::task::JoinHandle<io::Result<bool>> {
        self.state.update_blocks(&self.ledger, None)
    }
}

pub enum Transfer {
    Pass,
    Stop,
    Commit { forward: bool },
}

#[derive(Clone, Copy)]
struct Block {
    reason: &'static str,
    durable: bool,
}

impl Block {
    fn denial(self) -> Denial {
        if self.durable {
            Denial::Quota
        } else {
            Denial::Pending
        }
    }
}

#[derive(Clone, Default)]
struct Window {
    buckets: VecDeque<Bucket>,
    requests: u128,
    bytes: u128,
    block: Option<Block>,
}

#[derive(Clone, Default)]
struct Bucket {
    tick: u64,
    requests: u128,
    bytes: u128,
}

impl Window {
    fn expire(&mut self, policy: Policy, tick: u64) {
        let oldest = policy.oldest(tick);
        while self.buckets.front().is_some_and(|b| b.tick < oldest) {
            let bucket = self.buckets.pop_front().unwrap();
            self.requests -= bucket.requests;
            self.bytes -= bucket.bytes;
        }
    }

    fn reason(&self, policy: Policy) -> Option<&'static str> {
        if self.bytes > u128::from(policy.max_bytes) {
            Some("bytes")
        } else if self.requests > u128::from(policy.max_requests) {
            Some("requests")
        } else {
            None
        }
    }

    fn admit(&mut self, policy: Policy, tick: u64, exempt: bool) -> bool {
        self.expire(policy, tick);
        if self.block.is_some() {
            return false;
        }
        if !exempt {
            let reason = self.reason(policy).or_else(|| {
                (self.requests == u128::from(policy.max_requests)).then_some("requests")
            });
            if let Some(reason) = reason {
                self.block = Some(Block {
                    reason,
                    durable: false,
                });
                return false;
            }
        }
        self.bucket(tick).requests += 1;
        self.requests += 1;
        true
    }

    fn transfer(&mut self, policy: Policy, tick: u64, bytes: usize, exempt: bool) -> Transfer {
        self.expire(policy, tick);
        if self.block.is_some() {
            return Transfer::Stop;
        }
        if !exempt && let Some(reason) = self.reason(policy) {
            self.block = Some(Block {
                reason,
                durable: false,
            });
            return Transfer::Commit { forward: false };
        }
        // The frame crossing the byte limit is counted and can pass.
        self.bucket(tick).bytes += bytes as u128;
        self.bytes += bytes as u128;
        if !exempt && self.bytes > u128::from(policy.max_bytes) {
            self.block = Some(Block {
                reason: "bytes",
                durable: false,
            });
            Transfer::Commit { forward: true }
        } else {
            Transfer::Pass
        }
    }

    fn bucket(&mut self, tick: u64) -> &mut Bucket {
        if self.buckets.back().is_none_or(|b| b.tick != tick) {
            self.buckets.push_back(Bucket {
                tick,
                ..Bucket::default()
            });
        }
        self.buckets.back_mut().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> Policy {
        Policy {
            start: Instant::now(),
            epoch: Duration::ZERO,
            interval_secs: 1,
            intervals: 3,
            max_requests: 2,
            max_bytes: 5,
        }
    }

    #[test]
    fn first_excess_request_blocks_even_after_buckets_expire() {
        let policy = policy();
        let mut window = Window::default();
        assert!(window.admit(policy, 0, false));
        assert!(window.admit(policy, 1, false));
        assert!(!window.admit(policy, 1, false));
        assert!(matches!(
            window.transfer(policy, 1, 1, false),
            Transfer::Stop
        ));
        assert!(!window.admit(policy, 2, false));
        assert!(!window.admit(policy, 4, true));
        assert_eq!(window.requests, 0);
    }

    #[test]
    fn byte_frames_share_the_window_and_only_the_first_excess_frame_passes() {
        let policy = policy();
        let mut window = Window::default();
        assert!(matches!(
            window.transfer(policy, 0, 2, false),
            Transfer::Pass
        ));
        assert!(matches!(
            window.transfer(policy, 1, 3, false),
            Transfer::Pass
        ));
        assert!(window.admit(policy, 1, false));
        assert!(matches!(
            window.transfer(policy, 1, 1, false),
            Transfer::Commit { forward: true }
        ));
        assert!(matches!(
            window.transfer(policy, 2, 1, false),
            Transfer::Stop
        ));
        assert!(!window.admit(policy, 2, false));
        assert!(!window.admit(policy, 3, false));
        assert_eq!(window.bytes, 4);
    }
}
