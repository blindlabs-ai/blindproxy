use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::error::ProxyError;

const TOKEN_SCALE: u64 = 1_000;
const TOKEN_BITS: u32 = 26;
const TOKEN_MASK: u64 = (1u64 << TOKEN_BITS) - 1;
const TS_MAX: u64 = (1u64 << (64 - TOKEN_BITS)) - 2;

/// Maximum burst tokens representable in the packed 26-bit milli-token field.
pub const MAX_BURST_TOKENS: u64 = TOKEN_MASK / TOKEN_SCALE;

/// Lock-free, fixed-memory, power-of-2 sharded atomic token-bucket rate limiter.
///
/// Each shard stores a single `AtomicU64` packing `(last_refill_ms + 1, tokens_milli)`
/// updated strictly via CAS loops with zero mutexes and zero per-request allocations.
pub struct RateLimiter {
    shards: Box<[AtomicU64]>,
    mask: usize,
    rate_per_sec: u64,
    capacity_milli: u64,
    seed: u64,
    epoch: Instant,
}

impl RateLimiter {
    /// Creates a new sharded rate limiter with a randomized per-instance hash seed.
    ///
    /// Setting `rate_per_sec == 0` disables rate limiting cleanly.
    pub fn new(shards: usize, rate_per_sec: u64, burst: u64) -> Result<Self, ProxyError> {
        Self::with_seed(shards, rate_per_sec, burst, random_seed())
    }

    /// Creates a new sharded rate limiter with an explicit seed (useful for deterministic tests).
    pub fn with_seed(
        shards: usize,
        rate_per_sec: u64,
        burst: u64,
        seed: u64,
    ) -> Result<Self, ProxyError> {
        let table = init_shard_table(shards, "rate limit shards must be a power of 2", || {
            AtomicU64::new(0)
        })?;
        if rate_per_sec > 0 {
            if burst == 0 {
                return Err(ProxyError::Config("rate limit burst must be > 0 when rps > 0"));
            }
            if burst > MAX_BURST_TOKENS {
                return Err(ProxyError::Config("rate limit burst exceeds 67108 token limit"));
            }
        }
        Ok(Self {
            shards: table,
            mask: shards - 1,
            rate_per_sec,
            capacity_milli: burst.saturating_mul(TOKEN_SCALE),
            seed,
            epoch: Instant::now(),
        })
    }

    /// Returns the number of fixed atomic shards allocated.
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Attempts to consume 1 request token for `ip` using the limiter's monotonic clock.
    pub fn allow_ip(&self, ip: IpAddr) -> bool {
        if self.rate_per_sec == 0 {
            return true;
        }
        let elapsed = self.epoch.elapsed().as_millis();
        let now_ms = if elapsed > u128::from(TS_MAX) {
            TS_MAX
        } else {
            elapsed as u64
        };
        self.allow_ip_at(ip, now_ms)
    }

    /// Attempts to consume 1 request token for `ip` at an explicit monotonic millisecond timestamp.
    pub fn allow_ip_at(&self, ip: IpAddr, now_ms: u64) -> bool {
        if self.rate_per_sec == 0 {
            return true;
        }
        let bounded_now = now_ms.min(TS_MAX);
        let idx = self.shard_index(ip);
        let Some(slot) = self.shards.get(idx) else {
            return true;
        };
        let mut current = slot.load(Ordering::Acquire);

        loop {
            let (last_ms, tokens) = if current == 0 {
                (bounded_now, self.capacity_milli)
            } else {
                let stored_ts = current >> TOKEN_BITS;
                let last_ms = stored_ts.saturating_sub(1);
                let tokens = current & TOKEN_MASK;
                (last_ms, tokens)
            };

            let elapsed_ms = bounded_now.saturating_sub(last_ms);
            // Since 1 token == 1000 milli-tokens, rate_per_sec tokens/sec == rate_per_sec milli-tokens/ms.
            let refill = elapsed_ms.saturating_mul(self.rate_per_sec);
            let available = tokens.saturating_add(refill).min(self.capacity_milli);

            if available < TOKEN_SCALE {
                return false;
            }

            let next_tokens = available - TOKEN_SCALE;
            let next_ms = bounded_now.max(last_ms);
            let next_packed = ((next_ms + 1) << TOKEN_BITS) | (next_tokens & TOKEN_MASK);

            match slot.compare_exchange_weak(
                current,
                next_packed,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    /// Maps an IP address to a bounded shard index.
    ///
    /// IPv4-mapped IPv6 addresses normalize to IPv4, and native IPv6 addresses
    /// bucket by their `/64` network prefix to prevent `/64` spray evasion.
    fn shard_index(&self, ip: IpAddr) -> usize {
        ip_shard_index(ip, self.seed, self.mask)
    }
}

/// Lock-free, fixed-memory, power-of-2 sharded atomic per-IP active-connection tracker.
///
/// Each shard holds a single `AtomicU32` counter updated strictly via CAS loops
/// with zero mutexes and zero per-connection heap allocations.
pub struct IpConnLimiter {
    shards: Box<[AtomicU32]>,
    mask: usize,
    max_conns_per_ip: u32,
    seed: u64,
}

/// RAII guard for an active per-IP connection slot.
///
/// Atomically decrements the exact `AtomicU32` shard on `Drop` with zero heap
/// allocations and zero mutexes.
pub struct ConnGuard {
    limiter: Arc<IpConnLimiter>,
    shard_idx: usize,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Some(slot) = self.limiter.shards.get(self.shard_idx) {
            slot.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl IpConnLimiter {
    /// Creates a new sharded per-IP connection limiter with a randomized hash seed.
    pub fn new(shards: usize, max_conns_per_ip: u32) -> Result<Self, ProxyError> {
        Self::with_seed(shards, max_conns_per_ip, random_seed())
    }

    /// Creates a new sharded per-IP connection limiter with an explicit seed (for deterministic tests).
    pub fn with_seed(
        shards: usize,
        max_conns_per_ip: u32,
        seed: u64,
    ) -> Result<Self, ProxyError> {
        if max_conns_per_ip == 0 {
            return Err(ProxyError::Config("max_conns_per_ip must be > 0"));
        }
        let table = init_shard_table(shards, "per-ip conn shards must be a power of 2", || {
            AtomicU32::new(0)
        })?;
        Ok(Self {
            shards: table,
            mask: shards - 1,
            max_conns_per_ip,
            seed,
        })
    }

    /// Returns the number of fixed atomic shards allocated.
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    /// Returns the maximum concurrent connections permitted per IP shard.
    pub fn max_conns_per_ip(&self) -> u32 {
        self.max_conns_per_ip
    }

    /// Returns the current active connection count in the shard for `ip`.
    pub fn active_for_ip(&self, ip: IpAddr) -> u32 {
        let idx = ip_shard_index(ip, self.seed, self.mask);
        self.shards.get(idx).map_or(0, |s| s.load(Ordering::Acquire))
    }

    /// Attempts to acquire one active connection slot for `ip` using a lock-free CAS loop.
    ///
    /// Returns an RAII `ConnGuard` that decrements the shard atomically on `Drop`, or `None`
    /// if the shard is already at `max_conns_per_ip`.
    pub fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<ConnGuard> {
        let idx = ip_shard_index(ip, self.seed, self.mask);
        let slot = self.shards.get(idx)?;
        let mut current = slot.load(Ordering::Acquire);

        loop {
            if current >= self.max_conns_per_ip {
                return None;
            }
            match slot.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(ConnGuard {
                        limiter: Arc::clone(self),
                        shard_idx: idx,
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

fn init_shard_table<T>(
    shards: usize,
    err_msg: &'static str,
    make: impl Fn() -> T,
) -> Result<Box<[T]>, ProxyError> {
    if shards == 0 || !shards.is_power_of_two() {
        return Err(ProxyError::Config(err_msg));
    }
    let mut table = Vec::with_capacity(shards);
    for _ in 0..shards {
        table.push(make());
    }
    Ok(table.into_boxed_slice())
}

fn random_seed() -> u64 {
    let state = RandomState::new();
    let mut hasher = state.build_hasher();
    hasher.write_u64(0x9e37_79b9_7f4a_7c15);
    hasher.finish()
}

fn ip_shard_index(ip: IpAddr, seed: u64, mask: usize) -> usize {
    let key = match ip {
        IpAddr::V4(v4) => u64::from(u32::from(v4)) | (1u64 << 32),
        IpAddr::V6(v6) => normalize_v6_key(v6),
    };
    (fmix64(key ^ seed) as usize) & mask
}

fn normalize_v6_key(v6: Ipv6Addr) -> u64 {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return u64::from(u32::from(v4)) | (1u64 << 32);
    }
    let octets = v6.octets();
    let prefix64 = u64::from_be_bytes([
        octets[0], octets[1], octets[2], octets[3], octets[4], octets[5], octets[6], octets[7],
    ]);
    prefix64 ^ (2u64 << 62)
}

#[inline]
const fn fmix64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    x ^ (x >> 33)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn burst_and_refill_exactness() {
        let limiter = RateLimiter::with_seed(64, 10, 5, 42).expect("valid limiter");
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));

        for _ in 0..5 {
            assert!(limiter.allow_ip_at(ip, 1_000));
        }
        assert!(!limiter.allow_ip_at(ip, 1_000));
        assert!(!limiter.allow_ip_at(ip, 1_099));

        // At 10 rps, 100 ms accrues exactly 1 token.
        assert!(limiter.allow_ip_at(ip, 1_100));
        assert!(!limiter.allow_ip_at(ip, 1_100));

        // After 1 second, bucket caps at burst = 5 (never exceeds capacity).
        for _ in 0..5 {
            assert!(limiter.allow_ip_at(ip, 2_100));
        }
        assert!(!limiter.allow_ip_at(ip, 2_100));
    }

    fn aliased_ip_pairs() -> [(IpAddr, IpAddr); 2] {
        [
            (
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                IpAddr::V6(Ipv4Addr::new(192, 0, 2, 10).to_ipv6_mapped()),
            ),
            (
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0x0002, 0, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0x0001, 0x0002, 0xffff, 0, 0, 99)),
            ),
        ]
    }

    #[test]
    fn ipv4_mapped_and_v6_prefix_normalization() {
        let limiter = RateLimiter::with_seed(1024, 1, 2, 99).expect("valid limiter");
        for (a, b) in aliased_ip_pairs() {
            assert!(limiter.allow_ip_at(a, 100));
            assert!(limiter.allow_ip_at(b, 100));
            assert!(!limiter.allow_ip_at(a, 100));
        }
    }

    #[test]
    fn validation_and_disabled_mode() {
        assert!(RateLimiter::with_seed(0, 10, 10, 1).is_err());
        assert!(RateLimiter::with_seed(3, 10, 10, 1).is_err());
        assert!(RateLimiter::with_seed(16, 10, 0, 1).is_err());
        assert!(RateLimiter::with_seed(16, 10, MAX_BURST_TOKENS + 1, 1).is_err());

        let disabled = RateLimiter::with_seed(16, 0, 0, 1).expect("disabled limiter");
        assert_eq!(disabled.shard_count(), 16);
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for _ in 0..32 {
            assert!(disabled.allow_ip_at(ip, 0));
        }
    }

    #[test]
    fn concurrent_cas_grants_exact_burst() {
        let limiter = Arc::new(RateLimiter::with_seed(64, 5, 20, 777).expect("limiter"));
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let lim = Arc::clone(&limiter);
            handles.push(thread::spawn(move || {
                let mut granted = 0usize;
                for _ in 0..16 {
                    if lim.allow_ip_at(ip, 500) {
                        granted += 1;
                    }
                }
                granted
            }));
        }
        let mut total_granted = 0usize;
        for h in handles {
            total_granted += h.join().expect("worker joined");
        }
        assert_eq!(total_granted, 20);
    }

    #[test]
    fn ip_conn_limiter_cap_and_raii_drop() {
        let limiter = Arc::new(IpConnLimiter::with_seed(1024, 2, 12345).expect("valid limiter"));
        assert_eq!(limiter.shard_count(), 1024);
        assert_eq!(limiter.max_conns_per_ip(), 2);

        let ip_a = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        let ip_b = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11));

        assert_eq!(limiter.active_for_ip(ip_a), 0);
        let g1 = limiter.try_acquire(ip_a).expect("1st slot");
        assert_eq!(limiter.active_for_ip(ip_a), 1);
        let g2 = limiter.try_acquire(ip_a).expect("2nd slot");
        assert_eq!(limiter.active_for_ip(ip_a), 2);

        // Counterfactual: 3rd concurrent slot for ip_a MUST be rejected.
        assert!(limiter.try_acquire(ip_a).is_none());
        assert_eq!(limiter.active_for_ip(ip_a), 2);

        // Independent IP still succeeds cleanly.
        let gb = limiter.try_acquire(ip_b).expect("ip_b slot");
        assert_eq!(limiter.active_for_ip(ip_b), 1);

        // Dropping g1 immediately frees 1 slot for ip_a.
        drop(g1);
        assert_eq!(limiter.active_for_ip(ip_a), 1);
        let g3 = limiter.try_acquire(ip_a).expect("re-acquired slot after drop");
        assert_eq!(limiter.active_for_ip(ip_a), 2);
        assert!(limiter.try_acquire(ip_a).is_none());

        drop(g2);
        drop(g3);
        drop(gb);
        assert_eq!(limiter.active_for_ip(ip_a), 0);
        assert_eq!(limiter.active_for_ip(ip_b), 0);
    }

    #[test]
    fn ip_conn_limiter_ipv4_mapped_and_v6_prefix() {
        let limiter = Arc::new(IpConnLimiter::with_seed(1024, 2, 99).expect("valid limiter"));
        for (a, b) in aliased_ip_pairs() {
            let g1 = limiter.try_acquire(a).expect("first slot");
            let g2 = limiter.try_acquire(b).expect("aliased second slot");
            assert!(limiter.try_acquire(a).is_none());
            drop((g1, g2));
            assert_eq!(limiter.active_for_ip(a), 0);
        }
    }

    #[test]
    fn ip_conn_limiter_validation_and_concurrent_cas() {
        assert!(IpConnLimiter::with_seed(0, 2, 1).is_err());
        assert!(IpConnLimiter::with_seed(3, 2, 1).is_err());
        assert!(IpConnLimiter::with_seed(16, 0, 1).is_err());

        let limiter = Arc::new(IpConnLimiter::with_seed(64, 2, 777).expect("limiter"));
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let peak = Arc::new(AtomicU32::new(0));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let lim = Arc::clone(&limiter);
            let pk = Arc::clone(&peak);
            handles.push(thread::spawn(move || {
                let mut acquired = 0usize;
                for _ in 0..16 {
                    if let Some(guard) = lim.try_acquire(ip) {
                        let cur = lim.active_for_ip(ip);
                        pk.fetch_max(cur, Ordering::AcqRel);
                        assert!(cur <= 2);
                        acquired += 1;
                        thread::yield_now();
                        drop(guard);
                    }
                }
                acquired
            }));
        }
        let mut total = 0usize;
        for h in handles {
            total += h.join().expect("worker joined");
        }
        assert!(total > 0);
        assert!(peak.load(Ordering::Acquire) <= 2);
        assert_eq!(limiter.active_for_ip(ip), 0);
    }
}
