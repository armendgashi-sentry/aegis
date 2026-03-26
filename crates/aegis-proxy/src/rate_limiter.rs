use std::num::NonZeroU32;
use std::sync::Arc;

use dashmap::DashMap;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};

/// Per-target rate limiter using token bucket algorithm.
pub struct ProxyRateLimiter {
    limiters: DashMap<String, Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>>,
    rps: NonZeroU32,
    burst: NonZeroU32,
    per_target: bool,
    global: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
}

impl ProxyRateLimiter {
    pub fn new(rps: u32, burst: u32, per_target: bool) -> Self {
        let rps = NonZeroU32::new(rps).unwrap_or(NonZeroU32::new(10).unwrap());
        let burst = NonZeroU32::new(burst).unwrap_or(NonZeroU32::new(50).unwrap());

        let quota = Quota::per_second(rps).allow_burst(burst);
        let global = Arc::new(RateLimiter::direct(quota));

        Self {
            limiters: DashMap::new(),
            rps,
            burst,
            per_target,
            global,
        }
    }

    /// Check if a request to the given host is allowed under rate limits.
    pub fn check(&self, host: &str) -> bool {
        if self.per_target {
            let limiter = self
                .limiters
                .entry(host.to_string())
                .or_insert_with(|| {
                    let quota = Quota::per_second(self.rps).allow_burst(self.burst);
                    Arc::new(RateLimiter::direct(quota))
                })
                .clone();

            limiter.check().is_ok()
        } else {
            self.global.check().is_ok()
        }
    }
}
