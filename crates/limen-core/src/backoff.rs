//! Exponential backoff with full jitter (AWS Architecture Blog, "Exponential
//! Backoff And Jitter"): sleep = random(0, min(cap, base * 2^attempt)).

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Backoff {
    base: Duration,
    cap: Duration,
    attempt: u32,
}

impl Backoff {
    #[must_use]
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self {
            base,
            cap,
            attempt: 0,
        }
    }

    /// Next delay to wait. `jitter` must be uniform in [0, 1). It's passed in
    /// so tests are deterministic.
    pub fn next_delay(&mut self, jitter: f64) -> Duration {
        let exp = self
            .base
            .saturating_mul(1u32.checked_shl(self.attempt.min(31)).unwrap_or(u32::MAX));
        let ceiling = exp.min(self.cap);
        self.attempt = self.attempt.saturating_add(1);
        ceiling.mul_f64(jitter.clamp(0.0, 1.0))
    }

    /// Ceiling for the next attempt, without jitter. Exposed for tests and logs.
    #[must_use]
    pub fn current_ceiling(&self) -> Duration {
        let exp = self
            .base
            .saturating_mul(1u32.checked_shl(self.attempt.min(31)).unwrap_or(u32::MAX));
        exp.min(self.cap)
    }

    /// Call after a successful connection.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_exponentially_and_caps() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
        let ceilings: Vec<u64> = (0..10)
            .map(|_| {
                let c = b.current_ceiling().as_secs();
                b.next_delay(0.5);
                c
            })
            .collect();
        assert_eq!(ceilings, [1, 2, 4, 8, 16, 32, 60, 60, 60, 60]);
    }

    #[test]
    fn jitter_scales_within_ceiling_and_reset_restarts() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
        assert_eq!(b.next_delay(0.0), Duration::ZERO);
        assert_eq!(b.next_delay(0.5), Duration::from_secs(1));
        b.reset();
        assert_eq!(b.current_ceiling(), Duration::from_secs(1));
    }

    #[test]
    fn many_attempts_do_not_overflow() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
        for _ in 0..1000 {
            assert!(b.next_delay(0.99) <= Duration::from_secs(60));
        }
    }
}
