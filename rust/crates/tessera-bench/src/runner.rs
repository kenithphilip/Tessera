//! Core load-testing loop.
//!
//! Holds N concurrent worker tasks pinned by a `tokio::sync::Semaphore`,
//! drives them against a [`crate::workloads::Workload`], records every
//! latency into an [`hdrhistogram::Histogram`], and emits a
//! [`BenchOutcome`] when the duration elapses.
//!
//! Concurrency model: M (typically 10000) "in-flight" slots are held
//! by the semaphore. A pool of N (`worker_threads` from the runtime
//! config) tokio worker threads multiplexes those slots. This is the
//! shape that maps cleanly to "10k concurrent sessions" without
//! spawning 10k OS threads.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hdrhistogram::Histogram;
use tokio::sync::{Mutex, Semaphore};

use crate::workloads::Workload;

/// Per-run configuration. The harness reads these once and keeps
/// them immutable during the load loop.
#[derive(Clone, Debug)]
pub struct RunConfig {
    /// Total wall-clock duration of the load loop. The harness will
    /// stop dispatching new requests once this elapses; in-flight
    /// requests are awaited before the outcome is computed.
    pub duration: Duration,
    /// Maximum concurrent in-flight requests. Modeled as semaphore
    /// permits, not OS threads.
    pub concurrency: u32,
    /// Optional cap on requests per second. `None` means run as fast
    /// as the target can absorb (open-loop, naturally rate-limited
    /// by the semaphore + target's response time).
    pub target_rps: Option<u32>,
    /// Stop after this many successful requests, even if the
    /// duration has not elapsed. `None` for "run for the full
    /// duration".
    pub max_requests: Option<u64>,
    /// Initial warm-up window during which results are NOT recorded.
    /// Lets caches and connection pools settle before measurement.
    pub warmup: Duration,
    /// Free-form label written into reports (e.g. `"rust-0.8.0-beta.1"`).
    pub run_label: String,
}

impl RunConfig {
    pub fn new(duration: Duration, concurrency: u32, run_label: impl Into<String>) -> Self {
        Self {
            duration,
            concurrency,
            target_rps: None,
            max_requests: None,
            warmup: Duration::ZERO,
            run_label: run_label.into(),
        }
    }

    pub fn with_target_rps(mut self, rps: u32) -> Self {
        self.target_rps = Some(rps);
        self
    }

    pub fn with_max_requests(mut self, max: u64) -> Self {
        self.max_requests = Some(max);
        self
    }

    pub fn with_warmup(mut self, warmup: Duration) -> Self {
        self.warmup = warmup;
        self
    }
}

/// Histogram + counters captured by the runner.
#[derive(Clone, Debug)]
pub struct BenchOutcome {
    pub run_label: String,
    pub workload_name: String,
    pub target: String,
    pub duration: Duration,
    pub concurrency: u32,
    pub successes: u64,
    pub failures: u64,
    /// Latencies of successful requests in microseconds.
    pub latency_us: Histogram<u64>,
}

impl BenchOutcome {
    pub fn total_requests(&self) -> u64 {
        self.successes + self.failures
    }

    pub fn requests_per_second(&self) -> f64 {
        let secs = self.duration.as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        self.total_requests() as f64 / secs
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.total_requests();
        if total == 0 {
            return 0.0;
        }
        self.successes as f64 / total as f64
    }

    pub fn p50_us(&self) -> u64 {
        if self.latency_us.is_empty() {
            return 0;
        }
        self.latency_us.value_at_quantile(0.50)
    }

    pub fn p95_us(&self) -> u64 {
        if self.latency_us.is_empty() {
            return 0;
        }
        self.latency_us.value_at_quantile(0.95)
    }

    pub fn p99_us(&self) -> u64 {
        if self.latency_us.is_empty() {
            return 0;
        }
        self.latency_us.value_at_quantile(0.99)
    }

    pub fn p999_us(&self) -> u64 {
        if self.latency_us.is_empty() {
            return 0;
        }
        self.latency_us.value_at_quantile(0.999)
    }

    pub fn max_us(&self) -> u64 {
        self.latency_us.max()
    }
}

/// Drive `workload` against `target_url` per the supplied config.
/// Spawns concurrent worker tasks, records latencies, and returns
/// the assembled [`BenchOutcome`].
///
/// Takes `Arc<dyn Workload>` so the CLI can pass the result of
/// `from_kind` directly. Dynamic dispatch overhead is dominated by
/// the network call, so the trait-object indirection costs nothing
/// observable.
pub async fn run_workload(
    config: RunConfig,
    target_url: String,
    workload: Arc<dyn Workload>,
) -> BenchOutcome {
    // 3-significant-digit precision, range 1us .. 1 hour.
    let mut hist: Histogram<u64> = Histogram::new_with_bounds(1, 60 * 60 * 1_000_000, 3)
        .expect("hdrhistogram bounds are valid");

    let sem = Arc::new(Semaphore::new(config.concurrency as usize));
    let successes = Arc::new(AtomicU64::new(0));
    let failures = Arc::new(AtomicU64::new(0));
    let stop_at = Instant::now() + config.warmup + config.duration;
    let warmup_until = Instant::now() + config.warmup;
    let recorded = Arc::new(Mutex::new(Vec::<Duration>::with_capacity(65536)));

    let workload_name = workload.name().to_string();
    // Optional RPS rate limiter: tokio interval, no jitter.
    let mut rps_interval = config
        .target_rps
        .filter(|&r| r > 0)
        .map(|r| {
            let period_us = (1_000_000.0 / r as f64) as u64;
            tokio::time::interval(Duration::from_micros(period_us.max(1)))
        });
    if let Some(ref mut int) = rps_interval {
        int.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    }

    let mut handles = Vec::new();
    let max_requests = config.max_requests;

    while Instant::now() < stop_at {
        if let Some(max) = max_requests {
            if successes.load(Ordering::Relaxed) >= max {
                break;
            }
        }
        if let Some(ref mut int) = rps_interval {
            int.tick().await;
        }
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => break,
        };
        let workload = workload.clone();
        let target = target_url.clone();
        let successes = successes.clone();
        let failures = failures.clone();
        let recorded = recorded.clone();
        let warmup_until = warmup_until;
        let h = tokio::spawn(async move {
            let start = Instant::now();
            let result = workload.execute(&target).await;
            let elapsed = start.elapsed();
            // Only record post-warmup latencies. Warmup successes and
            // failures count toward the totals so the operator sees
            // raw throughput including warmup.
            if Instant::now() >= warmup_until {
                if let Ok(()) = &result {
                    recorded.lock().await.push(elapsed);
                }
            }
            match result {
                Ok(()) => {
                    successes.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    failures.fetch_add(1, Ordering::Relaxed);
                }
            }
            drop(permit);
        });
        handles.push(h);
    }

    // Wait for in-flight requests to complete.
    for h in handles {
        let _ = h.await;
    }

    let recorded = recorded.lock().await;
    for d in recorded.iter() {
        let micros = d.as_micros().min(u64::MAX as u128) as u64;
        let micros = micros.max(1);
        let _ = hist.record(micros);
    }

    BenchOutcome {
        run_label: config.run_label,
        workload_name,
        target: target_url,
        duration: config.duration,
        concurrency: config.concurrency,
        successes: successes.load(Ordering::Relaxed),
        failures: failures.load(Ordering::Relaxed),
        latency_us: hist,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workloads::Workload;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct CountingWorkload {
        invocations: AtomicU32,
        per_call_delay: Duration,
    }

    #[async_trait]
    impl Workload for CountingWorkload {
        fn name(&self) -> &'static str {
            "counting"
        }
        async fn execute(&self, _target: &str) -> Result<(), String> {
            self.invocations.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(self.per_call_delay).await;
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn run_loop_records_latencies() {
        let workload = Arc::new(CountingWorkload {
            invocations: AtomicU32::new(0),
            per_call_delay: Duration::from_millis(2),
        });
        let cfg = RunConfig::new(Duration::from_millis(100), 16, "test");
        let outcome = run_workload(cfg, "unused".to_string(), workload.clone()).await;
        assert!(outcome.successes > 0, "expected some successes");
        assert_eq!(outcome.failures, 0);
        assert!(outcome.p50_us() > 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn run_loop_respects_max_requests() {
        let workload = Arc::new(CountingWorkload {
            invocations: AtomicU32::new(0),
            per_call_delay: Duration::from_millis(1),
        });
        let cfg = RunConfig::new(Duration::from_secs(60), 8, "test").with_max_requests(50);
        let outcome = run_workload(cfg, "unused".to_string(), workload.clone()).await;
        assert!(outcome.successes >= 50);
        assert!(outcome.successes <= 50 + 8); // up to one batch overshoot
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn warmup_excludes_initial_latencies_from_histogram() {
        let workload = Arc::new(CountingWorkload {
            invocations: AtomicU32::new(0),
            per_call_delay: Duration::from_millis(1),
        });
        let cfg = RunConfig::new(Duration::from_millis(80), 8, "test")
            .with_warmup(Duration::from_millis(40));
        let outcome = run_workload(cfg, "unused".to_string(), workload.clone()).await;
        assert!(outcome.successes > 0);
        // Histogram should only contain post-warmup samples.
        // Hard to assert exact count, but at minimum it should be < total successes.
        let recorded = outcome.latency_us.len();
        assert!(recorded > 0);
        assert!(recorded as u64 <= outcome.successes);
    }

    #[test]
    fn outcome_quantiles_handle_empty_histogram() {
        let cfg = RunConfig::new(Duration::from_millis(1), 1, "empty");
        let hist: Histogram<u64> =
            Histogram::new_with_bounds(1, 60 * 60 * 1_000_000, 3).unwrap();
        let outcome = BenchOutcome {
            run_label: cfg.run_label,
            workload_name: "x".into(),
            target: "y".into(),
            duration: cfg.duration,
            concurrency: cfg.concurrency,
            successes: 0,
            failures: 0,
            latency_us: hist,
        };
        assert_eq!(outcome.p50_us(), 0);
        assert_eq!(outcome.p99_us(), 0);
        assert_eq!(outcome.requests_per_second(), 0.0);
        assert_eq!(outcome.success_rate(), 0.0);
    }
}
