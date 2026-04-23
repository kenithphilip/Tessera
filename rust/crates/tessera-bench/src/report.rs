//! Markdown + CSV emitters for [`crate::runner::BenchOutcome`].
//!
//! Every run prints a markdown summary to stdout. The same rows can
//! be appended to `rust/bench/results.md` and dumped to a CSV under
//! `rust/bench/results/<git-sha>-<timestamp>.csv` for Grafana
//! ingestion.

use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::Utc;

use crate::runner::BenchOutcome;

/// Bundle of outcomes that share a header (typically one outcome
/// per `compare` invocation, or many for `sustained`).
#[derive(Clone, Debug)]
pub struct BenchReport {
    pub title: String,
    pub generated_at: String,
    pub outcomes: Vec<BenchOutcome>,
}

impl BenchReport {
    pub fn new(title: impl Into<String>, outcomes: Vec<BenchOutcome>) -> Self {
        Self {
            title: title.into(),
            generated_at: Utc::now().to_rfc3339(),
            outcomes,
        }
    }
}

/// Render the report as a markdown table suitable for stdout and
/// for appending to `bench/results.md`.
pub fn format_markdown_table(report: &BenchReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("\n## {}\n\n", report.title));
    out.push_str(&format!("Generated: `{}`\n\n", report.generated_at));
    out.push_str("| Run | Workload | Target | Duration | Concurrency | Successes | Failures | RPS | p50 ms | p95 ms | p99 ms | p99.9 ms | max ms | Success rate |\n");
    out.push_str("|-----|----------|--------|----------|-------------|-----------|----------|-----|--------|--------|--------|----------|--------|--------------|\n");
    for o in &report.outcomes {
        out.push_str(&format!(
            "| `{}` | {} | `{}` | {:.1}s | {} | {} | {} | {:.0} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2}% |\n",
            o.run_label,
            o.workload_name,
            o.target,
            o.duration.as_secs_f64(),
            o.concurrency,
            o.successes,
            o.failures,
            o.requests_per_second(),
            o.p50_us() as f64 / 1000.0,
            o.p95_us() as f64 / 1000.0,
            o.p99_us() as f64 / 1000.0,
            o.p999_us() as f64 / 1000.0,
            o.max_us() as f64 / 1000.0,
            o.success_rate() * 100.0,
        ));
    }
    out
}

/// Append the markdown table to a results file. Creates the file
/// (and any parent dirs) if missing.
pub fn write_markdown_append(report: &BenchReport, path: impl AsRef<Path>) -> std::io::Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        create_dir_all(parent)?;
    }
    let body = format_markdown_table(report);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    file.write_all(body.as_bytes())?;
    Ok(())
}

/// Drop the report as a CSV at `dir/<sha>-<rfc3339>.csv`. Returns
/// the resolved path.
pub fn write_csv(
    report: &BenchReport,
    dir: impl AsRef<Path>,
    git_sha: Option<&str>,
) -> std::io::Result<PathBuf> {
    create_dir_all(dir.as_ref())?;
    let sha = git_sha.unwrap_or("unknown");
    let ts = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let filename = format!("{sha}-{ts}.csv");
    let path = dir.as_ref().join(filename);
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)?;
    writeln!(
        file,
        "title,run_label,workload,target,duration_seconds,concurrency,successes,failures,rps,p50_us,p95_us,p99_us,p999_us,max_us,success_rate,generated_at"
    )?;
    for o in &report.outcomes {
        writeln!(
            file,
            "{},{},{},{},{:.3},{},{},{},{:.3},{},{},{},{},{},{:.6},{}",
            csv_escape(&report.title),
            csv_escape(&o.run_label),
            o.workload_name,
            csv_escape(&o.target),
            o.duration.as_secs_f64(),
            o.concurrency,
            o.successes,
            o.failures,
            o.requests_per_second(),
            o.p50_us(),
            o.p95_us(),
            o.p99_us(),
            o.p999_us(),
            o.max_us(),
            o.success_rate(),
            report.generated_at,
        )?;
    }
    Ok(path)
}

fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::BenchOutcome;
    use hdrhistogram::Histogram;
    use std::time::Duration;

    fn outcome_with(p50_us: u64, p95_us: u64, successes: u64, failures: u64) -> BenchOutcome {
        let mut hist = Histogram::<u64>::new_with_bounds(1, 60_000_000_000, 3).unwrap();
        // Synthesize samples to match the requested p50/p95 roughly.
        for _ in 0..(successes / 2) {
            let _ = hist.record(p50_us);
        }
        for _ in 0..(successes / 2) {
            let _ = hist.record(p95_us);
        }
        BenchOutcome {
            run_label: "rust-test".into(),
            workload_name: "evaluate".into(),
            target: "http://localhost:8081".into(),
            duration: Duration::from_secs(10),
            concurrency: 100,
            successes,
            failures,
            latency_us: hist,
        }
    }

    #[test]
    fn markdown_table_renders_columns() {
        let report = BenchReport::new("test run", vec![outcome_with(100, 500, 100, 0)]);
        let s = format_markdown_table(&report);
        assert!(s.contains("test run"));
        assert!(s.contains("evaluate"));
        assert!(s.contains("rust-test"));
        // p50 of 100us is 0.10ms; rendered as 0.10.
        assert!(s.contains("0.10"));
    }

    #[test]
    fn write_markdown_append_creates_and_appends() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/results.md");
        let report = BenchReport::new("first", vec![outcome_with(100, 500, 50, 0)]);
        write_markdown_append(&report, &path).unwrap();
        let report2 = BenchReport::new("second", vec![outcome_with(200, 600, 50, 0)]);
        write_markdown_append(&report2, &path).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("first"));
        assert!(body.contains("second"));
    }

    #[test]
    fn write_csv_emits_header_and_row_per_outcome() {
        let dir = tempfile::tempdir().unwrap();
        let outcomes = vec![outcome_with(100, 500, 1000, 5), outcome_with(150, 600, 800, 0)];
        let report = BenchReport::new("compare", outcomes);
        let path = write_csv(&report, dir.path(), Some("abc123")).unwrap();
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert!(lines[0].starts_with("title,run_label,workload"));
        assert_eq!(lines.len(), 3);
        assert!(lines[1].contains("evaluate"));
        assert!(path.file_name().unwrap().to_string_lossy().starts_with("abc123-"));
    }

    #[test]
    fn csv_escape_handles_embedded_quotes_and_commas() {
        assert_eq!(csv_escape("simple"), "simple");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("she said \"hi\""), "\"she said \"\"hi\"\"\"");
    }
}
