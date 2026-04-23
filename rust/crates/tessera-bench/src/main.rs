//! Tessera bench harness binary entry point. See `--help` for full
//! subcommand list. Built on tokio + reqwest + hdrhistogram.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tessera_bench::report::{format_markdown_table, write_csv, write_markdown_append, BenchReport};
use tessera_bench::runner::{run_workload, RunConfig};
use tessera_bench::workloads::{from_kind, WorkloadKind};

#[derive(Parser, Debug)]
#[command(
    name = "tessera-bench",
    version,
    about = "Load harness for the Tessera Rust gateway and the Python AgentMesh proxy.",
    long_about = "Drives concurrent workloads against one or two HTTP targets and emits markdown + CSV reports.\n\nDuration accepts s/m/h suffixes (e.g. 60s, 5m). Concurrency is the cap on in-flight requests.\n\nExamples:\n  tessera-bench evaluate --target http://localhost:8081 --duration 30s --concurrency 100\n  tessera-bench mixed --target http://localhost:8081 --duration 60s --concurrency 1000 --warmup 5s\n  tessera-bench compare --rust-target http://localhost:8081 --python-target http://localhost:8082 --duration 60s --concurrency 1000"
)]
struct Cli {
    /// Append the markdown summary to this file.
    #[arg(long, global = true)]
    report_file: Option<PathBuf>,
    /// Drop a CSV under this directory (filename is `<git-sha>-<rfc3339>.csv`).
    #[arg(long, global = true)]
    csv_dir: Option<PathBuf>,
    /// Free-form git sha used in the CSV filename. Defaults to "unknown".
    #[arg(long, global = true)]
    git_sha: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run one workload against one target.
    Evaluate(SingleArgs),
    Label(SingleArgs),
    AuditVerify(SingleArgs),
    Mixed(SingleArgs),
    /// Long-duration soak. Same wire shape as `mixed` but reported
    /// distinctly. Defaults: 30 minute duration, 1000 concurrency.
    Sustained(SustainedArgs),
    /// Run the same workload against two targets and emit a
    /// side-by-side report.
    Compare(CompareArgs),
}

#[derive(clap::Args, Debug)]
struct SingleArgs {
    /// Target URL (e.g. `http://localhost:8081`).
    #[arg(long)]
    target: String,
    /// Total duration (s, m, h suffixes accepted).
    #[arg(long, default_value = "30s")]
    duration: String,
    /// Maximum concurrent in-flight requests.
    #[arg(long, default_value_t = 100)]
    concurrency: u32,
    /// Optional cap on requests per second.
    #[arg(long)]
    rps: Option<u32>,
    /// Stop after this many successful requests.
    #[arg(long)]
    max_requests: Option<u64>,
    /// Warm-up window. Latencies during this window are not recorded.
    #[arg(long, default_value = "0s")]
    warmup: String,
    /// Free-form label to identify this run in reports.
    #[arg(long, default_value = "rust-current")]
    run_label: String,
}

#[derive(clap::Args, Debug)]
struct SustainedArgs {
    #[arg(long)]
    target: String,
    #[arg(long, default_value = "30m")]
    duration: String,
    #[arg(long, default_value_t = 1000)]
    concurrency: u32,
    #[arg(long)]
    rps: Option<u32>,
    #[arg(long, default_value = "30s")]
    warmup: String,
    #[arg(long, default_value = "rust-sustained")]
    run_label: String,
}

#[derive(clap::Args, Debug)]
struct CompareArgs {
    /// First target (typically the Rust gateway).
    #[arg(long)]
    rust_target: String,
    /// Second target (typically the Python AgentMesh proxy).
    #[arg(long)]
    python_target: String,
    /// Workload to drive against both targets.
    #[arg(long, default_value = "mixed")]
    workload: String,
    #[arg(long, default_value = "60s")]
    duration: String,
    #[arg(long, default_value_t = 1000)]
    concurrency: u32,
    #[arg(long)]
    rps: Option<u32>,
    #[arg(long, default_value = "10s")]
    warmup: String,
    #[arg(long, default_value = "rust")]
    rust_label: String,
    #[arg(long, default_value = "python")]
    python_label: String,
}

fn parse_duration(input: &str) -> Result<Duration, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("empty duration".into());
    }
    let (value_str, unit) = match s.chars().last() {
        Some(c) if c.is_ascii_digit() => (s, "s"),
        Some(c) if "smh".contains(c) => (&s[..s.len() - 1], &s[s.len() - 1..]),
        Some(_) => return Err(format!("unknown duration suffix in {input:?}")),
        None => return Err("empty duration".into()),
    };
    let value: u64 = value_str
        .parse()
        .map_err(|e| format!("invalid duration number {value_str:?}: {e}"))?;
    Ok(match unit {
        "s" => Duration::from_secs(value),
        "m" => Duration::from_secs(value * 60),
        "h" => Duration::from_secs(value * 60 * 60),
        other => return Err(format!("unknown unit {other:?}")),
    })
}

fn build_run_config(
    duration_str: &str,
    concurrency: u32,
    rps: Option<u32>,
    max_requests: Option<u64>,
    warmup_str: &str,
    label: &str,
) -> Result<RunConfig, String> {
    let duration = parse_duration(duration_str)?;
    let warmup = parse_duration(warmup_str)?;
    let mut cfg = RunConfig::new(duration, concurrency, label).with_warmup(warmup);
    if let Some(r) = rps {
        cfg = cfg.with_target_rps(r);
    }
    if let Some(m) = max_requests {
        cfg = cfg.with_max_requests(m);
    }
    Ok(cfg)
}

async fn run_single(
    args: SingleArgs,
    kind: WorkloadKind,
    title: &str,
    cli: &Cli,
) -> Result<(), String> {
    let cfg = build_run_config(
        &args.duration,
        args.concurrency,
        args.rps,
        args.max_requests,
        &args.warmup,
        &args.run_label,
    )?;
    let workload = from_kind(kind);
    println!(
        "Running {} workload against {} for {:.1}s at concurrency {} ...",
        kind.as_str(),
        args.target,
        cfg.duration.as_secs_f64(),
        cfg.concurrency
    );
    let outcome = run_workload(cfg, args.target, workload).await;
    let report = BenchReport::new(title, vec![outcome]);
    print!("{}", format_markdown_table(&report));
    if let Some(path) = &cli.report_file {
        if let Err(e) = write_markdown_append(&report, path) {
            eprintln!("warning: could not append markdown to {}: {e}", path.display());
        }
    }
    if let Some(dir) = &cli.csv_dir {
        match write_csv(&report, dir, cli.git_sha.as_deref()) {
            Ok(p) => eprintln!("CSV: {}", p.display()),
            Err(e) => eprintln!("warning: could not write CSV under {}: {e}", dir.display()),
        }
    }
    Ok(())
}

async fn run_sustained(args: SustainedArgs, cli: &Cli) -> Result<(), String> {
    let cfg = build_run_config(
        &args.duration,
        args.concurrency,
        args.rps,
        None,
        &args.warmup,
        &args.run_label,
    )?;
    let workload = from_kind(WorkloadKind::Sustained);
    println!(
        "Running sustained workload against {} for {:.1}s at concurrency {} (warmup {:.1}s) ...",
        args.target,
        cfg.duration.as_secs_f64(),
        cfg.concurrency,
        cfg.warmup.as_secs_f64(),
    );
    let outcome = run_workload(cfg, args.target, workload).await;
    let report = BenchReport::new("sustained", vec![outcome]);
    print!("{}", format_markdown_table(&report));
    if let Some(path) = &cli.report_file {
        if let Err(e) = write_markdown_append(&report, path) {
            eprintln!("warning: could not append markdown to {}: {e}", path.display());
        }
    }
    if let Some(dir) = &cli.csv_dir {
        match write_csv(&report, dir, cli.git_sha.as_deref()) {
            Ok(p) => eprintln!("CSV: {}", p.display()),
            Err(e) => eprintln!("warning: could not write CSV under {}: {e}", dir.display()),
        }
    }
    Ok(())
}

async fn run_compare(args: CompareArgs, cli: &Cli) -> Result<(), String> {
    let kind = WorkloadKind::parse(&args.workload)?;
    let workload_arc = from_kind(kind);
    // Reuse the same Arc across both runs; each call owns its own
    // semaphore + histograms.
    let workload_for_python: Arc<dyn tessera_bench::workloads::Workload> = workload_arc.clone();
    let workload_for_rust: Arc<dyn tessera_bench::workloads::Workload> = workload_arc;

    let rust_cfg = build_run_config(
        &args.duration,
        args.concurrency,
        args.rps,
        None,
        &args.warmup,
        &args.rust_label,
    )?;
    println!(
        "Compare A: {} workload against {} (label={}) ...",
        kind.as_str(),
        args.rust_target,
        args.rust_label
    );
    let rust_outcome = run_workload(rust_cfg, args.rust_target, workload_for_rust).await;

    let python_cfg = build_run_config(
        &args.duration,
        args.concurrency,
        args.rps,
        None,
        &args.warmup,
        &args.python_label,
    )?;
    println!(
        "Compare B: {} workload against {} (label={}) ...",
        kind.as_str(),
        args.python_target,
        args.python_label
    );
    let python_outcome = run_workload(python_cfg, args.python_target, workload_for_python).await;

    let title = format!("compare ({})", kind.as_str());
    let report = BenchReport::new(title, vec![rust_outcome, python_outcome]);
    print!("{}", format_markdown_table(&report));
    if let Some(path) = &cli.report_file {
        if let Err(e) = write_markdown_append(&report, path) {
            eprintln!("warning: could not append markdown to {}: {e}", path.display());
        }
    }
    if let Some(dir) = &cli.csv_dir {
        match write_csv(&report, dir, cli.git_sha.as_deref()) {
            Ok(p) => eprintln!("CSV: {}", p.display()),
            Err(e) => eprintln!("warning: could not write CSV under {}: {e}", dir.display()),
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let cli = Cli::parse();
    match cli.command.clone() {
        Command::Evaluate(args) => run_single(args, WorkloadKind::Evaluate, "evaluate", &cli).await,
        Command::Label(args) => run_single(args, WorkloadKind::Label, "label", &cli).await,
        Command::AuditVerify(args) => {
            run_single(args, WorkloadKind::AuditVerify, "audit-verify", &cli).await
        }
        Command::Mixed(args) => run_single(args, WorkloadKind::Mixed, "mixed", &cli).await,
        Command::Sustained(args) => run_sustained(args, &cli).await,
        Command::Compare(args) => run_compare(args, &cli).await,
    }
}

// `Cli` is consumed once but `cli.command` is matched after building
// child args; clone the whole CLI so the global flags are accessible
// from each handler.
impl Clone for Command {
    fn clone(&self) -> Self {
        match self {
            Self::Evaluate(a) => Self::Evaluate(a.clone()),
            Self::Label(a) => Self::Label(a.clone()),
            Self::AuditVerify(a) => Self::AuditVerify(a.clone()),
            Self::Mixed(a) => Self::Mixed(a.clone()),
            Self::Sustained(a) => Self::Sustained(a.clone()),
            Self::Compare(a) => Self::Compare(a.clone()),
        }
    }
}

impl Clone for SingleArgs {
    fn clone(&self) -> Self {
        Self {
            target: self.target.clone(),
            duration: self.duration.clone(),
            concurrency: self.concurrency,
            rps: self.rps,
            max_requests: self.max_requests,
            warmup: self.warmup.clone(),
            run_label: self.run_label.clone(),
        }
    }
}

impl Clone for SustainedArgs {
    fn clone(&self) -> Self {
        Self {
            target: self.target.clone(),
            duration: self.duration.clone(),
            concurrency: self.concurrency,
            rps: self.rps,
            warmup: self.warmup.clone(),
            run_label: self.run_label.clone(),
        }
    }
}

impl Clone for CompareArgs {
    fn clone(&self) -> Self {
        Self {
            rust_target: self.rust_target.clone(),
            python_target: self.python_target.clone(),
            workload: self.workload.clone(),
            duration: self.duration.clone(),
            concurrency: self.concurrency,
            rps: self.rps,
            warmup: self.warmup.clone(),
            rust_label: self.rust_label.clone(),
            python_label: self.python_label.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_accepts_seconds() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn parse_duration_accepts_minutes() {
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn parse_duration_accepts_hours() {
        assert_eq!(parse_duration("2h").unwrap(), Duration::from_secs(7200));
    }

    #[test]
    fn parse_duration_default_unit_is_seconds() {
        assert_eq!(parse_duration("60").unwrap(), Duration::from_secs(60));
    }

    #[test]
    fn parse_duration_rejects_garbage() {
        assert!(parse_duration("xyz").is_err());
    }
}
