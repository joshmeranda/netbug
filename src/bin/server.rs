#[macro_use]
extern crate clap;

use std::fs;
use std::fs::{DirEntry, File};
use std::io::{ErrorKind, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use clap::{App, AppSettings, Arg, ArgGroup, SubCommand};
use netbug::behavior::evaluate::{BehaviorEvaluation, BehaviorReport};
use netbug::config::server::ServerConfig;
use netbug::error::NbugError;

use netbug::receive;
use netbug::process;

#[tokio::main]
async fn run(cfg: ServerConfig) {
    println!("Starting server...");

    let listener = match TcpListener::bind(cfg.srv_addr) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("Error binding to socket '{}': {}", cfg.srv_addr, err);
            return;
        },
    };

    listener.set_nonblocking(true);

    if !cfg.report_dir.exists() {
        if let Err(err) = fs::create_dir_all(cfg.report_dir.clone()) {
            eprintln!(
                "Unable to create report directory art '{}': {}",
                cfg.report_dir.to_str().unwrap(),
                err
            );
        }
    }

    let is_signal_received = Arc::new(AtomicBool::new(false));
    if let Err(err) = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&is_signal_received)) {
        eprintln!("Error establishing signal handler for server, may not shut down correctly: {}", err);
    }

    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);

    let processor_task = tokio::spawn({
        let behaviors = cfg.behaviors;
        let report_dir = PathBuf::from(cfg.report_dir.as_path());

        async move {
            if let Err(err) = process::process(&behaviors, receiver, report_dir.as_path()).await {
                eprintln!("Error processing pcaps: {}", err);
            }
        }
    });

    if let Err(err) = receive::receive(listener, cfg.pcap_dir, sender, Arc::clone(&is_signal_received)).await {
        eprintln!("Error receiving pcap: {}", err)
    }

    tokio::join!(processor_task);

    println!("Stopping server...");
}

enum ReportFilter {
    All,
    Passed,
    Failed,
}

fn get_report_path(report_dir: PathBuf, offset: usize) -> Option<PathBuf> {
    let read = match fs::read_dir(report_dir) {
        Err(_) => return None,
        Ok(read) => read,
    };

    let mut entries: Vec<DirEntry> = read.map(|entry| entry.unwrap()).collect();
    entries.sort_by(|left, right| {
        let left_time = left.metadata().unwrap().created().unwrap();
        let right_time = right.metadata().unwrap().created().unwrap();

        // left_time < right_time

        left_time.cmp(&right_time)
    });

    entries.get(offset).map(|entry| entry.path())
}

fn report(cfg: ServerConfig, filter: ReportFilter, offset: usize) {
    let report_path = match get_report_path(cfg.report_dir, offset) {
        Some(path) => path,
        None => {
            eprintln!(
                "Could not find a report with the given offset. Please make sure you have at least {} report(s)",
                offset + 1
            );
            return;
        },
    };

    let content = match fs::read_to_string(report_path.clone()) {
        Ok(content) => content,
        Err(err) => {
            eprintln!(
                "An error occurred reading '{}': {}",
                report_path.to_str().unwrap(),
                err
            );
            return;
        },
    };

    // let report: BehaviorReport = match serde_json::from_str(content.as_str()) {
    let report: BehaviorReport = match serde_json::from_str(content.as_str()) {
        Ok(report) => report,
        Err(err) => {
            eprintln!(
                "An error occurred reading '{}': {}",
                report_path.to_str().unwrap(),
                err
            );
            return;
        },
    };

    let evals: Vec<&BehaviorEvaluation> = report
        .iter()
        .filter(|eval| match filter {
            ReportFilter::All => true,
            ReportFilter::Passed => eval.passed(),
            ReportFilter::Failed => !eval.passed(),
        })
        .collect();

    for eval in evals {
        println!("{} -> {}", eval.source().to_string(), eval.destination().to_string());

        for (name, status) in eval.data() {
            println!("{} : {}", name, status.to_string());
        }

        println!();
    }
}

fn main() {
    let matches = App::new("nbug")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Start the nbug server to view ")
        .settings(&[
            AppSettings::SubcommandRequiredElseHelp,
            AppSettings::UnifiedHelpMessage,
            AppSettings::VersionlessSubcommands,
        ])
        .subcommand(SubCommand::with_name("run").about("run the nbug server"))
        .subcommand(
            SubCommand::with_name("report")
                .about("show a human readable report of the recevied pcaps")
                .arg(
                    Arg::with_name("failed")
                        .help("only show report of failing behaviors")
                        .long("failed")
                        .short("f"),
                )
                .arg(
                    Arg::with_name("passed")
                        .help("only show report of passing behaviors")
                        .long("passed")
                        .short("p"),
                )
                .group(
                    ArgGroup::with_name("filters")
                        .args(&["failed", "passed"])
                        .multiple(false),
                )
                .arg(
                    Arg::with_name("offset")
                        .help(
                            "show the n + 1 th most recent report (0 shows the most recent, 1 shows the 2nd most \
                             recent, ...)",
                        )
                        .long("offset")
                        .short("o")
                        .takes_value(true),
                ),
        )
        .get_matches();

    let server_cfg = match ServerConfig::from_path("examples/config/server.toml") {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err);
            return;
        },
    };

    if let Some(sub_matches) = matches.subcommand_matches("report") {
        let filter = if sub_matches.is_present("failed") {
            ReportFilter::Failed
        } else if matches.is_present("passed") {
            ReportFilter::Passed
        } else {
            ReportFilter::All
        };

        let offset = match sub_matches.value_of("offset") {
            Some(offset) => match offset.parse::<usize>() {
                Ok(offset) => offset,
                Err(_) => {
                    eprintln!("Bad offset value");
                    return;
                },
            },
            None => 0,
        };

        report(server_cfg, filter, offset);
    } else {
        run(server_cfg)
    }
}
