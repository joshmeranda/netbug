#[macro_use]
extern crate clap;

use std::error::Error;
use std::fs;
use std::fs::{DirEntry, File, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use clap::{App, AppSettings, Arg, ArgGroup, SubCommand};
use netbug::behavior::evaluate::{BehaviorEvaluation, BehaviorReport};
use netbug::config::server::ServerConfig;
use netbug::process::PcapProcessor;
use netbug::receiver::Receiver;

fn run(cfg: ServerConfig) {
    println!("Starting server...");

    let listener = match TcpListener::bind(cfg.srv_addr) {
        Ok(listener) => listener,
        Err(err) => {
            eprintln!("Error binding to socket '{}': {}", cfg.srv_addr, err.to_string());
            return;
        },
    };

    let mut receiver = match Receiver::new(listener, cfg.pcap_dir.clone()) {
        Ok(receiver) => receiver,
        Err(err) => {
            eprintln!("Error creating pcap receiver: {}", err.to_string());
            return;
        },
    };

    let processor = PcapProcessor::new(&cfg.behaviors, cfg.pcap_dir.to_path_buf());

    if !cfg.report_dir.exists() {
        fs::create_dir_all(cfg.report_dir.clone());
    }

    loop {
        match receiver.receive() {
            Ok(paths) =>
                for path in paths {
                    println!("Received pcap -> {}", path.to_str().unwrap())
                },
            Err(err) => eprintln!("Error receiving pcap: {}", err.to_string()),
        }

        match processor.process() {
            Ok(report) => {
                let content = serde_json::to_string(&report).unwrap();

                let mut path = cfg.report_dir.clone();

                if cfg.overwrite_report {
                    path.push("report.json");
                } else {
                    let now = SystemTime::now();
                    let date: DateTime<Utc> = DateTime::from(now);
                    let timestamp = date.to_rfc3339();

                    path.push(format!("report_{}.json", timestamp));
                }

                match File::create(&path) {
                    Ok(mut file) =>
                        if let Err(err) = write!(file, "{}", content) {
                            eprintln!(
                                "error writing to file '{}': {}",
                                path.to_str().unwrap(),
                                err.to_string()
                            );
                        },
                    Err(err) => println!(
                        "could not create report at '{}': {}",
                        path.to_str().unwrap(),
                        err.to_string()
                    ),
                }
            },
            Err(err) => eprintln!("Error processing pcaps: {}", err.to_string()),
        }
    }

    println!("Stopping server...");
}

enum ReportFilter {
    All,
    Passed,
    Failed,
}

fn get_report_path(report_dir: PathBuf, offset: usize) -> Option<PathBuf> {
    let read = match fs::read_dir(report_dir) {
        Err(err) => return None,
        Ok(read) => read,
    };

    let mut entries: Vec<DirEntry> = read.map(|entry| entry.unwrap()).collect();
    entries.sort_by(|left, right| {
        let left_time = left.metadata().unwrap().created().unwrap();
        let right_time = right.metadata().unwrap().created().unwrap();

        // left_time < right_time

        left_time.cmp(&right_time)
    });

    match entries.get(offset) {
        None => None,
        Some(entry) => Some(entry.path()),
    }
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
                err.to_string()
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
                err.to_string()
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
            eprintln!("{}", err.to_string());
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
                Err(err) => {
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
