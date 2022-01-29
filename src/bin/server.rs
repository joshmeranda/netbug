#[macro_use]
extern crate clap;

use std::fs;
use std::fs::{DirEntry, File};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::{App, AppSettings, Arg, ArgGroup, SubCommand};
use log::LevelFilter;
use netbug::behavior::evaluate::{BehaviorEvaluation, BehaviorReport};
use netbug::config::server::ServerConfig;
use netbug::{process, receive};
use simplelog::{Config, WriteLogger};

#[tokio::main]
async fn run(cfg: ServerConfig) {
    log::info!("Starting server...");

    let listener = match TcpListener::bind(cfg.srv_addr) {
        Ok(listener) => listener,
        Err(err) => {
            log::error!("Error binding to socket '{}': {}", cfg.srv_addr, err);
            return;
        },
    };

    if let Err(err) = listener.set_nonblocking(true) {
        log::warn!("cannot establish non-blocking tcp listener: {}", err);
    }

    if !cfg.report_dir.exists() {
        if let Err(err) = fs::create_dir_all(cfg.report_dir.clone()) {
            log::warn!(
                "Unable to create report directory art '{}': {}",
                cfg.report_dir.to_str().unwrap(),
                err
            );
        }
    }

    let is_signal_received = Arc::new(AtomicBool::new(false));
    if let Err(err) = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&is_signal_received)) {
        log::warn!(
            "Error establishing signal handler for server, may not shut down correctly: {}",
            err
        );
    }

    let (sender, receiver) = tokio::sync::mpsc::channel(1);

    let processor_task = tokio::spawn({
        let behaviors = cfg.behaviors;
        let report_dir = PathBuf::from(cfg.report_dir.as_path());

        async move {
            if let Err(err) = process::process(&behaviors, receiver, report_dir.as_path()).await {
                log::warn!("Error processing pcaps: {}", err);
            }
        }
    });

    if let Err(err) = receive::receive(listener, cfg.pcap_dir, sender, Arc::clone(&is_signal_received)).await {
        log::warn!("Error receiving pcap: {}", err)
    }

    let (processor_join,) = tokio::join!(processor_task);

    if let Err(err) = processor_join {
        log::warn!("error waiting for processor thread to join: {}", err);
    }

    log::info!("Stopping server...");
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
            eprintln!("An error occurred reading '{}': {}", report_path.to_str().unwrap(), err);
            return;
        },
    };

    // let report: BehaviorReport = match serde_json::from_str(content.as_str()) {
    let report: BehaviorReport = match serde_json::from_str(content.as_str()) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("An error occurred reading '{}': {}", report_path.to_str().unwrap(), err);
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
        .before_help(
            "any argument here which overlaps with a configuration field ignore the configured value in favor for the \
             explicitly passed value",
        )
        .settings(&[
            AppSettings::SubcommandRequiredElseHelp,
            AppSettings::UnifiedHelpMessage,
            AppSettings::VersionlessSubcommands,
        ])
        .subcommand(
            SubCommand::with_name("run")
                .about("run the nbug server")
                .arg(Arg::with_name("log_file").short("f").long("log-file").takes_value(true)),
        )
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

    let log_init_result = match matches.value_of("log-file") {
        Some(p) => match File::create(p) {
            Ok(f) => WriteLogger::init(LevelFilter::Info, Config::default(), f),
            Err(err) => {
                eprintln!("could not create log file at '{}': {}", p, err);
                return;
            },
        },
        None => WriteLogger::init(LevelFilter::Info, Config::default(), std::io::stdout()),
    };

    if let Err(err) = log_init_result {
        eprintln!("could not establish global logger: {}", err)
    }

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
