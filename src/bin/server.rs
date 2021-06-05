#[macro_use]
extern crate clap;

use std::error::Error;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use chrono::{DateTime, Utc};
use clap::{App, Arg, ArgGroup, SubCommand};
use netbug::config::server::ServerConfig;
use netbug::error::Result;
use netbug::process::PcapProcessor;
use netbug::receiver::Receiver;

fn run(cfg: ServerConfig) {
    println!("Starting server...");

    let mut receiver = match Receiver::new(cfg.srv_addr, cfg.pcap_dir.clone()) {
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

fn report(cfg: ServerConfig) {}

fn main() {
    let matches = App::new("nbug")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Start the nbug server to view ")
        .subcommand(SubCommand::with_name("run").about("run the nbug server"))
        .subcommand(
            SubCommand::with_name("report")
                .about("send a human readable report of the recevied pcaps")
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

    run(server_cfg);
}
