#[macro_use]
extern crate clap;
extern crate netbug;

use std::fs::File;
use std::str::FromStr;
use std::time::Duration;

use clap::{App, Arg};
use clokwerk::{Interval, Scheduler};
use log::LevelFilter;
use netbug::client::Client;
use netbug::config::client::{CaptureInterval, ClientConfig};
use signal_hook::consts::signal;
use signal_hook::iterator::Signals;
use simplelog::{Config, WriteLogger};

fn run_scheduled(mut client: Client, interval: Interval) {
    run_once(&mut client);

    let mut scheduler = Scheduler::new();
    scheduler.every(interval).run(move || run_once(&mut client));

    let handle = scheduler.watch_thread(Duration::from_secs(1));

    let mut signals = Signals::new(&[signal::SIGINT]).unwrap();

    signals.wait();
    handle.stop();
}

fn run_once(client: &mut Client) {
    if let Err(err) = client.start_capture() {
        log::error!("{}", err);
        return;
    }

    let result = if client.allow_concurrent {
        client.run_behaviors_concurrent()
    } else {
        client.run_behaviors()
    };

    if let Err(err) = result {
        log::error!("{}", err);
        return;
    }

    if let Err(err) = client.stop_capture() {
        log::warn!("Could not stop packet capture: {}", err);
    }

    if let Err(err) = client.transfer_all() {
        log::warn!("Transfer error: {}", err);
    }
}

fn main() {
    let matches = App::new("nbug")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Run one of the NetBug client tools")
        .before_help(
            "any argument here which overlaps with a configuration field ignore the configured value in favor for the \
             explicitly passed value",
        )
        .arg(
            Arg::with_name("scheduled")
                .long("scheduled")
                .short("s")
                .help(
                    "run the client indefinitely taking captures at startup and then according to the configured \
                     schedule",
                )
                .takes_value(true),
        )
        .arg(Arg::with_name("log_file").short("f").long("log-file").takes_value(true))
        .get_matches();

    let client_cfg = match ClientConfig::from_path("examples/config/client.toml") {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err);
            return;
        },
    };

    let interval = if matches.is_present("scheduled") {
        match CaptureInterval::from_str(matches.value_of("scheduled").unwrap()) {
            Ok(i) => i,
            Err(err) => {
                eprintln!(
                    "invalid capture interval '{}': {}",
                    matches.value_of("scheduled").unwrap(),
                    err
                );
                return;
            },
        }
    } else {
        client_cfg.interval
    };

    let mut client: Client = Client::from_config(client_cfg);

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

    if matches.is_present("scheduled") {
        run_scheduled(client, interval.0);
    } else {
        run_once(&mut client);
    }
}
