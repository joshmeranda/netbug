#[macro_use]
extern crate clap;
extern crate netbug;

use std::str::FromStr;
use std::time::Duration;

use clap::{App, Arg};
use clokwerk::{Interval, Scheduler};
use signal_hook::consts::signal;
use signal_hook::iterator::Signals;
use netbug::client::Client;
use netbug::config::client::{CaptureInterval, ClientConfig};

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
        eprintln!("{}", err);
        return;
    }

    let result = if client.allow_concurrent {
        client.run_behaviors_concurrent()
    } else {
        client.run_behaviors()
    };

    if let Err(err) = result {
        eprintln!("{}", err);
        return;
    }

    if let Err(err) = client.stop_capture() {

        eprintln!("Could not stop packet capture: {}", err);
    }

    if let Err(err) = client.transfer_all() {
        eprintln!("Transfer error: {}", err);
    }
}

fn main() {
    let matches = App::new("nbug")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Run one of the NetBug client tools")
        .before_help("any argument here which overlaps with a configuration field ignore the configured value in favor for the explicitly passed value")
        .arg(Arg::with_name("scheduled").long("scheduled").short("s").help(
            "run the client indefinitely taking captures at startup and then according to the configured schedule",
        ).takes_value(true))
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
                eprintln!("invalid capture interval '{}': {}", matches.value_of("scheduled").unwrap(), err);
                return
            }
        }
    } else {
        client_cfg.interval
    };

    let mut client: Client = Client::from_config(client_cfg);

    if matches.is_present("scheduled") {
        run_scheduled(client, interval.0);
    } else {
        run_once(&mut client);
    }
}
