#[macro_use]
extern crate clap;
extern crate netbug;

use std::time::Duration;

use clap::{App, Arg};
use clokwerk::{Interval, Scheduler};
use netbug::client::Client;
use netbug::config::client::ClientConfig;

fn run_scheduled(mut client: Client, delay: Duration,  interval: Interval) {
    run_once(&mut client, delay);

    let mut scheduler = Scheduler::new();

    scheduler.every(interval).run(move || run_once(&mut client, delay));

    let _handle = scheduler.watch_thread(Duration::from_secs(1));

    // todo: handle interrupts
    loop { /* keep blocking for scheduled stuff */ }

    _handle.stop();
}

fn run_once(client: &mut Client, delay: Duration) {
    if let Err(err) = client.start_capture() {
        eprintln!("{}", err.to_string());
        return;
    }

    let result = if client.allow_concurrent {
        client.run_behaviors_concurrent()
    } else {
        client.run_behaviors()
    };

    if let Err(err) = result {
        eprintln!("{}", err.to_string());
        return;
    }

    std::thread::sleep(delay);

    if let Err(err) = client.stop_capture() {
        eprintln!("Could not stop packet capture: {}", err.to_string());
    }

    if let Err(err) = client.transfer_all() {
        eprintln!("Transfer error: {}", err.to_string());
    }
}

fn main() {
    let matches = App::new("nbug")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Run one of the NetBug client tools")
        .arg(Arg::with_name("scheduled").long("sched").short("s").help(
            "run the client indefinitely taking captures at startup and then according to the configured schedule \
             (not yet implemented)",
        ))
        .get_matches();

    let client_cfg = match ClientConfig::from_path("examples/config/client.toml") {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err.to_string());
            return;
        },
    };

    let delay = Duration::from_secs(client_cfg.delay as u64);
    let interval = client_cfg.interval;

    let mut client: Client = Client::from_config(client_cfg);

    if matches.is_present("scheduled") {
        run_scheduled(client, delay, interval.0);
    } else {
        run_once(&mut client, delay);
    }
}
