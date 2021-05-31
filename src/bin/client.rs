extern crate netbug;

use netbug::client::Client;
use netbug::config::client::ClientConfig;
use netbug::bpf::filter::FilterExpression;

fn capture(mut client: Client, delay: u8) {
    if let Err(err) = client.start_capture() {
        eprintln!("{}", err.to_string());
    } else {
        let result = if client.allow_concurrent {
            client.run_behaviors_concurrent()
        } else {
            client.run_behaviors()
        };

        if let Err(err) = result {
            eprintln!("{}", err.to_string());
        } else {
            // small delay  to ensure all relevant packets are dumped
            std::thread::sleep(std::time::Duration::from_secs(delay as u64));

            if let Err(err) = client.stop_capture() {
                eprintln!("Could not stop packet capture: {}", err.to_string());
            }

            if let Err(err) = client.transfer_all() {
                eprintln!("Transfer error: {}", err.to_string());
            }
        }
    }
}

fn main() {
    let client_cfg = match ClientConfig::from_path("examples/config/client.toml") {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err.to_string());
            return;
        },
    };

    let delay = client_cfg.delay;
    let mut client: Client = Client::from_config(client_cfg);

    capture(client, delay);

    // do other stuff...
}
