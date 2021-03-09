extern crate netbug;

use netbug::client::Client;
use netbug::config::client::ClientConfig;

fn main() {
    let client_cfg = match ClientConfig::from_path("examples/config/client.toml") {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{}", err.to_string());
            return;
        }
    };

    {
        let delay = client_cfg.delay;

        // explicit scope to drop any active captures from the
        let mut client: Client = Client::from_config(client_cfg);

        if let Err(err) = client.start_capture() {
            eprintln!("{}", err.to_string());
        } else if let Err(err) = client.run_behaviors() {
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

    // do other stuff...
}
