use pcap::Device;
use std::sync::{Mutex, Arc};
use std::thread::Builder;

fn main() {
    let capture_flag = Arc::new(Mutex::new(true));
    let devices = vec![Device::lookup().unwrap()];

    for device in devices {
        let flag = Arc::clone(&capture_flag);
        let device_name = String::from(device.name.clone());
        let capture_result = device.open();

        match capture_result {
            Ok(mut capture) => {
                let mut save_file = capture.savefile(format!("{}.pcap", &device_name)).unwrap();

                let builder = Builder::new()
                    .name(device_name);

                // todo: check that the thread was started successfully
                builder.spawn( move || {
                    loop {
                        let packet = capture.next();

                        if packet.is_ok() {
                            save_file.write(&packet.unwrap());
                        }

                        if ! *flag.lock().unwrap() {
                            break;
                        }
                    }
                });
            }
            Err(err) => {
                eprintln!("Unable to create a capture for device '{}'\n{}", device_name, err.to_string()    )
            }
        }
    }

    *capture_flag.lock().unwrap() = false;

    std::thread::sleep(std::time::Duration::new(10, 0));
}
