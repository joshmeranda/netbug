mod common;

use std::net::{TcpListener, Shutdown, UdpSocket};
use std::{thread, fs};
use std::thread::Builder;
use std::time::Duration;

use netbug::client::Client;
use netbug::config::client::ClientConfig;
use netbug::config::server::ServerConfig;
use netbug::receiver::Receiver;
use std::path::{PathBuf, Path};
use netbug::process::PcapProcessor;
use std::fs::File;
use std::io::{Write, Read};

fn run_tcp() {
    let listener = TcpListener::bind("127.0.0.1:8003").unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    let mut buffer = &mut [0u8; 163]; // the standard test message has 163 characters

    stream.read(buffer);
}

fn run_udp() {
    let mut socket = UdpSocket::bind("127.0.0.1:8004").unwrap();
    let mut buffer = &mut [0u8; 163]; // the standard test message has 163 characters

    let (_, addr) = socket.recv_from(buffer).unwrap();

    socket.send_to(buffer, &addr);
}

fn run_client() {
    let client_cfg = match ClientConfig::from_path(common::get_client_config_path()) {
        Ok(cfg) => cfg,
        Err(err) => panic!("failed to parse client config: {}", err.to_string()),
    };

    let delay = client_cfg.interval;

    let mut client: Client = Client::from_config(client_cfg);

    if let Err(err) = client.start_capture() {
        panic!("{}", err.to_string());
    }

    let result = if client.allow_concurrent {
        client.run_behaviors_concurrent()
    } else {
        client.run_behaviors()
    };

    if let Err(err) = result {
        panic!("{}", err.to_string());
    }

    if let Err(err) = client.stop_capture() {
        panic!("Could not stop packet capture: {}", err.to_string());
    }

    if let Err(err) = client.transfer_all() {
        panic!("Transfer error: {}", err.to_string());
    }
}

fn run_receiver() {
    let config = match ServerConfig::from_path(common::get_receiver_config_path()) {
        Ok(cfg) => cfg,
        Err(err) => panic!("failed to parse server config: {}", err.to_string()),
    };

    let listener = match TcpListener::bind(config.srv_addr) {
        Ok(listener) => listener,
        Err(err) => panic!("Error binding to socket '{}': {}", config.srv_addr, err.to_string()),
    };

    let mut receiver = Receiver::new(listener, config.pcap_dir.clone());

    receiver.receive();

    let processor = PcapProcessor::new(&config.behaviors, config.pcap_dir.to_path_buf());

    let report = processor.process().unwrap();
    let content = serde_json::to_string(&report).unwrap();
    let mut path = config.report_dir.clone();

    fs::create_dir_all(path.clone());

    path.push("report");

    let mut file = File::create(&path).unwrap();

    write!(file, "{}", content).unwrap();
}

#[test]
fn test_basic() {
    let udp_thread = Builder::new().name("tcp".to_string()).spawn(run_tcp);
    let udp_thread = Builder::new().name("udp".to_string()).spawn(run_udp);

    // todo: set up dummy tcp and udp servers
    let receiver_thread = Builder::new().name("receiver".to_string()).spawn(run_receiver).unwrap();

    thread::sleep(Duration::from_secs(1));

    let client_thread = Builder::new().name("client".to_string()).spawn(run_client).unwrap();

    client_thread.join().unwrap();
    receiver_thread.join().unwrap();


    let mut client_pcap_path = common::get_out_root();
    client_pcap_path.push("pcap");
    client_pcap_path.push("lo.pcap");

    assert!(client_pcap_path.exists(), format!("Expected file at '{}'", client_pcap_path.to_str().unwrap()));

    let mut receiver_pcap_path = common::get_out_root();
    receiver_pcap_path.push("recv_pcap");
    receiver_pcap_path.push("127.0.0.1");
    receiver_pcap_path.push("lo.pcap");

    assert!(receiver_pcap_path.exists(), format!("Expected file at '{}'", receiver_pcap_path.to_str().unwrap()));

    let client_pcap_meta = fs::metadata(client_pcap_path).unwrap();
    let receiver_pcap_meta = fs::metadata(receiver_pcap_path).unwrap();

    let client_pcap_len = client_pcap_meta.len();
    let receiver_pcap_len = receiver_pcap_meta.len();

    assert_eq!(client_pcap_len, receiver_pcap_len);

    let mut report_file_path = common::get_out_root();
    report_file_path.push("reports");
    report_file_path.push("report");

    let content = fs::read_to_string(report_file_path).unwrap();
    let raw = "{\"passing\":1,\"failing\":3,\"evaluations\":[{\"src\":\"127.0.0.1\",\"dst\":\"::1\",\"packet_status\":{\"Icmp Echo Reply\":\"NotReceived\",\"Icmp Echo Request\":\"Ok\"}},{\"src\":\"127.0.0.1\",\"dst\":\"127.0.0.1\",\"packet_status\":{\"TcpAck\":\"Ok\",\"TcpSyn\":\"Ok\",\"TcpSynAck\":\"Ok\",\"TcpFin\":\"Ok\"}},{\"src\":\"127.0.0.1\",\"dst\":\"127.0.0.1\",\"packet_status\":{\"Icmp Echo Reply\":\"Ok\",\"Icmp Echo Request\":\"Ok\"}},{\"src\":\"127.0.0.1\",\"dst\":\"127.0.0.1\",\"packet_status\":{\"UdpEgress\":\"Ok\",\"UdpIngress\":\"Ok\"}}]}";
    assert_eq!(content, raw);

    let out_path = common::get_out_root();
    assert!(out_path.exists());

    // fs::remove_dir_all(out_path);
}
