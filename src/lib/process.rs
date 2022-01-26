use std::convert::TryFrom;
use std::fs::File;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use std::io::Write;
use chrono::{DateTime, Utc};

use pcap::Capture;
use tokio::sync::mpsc::Receiver;

use crate::behavior::collector::BehaviorCollector;
use crate::behavior::Behavior;
use crate::error::Result;
use crate::protocols::ProtocolPacket;

/// Iterates over the given [`Receiver`] to process each new pcap as it is
/// received.
pub async fn process(behaviors: &[Behavior], mut receiver: Receiver<PathBuf>, report_dir: &Path) -> Result<()> {
    // todo: we probably want to pass a clean collector (with only behaviors) to `process_pcap`
    let mut collector = BehaviorCollector::new();

    for behavior in behaviors {
        collector.insert_behavior(behavior);
    }

    let collector = collector;

    // todo: keep in memory report and merge the newly created report into it, right now we will be generating reports
    //       for each interface rather than tracking on overarching report
    while let Some(path) = receiver.recv().await {
        let mut new_collector = collector.clone();

        match process_pcap(path.as_path(), &mut new_collector) {
            Ok(()) => {
                let report = new_collector.evaluate();
                let content = serde_json::to_string(&report).unwrap();

                let now = SystemTime::now();
                let date: DateTime<Utc> = DateTime::from(now);
                let timestamp = date.to_rfc3339();

                let report_path = report_dir.join(format!("report_{}.json", timestamp));

                match File::create(report_path) {
                    Ok(mut f) => write!(f, "{}", content).unwrap(),
                    Err(err) => match err.kind() {
                        ErrorKind::PermissionDenied => eprintln!("incorrect permission for report file"),
                        ErrorKind::NotFound => eprintln!("report directory or file could not be found"),
                        _ => eprintln!("could not write to report file")
                    }
                }
            },
            Err(err) => eprintln!("Error processing pcap '{}': {}", path.to_str().unwrap(), err),
        }
    }

    Ok(())
}

/// Process a single pcap file, by adding the found [ProtocolPacket]s
/// into the given [BehaviorCollector].
fn process_pcap(path: &Path, collector: &mut BehaviorCollector) -> Result<()> {
    let mut capture = Capture::from_file(path)?;

    while let Ok(packet) = capture.next() {
        match ProtocolPacket::try_from(packet.data) {
            Ok(protocol_packet) =>
                if let Err(err) = collector.insert_packet(protocol_packet) {
                    eprintln!("{}", err)
                },
            Err(err) => eprintln!("Error parsing packet: {}", err),
        }
    }

    Ok(())
}
