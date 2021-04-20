use std::collections::HashMap;

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PacketStatus {
    Ok, // the packet was received or not received as expected
    Received,
    NotReceived,
}

/// A simple evaluation of single behavior, including a breakdown of any
/// specific steps required by the behavior.
#[derive(Serialize)]
pub struct BehaviorEvaluation<'a> {
    /// The statuses of individual packets / packet types of the behavior's
    /// protocol.
    packet_status: HashMap<&'a str, PacketStatus>,
}

impl<'a> BehaviorEvaluation<'a> {
    pub fn new() -> BehaviorEvaluation<'a> {
        BehaviorEvaluation {
            packet_status: HashMap::new(),
        }
    }

    pub fn with_statuses(packet_status: HashMap<&'a str, PacketStatus>) -> BehaviorEvaluation {
        BehaviorEvaluation { packet_status }
    }

    pub fn insert_status(&mut self, key: &'a str, status: PacketStatus) { self.packet_status.insert(key, status); }

    pub fn passed(&self) -> bool { self.packet_status.values().all(|status| *status == PacketStatus::Ok) }
}

#[derive(Serialize)]
pub struct BehaviorReport<'a> {
    passing: usize,

    failing: usize,

    evaluations: Vec<BehaviorEvaluation<'a>>,
}

/// A collection of [BehaviorEvaluation]s
impl<'a> BehaviorReport<'a> {
    pub fn new() -> Self {
        BehaviorReport {
            passing:     0,
            failing:     0,
            evaluations: vec![],
        }
    }

    /// Add another evaluation to the report.
    pub fn add(&mut self, evaluation: BehaviorEvaluation<'a>) {
        match evaluation.passed() {
            true => self.passing += 1,
            false => self.failing += 1,
        }

        self.evaluations.push(evaluation);
    }
}
