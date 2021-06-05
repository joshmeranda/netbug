use std::collections::HashMap;

use crate::Addr;

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
    src: Addr,

    dst: Addr,

    /// The statuses of individual packets / packet types of the behavior's
    /// protocol.
    packet_status: HashMap<&'a str, PacketStatus>,
}

impl<'a> BehaviorEvaluation<'a> {
    pub fn new(src: Addr, dst: Addr) -> BehaviorEvaluation<'a> {
        BehaviorEvaluation {
            src,
            dst,
            packet_status: HashMap::new(),
        }
    }

    pub fn with_statuses(src: Addr, dst: Addr, packet_status: HashMap<&'a str, PacketStatus>) -> BehaviorEvaluation {
        BehaviorEvaluation {
            src,
            dst,
            packet_status,
        }
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

    pub fn iter(&'a mut self) -> ReportIterator<'a> { ReportIterator::new(&self.evaluations) }
}

pub struct ReportIterator<'a> {
    evaluations: &'a Vec<BehaviorEvaluation<'a>>,
    index:       usize,
}

impl<'a> ReportIterator<'a> {
    pub fn new(evaluations: &'a Vec<BehaviorEvaluation>) -> ReportIterator<'a> {
        ReportIterator { evaluations, index: 0 }
    }
}

impl<'a> Iterator for ReportIterator<'a> {
    type Item = &'a BehaviorEvaluation<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let eval = self.evaluations.get(self.index);

        if eval.is_some() {
            self.index += 1;
        }

        eval
    }
}
