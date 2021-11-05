use std::collections::hash_map::Iter;
use std::collections::HashMap;
use std::net::IpAddr;

use crate::Addr;

#[derive(Debug, Deserialize, Eq, Hash, Serialize, PartialEq)]
pub enum PacketStatus {
    Ok, // the packet was received or not received as expected
    Received,
    NotReceived,
}

impl ToString for PacketStatus {
    fn to_string(&self) -> String {
        match self {
            PacketStatus::Ok => "Ok",
            PacketStatus::Received => "Received",
            PacketStatus::NotReceived => "NotReceived",
        }
        .to_owned()
    }
}

/// A simple evaluation of single behavior, including a breakdown of any
/// specific steps required by the behavior.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct BehaviorEvaluation<'a> {
    src: IpAddr,

    dst: Addr,

    /// The statuses of individual packets / packet types of the behavior's
    /// protocol.
    #[serde(borrow)]
    packet_status: HashMap<&'a str, PacketStatus>,
}

impl<'a> BehaviorEvaluation<'a> {
    pub fn new(src: IpAddr, dst: Addr) -> BehaviorEvaluation<'a> {
        BehaviorEvaluation {
            src,
            dst,
            packet_status: HashMap::new(),
        }
    }

    pub fn with_statuses(src: IpAddr, dst: Addr, packet_status: HashMap<&'a str, PacketStatus>) -> BehaviorEvaluation {
        BehaviorEvaluation {
            src,
            dst,
            packet_status,
        }
    }

    pub fn insert_status(&mut self, key: &'a str, status: PacketStatus) { self.packet_status.insert(key, status); }

    pub fn passed(&self) -> bool { self.packet_status.values().all(|status| *status == PacketStatus::Ok) }

    pub fn source(&self) -> IpAddr { self.src }

    pub fn destination(&self) -> Addr { self.dst }

    pub fn data(&self) -> Iter<'_, &'a str, PacketStatus> { self.packet_status.iter() }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct BehaviorReport<'a> {
    passing: usize,

    failing: usize,

    #[serde(borrow)]
    evaluations: Vec<BehaviorEvaluation<'a>>,
}

/// A collection of [BehaviorEvaluation]s
impl<'a> BehaviorReport<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add another evaluation to the report.
    pub fn add(&mut self, evaluation: BehaviorEvaluation<'a>) {
        match evaluation.passed() {
            true => self.passing += 1,
            false => self.failing += 1,
        }

        self.evaluations.push(evaluation);
    }

    pub fn iter(&'a self) -> ReportIterator<'a> { ReportIterator::new(&self.evaluations) }
}

impl Default for BehaviorReport<'_> {
    fn default() -> Self {
        BehaviorReport {
            passing:     0,
            failing:     0,
            evaluations: vec![],
        }
    }
}

pub struct ReportIterator<'a> {
    evaluations: &'a [BehaviorEvaluation<'a>],
    index:       usize,
}

impl<'a> ReportIterator<'a> {
    pub fn new(evaluations: &'a [BehaviorEvaluation]) -> ReportIterator<'a> {
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

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::str::FromStr;

    use crate::behavior::evaluate::{BehaviorEvaluation, PacketStatus};
    use crate::Addr;

    fn get_simple_eval() -> BehaviorEvaluation<'static> {
        BehaviorEvaluation::new(
            IpAddr::from_str("127.0.0.1").unwrap(),
            Addr::from_str("127.0.0.1").unwrap(),
        )
    }

    #[test]
    fn test_passed_empty() {
        let eval = get_simple_eval();

        assert!(eval.passed());
    }

    #[test]
    fn test_passed_simple() {
        let mut eval = get_simple_eval();

        eval.insert_status("PASSED", PacketStatus::Ok);
        eval.insert_status("ALSO_PASSED", PacketStatus::Ok);

        assert!(eval.passed());
    }

    #[test]
    fn test_failing_not_received() {
        let mut eval = get_simple_eval();

        eval.insert_status("NOT_RECEIVED", PacketStatus::NotReceived);

        assert!(!eval.passed());
    }

    #[test]
    fn test_failing_received() {
        let mut eval = get_simple_eval();

        eval.insert_status("RECEIVED", PacketStatus::Received);

        assert!(!eval.passed());
    }

    #[test]
    fn test_mixed() {
        let mut eval = get_simple_eval();

        eval.insert_status("RECEIVED", PacketStatus::Received);
        eval.insert_status("NOT_RECEIVED", PacketStatus::NotReceived);
        eval.insert_status("RECEIVED", PacketStatus::Received);

        assert!(!eval.passed());
    }
}
