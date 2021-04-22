use std::collections::HashMap;

use crate::behavior::evaluate::BehaviorReport;
use crate::behavior::Behavior;
use crate::error::{NbugError, Result};
use crate::Addr;
use crate::protocols::ProtocolPacket;

/// A basic collector for [Behavior]s and their corresponding
/// [ProtocolPackets].
pub struct BehaviorCollector<'a> {
    behavior_map: HashMap<&'a Behavior, Vec<ProtocolPacket>>,
}

impl<'a> BehaviorCollector<'a> {
    pub fn new() -> BehaviorCollector<'a> {
        BehaviorCollector {
            behavior_map: HashMap::new(),
        }
    }

    pub fn with_behaviors(behaviors: &'a [&Behavior]) -> BehaviorCollector<'a> {
        let mut behavior_map = HashMap::new();

        for behavior in behaviors {
            behavior_map.insert(*behavior, vec![]);
        }

        BehaviorCollector { behavior_map }
    }

    /// Insert a new behavior into the collector.
    pub fn insert_behavior(&mut self, behavior: &'a Behavior) -> Result<()> {
        self.behavior_map.insert(behavior, vec![]);

        Ok(())
    }

    /// Insert a new header to the collector, if no matching behavior is found
    /// Err is returned.
    pub fn insert_packet(&mut self, packet: ProtocolPacket) -> Result<()> {
        let src = packet.source();
        let dst =  packet.source();

        for (behavior, headers) in &mut self.behavior_map {
            if behavior.protocol == packet.protocol_type()
                && (behavior.src == src && behavior.dst == dst
                    || behavior.src == dst && behavior.dst == src)
            {
                headers.push(packet);

                return Ok(());
            }
        }

        Err(NbugError::Processing(String::from(format!(
            "no behavior matches header: {} src: {} and dst: {}",
            packet.protocol_type() as u8,
            src.to_string(), dst.to_string()
        ))))
    }

    /// Produce a comprehensive report on the behaviors gathered by the
    /// collector, but consumes the collector.
    pub fn evaluate(self) -> BehaviorReport<'a> {
        let mut report = BehaviorReport::new();

        for (behavior, headers) in self.behavior_map {
            let evaluation = behavior.evaluate(headers);

            report.add(evaluation);
        }

        report
    }
}
