use std::collections::HashMap;

use crate::behavior::evaluate::BehaviorReport;
use crate::behavior::Behavior;
use crate::error::{NbugError, Result};
use crate::protocols::ProtocolPacketHeader;
use crate::Addr;

/// A basic collector for [Behavior]s and their corresponding
/// [ProtocolPacketHeaders].
pub struct BehaviorCollector<'a> {
    // todo: this vector probably takes up a lot of heap space and will cause a performance hit
    behavior_map: HashMap<&'a Behavior, Vec<Box<dyn ProtocolPacketHeader>>>,
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
    pub fn insert_header(&mut self, header: Box<dyn ProtocolPacketHeader>, src: Addr, dst: Addr) -> Result<()> {
        for (behavior, headers) in &mut self.behavior_map {
            // todo: better handle more protocols like tcp, udp, etc
            if behavior.protocol == header.protocol_type()
                && (behavior.src == src && behavior.dst == dst
                    || behavior.src == dst && behavior.dst == src)
            {
                headers.push(header);

                return Ok(());
            }
        }

        Err(NbugError::Processing(String::from(format!(
            "no behavior matches header: {} src: {} and dst: {}",
            header.protocol_type() as u8,
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
