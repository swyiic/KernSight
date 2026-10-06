//! Join UDP/53 DNS answers to later `connect()` peers of the same process.

use std::collections::HashMap;

use ksight_model::{EventPayload, SocketConnect};

/// Maps `(tgid, peer_ip)` to the DNS QNAME that answered with that address.
/// `global` is last-writer IP→QNAME so netd lookups can stamp later app connects.
#[derive(Debug, Default)]
pub struct DnsLineageTracker {
    answers: HashMap<(u32, String), String>,
    global: HashMap<String, String>,
}

impl DnsLineageTracker {
    /// Record DNS answers and stamp matching connect events.
    pub fn correlate(&mut self, event: &mut ksight_model::Event) {
        let pid = event.header.process.tgid;
        match &mut event.payload {
            EventPayload::DnsDatagram(datagram) => {
                let Some(qname) = datagram.qname.as_ref() else {
                    return;
                };
                if qname.is_empty() {
                    return;
                }
                for address in &datagram.addresses {
                    if self.answers.len() < 16_384 {
                        self.answers
                            .entry((pid, address.clone()))
                            .or_insert_with(|| qname.clone());
                    }
                    if self.global.len() < 16_384 {
                        self.global.insert(address.clone(), qname.clone());
                    }
                }
            }
            EventPayload::SocketConnect(connect) => {
                stamp_connect(&self.answers, &self.global, pid, connect);
            }
            EventPayload::ProcessLifecycle(lifecycle)
                if lifecycle.kind == ksight_model::ProcessLifecycleKind::Exit
                    && event.header.process.tid == event.header.process.tgid =>
            {
                self.answers.retain(|&(owner, _), _| owner != pid);
            }
            _ => {}
        }
    }
}

fn stamp_connect(
    answers: &HashMap<(u32, String), String>,
    global: &HashMap<String, String>,
    pid: u32,
    connect: &mut SocketConnect,
) {
    let Some(peer) = connect.peer_address.as_ref() else {
        return;
    };
    if let Some(name) = answers.get(&(pid, peer.clone())) {
        connect.resolved_name = Some(name.clone());
        return;
    }
    if let Some(name) = global.get(peer) {
        connect.resolved_name = Some(name.clone());
    }
}

