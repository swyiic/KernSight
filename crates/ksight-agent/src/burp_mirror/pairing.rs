//! Pair only within one captured connection; H2 stream IDs are connection-local.

use super::{HashMap, Instant, MessageOrigin, MirroredMessage, PairingBasis, VecDeque};

pub(super) type PendingRequests =
    HashMap<(u32, u64), VecDeque<(MirroredMessage, Option<MirroredMessage>, Instant)>>;
pub(super) type OrphanResponses = HashMap<(u32, u64), VecDeque<(MirroredMessage, Instant)>>;

fn compatible(request: &MirroredMessage, response: &MirroredMessage) -> bool {
    // A URL hint does not establish that an HTTP request was sent.
    if matches!(
        request.evidence.origin,
        MessageOrigin::UrlHint | MessageOrigin::SyntheticRequest
    ) {
        return false;
    }
    match (request.stream_id, response.stream_id) {
        (Some(left), Some(right)) => left == right,
        (None, None) => true,
        _ => false,
    }
}

fn basis(message: &MirroredMessage) -> PairingBasis {
    if message.stream_id.is_some() {
        PairingBasis::ConnectionAndH2Stream
    } else {
        PairingBasis::ConnectionOrder
    }
}

pub(super) fn take_orphan_response(
    orphans: &mut OrphanResponses,
    pid: u32,
    connection: u64,
    request: &MirroredMessage,
) -> Option<MirroredMessage> {
    let slot = orphans.get_mut(&(pid, connection))?;
    let index = slot.iter().position(|(response, _)| {
        response.is_pairable_response() && compatible(request, response)
    })?;
    let (mut response, _) = slot.remove(index)?;
    response.evidence.pairing = basis(&response);
    if slot.is_empty() {
        orphans.remove(&(pid, connection));
    }
    Some(response)
}

pub(super) fn take_pending_for_response(
    pending: &mut PendingRequests,
    pid: u32,
    connection: u64,
    response: &MirroredMessage,
) -> Option<MirroredMessage> {
    let slot = pending.get_mut(&(pid, connection))?;
    if !response.is_pairable_response() {
        return None;
    }
    let index = slot
        .iter()
        .position(|(request, paired, _)| paired.is_none() && compatible(request, response))?;
    let (mut request, _, _) = slot.remove(index)?;
    request.evidence.pairing = basis(response);
    if slot.is_empty() {
        pending.remove(&(pid, connection));
    }
    Some(request)
}
