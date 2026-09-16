//! Pair only within one captured connection; H2 stream IDs are connection-local.

use super::*;

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
    let index = slot
        .iter()
        .position(|(response, _)| compatible(request, response))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request(stream_id: Option<u32>) -> MirroredMessage {
        let mut message = StreamReassembler::default()
            .push(b"GET /test HTTP/1.1\r\nHost: fixture.example\r\n\r\n")
            .remove(0);
        message.stream_id = stream_id;
        message
    }

    fn response(stream_id: Option<u32>) -> MirroredMessage {
        let mut message = StreamReassembler::default()
            .push(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok")
            .remove(0);
        message.stream_id = stream_id;
        message
    }

    #[test]
    fn h2_same_id_on_other_connection_is_not_a_match() {
        let mut pending = PendingRequests::new();
        pending
            .entry((7, 0x1000))
            .or_default()
            .push_back((request(Some(1)), None, Instant::now()));
        assert!(take_pending_for_response(&mut pending, 7, 0x2000, &response(Some(1))).is_none());
        assert_eq!(pending[&(7, 0x1000)].len(), 1);
        let matched =
            take_pending_for_response(&mut pending, 7, 0x1000, &response(Some(1))).unwrap();
        assert_eq!(
            matched.evidence.pairing,
            PairingBasis::ConnectionAndH2Stream
        );
    }

    #[test]
    fn h2_unknown_stream_does_not_fall_back_to_fifo() {
        let mut pending = PendingRequests::new();
        pending
            .entry((7, 0x1000))
            .or_default()
            .push_back((request(Some(1)), None, Instant::now()));
        assert!(take_pending_for_response(&mut pending, 7, 0x1000, &response(Some(3))).is_none());
        assert!(take_pending_for_response(&mut pending, 7, 0x1000, &response(None)).is_none());
        assert_eq!(pending[&(7, 0x1000)].len(), 1);
    }

    #[test]
    fn orphan_h2_stream_and_connection_must_both_match() {
        let mut orphans = OrphanResponses::new();
        orphans
            .entry((7, 0x1000))
            .or_default()
            .push_back((response(Some(3)), Instant::now()));
        assert!(take_orphan_response(&mut orphans, 7, 0x2000, &request(Some(3))).is_none());
        assert!(take_orphan_response(&mut orphans, 7, 0x1000, &request(Some(1))).is_none());
        assert!(take_orphan_response(&mut orphans, 7, 0x1000, &request(Some(3))).is_some());
    }

    #[test]
    fn http1_same_host_in_another_connection_is_not_a_match() {
        let mut orphans = OrphanResponses::new();
        orphans
            .entry((7, 0x1000))
            .or_default()
            .push_back((response(None), Instant::now()));
        assert!(take_orphan_response(&mut orphans, 7, 0x2000, &request(None)).is_none());
        let matched = take_orphan_response(&mut orphans, 7, 0x1000, &request(None)).unwrap();
        assert_eq!(matched.evidence.pairing, PairingBasis::ConnectionOrder);
    }

    #[test]
    fn url_hint_cannot_consume_a_captured_response() {
        let mut orphans = OrphanResponses::new();
        orphans
            .entry((7, 0x1000))
            .or_default()
            .push_back((response(None), Instant::now()));
        let hint = request_from_http_url(b"https://fixture.example/test").unwrap();
        assert!(take_orphan_response(&mut orphans, 7, 0x1000, &hint).is_none());
        assert_eq!(orphans[&(7, 0x1000)].len(), 1);
    }
}
