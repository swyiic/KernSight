//! Cross-language raw ABI invariants.

use core::mem::{align_of, size_of};

use ksight_abi::{
    DecodeError, RawEventHeader, RawEventType, RawSensorId, RAW_ABI_VERSION, RAW_EVENT_HEADER_SIZE,
    RAW_PROCESS_EVENT_SIZE,
};

#[test]
fn raw_header_layout_is_stable() {
    assert_eq!(RAW_ABI_VERSION, 1);
    assert_eq!(size_of::<RawEventHeader>(), 96);
    assert_eq!(align_of::<RawEventHeader>(), 8);
    assert_eq!(RawSensorId::Process as u16, 1);
    assert_eq!(RawEventType::ProcessExec as u16, 0x0102);
    assert_eq!(RAW_EVENT_HEADER_SIZE, 96);
    assert_eq!(RAW_PROCESS_EVENT_SIZE, 360);
}

#[test]
fn raw_header_decodes_without_alignment_assumptions() {
    let mut bytes = vec![0_u8; RAW_EVENT_HEADER_SIZE];
    bytes[0..2].copy_from_slice(&RAW_ABI_VERSION.to_le_bytes());
    bytes[2..4].copy_from_slice(&96_u16.to_le_bytes());
    bytes[4..6].copy_from_slice(&(RawSensorId::Process as u16).to_le_bytes());
    bytes[6..8].copy_from_slice(&(RawEventType::ProcessExec as u16).to_le_bytes());
    bytes[8..12].copy_from_slice(&96_u32.to_le_bytes());
    bytes[16..24].copy_from_slice(&42_u64.to_le_bytes());

    let header = RawEventHeader::decode(&bytes).expect("valid header");
    assert_eq!(header.source_sequence, 42);
    assert_eq!(header.event_type, RawEventType::ProcessExec as u16);

    bytes[0..2].copy_from_slice(&2_u16.to_le_bytes());
    assert_eq!(
        RawEventHeader::decode(&bytes),
        Err(DecodeError::UnsupportedAbi(2))
    );
}
