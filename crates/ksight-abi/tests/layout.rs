//! Cross-language raw ABI invariants.

use core::mem::{align_of, size_of};

use ksight_abi::{
    DecodeError, RawEventHeader, RawEventType, RawSensorId, RAW_ABI_VERSION, RAW_BINDER_EVENT_SIZE,
    RAW_BINDER_FD_EVENT_SIZE, RAW_EVENT_HEADER_SIZE, RAW_FD_EVENT_SIZE, RAW_FILE_EVENT_SIZE,
    RAW_MEMORY_EVENT_SIZE, RAW_NETWORK_EVENT_SIZE, RAW_NETWORK_IO_EVENT_SIZE,
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
    assert_eq!(RAW_FILE_EVENT_SIZE, 376);
    assert_eq!(RAW_FD_EVENT_SIZE, 120);
    assert_eq!(RAW_MEMORY_EVENT_SIZE, 144);
    assert_eq!(RAW_NETWORK_EVENT_SIZE, 240);
    assert_eq!(RAW_NETWORK_IO_EVENT_SIZE, 128);
    assert_eq!(RAW_BINDER_EVENT_SIZE, 128);
    assert_eq!(RAW_BINDER_FD_EVENT_SIZE, 112);
    assert_eq!(RawEventType::NetworkConnect as u16, 0x0401);
    assert_eq!(RawEventType::NetworkAccept as u16, 0x0402);
    assert_eq!(RawEventType::NetworkSend as u16, 0x0403);
    assert_eq!(RawEventType::NetworkReceive as u16, 0x0404);
    assert_eq!(RawEventType::MemoryUnmap as u16, 0x0303);
    assert_eq!(RawEventType::MemoryRemap as u16, 0x0304);
    assert_eq!(RawEventType::MemoryBrk as u16, 0x0305);
    assert_eq!(RawEventType::FileDescriptorCloseRange as u16, 0x0204);
    assert_eq!(RawEventType::FileDescriptorRightsSend as u16, 0x0205);
    assert_eq!(RawEventType::FileDescriptorRightsReceive as u16, 0x0206);
    assert_eq!(RawEventType::BinderTransactionReceived as u16, 0x0502);
    assert_eq!(RawEventType::BinderFdReceived as u16, 0x0505);
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
