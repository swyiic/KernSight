//! Cross-language raw ABI invariants.

use core::mem::{align_of, size_of};

use ksight_abi::{RawEventHeader, RawEventType, RawSensorId, RAW_ABI_VERSION};

#[test]
fn raw_header_layout_is_stable() {
    assert_eq!(RAW_ABI_VERSION, 1);
    assert_eq!(size_of::<RawEventHeader>(), 96);
    assert_eq!(align_of::<RawEventHeader>(), 8);
    assert_eq!(RawSensorId::Process as u16, 1);
    assert_eq!(RawEventType::ProcessExec as u16, 0x0102);
}
