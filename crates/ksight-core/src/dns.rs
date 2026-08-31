//! Bounded DNS message parsing for L0 UDP/53 datagrams.
//!
//! Only QNAME and A/AAAA answers are extracted. Truncated or compressed-beyond-budget
//! packets return whatever was parsed so far.

/// Parsed DNS question plus A/AAAA answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// First question name, lowercased, without a trailing dot.
    pub qname: String,
    /// IPv4/IPv6 answer addresses as presentation strings.
    pub addresses: Vec<String>,
    /// True when the QR bit indicates a response.
    pub response: bool,
}

/// Parse a DNS payload copied from sendto/recvfrom on port 53.
#[must_use]
pub fn parse_dns_message(payload: &[u8]) -> Option<DnsRecord> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);
    if qdcount == 0 {
        return None;
    }
    let mut offset = 12_usize;
    let qname = read_name(payload, &mut offset)?;
    offset = offset.saturating_add(4);
    if offset > payload.len() {
        return None;
    }
    let mut addresses = Vec::new();
    for _ in 0..ancount.min(16) {
        if offset.saturating_add(10) > payload.len() {
            break;
        }
        let _ = read_name(payload, &mut offset)?;
        if offset.saturating_add(10) > payload.len() {
            break;
        }
        let rtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        let rdlength = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]) as usize;
        offset = offset.saturating_add(10);
        if offset.saturating_add(rdlength) > payload.len() {
            break;
        }
        match rtype {
            1 if rdlength == 4 => {
                addresses.push(format!(
                    "{}.{}.{}.{}",
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3]
                ));
            }
            28 if rdlength == 16 => {
                let mut octets = [0_u8; 16];
                octets.copy_from_slice(&payload[offset..offset + 16]);
                addresses.push(std::net::Ipv6Addr::from(octets).to_string());
            }
            _ => {}
        }
        offset = offset.saturating_add(rdlength);
    }
    Some(DnsRecord {
        qname,
        addresses,
        response: flags & 0x8000 != 0,
    })
}

fn read_name(payload: &[u8], offset: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut hops = 0_u8;
    let mut cursor = *offset;
    let mut jumped = false;
    loop {
        if hops >= 16 || cursor >= payload.len() {
            return None;
        }
        let len = payload[cursor];
        if len & 0xc0 == 0xc0 {
            if cursor + 1 >= payload.len() {
                return None;
            }
            let pointer = (((len & 0x3f) as usize) << 8) | usize::from(payload[cursor + 1]);
            if !jumped {
                *offset = cursor.saturating_add(2);
                jumped = true;
            }
            cursor = pointer;
            hops = hops.saturating_add(1);
            continue;
        }
        if len == 0 {
            if !jumped {
                *offset = cursor.saturating_add(1);
            }
            break;
        }
        let label_len = usize::from(len);
        cursor = cursor.saturating_add(1);
        if cursor.saturating_add(label_len) > payload.len() {
            return None;
        }
        let label = payload[cursor..cursor + label_len].to_vec();
        labels.push(String::from_utf8_lossy(&label).to_ascii_lowercase());
        cursor = cursor.saturating_add(label_len);
        if !jumped {
            *offset = cursor;
        }
    }
    let name = labels.join(".");
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_response() {
        let mut packet = vec![0_u8; 12];
        packet[2] = 0x81;
        packet[5] = 1;
        packet[7] = 1;
        packet.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        packet.extend_from_slice(&[0, 1, 0, 1]);
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4]);
        let parsed = parse_dns_message(&packet).expect("dns");
        assert!(parsed.response);
        assert_eq!(parsed.qname, "example.com");
        assert_eq!(parsed.addresses, vec!["1.2.3.4".to_owned()]);
    }

    #[test]
    fn aaaa_matches_std_ipv6_display() {
        let mut packet = vec![0_u8; 12];
        packet[2] = 0x81;
        packet[5] = 1;
        packet[7] = 1;
        packet.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        packet.extend_from_slice(&[0, 28, 0, 1]);
        let mut answer = vec![0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16];
        answer.extend_from_slice(
            &std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0x52f9, 0x58ff, 0xfec1, 0x7037).octets(),
        );
        packet.extend_from_slice(&answer);
        let parsed = parse_dns_message(&packet).expect("dns");
        assert_eq!(
            parsed.addresses,
            vec!["fe80::52f9:58ff:fec1:7037".to_owned()]
        );
    }
}
