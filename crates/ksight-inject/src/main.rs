//! Root helper: brief PTRACE_ATTACH, memfd `dlopen`, detach. Also a local
//! transparent CONNECT forwarder for per-UID iptables REDIRECT.

use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::process::{Command, ExitCode};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

fn origin_ports() -> &'static Mutex<HashMap<String, (u16, Option<SocketAddr>)>> {
    static HINTS: OnceLock<Mutex<HashMap<String, (u16, Option<SocketAddr>)>>> = OnceLock::new();
    HINTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn remember_origin_port(host: &str, port: u16, orig: Option<SocketAddr>) {
    if host.is_empty() || port == 80 || port == 443 {
        return;
    }
    if let Ok(mut map) = origin_ports().lock() {
        map.insert(host.to_ascii_lowercase(), (port, orig));
    }
}

fn lookup_origin_port(host: &str, connect_port: u16) -> (u16, Option<SocketAddr>) {
    let key = host.to_ascii_lowercase();
    if let Ok(map) = origin_ports().lock() {
        if let Some((port, orig)) = map.get(&key) {
            return (*port, *orig);
        }
    }
    (connect_port, None)
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(first) = args.next() else {
        eprintln!(
            "usage: ksight-inject <pid> <lib.so> | forward <port> <burp-host:port> [upstream-port] | upstream <port>"
        );
        return ExitCode::from(2);
    };
    if first == "upstream" {
        let Some(port_s) = args.next() else {
            return ExitCode::from(2);
        };
        let Ok(port) = port_s.parse::<u16>() else {
            return ExitCode::from(2);
        };
        if let Err(error) = upstream_listen(port, None) {
            eprintln!("ksight-inject upstream: {error}");
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }
    if first == "forward" {
        let Some(port_s) = args.next() else {
            return ExitCode::from(2);
        };
        let Some(burp) = args.next() else {
            return ExitCode::from(2);
        };
        let Ok(port) = port_s.parse::<u16>() else {
            return ExitCode::from(2);
        };
        let Ok(addr) = burp.parse::<SocketAddr>() else {
            eprintln!("ksight-inject forward: bad burp addr {burp}");
            return ExitCode::from(2);
        };
        let upstream_port = args.next().and_then(|value| value.parse::<u16>().ok());
        if let Err(error) = forward(port, addr, upstream_port) {
            eprintln!("ksight-inject forward: {error}");
            return ExitCode::from(1);
        }
        return ExitCode::SUCCESS;
    }
    let Ok(pid) = first.parse::<i32>() else {
        eprintln!("usage: ksight-inject <pid> <lib.so>");
        return ExitCode::from(2);
    };
    let Some(lib) = args.next() else {
        eprintln!("usage: ksight-inject <pid> <lib.so>");
        return ExitCode::from(2);
    };
    match inject(pid, &lib) {
        Ok(handle) => {
            eprintln!("ksight-inject pid={pid} handle={handle:#x}");
            if handle == 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("ksight-inject: {error}");
            ExitCode::from(1)
        }
    }
}

fn forward(port: u16, burp: SocketAddr, upstream_port: Option<u16>) -> Result<(), String> {
    if let Some(up_port) = upstream_port {
        thread::spawn(move || {
            if let Err(error) = upstream_listen(up_port, Some(burp)) {
                eprintln!("ksight-inject upstream: {error}");
                let _ = std::io::Write::flush(&mut std::io::stderr());
            }
        });
    }
    let listener = TcpListener::bind(("0.0.0.0", port)).map_err(|error| error.to_string())?;
    listener
        .set_nonblocking(false)
        .map_err(|error| error.to_string())?;
    eprintln!("ksight-inject forward :{port} -> {burp}");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    for incoming in listener.incoming() {
        let Ok(client) = incoming else {
            continue;
        };
        let orig = original_dst(&client);
        thread::spawn(move || {
            if let Err(error) = proxy_one(client, orig, burp) {
                eprintln!("ksight-inject proxy: {error}");
                let _ = std::io::Write::flush(&mut std::io::stderr());
            }
        });
    }
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn original_dst(stream: &TcpStream) -> Option<SocketAddr> {
    use std::os::fd::AsRawFd;
    unsafe {
        let fd = stream.as_raw_fd();
        let mut addr: libc::sockaddr_in = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        if libc::getsockopt(fd, libc::SOL_IP, 80, (&raw mut addr).cast(), &raw mut len) == 0
            && addr.sin_family as i32 == libc::AF_INET
        {
            let ip = u32::from_be(addr.sin_addr.s_addr);
            let port = u16::from_be(addr.sin_port);
            return Some(SocketAddr::from((std::net::Ipv4Addr::from(ip), port)));
        }
        let mut addr6: libc::sockaddr_in6 = std::mem::zeroed();
        let mut len6 = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        if libc::getsockopt(fd, 41, 80, (&raw mut addr6).cast(), &raw mut len6) == 0 {
            let port = u16::from_be(addr6.sin6_port);
            return Some(SocketAddr::from((
                std::net::Ipv6Addr::from(addr6.sin6_addr.s6_addr),
                port,
            )));
        }
        None
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn original_dst(_stream: &TcpStream) -> Option<SocketAddr> {
    None
}

fn proxy_one(
    mut client: TcpStream,
    orig: Option<SocketAddr>,
    burp: SocketAddr,
) -> Result<(), String> {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_secs(8)));
    let mut peek = vec![0_u8; 2048];
    let n = client.read(&mut peek).map_err(|error| error.to_string())?;
    if n == 0 {
        return Ok(());
    }
    peek.truncate(n);
    let sni = tls_sni(&peek);
    let http_host = http_host(&peek);
    let orig_port = orig.map(|addr| addr.port()).unwrap_or(443);
    if orig.is_some_and(|addr| addr.ip() == burp.ip()) {
        return Err("refusing CONNECT loop to Burp".into());
    }
    if passthrough_host(sni.as_deref().or(http_host.as_deref())) {
        return splice_origin(client, &peek, orig, sni.as_deref());
    }
    let mut upstream = TcpStream::connect_timeout(&burp, Duration::from_secs(5))
        .map_err(|error| format!("burp connect: {error}"))?;
    let _ = upstream.set_nodelay(true);
    let tls = peek.first() == Some(&0x16);
    let looks_http = http_host.is_some()
        || peek.starts_with(b"GET ")
        || peek.starts_with(b"POST ")
        || peek.starts_with(b"HEAD ")
        || peek.starts_with(b"PUT ")
        || peek.starts_with(b"PATCH")
        || peek.starts_with(b"DELETE")
        || peek.starts_with(b"OPTIONS");
    // Custom API ports (SGCC 28083 / Aliyun 28630) are TLS, not 443.
    if tls || orig_port == 443 || orig_port == 8443 || !looks_http {
        let host = sni
            .clone()
            .or(http_host.clone())
            .unwrap_or_else(|| orig.map(socket_ip_string).unwrap_or_default());
        if host.is_empty() {
            return Err("no SNI/Host for CONNECT".into());
        }
        remember_origin_port(&host, orig_port, orig);
        // Burp's upstream proxy is used for 80/443. Custom ports (28083/28630)
        // are advertised as 443 so Burp still fetches via the phone :18888;
        // the real port is restored in upstream_one.
        let burp_port = if orig_port == 80 { 80 } else { 443 };
        let authority = if host.contains(':') && !host.starts_with('[') {
            host
        } else {
            format!("{host}:{burp_port}")
        };
        eprintln!(
            "ksight-inject CONNECT {authority} sni={sni:?} orig={orig:?} real_port={orig_port}"
        );
        let _ = std::io::Write::flush(&mut std::io::stderr());
        let req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        upstream
            .write_all(req.as_bytes())
            .map_err(|error| error.to_string())?;
        let mut buf = [0_u8; 512];
        let mut got = Vec::new();
        loop {
            let n = upstream.read(&mut buf).map_err(|error| error.to_string())?;
            if n == 0 {
                return Err("burp closed CONNECT".into());
            }
            got.extend_from_slice(&buf[..n]);
            if got.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            if got.len() > 1024 {
                return Err("CONNECT response too large".into());
            }
        }
        let ok = got.starts_with(b"HTTP/1.0 200") || got.starts_with(b"HTTP/1.1 200");
        if !ok {
            return Err(format!(
                "CONNECT {}",
                String::from_utf8_lossy(&got[..got.len().min(80)])
            ));
        }
    }
    upstream
        .write_all(&peek)
        .map_err(|error| error.to_string())?;
    let _ = client.set_read_timeout(None);
    let _ = upstream.set_read_timeout(None);
    let mut client_up = client.try_clone().map_err(|error| error.to_string())?;
    let mut up_client = upstream.try_clone().map_err(|error| error.to_string())?;
    let a = thread::spawn(move || std::io::copy(&mut client_up, &mut upstream));
    let _ = std::io::copy(&mut up_client, &mut client);
    let _ = a.join();
    Ok(())
}

fn upstream_listen(port: u16, burp: Option<SocketAddr>) -> Result<(), String> {
    let listener = TcpListener::bind(("0.0.0.0", port)).map_err(|error| error.to_string())?;
    eprintln!("ksight-inject upstream CONNECT :{port} (Burp fetches origins via the phone)");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    for incoming in listener.incoming() {
        let Ok(client) = incoming else {
            continue;
        };
        thread::spawn(move || {
            if let Err(error) = upstream_one(client, burp) {
                eprintln!("ksight-inject upstream: {error}");
                let _ = std::io::Write::flush(&mut std::io::stderr());
            }
        });
    }
    Ok(())
}

fn upstream_one(mut client: TcpStream, burp: Option<SocketAddr>) -> Result<(), String> {
    let _ = client.set_nodelay(true);
    let _ = client.set_read_timeout(Some(Duration::from_secs(15)));
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 1024];
    let header_end = loop {
        let n = client.read(&mut tmp).map_err(|error| error.to_string())?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > 8192 {
            return Err("upstream headers too large".into());
        }
    };
    let headers = buf[..header_end].to_vec();
    let extra = buf[header_end..].to_vec();
    let text = String::from_utf8_lossy(&headers);
    let Some((host, port)) = parse_connect_target(&text) else {
        return Err(format!("not CONNECT {}", text.lines().next().unwrap_or("")));
    };
    if port == 18443 || port == 18888 || port == 0 {
        return Err(format!("refusing upstream port {port}"));
    }
    let (real_port, hinted) = lookup_origin_port(&host, port);
    let dest = if let Some(addr) = hinted {
        SocketAddr::new(addr.ip(), real_port)
    } else {
        resolve_host(&host, real_port)?
    };
    if dest.ip().is_loopback() || dest.ip().is_unspecified() {
        return Err(format!("refusing upstream {dest}"));
    }
    if burp.is_some_and(|addr| dest.ip() == addr.ip() && dest.port() == addr.port()) {
        return Err("refusing upstream loop to Burp".into());
    }
    let mut origin = TcpStream::connect_timeout(&dest, Duration::from_secs(12))
        .map_err(|error| format!("origin {host}:{real_port} ({dest}): {error}"))?;
    let _ = origin.set_nodelay(true);
    eprintln!("ksight-inject upstream CONNECT {host}:{real_port} -> {dest} (burp asked {port})");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .map_err(|error| error.to_string())?;
    if !extra.is_empty() {
        origin
            .write_all(&extra)
            .map_err(|error| error.to_string())?;
    }
    let _ = client.set_read_timeout(None);
    let _ = origin.set_read_timeout(None);
    let mut client_up = client.try_clone().map_err(|error| error.to_string())?;
    let mut up_client = origin.try_clone().map_err(|error| error.to_string())?;
    let a = thread::spawn(move || std::io::copy(&mut client_up, &mut origin));
    let _ = std::io::copy(&mut up_client, &mut client);
    let _ = a.join();
    Ok(())
}

fn passthrough_host(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    const NEEDLES: &[&str] = &[
        "csc-service",
        "csc-static",
        "csc-base",
        "csc-ols",
        "csc-apm",
        "osg-service",
        "lbs.sgmap.cn",
        ".sgmap.cn",
    ];
    NEEDLES.iter().any(|needle| host.contains(needle))
}

fn splice_origin(
    mut client: TcpStream,
    peek: &[u8],
    orig: Option<SocketAddr>,
    sni: Option<&str>,
) -> Result<(), String> {
    let dest = orig.ok_or_else(|| "passthrough needs SO_ORIGINAL_DST".to_owned())?;
    let dest = match dest {
        SocketAddr::V6(v6) => v6
            .ip()
            .to_ipv4_mapped()
            .map(|ip| SocketAddr::from((ip, dest.port())))
            .unwrap_or(dest),
        other => other,
    };
    eprintln!("ksight-inject PASSTHROUGH {sni:?} -> {dest} (real cert; no Burp MITM)");
    let _ = std::io::Write::flush(&mut std::io::stderr());
    let mut origin = TcpStream::connect_timeout(&dest, Duration::from_secs(12))
        .map_err(|error| format!("passthrough {dest}: {error}"))?;
    let _ = origin.set_nodelay(true);
    origin.write_all(peek).map_err(|error| error.to_string())?;
    let _ = client.set_read_timeout(None);
    let _ = origin.set_read_timeout(None);
    let mut client_up = client.try_clone().map_err(|error| error.to_string())?;
    let mut up_client = origin.try_clone().map_err(|error| error.to_string())?;
    let a = thread::spawn(move || std::io::copy(&mut client_up, &mut origin));
    let _ = std::io::copy(&mut up_client, &mut client);
    let _ = a.join();
    Ok(())
}

fn socket_ip_string(addr: SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(|v4| v4.to_string())
            .unwrap_or_else(|| ip.to_string()),
    }
}

fn parse_connect_target(headers: &str) -> Option<(String, u16)> {
    let first = headers.lines().next()?.trim_end();
    let rest = first.strip_prefix("CONNECT ")?;
    let authority = rest.split_whitespace().next()?;
    split_host_port(authority)
}

fn split_host_port(authority: &str) -> Option<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        let port = rest.strip_prefix(':')?.parse().ok()?;
        if host.is_empty() || port == 0 {
            return None;
        }
        return Some((host.to_owned(), port));
    }
    let (host, port_s) = authority.rsplit_once(':')?;
    let port = port_s.parse().ok()?;
    if host.is_empty() || port == 0 {
        return None;
    }
    Some((host.to_owned(), port))
}

fn resolve_host(host: &str, port: u16) -> Result<SocketAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    if let Ok(mut iter) = (host, port).to_socket_addrs() {
        if let Some(addr) = iter.find(|addr| addr.is_ipv4()) {
            return Ok(addr);
        }
    }
    if let Some(ip) = resolve_via_ping(host) {
        return Ok(SocketAddr::new(ip, port));
    }
    for server in dns_servers() {
        if let Ok(ip) = dns_query_a(server, host) {
            return Ok(SocketAddr::new(ip, port));
        }
    }
    Err(format!("resolve {host}"))
}

fn resolve_via_ping(host: &str) -> Option<IpAddr> {
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "2", host])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let start = text.find('(')?;
    let end = text[start + 1..].find(')')?;
    text[start + 1..start + 1 + end].parse().ok()
}

fn dns_servers() -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for key in ["net.dns1", "net.dns2", "dhcp.wlan0.dns1", "dhcp.wlan0.dns2"] {
        let Ok(output) = Command::new("getprop").arg(key).output() else {
            continue;
        };
        let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if let Ok(ip) = value.parse::<IpAddr>() {
            if !ip.is_unspecified() {
                out.push(SocketAddr::new(ip, 53));
            }
        }
    }
    if out.is_empty() {
        out.push(SocketAddr::from((Ipv4Addr::new(114, 114, 114, 114), 53)));
        out.push(SocketAddr::from((Ipv4Addr::new(223, 5, 5, 5), 53)));
    }
    out
}

fn dns_query_a(server: SocketAddr, name: &str) -> Result<IpAddr, String> {
    let mut query = Vec::new();
    query.extend_from_slice(&0x1234_u16.to_be_bytes());
    query.extend_from_slice(&0x0100_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("bad dns name".into());
        }
        query.push(u8::try_from(label.len()).unwrap_or(0));
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|error| error.to_string())?;
    let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
    sock.send_to(&query, server)
        .map_err(|error| error.to_string())?;
    let mut buf = [0_u8; 512];
    let (n, _) = sock
        .recv_from(&mut buf)
        .map_err(|error| error.to_string())?;
    parse_dns_a(&buf[..n])
}

fn parse_dns_a(msg: &[u8]) -> Result<IpAddr, String> {
    if msg.len() < 12 {
        return Err("short dns".into());
    }
    let questions = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let answers = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut i = 12_usize;
    for _ in 0..questions {
        i = skip_dns_name(msg, i)?;
        i = i.checked_add(4).ok_or("dns")?;
    }
    for _ in 0..answers {
        i = skip_dns_name(msg, i)?;
        if i + 10 > msg.len() {
            break;
        }
        let typ = u16::from_be_bytes([msg[i], msg[i + 1]]);
        let rdlen = u16::from_be_bytes([msg[i + 8], msg[i + 9]]) as usize;
        i += 10;
        if typ == 1 && rdlen == 4 && i + 4 <= msg.len() {
            return Ok(IpAddr::V4(Ipv4Addr::new(
                msg[i],
                msg[i + 1],
                msg[i + 2],
                msg[i + 3],
            )));
        }
        i = i.saturating_add(rdlen);
    }
    Err("no A".into())
}

fn skip_dns_name(msg: &[u8], mut i: usize) -> Result<usize, String> {
    let mut hops = 0_u8;
    loop {
        if hops > 10 || i >= msg.len() {
            return Err("dns name".into());
        }
        let len = msg[i];
        if len & 0xc0 == 0xc0 {
            return i.checked_add(2).ok_or_else(|| "dns name".into());
        }
        if len == 0 {
            return i.checked_add(1).ok_or_else(|| "dns name".into());
        }
        i = i.checked_add(1 + usize::from(len)).ok_or("dns name")?;
        hops += 1;
    }
}

fn tls_sni(buf: &[u8]) -> Option<String> {
    if buf.len() < 11 || buf[0] != 0x16 || buf[1] != 0x03 {
        return None;
    }
    let hs = buf.get(5..)?;
    if hs.first() != Some(&0x01) || hs.len() < 38 {
        return None;
    }
    let mut p = 4_usize;
    p = p.checked_add(2)?;
    p = p.checked_add(32)?;
    let sid_len = *hs.get(p)? as usize;
    p = p.checked_add(1)?.checked_add(sid_len)?;
    let cs_len = u16::from_be_bytes([*hs.get(p)?, *hs.get(p + 1)?]) as usize;
    p = p.checked_add(2)?.checked_add(cs_len)?;
    let comp_len = *hs.get(p)? as usize;
    p = p.checked_add(1)?.checked_add(comp_len)?;
    let ext_len = u16::from_be_bytes([*hs.get(p)?, *hs.get(p + 1)?]) as usize;
    p = p.checked_add(2)?;
    let ext_end = (p + ext_len).min(hs.len());
    while p + 4 <= ext_end {
        let typ = u16::from_be_bytes([hs[p], hs[p + 1]]);
        let len = u16::from_be_bytes([hs[p + 2], hs[p + 3]]) as usize;
        p += 4;
        if p + len > ext_end {
            break;
        }
        if typ == 0 && len >= 5 {
            let mut q = p + 2;
            if q < p + len && hs[q] == 0 {
                q += 1;
                if q + 2 <= p + len {
                    let nlen = u16::from_be_bytes([hs[q], hs[q + 1]]) as usize;
                    q += 2;
                    if q + nlen <= p + len {
                        return String::from_utf8(hs[q..q + nlen].to_vec()).ok();
                    }
                }
            }
        }
        p += len;
    }
    None
}

fn http_host(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("host") {
            let host = value.trim();
            if !host.is_empty() {
                return Some(host.to_owned());
            }
        }
    }
    None
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn inject(_pid: i32, _lib: &str) -> Result<u64, String> {
    Err("linux/android only".into())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn inject(pid: i32, lib: &str) -> Result<u64, String> {
    let lib = if process_is_32(pid) {
        let alt = lib.replace("libksight_tls.so", "libksight_tls32.so");
        if Path::new(&alt).is_file() {
            eprintln!("ksight-inject 32-bit target, using {alt}");
            alt
        } else {
            lib.to_owned()
        }
    } else {
        lib.to_owned()
    };
    let so = fs::read(&lib).map_err(|error| format!("read {lib}: {error}"))?;
    if so.len() < 52 || so[0] != 0x7f {
        return Err("not an ELF".into());
    }
    let memfd_create = find_sym(pid, "libc.so", "memfd_create");
    let syscall_fn = find_sym(pid, "libc.so", "syscall");
    let dlopen_ext = find_sym(pid, "linker64", "__loader_android_dlopen_ext")
        .or_else(|| find_sym(pid, "libdl.so", "android_dlopen_ext"))
        .or_else(|| find_sym(pid, "libc.so", "android_dlopen_ext"));
    let dlopen = find_sym(pid, "linker64", "__loader_dlopen")
        .or_else(|| find_sym(pid, "libdl.so", "dlopen"))
        .or_else(|| find_sym(pid, "libc.so", "dlopen"));
    let caller = find_map_start(pid, "libc.so").ok_or("libc map")?;
    eprintln!(
        "ksight-inject symbols memfd={:#x?} syscall={:#x?} dlopen_ext={:#x?} dlopen={:#x?} libc={:#x}",
        memfd_create, syscall_fn, dlopen_ext, dlopen, caller
    );
    if memfd_create.is_none() && syscall_fn.is_none() && dlopen.is_none() && dlopen_ext.is_none() {
        return Err("no dlopen/memfd symbols".into());
    }
    if process_is_32(pid) {
        clear_same_uid_tracer(pid);
    }
    let attached = attach_main(pid)?;
    let result = if process_is_32(pid) {
        inject_attached32(pid, &so, &lib, dlopen_ext, dlopen, caller)
    } else {
        inject_attached(
            pid,
            &so,
            &lib,
            memfd_create.or(syscall_fn),
            memfd_create.is_some(),
            dlopen_ext,
            dlopen,
            caller,
        )
    };
    detach_all(&attached);
    result
}

#[cfg(any(target_os = "android", target_os = "linux"))]
const PTRACE_SEIZE: i32 = 0x4206;
const PTRACE_INTERRUPT: i32 = 0x4207;
const WAIT_WALL: i32 = 0x4000_0000;

fn attach_main(pid: i32) -> Result<Vec<i32>, String> {
    unsafe {
        let seized = libc::ptrace(PTRACE_SEIZE, pid, 0, 0) == 0;
        if seized {
            let _ = libc::ptrace(PTRACE_INTERRUPT, pid, 0, 0);
        } else if libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0) != 0 {
            return Err(format!(
                "ptrace attach: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    if !wait_stop(pid, Duration::from_secs(5)) {
        unsafe {
            let _ = libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
        }
        return Err("wait attach".into());
    }
    Ok(vec![pid])
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn attach_all(pid: i32) -> Result<Vec<i32>, String> {
    let mut tids = attach_main(pid)?;
    let Ok(dir) = fs::read_dir(format!("/proc/{pid}/task")) else {
        return Ok(tids);
    };
    for entry in dir.flatten() {
        let Ok(tid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if tids.contains(&tid) {
            continue;
        }
        unsafe {
            if libc::ptrace(libc::PTRACE_ATTACH, tid, 0, 0) != 0 {
                continue;
            }
        }
        let _ = wait_stop(tid, Duration::from_millis(40));
        tids.push(tid);
    }
    eprintln!("ksight-inject attached {} threads", tids.len());
    Ok(tids)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn detach_all(tids: &[i32]) {
    for tid in tids {
        unsafe {
            let _ = libc::ptrace(libc::PTRACE_DETACH, *tid, 0, 0);
        }
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn wait_stop(tid: i32, timeout: Duration) -> bool {
    let start = Instant::now();
    loop {
        let mut status = 0;
        unsafe {
            let any = libc::waitpid(-1, &mut status, libc::WNOHANG | WAIT_WALL);
            if any > 0 && libc::WIFSTOPPED(status) {
                return true;
            }
            let waited = libc::waitpid(tid, &mut status, libc::WNOHANG | WAIT_WALL);
            if waited == tid && libc::WIFSTOPPED(status) {
                return true;
            }
        }
        if start.elapsed() >= timeout {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn inject_attached(
    pid: i32,
    so: &[u8],
    lib_path: &str,
    memfd_or_syscall: Option<u64>,
    memfd_is_direct: bool,
    dlopen_ext: Option<u64>,
    dlopen: Option<u64>,
    caller: u64,
) -> Result<u64, String> {
    let saved = read_regs(pid)?;
    let sp = (saved.sp.saturating_sub(0x1000)) & !0xf;
    let brk = caller + 0x800;
    let orig = peek_word(pid, brk)?;
    poke_word(pid, brk, 0xd420_0000)?;
    let result = inject_with_brk(
        pid,
        so,
        lib_path,
        &saved,
        sp,
        brk,
        memfd_or_syscall,
        memfd_is_direct,
        dlopen_ext,
        dlopen,
        caller,
    );
    let _ = poke_word(pid, brk, orig as u64);
    let _ = write_regs(pid, &saved);
    result
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn inject_with_brk(
    pid: i32,
    so: &[u8],
    lib_path: &str,
    saved: &Regs,
    sp: u64,
    brk: u64,
    memfd_or_syscall: Option<u64>,
    memfd_is_direct: bool,
    dlopen_ext: Option<u64>,
    dlopen: Option<u64>,
    caller: u64,
) -> Result<u64, String> {
    let name_addr = sp;
    poke_bytes(pid, name_addr, b"jit-cache\0")?;
    let memfd = if let Some(func) = memfd_or_syscall {
        if memfd_is_direct {
            remote_call(pid, func, brk, [name_addr, 1, 0, 0, 0, 0, 0, 0])? as i32
        } else {
            remote_call(pid, func, brk, [279, name_addr, 1, 0, 0, 0, 0, 0])? as i32
        }
    } else {
        -1
    };
    if memfd < 0 {
        return fallback_path_dlopen(pid, so, lib_path, saved, brk, dlopen, caller);
    }
    write_proc_fd(pid, memfd, so)?;

    let file_addr = sp + 32;
    poke_bytes(pid, file_addr, b"libpac.so\0")?;
    let info_addr = sp + 64;
    let mut info = [0_u8; 48];
    info[0] = 0x70;
    info[28..32].copy_from_slice(&(memfd as u32).to_le_bytes());
    poke_bytes(pid, info_addr, &info)?;

    let handle = if let Some(func) = dlopen_ext {
        remote_call(
            pid,
            func,
            brk,
            [file_addr, 2, info_addr, caller + 0x1000, 0, 0, 0, 0],
        )?
    } else {
        0
    };
    if handle != 0 {
        eprintln!("ksight-inject memfd dlopen handle={handle:#x}");
        return Ok(handle);
    }
    fallback_path_dlopen(pid, so, lib_path, saved, brk, dlopen, caller)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn fallback_path_dlopen(
    pid: i32,
    so: &[u8],
    lib_path: &str,
    saved: &Regs,
    brk: u64,
    dlopen: Option<u64>,
    caller: u64,
) -> Result<u64, String> {
    let dest = copy_into_app_libdir(pid, so).or_else(|| {
        let bland = "/data/local/tmp/ksight/libpac.so";
        if bland != lib_path {
            let _ = fs::copy(lib_path, bland);
        }
        Path::new(bland).exists().then(|| bland.to_owned())
    });
    let Some(dest) = dest else {
        return Err("memfd dlopen failed and no app lib dir".into());
    };
    let Some(func) = dlopen else {
        return Err("no dlopen symbol".into());
    };
    let path_addr = saved.sp.saturating_sub(0x800) & !0xf;
    poke_bytes(pid, path_addr, dest.as_bytes())?;
    poke_bytes(pid, path_addr + dest.len() as u64, &[0])?;
    let handle = remote_call(
        pid,
        func,
        brk,
        [path_addr, 2, caller + 0x1000, 0, 0, 0, 0, 0],
    )?;
    if handle == 0 {
        return Err(format!("dlopen {dest} returned 0"));
    }
    eprintln!("ksight-inject dlopen {dest} handle={handle:#x}");
    Ok(handle)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn copy_into_app_libdir(pid: i32, so: &[u8]) -> Option<String> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    let mut libdir = None;
    for line in maps.lines() {
        if let Some(idx) = line.find("/data/app/") {
            let path = &line[idx..];
            for needle in ["/lib/arm64", "/lib/arm"] {
                if let Some(lib_at) = path.find(needle) {
                    let dir = path[..lib_at + needle.len()].to_owned();
                    if Path::new(&dir).is_dir() {
                        libdir = Some(dir);
                        break;
                    }
                }
            }
            if libdir.is_some() {
                break;
            }
        }
    }
    let dir = libdir?;
    let dest = format!("{dir}/libpac.so");
    fs::write(&dest, so).ok()?;
    let _ = std::process::Command::new("chmod")
        .args(["0755", &dest])
        .status();
    let _ = std::process::Command::new("restorecon").arg(&dest).status();
    Some(dest)
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn write_proc_fd(pid: i32, fd: i32, data: &[u8]) -> Result<(), String> {
    let mut file = File::options()
        .write(true)
        .open(format!("/proc/{pid}/fd/{fd}"))
        .map_err(|error| format!("open target fd: {error}"))?;
    file.write_all(data)
        .map_err(|error| format!("write memfd: {error}"))?;
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn remote_call(pid: i32, func: u64, brk: u64, args: [u64; 8]) -> Result<u64, String> {
    let mut regs = read_regs(pid)?;
    for (index, arg) in args.iter().enumerate() {
        regs.regs[index] = *arg;
    }
    regs.regs[30] = brk;
    regs.pc = func;
    write_regs(pid, &regs)?;
    unsafe {
        if libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) != 0 {
            return Err("PTRACE_CONT".into());
        }
    }
    if !wait_stop(pid, Duration::from_secs(3)) {
        return Err("wait remote call".into());
    }
    let done = read_regs(pid)?;
    Ok(done.regs[0])
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn find_map_start(pid: i32, needle: &str) -> Option<u64> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    let mut fallback = None;
    for line in maps.lines() {
        if !line.contains(needle) || !line.contains(" 00000000 ") {
            continue;
        }
        let start = u64::from_str_radix(line.split('-').next()?, 16).ok()?;
        if line.contains("r--p") || line.contains("r-xp") {
            return Some(start);
        }
        if fallback.is_none() {
            fallback = Some(start);
        }
    }
    fallback
}

fn find_sym_elf32(elf: &[u8], base: u64, sym: &str) -> Option<u64> {
    let phoff = u32::from_le_bytes(elf.get(28..32)?.try_into().ok()?) as usize;
    let phentsize = u16::from_le_bytes(elf.get(42..44)?.try_into().ok()?) as usize;
    let phnum = u16::from_le_bytes(elf.get(44..46)?.try_into().ok()?);
    let mut loads = Vec::new();
    let mut dyn_vaddr = 0_u32;
    let mut dyn_sz = 0_u32;
    for i in 0..phnum {
        let ph = phoff + usize::from(i) * phentsize;
        let kind = u32::from_le_bytes(elf.get(ph..ph + 4)?.try_into().ok()?);
        let file_off = u32::from_le_bytes(elf.get(ph + 4..ph + 8)?.try_into().ok()?);
        let vaddr = u32::from_le_bytes(elf.get(ph + 8..ph + 12)?.try_into().ok()?);
        let filesz = u32::from_le_bytes(elf.get(ph + 16..ph + 20)?.try_into().ok()?);
        if kind == 1 {
            loads.push((file_off, vaddr, filesz));
        }
        if kind == 2 {
            dyn_vaddr = vaddr;
            dyn_sz = filesz;
        }
    }
    let v2o = |v: u32| -> Option<u32> {
        for (file_off, vaddr, filesz) in &loads {
            if v >= *vaddr && v < *vaddr + *filesz {
                return Some(file_off + (v - vaddr));
            }
        }
        None
    };
    let dyn_off = v2o(dyn_vaddr)? as usize;
    let mut strtab = 0_u32;
    let mut symtab = 0_u32;
    let mut syment = 16_u32;
    let mut off = 0_usize;
    while off + 8 <= dyn_sz as usize {
        let d = dyn_off + off;
        let tag = i32::from_le_bytes(elf.get(d..d + 4)?.try_into().ok()?);
        let val = u32::from_le_bytes(elf.get(d + 4..d + 8)?.try_into().ok()?);
        if tag == 0 {
            break;
        }
        if tag == 5 {
            strtab = val;
        } else if tag == 6 {
            symtab = val;
        } else if tag == 11 {
            syment = val;
        }
        off += 8;
    }
    let str_off = v2o(strtab)? as usize;
    let sym_off = v2o(symtab)? as usize;
    let mut s = 1_u32;
    while s < 16384 {
        let e = sym_off + (s * syment) as usize;
        let name = u32::from_le_bytes(elf.get(e..e + 4)?.try_into().ok()?);
        let value = u32::from_le_bytes(elf.get(e + 4..e + 8)?.try_into().ok()?);
        if name != 0 && value != 0 {
            let start = str_off + name as usize;
            let end = elf.get(start..)?.iter().position(|b| *b == 0)?;
            if &elf[start..start + end] == sym.as_bytes() {
                return Some(base + u64::from(value));
            }
        }
        s += 1;
    }
    None
}

fn clear_same_uid_tracer(pid: i32) {
    let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
        return;
    };
    let mut tracer = 0_i32;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("TracerPid:") {
            tracer = value.trim().parse().unwrap_or(0);
        }
    }
    if tracer > 1 && tracer != pid {
        eprintln!("ksight-inject clearing tracer pid={tracer}");
        unsafe {
            libc::kill(tracer, 9);
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn process_is_32(pid: i32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/maps"))
        .ok()
        .is_some_and(|maps| {
            maps.contains("/lib/bionic/libc.so") && !maps.contains("/lib64/bionic/libc.so")
        })
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn find_sym(pid: i32, needle: &str, sym: &str) -> Option<u64> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    let mut base = 0_u64;
    let mut path = String::new();
    for line in maps.lines() {
        if !line.contains(needle) || !line.contains(" 00000000 ") {
            continue;
        }
        let start = u64::from_str_radix(line.split('-').next()?, 16).ok()?;
        let mapped = line.split_whitespace().last().unwrap_or("").to_owned();
        if mapped.contains(needle) {
            if line.contains("r--p") || line.contains("r-xp") {
                base = start;
                path = mapped;
                break;
            }
            if base == 0 {
                base = start;
                path = mapped;
            }
        }
    }
    if base == 0 || path.is_empty() {
        return None;
    }
    let elf = fs::read(&path).ok()?;
    if elf.len() < 52 || elf[0] != 0x7f {
        return None;
    }
    if elf[4] == 1 {
        return find_sym_elf32(&elf, base, sym);
    }
    if elf[4] != 2 || elf.len() < 64 {
        return None;
    }
    let phoff = u64::from_le_bytes(elf[32..40].try_into().ok()?);
    let phentsize = u16::from_le_bytes(elf[54..56].try_into().ok()?);
    let phnum = u16::from_le_bytes(elf[56..58].try_into().ok()?);
    let mut loads = Vec::new();
    let mut dyn_vaddr = 0_u64;
    let mut dyn_sz = 0_u64;
    for i in 0..phnum {
        let ph = phoff as usize + usize::from(i) * usize::from(phentsize);
        let kind = u32::from_le_bytes(elf.get(ph..ph + 4)?.try_into().ok()?);
        let file_off = u64::from_le_bytes(elf.get(ph + 8..ph + 16)?.try_into().ok()?);
        let vaddr = u64::from_le_bytes(elf.get(ph + 16..ph + 24)?.try_into().ok()?);
        let filesz = u64::from_le_bytes(elf.get(ph + 32..ph + 40)?.try_into().ok()?);
        if kind == 1 {
            loads.push((file_off, vaddr, filesz));
        }
        if kind == 2 {
            dyn_vaddr = vaddr;
            dyn_sz = filesz;
        }
    }
    let v2o = |v: u64| -> Option<u64> {
        for (file_off, vaddr, filesz) in &loads {
            if v >= *vaddr && v < *vaddr + *filesz {
                return Some(file_off + (v - vaddr));
            }
        }
        None
    };
    let dyn_off = v2o(dyn_vaddr)? as usize;
    let mut strtab = 0_u64;
    let mut symtab = 0_u64;
    let mut syment = 24_u64;
    let mut off = 0_usize;
    while off + 16 <= dyn_sz as usize {
        let d = dyn_off + off;
        let tag = u64::from_le_bytes(elf.get(d..d + 8)?.try_into().ok()?);
        let val = u64::from_le_bytes(elf.get(d + 8..d + 16)?.try_into().ok()?);
        if tag == 0 {
            break;
        }
        if tag == 5 {
            strtab = val;
        } else if tag == 6 {
            symtab = val;
        } else if tag == 11 {
            syment = val;
        }
        off += 16;
    }
    let str_off = v2o(strtab)? as usize;
    let sym_off = v2o(symtab)? as usize;
    let mut s = 1_u64;
    while s < 16384 {
        let e = sym_off + (s * syment) as usize;
        let name = u32::from_le_bytes(elf.get(e..e + 4)?.try_into().ok()?);
        let value = u64::from_le_bytes(elf.get(e + 8..e + 16)?.try_into().ok()?);
        if name != 0 && value != 0 {
            let start = str_off + name as usize;
            let end = elf.get(start..)?.iter().position(|b| *b == 0)?;
            if &elf[start..start + end] == sym.as_bytes() {
                return Some(base + value);
            }
        }
        s += 1;
    }
    None
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[repr(C)]
struct Arm32Regs {
    r: [u32; 18],
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn read_regs32(pid: i32) -> Result<Arm32Regs, String> {
    unsafe {
        let mut regs = std::mem::zeroed::<Arm32Regs>();
        let mut iov = libc::iovec {
            iov_base: (&raw mut regs).cast(),
            iov_len: std::mem::size_of::<Arm32Regs>(),
        };
        if libc::ptrace(libc::PTRACE_GETREGSET, pid, NT_PRSTATUS, &raw mut iov) != 0 {
            return Err(format!("getregset32: {}", std::io::Error::last_os_error()));
        }
        eprintln!(
            "ksight-inject regs32 iov={} r0={:#x} sp={:#x} lr={:#x} pc={:#x} cpsr={:#x}",
            iov.iov_len, regs.r[0], regs.r[13], regs.r[14], regs.r[15], regs.r[16]
        );
        Ok(regs)
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn write_regs32(pid: i32, regs: &Arm32Regs) -> Result<(), String> {
    unsafe {
        let mut iov = libc::iovec {
            iov_base: (regs as *const Arm32Regs).cast::<libc::c_void>().cast_mut(),
            iov_len: std::mem::size_of::<Arm32Regs>(),
        };
        if libc::ptrace(libc::PTRACE_SETREGSET, pid, NT_PRSTATUS, &raw mut iov) != 0 {
            return Err(format!("setregset32: {}", std::io::Error::last_os_error()));
        }
        Ok(())
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn remote_call32(pid: i32, func: u64, brk: u64, args: [u32; 4]) -> Result<u32, String> {
    let mut regs = read_regs32(pid)?;
    for (index, arg) in args.iter().enumerate() {
        regs.r[index] = *arg;
    }
    let thumb = func & 1 != 0;
    regs.r[14] = brk as u32 | 1;
    regs.r[15] = func as u32 & !1;
    if thumb {
        regs.r[16] |= 0x20;
    } else {
        regs.r[16] &= !0x20;
    }
    write_regs32(pid, &regs)?;
    let check = read_regs32(pid)?;
    eprintln!(
        "ksight-inject32 after-set pc={:#x} lr={:#x} r0={:#x} cpsr={:#x} want_pc={:#x}",
        check.r[15], check.r[14], check.r[0], check.r[16], func
    );
    unsafe {
        if libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) != 0 {
            return Err("PTRACE_CONT32".into());
        }
    }
    if !wait_stop(pid, Duration::from_secs(8)) {
        return Err("wait remote call32".into());
    }
    let done = read_regs32(pid)?;
    Ok(done.r[0])
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn inject_attached32(
    pid: i32,
    so: &[u8],
    lib_path: &str,
    dlopen_ext: Option<u64>,
    dlopen: Option<u64>,
    caller: u64,
) -> Result<u64, String> {
    let saved = read_regs32(pid)?;
    let rx = find_map_rx(pid, "libc.so").unwrap_or(caller);
    let brk = rx + 0x800;
    let mut orig = [0_u8; 4];
    let _ = process_vm_rw(pid, brk, &mut orig, false);
    let bkpt = [0x00_u8, 0xbe, 0x00, 0xbe];
    poke_bytes(pid, brk, &bkpt)?;
    let dest = copy_into_app_libdir(pid, so)
        .or_else(|| {
            let bland = "/data/local/tmp/ksight/libpac32.so";
            let _ = fs::write(bland, so);
            Path::new(bland).exists().then_some(bland.to_owned())
        })
        .ok_or_else(|| "no dest for 32-bit so".to_owned())?;
    let Some(func) = dlopen.or(dlopen_ext) else {
        let _ = process_vm_rw(pid, brk, &orig, true);
        let _ = write_regs32(pid, &saved);
        return Err("no 32-bit dlopen".into());
    };
    eprintln!("ksight-inject32 dlopen {dest} via {func:#x}");
    let path_addr = (u64::from(saved.r[13]).saturating_sub(0x400)) & !7;
    let mut path = dest.into_bytes();
    path.push(0);
    poke_bytes(pid, path_addr, &path)?;
    let handle = remote_call32(pid, func, brk, [path_addr as u32, 2, 0, 0]);
    let _ = process_vm_rw(pid, brk, &orig, true);
    let _ = write_regs32(pid, &saved);
    let handle = handle?;
    if handle == 0 {
        return Err("dlopen32 returned 0".into());
    }
    eprintln!("ksight-inject32 handle={handle:#x}");
    Ok(u64::from(handle))
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn find_map_rx(pid: i32, needle: &str) -> Option<u64> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    for line in maps.lines() {
        if line.contains(needle) && line.contains("r-xp") {
            return u64::from_str_radix(line.split('-').next()?, 16).ok();
        }
    }
    None
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn peek_word(pid: i32, addr: u64) -> Result<i64, String> {
    unsafe {
        *libc::__errno_location() = 0;
        let word = libc::ptrace(libc::PTRACE_PEEKDATA, pid, addr, 0);
        if word == -1 && errno() != 0 {
            let mut buf = [0_u8; 8];
            if process_vm_rw(pid, addr, &mut buf, false).is_ok() {
                return Ok(i64::from_le_bytes(buf));
            }
            return Err(format!(
                "peek {addr:#x}: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(word)
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn poke_word(pid: i32, addr: u64, word: u64) -> Result<(), String> {
    let bytes = word.to_le_bytes();
    if process_vm_rw(pid, addr, &bytes, true).is_ok() {
        return Ok(());
    }
    unsafe {
        if libc::ptrace(libc::PTRACE_POKEDATA, pid, addr, word as libc::c_long) != 0 {
            return Err(format!(
                "poke {addr:#x}: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn process_vm_rw(pid: i32, addr: u64, buf: &[u8], write: bool) -> Result<(), String> {
    unsafe {
        let mut local = libc::iovec {
            iov_base: buf.as_ptr().cast::<libc::c_void>().cast_mut(),
            iov_len: buf.len(),
        };
        let mut remote = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let n = if write {
            libc::process_vm_writev(pid, &raw const local, 1, &raw const remote, 1, 0)
        } else {
            libc::process_vm_readv(pid, &raw const local, 1, &raw const remote, 1, 0)
        };
        if n == buf.len() as isize {
            Ok(())
        } else {
            Err("process_vm".into())
        }
    }
}

fn poke_bytes(pid: i32, addr: u64, bytes: &[u8]) -> Result<(), String> {
    let mut off = 0_usize;
    while off < bytes.len() {
        unsafe {
            *libc::__errno_location() = 0;
            let existing = libc::ptrace(libc::PTRACE_PEEKDATA, pid, addr + off as u64, 0);
            if existing == -1 && errno() != 0 {
                return Err("peekdata".into());
            }
            let mut word = existing as u64;
            let chunk = (bytes.len() - off).min(8);
            for (i, b) in bytes[off..off + chunk].iter().enumerate() {
                word &= !(0xff_u64 << (8 * i));
                word |= u64::from(*b) << (8 * i);
            }
            if libc::ptrace(
                libc::PTRACE_POKEDATA,
                pid,
                addr + off as u64,
                word as libc::c_long,
            ) != 0
            {
                return Err("pokedata".into());
            }
        }
        off += 8;
    }
    Ok(())
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[repr(C)]
struct Aarch64Regs {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

#[cfg(any(target_os = "android", target_os = "linux"))]
type Regs = Aarch64Regs;

#[cfg(not(any(target_os = "android", target_os = "linux")))]
type Regs = Aarch64Regs;

const NT_PRSTATUS: i64 = 1;

#[cfg(all(
    any(target_os = "android", target_os = "linux"),
    target_arch = "aarch64"
))]
fn read_regs(pid: i32) -> Result<Regs, String> {
    unsafe {
        let mut regs = std::mem::zeroed::<Aarch64Regs>();
        let mut iov = libc::iovec {
            iov_base: (&raw mut regs).cast(),
            iov_len: std::mem::size_of::<Aarch64Regs>(),
        };
        if libc::ptrace(libc::PTRACE_GETREGSET, pid, NT_PRSTATUS, &raw mut iov) != 0 {
            return Err("getregset".into());
        }
        Ok(regs)
    }
}

#[cfg(all(
    any(target_os = "android", target_os = "linux"),
    target_arch = "aarch64"
))]
fn write_regs(pid: i32, regs: &Regs) -> Result<(), String> {
    unsafe {
        let mut iov = libc::iovec {
            iov_base: (regs as *const Aarch64Regs)
                .cast::<libc::c_void>()
                .cast_mut(),
            iov_len: std::mem::size_of::<Aarch64Regs>(),
        };
        if libc::ptrace(libc::PTRACE_SETREGSET, pid, NT_PRSTATUS, &raw mut iov) != 0 {
            return Err("setregset".into());
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "aarch64"))]
fn read_regs(_pid: i32) -> Result<Regs, String> {
    Err("aarch64 only".into())
}

#[cfg(not(target_arch = "aarch64"))]
fn write_regs(_pid: i32, _regs: &Regs) -> Result<(), String> {
    Err("aarch64 only".into())
}

#[cfg(test)]
mod tests {
    use super::{parse_connect_target, parse_dns_a, split_host_port};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn parse_connect_host_port() {
        let got = parse_connect_target(
            "CONNECT map.sgcc.com.cn:443 HTTP/1.1\r\nHost: map.sgcc.com.cn:443\r\n\r\n",
        );
        assert_eq!(got, Some(("map.sgcc.com.cn".into(), 443)));
        assert_eq!(
            split_host_port("[2001:db8::1]:8443"),
            Some(("2001:db8::1".into(), 8443))
        );
        assert!(parse_connect_target("GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn parse_dns_a_record() {
        // id=0x1234, qd=1, an=1, question example.com, answer 93.184.216.34
        let mut msg = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        msg.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        msg.extend_from_slice(&[0, 1, 0, 1]);
        msg.extend_from_slice(&[
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        ]);
        msg.extend_from_slice(&[93, 184, 216, 34]);
        assert_eq!(
            parse_dns_a(&msg).unwrap(),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
        );
    }
}
