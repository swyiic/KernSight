//! Per-UID transparent intercept: every outbound TCP port to Burp CONNECT,
//! and non-DNS UDP dropped so QUIC cannot skip the proxy.

use std::fs::OpenOptions;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};

const FORWARD_PORT: u16 = 18443;
const UPSTREAM_PORT: u16 = 18888;
const INJECT: &str = "/data/local/tmp/ksight/ksight-inject";

/// Installed iptables rules and the local forwarder child, removed on drop.
pub struct MitmRedirect {
    uid: u32,
    child: Option<Child>,
}

impl MitmRedirect {
    /// Redirect this app UID's outbound TCP on **every port** (not a 80/443
    /// list) to a local CONNECT forwarder. Non-DNS UDP is rejected so QUIC
    /// falls back to TLS/TCP. Loopback is left alone. Pinning still applies:
    /// the TLS peer is Burp.
    ///
    /// Also binds `:18888` as an HTTP CONNECT proxy so Burp can fetch origins
    /// through the phone (`adb forward tcp:18888 tcp:18888`).
    ///
    /// # Errors
    ///
    /// Returns when `iptables` or the forwarder cannot be started.
    pub fn install(uid: u32, burp: SocketAddr) -> Result<Self, String> {
        if uid < 10000 {
            return Err("refusing to redirect a system UID".to_owned());
        }
        let _ = Command::new("sh")
            .args([
                "-c",
                "fuser -k 18443/tcp >/dev/null 2>&1; fuser -k 18888/tcp >/dev/null 2>&1; true",
            ])
            .status();
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/data/local/tmp/ksight/mitm-forward.log")
            .ok();
        let mut cmd = Command::new(INJECT);
        cmd.args([
            "forward",
            &FORWARD_PORT.to_string(),
            &burp.to_string(),
            &UPSTREAM_PORT.to_string(),
        ]);
        if let Some(file) = log {
            let stdio = Stdio::from(file);
            cmd.stdout(stdio);
            // stderr needs a second handle; reopen
            if let Ok(err) = OpenOptions::new()
                .create(true)
                .append(true)
                .open("/data/local/tmp/ksight/mitm-forward.log")
            {
                cmd.stderr(Stdio::from(err));
            }
        }
        let child = cmd.spawn().map_err(|error| format!("forwarder: {error}"))?;
        let redirect = Self {
            uid,
            child: Some(child),
        };
        redirect.purge_uid_rules();
        if let Err(error) = redirect.apply_tcp("-I") {
            return Err(error);
        }
        let _ = redirect.apply_udp("-I");
        let _ = redirect.apply_ipv6("-I");
        let _ = redirect.apply_input("-I");
        let lan = lan_ipv4().unwrap_or_else(|| "PHONE_IP".to_owned());
        eprintln!(
            "mitm-redirect uid={uid} all TCP :{FORWARD_PORT} -> {burp}; UDP except DNS rejected; IPv6 rejected; Burp upstream 127.0.0.1:{UPSTREAM_PORT} or {lan}:{UPSTREAM_PORT}"
        );
        Ok(redirect)
    }

    fn apply_tcp(&self, insert_or_delete: &str) -> Result<(), String> {
        for binary in ["iptables", "ip6tables"] {
            let loopback = if binary == "iptables" {
                "127.0.0.0/8"
            } else {
                "::1"
            };
            let status = Command::new(binary)
                .args([
                    "-t",
                    "nat",
                    insert_or_delete,
                    "OUTPUT",
                    "-p",
                    "tcp",
                    "-m",
                    "owner",
                    "--uid-owner",
                    &self.uid.to_string(),
                    "!",
                    "-d",
                    loopback,
                    "-m",
                    "tcp",
                    "!",
                    "--dport",
                    "53",
                    "-j",
                    "REDIRECT",
                    "--to-ports",
                    &FORWARD_PORT.to_string(),
                ])
                .status();
            match status {
                Ok(status) if status.success() || insert_or_delete == "-D" => {}
                Ok(_) if binary == "ip6tables" => {}
                Ok(_) => {
                    return Err(format!("{binary} {insert_or_delete} all-tcp failed"));
                }
                Err(_) if binary == "ip6tables" => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }

    fn apply_udp(&self, insert_or_delete: &str) -> Result<(), String> {
        for binary in ["iptables", "ip6tables"] {
            let loopback = if binary == "iptables" {
                "127.0.0.0/8"
            } else {
                "::1"
            };
            let reject = if binary == "iptables" {
                "icmp-port-unreachable"
            } else {
                "icmp6-port-unreachable"
            };
            let status = Command::new(binary)
                .args([
                    insert_or_delete,
                    "OUTPUT",
                    "-p",
                    "udp",
                    "-m",
                    "owner",
                    "--uid-owner",
                    &self.uid.to_string(),
                    "!",
                    "-d",
                    loopback,
                    "-m",
                    "udp",
                    "!",
                    "--dport",
                    "53",
                    "-j",
                    "REJECT",
                    "--reject-with",
                    reject,
                ])
                .status();
            match status {
                Ok(status) if status.success() || insert_or_delete == "-D" => {}
                Ok(_) if binary == "ip6tables" => {}
                Ok(_) => {
                    let drop = Command::new(binary)
                        .args([
                            insert_or_delete,
                            "OUTPUT",
                            "-p",
                            "udp",
                            "-m",
                            "owner",
                            "--uid-owner",
                            &self.uid.to_string(),
                            "!",
                            "-d",
                            loopback,
                            "-m",
                            "udp",
                            "!",
                            "--dport",
                            "53",
                            "-j",
                            "DROP",
                        ])
                        .status();
                    match drop {
                        Ok(status) if status.success() || insert_or_delete == "-D" => {}
                        Ok(_) if binary == "ip6tables" => {}
                        Ok(_) => {
                            return Err(format!("{binary} {insert_or_delete} udp-block failed"));
                        }
                        Err(_) if binary == "ip6tables" => {}
                        Err(error) => return Err(error.to_string()),
                    }
                }
                Err(_) if binary == "ip6tables" => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }

    fn apply_ipv6(&self, insert_or_delete: &str) -> Result<(), String> {
        let status = Command::new("ip6tables")
            .args([
                insert_or_delete,
                "OUTPUT",
                "-m",
                "owner",
                "--uid-owner",
                &self.uid.to_string(),
                "-j",
                "REJECT",
            ])
            .status();
        match status {
            Ok(status) if status.success() || insert_or_delete == "-D" => Ok(()),
            Ok(_) => {
                let drop = Command::new("ip6tables")
                    .args([
                        insert_or_delete,
                        "OUTPUT",
                        "-m",
                        "owner",
                        "--uid-owner",
                        &self.uid.to_string(),
                        "-j",
                        "DROP",
                    ])
                    .status();
                match drop {
                    Ok(status) if status.success() || insert_or_delete == "-D" => Ok(()),
                    Ok(_) => Err("ip6tables ipv6-block failed".into()),
                    Err(error) => Err(error.to_string()),
                }
            }
            Err(error) => Err(error.to_string()),
        }
    }

    fn purge_uid_rules(&self) {
        for binary in ["iptables", "ip6tables"] {
            if let Ok(output) = Command::new(binary)
                .args(["-t", "nat", "-S", "OUTPUT"])
                .output()
            {
                let uid = self.uid.to_string();
                let port = FORWARD_PORT.to_string();
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    if !line.contains(&uid) || !line.contains("REDIRECT") || !line.contains(&port) {
                        continue;
                    }
                    let Some(rest) = line.strip_prefix("-A OUTPUT ") else {
                        continue;
                    };
                    let mut args = vec![
                        "-t".to_owned(),
                        "nat".to_owned(),
                        "-D".to_owned(),
                        "OUTPUT".to_owned(),
                    ];
                    args.extend(rest.split_whitespace().map(str::to_owned));
                    let _ = Command::new(binary).args(&args).status();
                }
            }
            if let Ok(output) = Command::new(binary).args(["-S", "OUTPUT"]).output() {
                let uid = self.uid.to_string();
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    if !line.contains(&uid) {
                        continue;
                    }
                    if !(line.contains("REJECT") || line.contains("DROP")) {
                        continue;
                    }
                    let Some(rest) = line.strip_prefix("-A OUTPUT ") else {
                        continue;
                    };
                    let mut args = vec!["-D".to_owned(), "OUTPUT".to_owned()];
                    args.extend(rest.split_whitespace().map(str::to_owned));
                    let _ = Command::new(binary).args(&args).status();
                }
            }
        }
        let _ = self.apply_input("-D");
    }

    fn apply_input(&self, insert_or_delete: &str) -> Result<(), String> {
        for binary in ["iptables", "ip6tables"] {
            let status = Command::new(binary)
                .args([
                    insert_or_delete,
                    "INPUT",
                    "-p",
                    "tcp",
                    "--dport",
                    &UPSTREAM_PORT.to_string(),
                    "-j",
                    "ACCEPT",
                ])
                .status();
            match status {
                Ok(status) if status.success() || insert_or_delete == "-D" => {}
                Ok(_) if binary == "ip6tables" => {}
                Ok(_) => {
                    return Err(format!(
                        "{binary} {insert_or_delete} INPUT {UPSTREAM_PORT} failed"
                    ));
                }
                Err(_) if binary == "ip6tables" => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        Ok(())
    }
}

impl Drop for MitmRedirect {
    fn drop(&mut self) {
        self.purge_uid_rules();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn lan_ipv4() -> Option<String> {
    let output = Command::new("ip")
        .args(["-o", "-4", "addr", "show", "scope", "global"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if !(line.contains("wlan") || line.contains("ap") || line.contains("eth")) {
            continue;
        }
        let Some(rest) = line.split("inet ").nth(1) else {
            continue;
        };
        let ip = rest.split('/').next()?.trim();
        if !ip.is_empty() {
            return Some(ip.to_owned());
        }
    }
    for line in text.lines() {
        let Some(rest) = line.split("inet ").nth(1) else {
            continue;
        };
        let ip = rest.split('/').next()?.trim();
        if !ip.is_empty() && ip != "127.0.0.1" {
            return Some(ip.to_owned());
        }
    }
    None
}

/// Read `packages.list` for the app's UID.
#[must_use]
pub fn uid_for_package(package: &str) -> Option<u32> {
    let text = std::fs::read_to_string("/data/system/packages.list").ok()?;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let name = parts.next()?;
        if name != package {
            continue;
        }
        return parts.next()?.parse().ok();
    }
    None
}
