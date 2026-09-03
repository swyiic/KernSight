use anyhow::Result;
use ksight_core::{
    current_capabilities, semantic_keypoints, CapabilityStage, ObservationTier, SessionGraph,
    SessionReport, VisibilityRisk,
};

pub(crate) fn print_capabilities(json: bool) -> Result<()> {
    let capabilities = current_capabilities();
    if json {
        println!("{}", serde_json::to_string_pretty(&capabilities)?);
        return Ok(());
    }

    println!("KernSight capability matrix");
    println!("L0 Observe = whole-device kernel facts; L1 Inspect = selected-process semantics; L2 Forensic = explicit intrusive evidence\n");
    for capability in capabilities {
        println!(
            "[{:<8}] {:<10} {:<6} {}",
            stage_name(capability.stage),
            tier_name(capability.tier),
            risk_name(capability.visibility),
            capability.title
        );
        println!("  {}", capability.detail);
    }
    Ok(())
}

pub(crate) fn print_keypoints(json: bool) -> Result<()> {
    let keypoints = semantic_keypoints();
    if json {
        println!("{}", serde_json::to_string_pretty(&keypoints)?);
        return Ok(());
    }
    println!("KernSight L1 semantic keypoints (registry only; all disabled by default)\n");
    for keypoint in keypoints {
        println!(
            "[{}] {} | {}",
            stage_name(keypoint.stage),
            keypoint.id,
            keypoint.layer
        );
        println!("  objective: {}", keypoint.objective);
        println!("  selector: {}", keypoint.selector);
        println!("  validation: {}", keypoint.validation);
        println!("  detection: {}", keypoint.detection_surface);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn print_session_report(report: &SessionReport, top: usize) {
    let duration_ns = match (report.first_monotonic_ns, report.last_monotonic_ns) {
        (Some(first), Some(last)) => last.saturating_sub(first),
        _ => 0,
    };
    println!(
        "Session {} | {} events | {}.{:03}s",
        report
            .session_id
            .map_or_else(|| "empty".to_owned(), |value| value.to_string()),
        report.total_events,
        duration_ns / 1_000_000_000,
        (duration_ns % 1_000_000_000) / 1_000_000
    );
    if report.total_events == 0 {
        println!("No retained events are available in this replay range.");
        return;
    }

    print_environment_integrity(report);

    print_sensor_quality(report);
    print_lifecycle_summaries(report);

    println!("\nApplications / processes (top {top})");
    for process in report.processes.iter().take(top) {
        println!(
            "  {} | events={} | pids={}",
            process.label,
            process.event_count,
            join_numbers(&process.process_ids)
        );
    }

    println!("\nBinder relations (top {top})");
    if report.binder_relations.is_empty() {
        println!("  none captured");
    }
    for relation in report.binder_relations.iter().take(top) {
        let codes = relation
            .codes
            .iter()
            .take(6)
            .map(|(code, count)| format!("{code:#x}×{count}"))
            .collect::<Vec<_>>()
            .join(", ");
        let interfaces = relation
            .interfaces
            .iter()
            .take(4)
            .map(|(name, count)| format!("{name}×{count}"))
            .collect::<Vec<_>>()
            .join(", ");
        let interface_note = if interfaces.is_empty() {
            String::new()
        } else {
            format!(" | ifaces=[{interfaces}]")
        };
        println!(
            "  {}({}) -> {}({}) | requests={} replies={} | codes=[{}]{interface_note}",
            relation.source,
            relation.source_process_id,
            relation.target,
            relation
                .target_process_id
                .map_or_else(|| "?".to_owned(), |value| value.to_string()),
            relation.requests,
            relation.replies,
            codes
        );
    }

    println!("\nDEX / ELF / file candidates (top {top})");
    if report.artifacts.is_empty() {
        println!("  none captured");
    }
    for artifact in report.artifacts.iter().take(top) {
        let digest = artifact
            .content_sha256
            .as_deref()
            .map_or_else(String::new, |value| format!(" sha256={value}"));
        println!(
            "  [{}] open-attempts={} success={} failed={} maps={}{} {}",
            artifact.category,
            artifact.open_attempts,
            artifact.successful_opens,
            artifact.failed_opens,
            artifact.mappings,
            digest,
            artifact.path
        );
    }

    println!("\nNetwork peers (top {top})");
    if report.network_peers.is_empty() {
        println!("  none captured");
    }
    for peer in report.network_peers.iter().take(top) {
        println!(
            "  {}({}) <-> {}:{} | outbound={}/{}/in-progress={} inbound-accepted={} bytes-out/in={}/{} mmsg-out/in={}/{} sni={} alpn={} http={}",
            peer.source,
            peer.source_process_id,
            peer.peer,
            peer.port
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
            peer.attempts,
            peer.successful,
            peer.in_progress,
            peer.accepted,
            peer.sent_bytes,
            peer.received_bytes,
            peer.sent_messages,
            peer.received_messages,
            peer.sni.as_deref().unwrap_or("-"),
            peer.alpn.as_deref().unwrap_or("-"),
            peer.http_host.as_deref().or(peer.http_method.as_deref()).unwrap_or("-")
        );
    }

    println!("\nInspect hits (top {top})");
    if report.inspect_hits.is_empty() {
        println!("  none captured");
    }
    for hit in report.inspect_hits.iter().take(top) {
        let method = match (
            hit.binder_interface.as_deref(),
            hit.binder_method.as_deref(),
        ) {
            (Some(interface), Some(name)) => format!(" {interface}::{name}"),
            (Some(interface), None) => format!(" {interface}"),
            _ => String::new(),
        };
        let joined = hit.binder_transaction_id.map_or_else(String::new, |id| {
            format!(
                " txn={id}{}",
                hit.reply_latency_ns
                    .map_or_else(String::new, |ns| format!(" reply-ns={ns}"))
            )
        });
        println!(
            "  {}({}) {} hits={} attached={}{method}{joined} {}",
            hit.adapter,
            hit.process_id,
            hit.binder_code
                .map_or_else(|| "-".to_owned(), |code| format!("{code:#x}")),
            hit.hits,
            hit.attached,
            hit.last_detail.replace('\n', " ")
        );
    }

    println!("\nTLS plaintext (Inspect, top {top})");
    if report.plaintext.is_empty() {
        println!("  none captured");
    }
    for row in report.plaintext.iter().take(top) {
        println!(
            "  {}({}) {} class={} {} writes requested/captured={}/{} preview={}",
            row.source,
            row.process_id,
            row.adapter,
            if row.content_class.is_empty() {
                "unknown"
            } else {
                row.content_class.as_str()
            },
            row.count,
            row.requested_bytes,
            row.captured_bytes,
            row.preview.as_deref().unwrap_or("-").replace('\n', "\\n")
        );
    }

    println!("\nHTTP calls from TLS plaintext (Inspect, top {top})");
    if report.http_calls.is_empty() {
        println!("  none parsed (need HTTP/1 or JSON preview; HTTP/2 frames are not decoded)");
    }
    for row in report.http_calls.iter().take(top) {
        let host = row.host.as_deref().unwrap_or("-");
        let tracker = if row.third_party { " tracker" } else { "" };
        let keys = row
            .body_keys
            .iter()
            .chain(row.query_keys.iter())
            .take(8)
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        let redacted = row.redacted_body_keys.join(",");
        let origin = if row.origin.is_empty() {
            "inspect"
        } else {
            row.origin.as_str()
        };
        println!(
            "  {}({}) {origin} {} {} {host}{}{tracker} ×{} status={} keys=[{keys}] redacted=[{redacted}]",
            row.source,
            row.process_id,
            row.direction,
            row.method,
            row.path,
            row.count,
            row.status
                .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        );
    }

    if !report.loopback_scans.is_empty() {
        println!("\nLoopback connect scans");
        for scan in report.loopback_scans.iter().take(top) {
            println!(
                "  {}({}) {} ports {}-{} unique={} attempts={}",
                scan.source,
                scan.process_id,
                scan.address,
                scan.port_min,
                scan.port_max,
                scan.unique_ports,
                scan.attempts
            );
        }
    }

    println!("\nScheduler wakeups (top {top})");
    if report.sched_wakeups.is_empty() {
        println!("  none captured");
    }
    for wakeup in report.sched_wakeups.iter().take(top) {
        println!(
            "  {}({}) -> tid {} | count={}",
            wakeup.waker, wakeup.waker_process_id, wakeup.wakee_tid, wakeup.count
        );
    }

    println!(
        "\nL0 graph | entities={} edges={} (query with `device graph`)",
        report.graph.entities.len(),
        report.graph.edges.len()
    );
    for edge in report.graph.edges.iter().take(top) {
        println!(
            "  [{:?}] {} --{}--> {}",
            edge.strength, edge.from, edge.relation, edge.to
        );
    }

    print_limitations(report);
}

pub(crate) fn print_graph(graph: &SessionGraph) {
    println!(
        "L0 graph query | entities={} edges={} dump_ids={}",
        graph.entities.len(),
        graph.edges.len(),
        graph.dump_ids.len()
    );
    if graph.entities.is_empty() && graph.edges.is_empty() {
        println!("  no matching entities or edges");
    }
    for entity in &graph.entities {
        println!(
            "  entity {:?} {} | {}",
            entity.kind, entity.key, entity.label
        );
    }
    for edge in &graph.edges {
        println!(
            "  [{:?}] {} --{}--> {}",
            edge.strength, edge.from, edge.relation, edge.to
        );
    }
    if !graph.limitations.is_empty() {
        println!("limitations");
        for limitation in &graph.limitations {
            println!("  - {limitation}");
        }
    }
}

fn print_sensor_quality(report: &SessionReport) {
    println!("\nSensors");
    for (sensor, count) in &report.sensor_counts {
        println!("  {sensor:?}: {count}");
    }
    println!(
        "  quality: lost={} truncated={} sampled={} max-sample=1/{} opaque={}",
        report.quality.lost_records,
        report.quality.truncated_events,
        report.quality.sampled_events,
        report.quality.max_sample_one_in.max(1),
        report.quality.opaque_events
    );
    if !report.quality.lost_by_sensor.is_empty() {
        let drops = report
            .quality
            .lost_by_sensor
            .iter()
            .map(|(sensor, count)| format!("{sensor:?}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  kernel ring drops: {drops}");
    }
    if !report.quality.truncated_by_source.is_empty() {
        let sources = report
            .quality
            .truncated_by_source
            .iter()
            .map(|(source, count)| format!("{source}={count}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("  truncation sources: {sources}");
    }
}

fn print_limitations(report: &SessionReport) {
    println!("\nCurrent interpretation limits");
    for limitation in &report.limitations {
        println!("  - {limitation}");
    }
    println!("\nRaw evidence is unchanged; use `device replay` for event-level detail.");
}

fn print_environment_integrity(report: &SessionReport) {
    println!("\nEnvironment / execution integrity");
    if let Some(environment) = report.environment.as_ref() {
        println!(
            "  collector={:?} developer={:?} usb-debug={:?} wireless-debug={:?} root={} selinux-enforcing={:?} verified-boot={} bootloader-locked={:?}",
            environment.collector_mode,
            environment.developer_options,
            environment.usb_debugging,
            environment.wireless_debugging,
            environment.root_authorized,
            environment.selinux_enforcing,
            environment.verified_boot_state.as_deref().unwrap_or("unknown"),
            environment.bootloader_locked
        );
        println!(
            "  target-behavior-may-be-altered={} transitions={} warnings={}",
            environment.target_behavior_may_be_altered,
            report.environment_transitions,
            if environment.warnings.is_empty() {
                "none".to_owned()
            } else {
                environment.warnings.join(", ")
            }
        );
    } else {
        println!("  environment metadata missing");
    }
    if let Some(completion) = report.completion.as_ref() {
        let dropped = completion.dropped_by_sensor.values().copied().sum::<u64>();
        println!(
            "  execution-complete={} stop={:?} live={} invalid={} dropped={} filtered-scope={} filtered-threads={} filtered-collector={}",
            report.execution_complete,
            completion.stop_reason,
            completion.live_events,
            completion.invalid_records,
            dropped,
            completion.filtered_scope,
            completion.filtered_threads,
            completion.filtered_collector
        );
    } else {
        println!("  execution-complete=false completion marker missing");
    }
}

#[allow(clippy::too_many_lines)]
fn print_lifecycle_summaries(report: &SessionReport) {
    println!(
        "  graph: entities={} edges={}",
        report.graph.entities.len(),
        report.graph.edges.len()
    );
    println!(
        "  fd lifecycle: observed={} open={} close={} close_range={} dup={} active={} unknown-close={} complete={}",
        report.fd_lifecycle.lineage_observed,
        report.fd_lifecycle.successful_opens,
        report.fd_lifecycle.successful_closes,
        report.fd_lifecycle.successful_close_ranges,
        report.fd_lifecycle.successful_duplicates,
        report.fd_lifecycle.active_at_end,
        report.fd_lifecycle.closes_without_observed_origin,
        report.fd_lifecycle.lineage_complete
    );
    if !report.binder_fd_transfers.is_empty() {
        println!(
            "  binder fd transfers: {}",
            report.binder_fd_transfers.len()
        );
    }
    if report.dns_datagrams > 0 || !report.dns_names.is_empty() {
        let named = report
            .network_peers
            .iter()
            .filter(|peer| peer.resolved_name.is_some())
            .count();
        println!(
            "  dns: datagrams={} names={} peers-with-qname={}",
            report.dns_datagrams,
            report.dns_names.len(),
            named
        );
    }
    if report.handshake_events > 0 || !report.handshake_names.is_empty() {
        let named = report
            .network_peers
            .iter()
            .filter(|peer| peer.sni.is_some() || peer.http_host.is_some())
            .count();
        println!(
            "  handshake: events={} names={} peers-with-sni-or-host={}",
            report.handshake_events,
            report.handshake_names.len(),
            named
        );
    }
    println!(
        "  memory lifecycle: map={} protect={} unmap={} remap={} brk={} matched/unmatched={}/{} active={} mapped-bytes={} unmapped-bytes={}",
        report.memory_lifecycle.successful_maps,
        report.memory_lifecycle.successful_protects,
        report.memory_lifecycle.successful_unmaps,
        report.memory_lifecycle.successful_remaps,
        report.memory_lifecycle.successful_brk,
        report.memory_lifecycle.unmaps_with_observed_mapping,
        report.memory_lifecycle.unmaps_without_observed_mapping,
        report.memory_lifecycle.active_regions_at_end,
        report.memory_lifecycle.mapped_bytes,
        report.memory_lifecycle.unmapped_bytes
    );
    println!(
        "  observed mapping spans: {} (unmap does not drop them; dump VMA overlaps_mmap is correlated)",
        report.observed_mappings.len()
    );
    if report.merged_dumps.is_empty() {
        println!("  merged dumps: none");
    } else {
        let dumps = report
            .merged_dumps
            .iter()
            .map(|dump| format!("{}={}", dump.package, dump.dump_id))
            .collect::<Vec<_>>()
            .join(" ");
        println!("  merged dumps: {dumps}");
    }
    println!(
        "  socket lifecycle: connect={} associated={} accept={}/{} io-send/recv={}/{} bytes-out/in={}/{} mmsg-out/in={}/{} io-failed={} io-unmatched={} dup={} close={} active={}",
        report.socket_lifecycle.connect_attempts,
        report.socket_lifecycle.connected_or_in_progress,
        report.socket_lifecycle.accepted_descriptors,
        report.socket_lifecycle.accept_attempts,
        report.socket_lifecycle.send_calls,
        report.socket_lifecycle.receive_calls,
        report.socket_lifecycle.sent_bytes,
        report.socket_lifecycle.received_bytes,
        report.socket_lifecycle.sent_messages,
        report.socket_lifecycle.received_messages,
        report.socket_lifecycle.failed_io,
        report.socket_lifecycle.io_without_observed_lifecycle,
        report.socket_lifecycle.duplicated_descriptors,
        report.socket_lifecycle.closed_descriptors,
        report.socket_lifecycle.active_at_end
    );
    println!(
        "  Binder lifecycle: submitted={} delivered={} two-way={} one-way={} replies={} paired={} avg-delivery-ns={} avg-reply-ns={}",
        report.binder_lifecycle.submitted,
        report.binder_lifecycle.delivered,
        report.binder_lifecycle.two_way_submitted,
        report.binder_lifecycle.one_way_submitted,
        report.binder_lifecycle.reply_submitted,
        report.binder_lifecycle.paired_replies,
        report
            .binder_lifecycle
            .average_delivery_ns
            .map_or_else(|| "-".to_owned(), |value| value.to_string()),
        report
            .binder_lifecycle
            .average_reply_ns
            .map_or_else(|| "-".to_owned(), |value| value.to_string())
    );
}

fn stage_name(stage: CapabilityStage) -> &'static str {
    match stage {
        CapabilityStage::Implemented => "ready",
        CapabilityStage::Partial => "partial",
        CapabilityStage::Planned => "planned",
        CapabilityStage::Research => "research",
    }
}

fn tier_name(tier: ObservationTier) -> &'static str {
    match tier {
        ObservationTier::ObserveL0 => "L0-observe",
        ObservationTier::InspectL1 => "L1-inspect",
        ObservationTier::ForensicL2 => "L2-forensic",
    }
}

fn risk_name(risk: VisibilityRisk) -> &'static str {
    match risk {
        VisibilityRisk::Low => "low",
        VisibilityRisk::Medium => "medium",
        VisibilityRisk::High => "high",
    }
}

fn join_numbers(values: &[u32]) -> String {
    values
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}
