//! Cross-layer analysis graph: entities and explicit edge strength.
//!
//! Observe sessions produce kernel facts. The analysis plane must not present time proximity as a
//! proven causal relationship. Edges are therefore classified as confirmed, correlated, or inferred.

use ksight_model::{ArtifactKind, ArtifactProvenance, ArtifactRef, SensorKind};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    BinderFdTransfer, BinderReplyPair, DumpArtifact, InspectHitActivity, MappingSource,
    ObservedMapping, ProcessActivity, ProcessInstanceRef,
};

/// Half-open interval overlap. Degenerate ranges never overlap.
#[must_use]
pub fn ranges_overlap(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < a_end && b_start < b_end && a_start < b_end && b_start < a_end
}

fn dump_artifact_key(artifact: &DumpArtifact) -> String {
    artifact.sha256.as_ref().map_or_else(
        || format!("artifact:{}", artifact.relative_path),
        |sha256| format!("artifact:sha256:{sha256}"),
    )
}

fn dump_artifact_ref(artifact: &DumpArtifact) -> Option<ArtifactRef> {
    let kind = match artifact.kind.as_str() {
        "dex" => ArtifactKind::Dex,
        "elf" => ArtifactKind::Elf,
        _ => ArtifactKind::OpaqueBinary,
    };
    let provenance = match artifact.source.as_str() {
        "memory-dex" | "heap-blob" => ArtifactProvenance::RuntimeSnapshot,
        "runtime-so" => ArtifactProvenance::Loaded,
        "apk-dex" | "apk-assets" | "install-lib" => ArtifactProvenance::Original,
        _ => ArtifactProvenance::Inferred,
    };
    Some(ArtifactRef {
        kind,
        provenance,
        sha256: artifact.sha256.clone()?,
        size: artifact.bytes,
        label: Some(artifact.relative_path.clone()),
    })
}

/// Strength of a reconstructed relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeStrength {
    /// Directly observed by a single sensor with matching identifiers.
    Confirmed,
    /// Joined by stable identifiers across sensors, without a single kernel fact proving causality.
    Correlated,
    /// Heuristic or time-adjacent reconstruction that must not be displayed as proof.
    Inferred,
}

/// Named entity classes the analysis plane may materialize from L0 facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphEntityKind {
    /// Process identity across PID reuse.
    ProcessInstance,
    /// Thread within a process instance.
    Thread,
    /// File descriptor owned by a process.
    Fd,
    /// Path or inode-less file identity.
    FileObject,
    /// Network 5-tuple reconstructed from connect/accept/FD events.
    SocketFlow,
    /// Binder driver transaction.
    BinderTransaction,
    /// Virtual-memory mapping interval.
    MemoryMapping,
    /// DEX/ELF or other code artifact.
    CodeArtifact,
    /// Forensic dump-package catalog bound into a session graph.
    EvidenceDump,
    /// Selected-process Inspect adapter hit (never an Observe fact).
    InspectHit,
    /// DNS QNAME observed on UDP/53.
    DnsName,
    /// TLS SNI or HTTP Host observed on a first write.
    HostName,
}

/// One node in a session analysis graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEntity {
    /// Entity class.
    pub kind: GraphEntityKind,
    /// Session that produced the evidence.
    pub session_id: Uuid,
    /// Stable identifier within the session, for example `pid:fd` or a transaction id.
    pub key: String,
    /// Operator-facing label.
    pub label: String,
    /// Sensors that contributed facts.
    pub sensors: Vec<SensorKind>,
    /// Optional content-addressed artifact.
    pub artifact: Option<ArtifactRef>,
    /// Stable process instance (`boot_id:pid:start_time_ns`) when this node is a process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_instance_id: Option<String>,
}

/// Directed relationship between two entities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphEdge {
    /// Source entity key.
    pub from: String,
    /// Destination entity key.
    pub to: String,
    /// Relationship name, for example `owns`, `maps`, `sends`, `loads`.
    pub relation: String,
    /// Evidence strength.
    pub strength: EdgeStrength,
    /// Sensor that justified the edge when applicable.
    pub sensor: Option<SensorKind>,
}

/// Bounded graph extracted from one session report range.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionGraph {
    /// Materialized entities.
    pub entities: Vec<GraphEntity>,
    /// Directed edges.
    pub edges: Vec<GraphEdge>,
    /// Limitations that apply to this reconstruction.
    pub limitations: Vec<String>,
    /// dump-package identifiers merged into this graph. Not an L0 session id.
    #[serde(default)]
    pub dump_ids: Vec<String>,
}

/// Filter for a previously built L0 graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphQuery {
    /// Substring matched against entity keys, labels, and edge endpoints.
    pub entity: Option<String>,
    /// Exact relation name such as `binder` or `connects`.
    pub relation: Option<String>,
    /// Required edge strength.
    pub strength: Option<EdgeStrength>,
    /// Maximum entities and edges to return.
    pub limit: usize,
}

impl Default for GraphQuery {
    fn default() -> Self {
        Self {
            entity: None,
            relation: None,
            strength: None,
            limit: 64,
        }
    }
}

impl EdgeStrength {
    /// Parse a serialized strength name.
    pub fn parse_name(name: &str) -> Option<Self> {
        match name {
            "confirmed" => Some(Self::Confirmed),
            "correlated" => Some(Self::Correlated),
            "inferred" => Some(Self::Inferred),
            _ => None,
        }
    }
}

impl SessionGraph {
    /// Empty graph with the standard L0 limitation notice.
    pub fn l0_placeholder() -> Self {
        Self {
            entities: Vec::new(),
            edges: Vec::new(),
            limitations: vec![
                "L0 facts establish process, FD, mapping, socket, and Binder identity; they do not prove application-level causality".to_owned(),
                "time proximity is never a confirmed edge".to_owned(),
            ],
            dump_ids: Vec::new(),
        }
    }

    /// Insert a pid-qualified process node and a correlated package `contains` edge.
    pub fn ensure_process(&mut self, session_id: Uuid, label: &str, pid: u32) -> String {
        self.ensure_process_instance(session_id, label, pid, None)
    }

    /// Insert a process instance node keyed by `boot_id:pid:start_time_ns` when known.
    pub fn ensure_process_instance(
        &mut self,
        session_id: Uuid,
        label: &str,
        pid: u32,
        instance: Option<&ProcessInstanceRef>,
    ) -> String {
        if pid == 0 && instance.is_none() {
            return format!("process:{label}");
        }
        let package_key = format!("process:{label}");
        let (key, instance_id, node_label) = if let Some(instance) = instance {
            (
                format!("procinst:{}", instance.process_instance_id),
                Some(instance.process_instance_id.clone()),
                format!(
                    "{label} pid={} start={}",
                    instance.pid, instance.start_time_ns
                ),
            )
        } else {
            (
                format!("process:{label}:{pid}"),
                None,
                format!("{label} pid={pid}"),
            )
        };
        if self.entities.iter().any(|entity| entity.key == key) {
            return key;
        }
        self.entities.push(GraphEntity {
            kind: GraphEntityKind::ProcessInstance,
            session_id,
            key: key.clone(),
            label: node_label,
            sensors: Vec::new(),
            artifact: None,
            process_instance_id: instance_id,
        });
        if self.entities.iter().any(|entity| entity.key == package_key) {
            self.edges.push(GraphEdge {
                from: package_key,
                to: key.clone(),
                relation: "contains".to_owned(),
                strength: EdgeStrength::Correlated,
                sensor: Some(SensorKind::Process),
            });
        }
        key
    }

    /// Materialize confirmed Binder/socket/sched edges and file identities from a report.
    #[allow(clippy::too_many_lines)]
    pub fn from_l0(
        session_id: Option<Uuid>,
        processes: &[crate::ProcessActivity],
        binder: &[crate::BinderRelation],
        artifacts: &[crate::ArtifactActivity],
        peers: &[crate::NetworkPeerActivity],
        sched: &[crate::SchedWakeupActivity],
    ) -> Self {
        let session_id = session_id.unwrap_or(Uuid::nil());
        let mut graph = Self::l0_placeholder();
        graph.limitations.push(
            "process graph keys prefer procinst:{boot_id:pid:start_time_ns}; pid-only keys remain when start_time was not observed".to_owned(),
        );
        for process in processes.iter().take(64) {
            graph.entities.push(GraphEntity {
                kind: GraphEntityKind::ProcessInstance,
                session_id,
                key: format!("process:{}", process.label),
                label: process.label.clone(),
                sensors: process.sensor_counts.keys().copied().collect(),
                artifact: None,
                process_instance_id: None,
            });
            for instance in process.instances.iter().take(16) {
                let _ = graph.ensure_process_instance(
                    session_id,
                    &process.label,
                    instance.pid,
                    Some(instance),
                );
            }
        }
        for relation in binder.iter().take(128) {
            let from = graph.ensure_process_instance(
                session_id,
                &relation.source,
                relation.source_process_id,
                instance_for_pid(processes, relation.source_process_id),
            );
            let to = graph.ensure_process_instance(
                session_id,
                &relation.target,
                relation.target_process_id.unwrap_or(0),
                relation
                    .target_process_id
                    .and_then(|pid| instance_for_pid(processes, pid)),
            );
            graph.edges.push(GraphEdge {
                from,
                to,
                relation: "binder".to_owned(),
                strength: EdgeStrength::Confirmed,
                sensor: Some(SensorKind::Binder),
            });
        }
        for artifact in artifacts.iter().take(64) {
            let key = format!("file:{}", artifact.path);
            graph.entities.push(GraphEntity {
                kind: if artifact.category == "dex" || artifact.category == "elf" {
                    GraphEntityKind::CodeArtifact
                } else {
                    GraphEntityKind::FileObject
                },
                session_id,
                key: key.clone(),
                label: artifact.path.clone(),
                sensors: vec![SensorKind::File, SensorKind::Memory],
                artifact: None,
                process_instance_id: None,
            });
        }
        for peer in peers.iter().take(64) {
            let key = format!("socket:{}:{}", peer.peer, peer.port.unwrap_or(0));
            graph.entities.push(GraphEntity {
                kind: GraphEntityKind::SocketFlow,
                session_id,
                key: key.clone(),
                label: peer.peer.clone(),
                sensors: vec![SensorKind::Network],
                artifact: None,
                process_instance_id: None,
            });
            let from = graph.ensure_process_instance(
                session_id,
                &peer.source,
                peer.source_process_id,
                instance_for_pid(processes, peer.source_process_id),
            );
            graph.edges.push(GraphEdge {
                from: from.clone(),
                to: key.clone(),
                relation: "connects".to_owned(),
                strength: EdgeStrength::Confirmed,
                sensor: Some(SensorKind::Network),
            });
            if let Some(name) = peer.resolved_name.as_deref() {
                let dns_key = format!("dns:{name}");
                if !graph.entities.iter().any(|entity| entity.key == dns_key) {
                    graph.entities.push(GraphEntity {
                        kind: GraphEntityKind::DnsName,
                        session_id,
                        key: dns_key.clone(),
                        label: name.to_owned(),
                        sensors: vec![SensorKind::Network],
                        artifact: None,
                        process_instance_id: None,
                    });
                }
                graph.edges.push(GraphEdge {
                    from: dns_key,
                    to: key.clone(),
                    relation: "answers".to_owned(),
                    strength: EdgeStrength::Correlated,
                    sensor: Some(SensorKind::Network),
                });
            }
            for (name, relation) in [
                (peer.sni.as_deref(), "sni"),
                (peer.http_host.as_deref(), "http_host"),
            ] {
                let Some(name) = name else {
                    continue;
                };
                let host_key = format!("host:{name}");
                if !graph.entities.iter().any(|entity| entity.key == host_key) {
                    graph.entities.push(GraphEntity {
                        kind: GraphEntityKind::HostName,
                        session_id,
                        key: host_key.clone(),
                        label: name.to_owned(),
                        sensors: vec![SensorKind::Network],
                        artifact: None,
                        process_instance_id: None,
                    });
                }
                graph.edges.push(GraphEdge {
                    from: host_key,
                    to: key.clone(),
                    relation: relation.to_owned(),
                    strength: EdgeStrength::Correlated,
                    sensor: Some(SensorKind::Network),
                });
            }
        }
        for wakeup in sched.iter().take(128) {
            let from = graph.ensure_process_instance(
                session_id,
                &wakeup.waker,
                wakeup.waker_process_id,
                instance_for_pid(processes, wakeup.waker_process_id),
            );
            let to = format!("thread:{}", wakeup.wakee_tid);
            graph.entities.push(GraphEntity {
                kind: GraphEntityKind::Thread,
                session_id,
                key: to.clone(),
                label: format!("tid {}", wakeup.wakee_tid),
                sensors: vec![SensorKind::Sched],
                artifact: None,
                process_instance_id: None,
            });
            graph.edges.push(GraphEdge {
                from,
                to,
                relation: "wakes".to_owned(),
                strength: EdgeStrength::Confirmed,
                sensor: Some(SensorKind::Sched),
            });
        }
        graph
    }

    /// Bind dump-package DEX/SO files to a process instance.
    ///
    /// Edges are `correlated`: the dump copied bytes from a mapping or the APK, which is
    /// not the same as a confirmed mmap/open syscall.
    #[must_use]
    pub fn from_package_dump(
        session_id: Uuid,
        package: &str,
        pids: &[u32],
        artifacts: &[crate::DumpArtifact],
    ) -> Self {
        let mut graph = Self::l0_placeholder();
        graph.limitations.push(
            "dump DEX/SO artifacts are correlated with a process instance and optional VMA; they do not prove mmap or open causality".to_owned(),
        );
        let dump_key = format!("dump:{session_id}");
        graph.dump_ids.push(session_id.to_string());
        graph.entities.push(GraphEntity {
            kind: GraphEntityKind::EvidenceDump,
            session_id,
            key: dump_key.clone(),
            label: format!("{package} dump"),
            sensors: Vec::new(),
            artifact: None,
            process_instance_id: None,
        });
        for pid in pids.iter().copied().take(16) {
            let _ = graph.ensure_process(session_id, package, pid);
        }
        let package_key =
            graph.ensure_process(session_id, package, pids.first().copied().unwrap_or(0));
        graph.edges.push(GraphEdge {
            from: dump_key,
            to: package_key.clone(),
            relation: "records".to_owned(),
            strength: EdgeStrength::Correlated,
            sensor: None,
        });
        for artifact in artifacts.iter().take(256) {
            let key = dump_artifact_key(artifact);
            if !graph.entities.iter().any(|entity| entity.key == key) {
                graph.entities.push(GraphEntity {
                    kind: GraphEntityKind::CodeArtifact,
                    session_id,
                    key: key.clone(),
                    label: format!(
                        "{} {} {}",
                        artifact.kind, artifact.source, artifact.relative_path
                    ),
                    sensors: Vec::new(),
                    artifact: dump_artifact_ref(artifact),
                    process_instance_id: None,
                });
            }
            let from = artifact.pid.map_or_else(
                || package_key.clone(),
                |pid| graph.ensure_process(session_id, package, pid),
            );
            let relation = if artifact.source == "heap-blob" || artifact.source == "memory-dex" {
                "produced"
            } else if artifact.source == "runtime-so" {
                "loaded"
            } else {
                "contains"
            };
            if !graph
                .edges
                .iter()
                .any(|edge| edge.from == from && edge.to == key && edge.relation == relation)
            {
                graph.edges.push(GraphEdge {
                    from,
                    to: key.clone(),
                    relation: relation.to_owned(),
                    strength: EdgeStrength::Correlated,
                    sensor: None,
                });
            }
            if let (Some(pid), Some(start), Some(end)) =
                (artifact.pid, artifact.vma_start, artifact.vma_end)
            {
                let vma_key = format!("vma:{pid}:{start:x}-{end:x}");
                if !graph.entities.iter().any(|entity| entity.key == vma_key) {
                    graph.entities.push(GraphEntity {
                        kind: GraphEntityKind::MemoryMapping,
                        session_id,
                        key: vma_key.clone(),
                        label: artifact
                            .map_path
                            .clone()
                            .unwrap_or_else(|| format!("{start:#x}-{end:#x}")),
                        sensors: Vec::new(),
                        artifact: None,
                        process_instance_id: None,
                    });
                }
                if !graph.edges.iter().any(|edge| {
                    edge.from == key && edge.to == vma_key && edge.relation == "extracted_from"
                }) {
                    graph.edges.push(GraphEdge {
                        from: key,
                        to: vma_key,
                        relation: "extracted_from".to_owned(),
                        strength: EdgeStrength::Correlated,
                        sensor: None,
                    });
                }
            }
        }
        graph
    }

    /// Insert a mapping interval node. `mmap` syscalls are Memory-sensor facts; snapshots are not.
    pub fn ensure_mapping(&mut self, session_id: Uuid, mapping: &ObservedMapping) -> String {
        let key = mapping.graph_key();
        if self.entities.iter().any(|entity| entity.key == key) {
            return key;
        }
        let sensors = if mapping.source == MappingSource::Mmap {
            vec![SensorKind::Memory]
        } else {
            Vec::new()
        };
        self.entities.push(GraphEntity {
            kind: GraphEntityKind::MemoryMapping,
            session_id,
            key: key.clone(),
            label: mapping
                .backing_path
                .clone()
                .unwrap_or_else(|| format!("{:#x}-{:#x}", mapping.start, mapping.end)),
            sensors,
            artifact: None,
            process_instance_id: None,
        });
        key
    }

    /// Materialize bounded L0 mapping nodes.
    ///
    /// `mmap`/`mremap` process `maps` edges are confirmed kernel facts. VMA-baseline and
    /// dump-time `/proc/<pid>/maps` rows are correlated snapshots.
    pub fn attach_observed_mappings(
        &mut self,
        session_id: Uuid,
        mappings: &[ObservedMapping],
        processes: &[ProcessActivity],
    ) {
        let mut ranked = mappings.to_vec();
        crate::rank_observed_mappings(&mut ranked);
        for mapping in ranked.iter().take(64) {
            let to = self.ensure_mapping(session_id, mapping);
            let label = label_for_pid(processes, mapping.process_id);
            let from = self.ensure_process_instance(
                session_id,
                &label,
                mapping.process_id,
                instance_for_pid(processes, mapping.process_id),
            );
            if self
                .edges
                .iter()
                .any(|edge| edge.from == from && edge.to == to && edge.relation == "maps")
            {
                continue;
            }
            let strength = if mapping.source == MappingSource::Mmap {
                EdgeStrength::Confirmed
            } else {
                EdgeStrength::Correlated
            };
            self.edges.push(GraphEdge {
                from,
                to,
                relation: "maps".to_owned(),
                strength,
                sensor: Some(SensorKind::Memory),
            });
        }
    }

    /// Join dump VMA ranges with observed mapping intervals as `overlaps_mmap`.
    ///
    /// Strength is always correlated, including exact address matches. A dump is a later
    /// snapshot and is not a kernel mmap fact.
    pub fn correlate_dump_vmas(
        &mut self,
        session_id: Uuid,
        artifacts: &[DumpArtifact],
        mappings: &[ObservedMapping],
    ) {
        if artifacts.is_empty() || mappings.is_empty() {
            return;
        }
        self.push_limitation(
            "dump VMA overlap with mmap/baseline/maps is correlated; a later dump snapshot does not prove the mapping existed at mmap time",
        );
        let mut seen = std::collections::BTreeSet::<(u32, u64, u64)>::new();
        for artifact in artifacts.iter().take(256) {
            let (Some(pid), Some(vma_start), Some(vma_end)) =
                (artifact.pid, artifact.vma_start, artifact.vma_end)
            else {
                continue;
            };
            if vma_end <= vma_start || !seen.insert((pid, vma_start, vma_end)) {
                continue;
            }
            let artifact_key = dump_artifact_key(artifact);
            if !self
                .entities
                .iter()
                .any(|entity| entity.key == artifact_key)
            {
                continue;
            }
            let vma_key = format!("vma:{pid}:{vma_start:x}-{vma_end:x}");
            if !self.entities.iter().any(|entity| entity.key == vma_key) {
                self.entities.push(GraphEntity {
                    kind: GraphEntityKind::MemoryMapping,
                    session_id,
                    key: vma_key.clone(),
                    label: artifact
                        .map_path
                        .clone()
                        .unwrap_or_else(|| format!("{vma_start:#x}-{vma_end:#x}")),
                    sensors: Vec::new(),
                    artifact: None,
                    process_instance_id: None,
                });
            }
            let Some(mapping) = best_overlapping_mapping(mappings, pid, vma_start, vma_end) else {
                continue;
            };
            let mmap_key = self.ensure_mapping(session_id, mapping);
            if vma_key == mmap_key {
                continue;
            }
            if self.edges.iter().any(|edge| {
                edge.from == vma_key && edge.to == mmap_key && edge.relation == "overlaps_mmap"
            }) {
                continue;
            }
            self.edges.push(GraphEdge {
                from: vma_key,
                to: mmap_key,
                relation: "overlaps_mmap".to_owned(),
                strength: EdgeStrength::Correlated,
                sensor: Some(SensorKind::Memory),
            });
        }
    }

    /// Union entities, edges, and limitations from another graph without upgrading strength.
    pub fn merge_from(&mut self, other: &Self) {
        for entity in &other.entities {
            if !self
                .entities
                .iter()
                .any(|existing| existing.key == entity.key)
            {
                self.entities.push(entity.clone());
            }
        }
        for edge in &other.edges {
            if !self.edges.iter().any(|existing| {
                existing.from == edge.from
                    && existing.to == edge.to
                    && existing.relation == edge.relation
            }) {
                self.edges.push(edge.clone());
            }
        }
        for line in &other.limitations {
            self.push_limitation(line.clone());
        }
        for dump_id in &other.dump_ids {
            if !self.dump_ids.iter().any(|existing| existing == dump_id) {
                self.dump_ids.push(dump_id.clone());
            }
        }
    }

    fn push_limitation(&mut self, line: impl Into<String>) {
        let line = line.into();
        if !self.limitations.iter().any(|existing| existing == &line) {
            self.limitations.push(line);
        }
    }

    /// Return a bounded subgraph. This is the query API; the report dump is not the query surface.
    #[must_use]
    pub fn query(&self, query: &GraphQuery) -> Self {
        let limit = query.limit.max(1);
        let entity = query.entity.as_deref().unwrap_or("");
        let edges = self
            .edges
            .iter()
            .filter(|edge| {
                query
                    .relation
                    .as_ref()
                    .is_none_or(|relation| edge.relation == *relation)
                    && query
                        .strength
                        .is_none_or(|strength| edge.strength == strength)
                    && (entity.is_empty() || edge.from.contains(entity) || edge.to.contains(entity))
            })
            .take(limit)
            .cloned()
            .collect::<Vec<_>>();
        let mut keys = edges
            .iter()
            .flat_map(|edge| [edge.from.clone(), edge.to.clone()])
            .collect::<std::collections::BTreeSet<_>>();
        let entities = self
            .entities
            .iter()
            .filter(|entity_row| {
                if keys.contains(&entity_row.key) {
                    return true;
                }
                if entity.is_empty() {
                    return edges.is_empty();
                }
                let matched = entity_row.key.contains(entity) || entity_row.label.contains(entity);
                if matched {
                    keys.insert(entity_row.key.clone());
                }
                matched
            })
            .take(limit)
            .cloned()
            .collect();
        Self {
            entities,
            edges,
            limitations: self.limitations.clone(),
            dump_ids: self.dump_ids.clone(),
        }
    }
}

fn instance_for_pid(processes: &[ProcessActivity], pid: u32) -> Option<&ProcessInstanceRef> {
    processes
        .iter()
        .flat_map(|process| process.instances.iter())
        .find(|instance| instance.pid == pid)
}

/// Bind Inspect adapter hits as correlated evidence. They are never Observe facts.
impl SessionGraph {
    /// Record bounded Inspect hits as `inspect_hit` edges from process instances.
    pub fn attach_inspect_hits(
        &mut self,
        session_id: Uuid,
        hits: &[InspectHitActivity],
        processes: &[ProcessActivity],
    ) {
        self.push_limitation(
            "inspect_hit edges are selected-process adapter observations; they are not L0 kernel facts. Parcel C++ fields are not decoded. JNIEnv plaintext uses exported GetFunctionTable + jni.h slots. Exported Parcel writers are paired by TID. transact joins L0 binder:req by tid+code as correlated joined_transact",
        );
        for hit in hits.iter().take(64) {
            if hit.hits == 0 && !hit.attached {
                continue;
            }
            let to = format!("inspect:{}:{}", hit.adapter, hit.process_id);
            if !self.entities.iter().any(|entity| entity.key == to) {
                self.entities.push(GraphEntity {
                    kind: GraphEntityKind::InspectHit,
                    session_id,
                    key: to.clone(),
                    label: match (
                        hit.binder_interface.as_deref(),
                        hit.binder_method.as_deref(),
                    ) {
                        (Some(interface), Some(method)) => format!(
                            "{} pid={} hits={} {interface}::{method}",
                            hit.adapter, hit.process_id, hit.hits
                        ),
                        (Some(interface), None) => format!(
                            "{} pid={} hits={} {interface}",
                            hit.adapter, hit.process_id, hit.hits
                        ),
                        _ => format!("{} pid={} hits={}", hit.adapter, hit.process_id, hit.hits),
                    },
                    sensors: Vec::new(),
                    artifact: None,
                    process_instance_id: hit.process_instance_id.clone(),
                });
            }
            let label = label_for_pid(processes, hit.process_id);
            let from = self.ensure_process_instance(
                session_id,
                &label,
                hit.process_id,
                instance_for_pid(processes, hit.process_id),
            );
            if !self
                .edges
                .iter()
                .any(|edge| edge.from == from && edge.to == to && edge.relation == "inspect_hit")
            {
                self.edges.push(GraphEdge {
                    from,
                    to: to.clone(),
                    relation: "inspect_hit".to_owned(),
                    strength: EdgeStrength::Correlated,
                    sensor: None,
                });
            }
            if let Some(txn_id) = hit.binder_transaction_id {
                let req_key = format!("binder:req:{txn_id}");
                if !self.entities.iter().any(|entity| entity.key == req_key) {
                    self.entities.push(GraphEntity {
                        kind: GraphEntityKind::BinderTransaction,
                        session_id,
                        key: req_key.clone(),
                        label: format!(
                            "binder request {txn_id} code={}",
                            hit.binder_code.unwrap_or(0)
                        ),
                        sensors: vec![SensorKind::Binder],
                        artifact: None,
                        process_instance_id: None,
                    });
                }
                if !self.edges.iter().any(|edge| {
                    edge.from == to && edge.to == req_key && edge.relation == "joined_transact"
                }) {
                    self.edges.push(GraphEdge {
                        from: to,
                        to: req_key,
                        relation: "joined_transact".to_owned(),
                        strength: EdgeStrength::Correlated,
                        sensor: None,
                    });
                }
            }
        }
    }

    /// Pair two-way Binder RPCs as confirmed `binder_reply` / `replies_to` edges.
    ///
    /// The kernel `debug_id` link is a single-sensor fact, not time proximity.
    pub fn attach_binder_replies(
        &mut self,
        session_id: Uuid,
        pairs: &[BinderReplyPair],
        processes: &[ProcessActivity],
    ) {
        for pair in pairs.iter().take(64) {
            let client_label = label_for_pid(processes, pair.client_process_id);
            let server_label = label_for_pid(processes, pair.server_process_id);
            let client = self.ensure_process_instance(
                session_id,
                &client_label,
                pair.client_process_id,
                instance_for_pid(processes, pair.client_process_id),
            );
            let server = self.ensure_process_instance(
                session_id,
                &server_label,
                pair.server_process_id,
                instance_for_pid(processes, pair.server_process_id),
            );
            let req_key = format!("binder:req:{}", pair.request_transaction_id);
            let reply_key = format!("binder:reply:{}", pair.reply_transaction_id);
            if !self.entities.iter().any(|entity| entity.key == req_key) {
                self.entities.push(GraphEntity {
                    kind: GraphEntityKind::BinderTransaction,
                    session_id,
                    key: req_key.clone(),
                    label: format!(
                        "binder request {} code={}",
                        pair.request_transaction_id, pair.code
                    ),
                    sensors: vec![SensorKind::Binder],
                    artifact: None,
                    process_instance_id: None,
                });
            }
            if !self.entities.iter().any(|entity| entity.key == reply_key) {
                self.entities.push(GraphEntity {
                    kind: GraphEntityKind::BinderTransaction,
                    session_id,
                    key: reply_key.clone(),
                    label: format!(
                        "binder reply {} ({} ns)",
                        pair.reply_transaction_id, pair.latency_ns
                    ),
                    sensors: vec![SensorKind::Binder],
                    artifact: None,
                    process_instance_id: None,
                });
            }
            if !self
                .edges
                .iter()
                .any(|edge| edge.from == client && edge.to == req_key && edge.relation == "issues")
            {
                self.edges.push(GraphEdge {
                    from: client.clone(),
                    to: req_key.clone(),
                    relation: "issues".to_owned(),
                    strength: EdgeStrength::Confirmed,
                    sensor: Some(SensorKind::Binder),
                });
            }
            if !self.edges.iter().any(|edge| {
                edge.from == server && edge.to == reply_key && edge.relation == "returns"
            }) {
                self.edges.push(GraphEdge {
                    from: server.clone(),
                    to: reply_key.clone(),
                    relation: "returns".to_owned(),
                    strength: EdgeStrength::Confirmed,
                    sensor: Some(SensorKind::Binder),
                });
            }
            if !self.edges.iter().any(|edge| {
                edge.from == reply_key && edge.to == req_key && edge.relation == "replies_to"
            }) {
                self.edges.push(GraphEdge {
                    from: reply_key,
                    to: req_key,
                    relation: "replies_to".to_owned(),
                    strength: EdgeStrength::Confirmed,
                    sensor: Some(SensorKind::Binder),
                });
            }
            if !self.edges.iter().any(|edge| {
                edge.from == server && edge.to == client && edge.relation == "binder_reply"
            }) {
                self.edges.push(GraphEdge {
                    from: server,
                    to: client,
                    relation: "binder_reply".to_owned(),
                    strength: EdgeStrength::Confirmed,
                    sensor: Some(SensorKind::Binder),
                });
            }
        }
    }

    /// Pair Binder FD send/receive as confirmed `transfers_fd` edges.
    pub fn attach_binder_fd_transfers(
        &mut self,
        session_id: Uuid,
        transfers: &[BinderFdTransfer],
        processes: &[ProcessActivity],
    ) {
        for transfer in transfers.iter().take(128) {
            let from_fd = format!("fd:{}:{}", transfer.source_process_id, transfer.source_fd);
            let to_fd = format!("fd:{}:{}", transfer.target_process_id, transfer.target_fd);
            if !self.entities.iter().any(|entity| entity.key == from_fd) {
                self.entities.push(GraphEntity {
                    kind: GraphEntityKind::Fd,
                    session_id,
                    key: from_fd.clone(),
                    label: format!("fd {} ({})", transfer.source_fd, transfer.origin),
                    sensors: vec![SensorKind::Binder, SensorKind::File],
                    artifact: None,
                    process_instance_id: None,
                });
            }
            if !self.entities.iter().any(|entity| entity.key == to_fd) {
                self.entities.push(GraphEntity {
                    kind: GraphEntityKind::Fd,
                    session_id,
                    key: to_fd.clone(),
                    label: format!("fd {} via binder", transfer.target_fd),
                    sensors: vec![SensorKind::Binder],
                    artifact: None,
                    process_instance_id: None,
                });
            }
            let source_label = label_for_pid(processes, transfer.source_process_id);
            let target_label = label_for_pid(processes, transfer.target_process_id);
            let from_proc = self.ensure_process_instance(
                session_id,
                &source_label,
                transfer.source_process_id,
                instance_for_pid(processes, transfer.source_process_id),
            );
            let to_proc = self.ensure_process_instance(
                session_id,
                &target_label,
                transfer.target_process_id,
                instance_for_pid(processes, transfer.target_process_id),
            );
            self.edges.push(GraphEdge {
                from: from_proc,
                to: from_fd.clone(),
                relation: "owns".to_owned(),
                strength: EdgeStrength::Correlated,
                sensor: Some(SensorKind::File),
            });
            self.edges.push(GraphEdge {
                from: to_proc,
                to: to_fd.clone(),
                relation: "owns".to_owned(),
                strength: EdgeStrength::Correlated,
                sensor: Some(SensorKind::File),
            });
            if !self.edges.iter().any(|edge| {
                edge.from == from_fd && edge.to == to_fd && edge.relation == "transfers_fd"
            }) {
                self.edges.push(GraphEdge {
                    from: from_fd,
                    to: to_fd,
                    relation: "transfers_fd".to_owned(),
                    strength: EdgeStrength::Confirmed,
                    sensor: Some(SensorKind::Binder),
                });
            }
        }
    }

    /// Join ART `DexFileLoader::Open` hits to dump DEX artifacts.
    ///
    /// Edges are correlated: an exported Open path/size matched a copied file, which
    /// is not a Java `ClassLoader` instance and not a kernel mmap fact.
    pub fn attach_art_open_joins(
        &mut self,
        session_id: Uuid,
        package: &str,
        joins: &[(u32, String, String)],
    ) {
        for (pid, open_path, artifact_key) in joins.iter().take(64) {
            let proc = self.ensure_process(session_id, package, *pid);
            let open_key = format!("art_open:{pid}:{open_path}");
            if !self.entities.iter().any(|entity| entity.key == open_key) {
                self.entities.push(GraphEntity {
                    kind: GraphEntityKind::InspectHit,
                    session_id,
                    key: open_key.clone(),
                    label: format!("ART Open {open_path}"),
                    sensors: Vec::new(),
                    artifact: None,
                    process_instance_id: None,
                });
            }
            if !self.edges.iter().any(|edge| {
                edge.from == proc && edge.to == open_key && edge.relation == "art_opens"
            }) {
                self.edges.push(GraphEdge {
                    from: proc.clone(),
                    to: open_key.clone(),
                    relation: "art_opens".to_owned(),
                    strength: EdgeStrength::Correlated,
                    sensor: None,
                });
            }
            if !self.edges.iter().any(|edge| {
                edge.from == open_key && edge.to == *artifact_key && edge.relation == "joined_dex"
            }) {
                self.edges.push(GraphEdge {
                    from: open_key,
                    to: artifact_key.clone(),
                    relation: "joined_dex".to_owned(),
                    strength: EdgeStrength::Correlated,
                    sensor: None,
                });
            }
        }
    }
}

fn best_overlapping_mapping(
    mappings: &[ObservedMapping],
    pid: u32,
    start: u64,
    end: u64,
) -> Option<&ObservedMapping> {
    mappings
        .iter()
        .filter(|mapping| mapping.process_id == pid && mapping.overlaps(start, end))
        .max_by_key(|mapping| overlap_keep_score(mapping, start, end))
}

fn overlap_keep_score(mapping: &ObservedMapping, start: u64, end: u64) -> (u8, u8, u8, u64, u8) {
    let exact = u8::from(mapping.start == start && mapping.end == end);
    let contains = u8::from(mapping.start <= start && mapping.end >= end);
    let mmap = u8::from(mapping.source == MappingSource::Mmap);
    let lo = mapping.start.max(start);
    let hi = mapping.end.min(end);
    let overlap = hi.saturating_sub(lo);
    let not_file = u8::from(
        !mapping
            .backing_path
            .as_deref()
            .is_some_and(|path| path.starts_with('/')),
    );
    (exact, contains, mmap, overlap, not_file)
}

fn label_for_pid(processes: &[ProcessActivity], pid: u32) -> String {
    processes
        .iter()
        .find(|process| process.process_ids.contains(&pid))
        .map_or_else(|| format!("pid:{pid}"), |process| process.label.clone())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn sample_graph() -> SessionGraph {
        let session_id = Uuid::nil();
        SessionGraph {
            entities: vec![
                GraphEntity {
                    kind: GraphEntityKind::ProcessInstance,
                    session_id,
                    key: "process:a".to_owned(),
                    label: "a".to_owned(),
                    sensors: vec![SensorKind::Binder],
                    artifact: None,
                    process_instance_id: None,
                },
                GraphEntity {
                    kind: GraphEntityKind::ProcessInstance,
                    session_id,
                    key: "process:b".to_owned(),
                    label: "b".to_owned(),
                    sensors: vec![SensorKind::Binder],
                    artifact: None,
                    process_instance_id: None,
                },
                GraphEntity {
                    kind: GraphEntityKind::SocketFlow,
                    session_id,
                    key: "socket:10.0.0.1:443".to_owned(),
                    label: "10.0.0.1".to_owned(),
                    sensors: vec![SensorKind::Network],
                    artifact: None,
                    process_instance_id: None,
                },
            ],
            edges: vec![
                GraphEdge {
                    from: "process:a".to_owned(),
                    to: "process:b".to_owned(),
                    relation: "binder".to_owned(),
                    strength: EdgeStrength::Confirmed,
                    sensor: Some(SensorKind::Binder),
                },
                GraphEdge {
                    from: "process:a".to_owned(),
                    to: "socket:10.0.0.1:443".to_owned(),
                    relation: "connects".to_owned(),
                    strength: EdgeStrength::Confirmed,
                    sensor: Some(SensorKind::Network),
                },
            ],
            limitations: SessionGraph::l0_placeholder().limitations,
            dump_ids: Vec::new(),
        }
    }

    #[test]
    fn process_instance_keys_are_first_class() {
        let processes = [ProcessActivity {
            label: "com.example".to_owned(),
            package: Some("com.example".to_owned()),
            process_ids: vec![10],
            instances: vec![ProcessInstanceRef {
                process_instance_id: "boot:10:99".to_owned(),
                boot_id: Uuid::nil(),
                pid: 10,
                start_time_ns: 99,
            }],
            event_count: 1,
            sensor_counts: BTreeMap::new(),
        }];
        let binder = [crate::BinderRelation {
            source: "com.example".to_owned(),
            source_process_id: 10,
            target: "system".to_owned(),
            target_process_id: Some(1),
            requests: 1,
            replies: 0,
            codes: BTreeMap::new(),
            paired_replies: 0,
            interfaces: BTreeMap::new(),
        }];
        let graph = SessionGraph::from_l0(None, &processes, &binder, &[], &[], &[]);
        assert!(graph
            .entities
            .iter()
            .any(|entity| entity.key == "procinst:boot:10:99"
                && entity.process_instance_id.as_deref() == Some("boot:10:99")));
        assert!(graph
            .edges
            .iter()
            .any(|edge| { edge.relation == "binder" && edge.from == "procinst:boot:10:99" }));
        let hits = [InspectHitActivity {
            adapter: "binder_userspace".to_owned(),
            process_id: 10,
            process_instance_id: Some("boot:10:99".to_owned()),
            attached: true,
            hits: 2,
            last_detail: "handle=3 code=0x1".to_owned(),
            binder_handle: Some(3),
            binder_code: Some(1),
            binder_interface: Some("android.os.IServiceManager".to_owned()),
            binder_method: Some("getService".to_owned()),
            binder_method_source: Some("aosp_stub".to_owned()),
            binder_strings: Some(vec!["activity".to_owned()]),
            binder_ints: Some(vec![1]),
            binder_int64s: None,
            binder_bools: None,
            binder_fds: None,
            binder_blobs: None,
            binder_binders: None,
            binder_transaction_id: Some(42),
            reply_latency_ns: Some(5_000),
        }];
        let mut graph = graph;
        graph.attach_inspect_hits(Uuid::nil(), &hits, &processes);
        assert!(graph.edges.iter().any(
            |edge| edge.relation == "inspect_hit" && edge.strength == EdgeStrength::Correlated
        ));
        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.relation == "joined_transact"
                && edge.strength == EdgeStrength::Correlated
                && edge.to == "binder:req:42"));
    }

    #[test]
    fn query_is_the_graph_surface() {
        let graph = sample_graph();
        let binder = graph.query(&GraphQuery {
            relation: Some("binder".to_owned()),
            limit: 8,
            ..GraphQuery::default()
        });
        assert_eq!(binder.edges.len(), 1);
        assert_eq!(binder.edges[0].relation, "binder");
        assert!(binder
            .entities
            .iter()
            .any(|entity| entity.key == "process:a"));

        let named = graph.query(&GraphQuery {
            entity: Some("10.0.0.1".to_owned()),
            limit: 8,
            ..GraphQuery::default()
        });
        assert_eq!(named.edges.len(), 1);
        assert_eq!(named.edges[0].relation, "connects");
    }

    #[test]
    fn dump_artifacts_are_correlated_not_confirmed() {
        let artifact = crate::DumpArtifact {
            kind: "dex".to_owned(),
            source: "heap-blob".to_owned(),
            relative_path: "apk-dex/split/blob-1-1000_part00_0.dex".to_owned(),
            bytes: 1024,
            magic: "dex".to_owned(),
            pid: Some(1),
            vma_start: Some(0x1000),
            vma_end: Some(0x2000),
            map_path: Some("[anon:scudo:secondary]".to_owned()),
            dex_offset: Some(0),
            sha256: None,
        };
        let graph = SessionGraph::from_package_dump(
            Uuid::nil(),
            "mobi.w3studio.apps.android.shsmy.phone",
            &[1],
            &[artifact],
        );
        assert!(graph
            .edges
            .iter()
            .all(|edge| edge.strength == EdgeStrength::Correlated));
        assert!(graph.edges.iter().any(|edge| edge.relation == "produced"));
        assert!(graph
            .edges
            .iter()
            .any(|edge| edge.relation == "extracted_from"));
        assert!(graph
            .entities
            .iter()
            .any(|entity| entity.kind == GraphEntityKind::CodeArtifact));
        assert!(graph
            .entities
            .iter()
            .any(|entity| entity.kind == GraphEntityKind::MemoryMapping));
        assert!(graph
            .limitations
            .iter()
            .any(|line| line.contains("correlated")));
        assert_eq!(graph.dump_ids.len(), 1);
        assert!(graph
            .entities
            .iter()
            .any(|entity| entity.kind == GraphEntityKind::EvidenceDump));
        assert!(graph.edges.iter().any(|edge| edge.relation == "records"));
    }

    #[test]
    fn dump_vma_mmap_overlap_is_correlated_even_when_addresses_match() {
        let artifact = crate::DumpArtifact {
            kind: "dex".to_owned(),
            source: "heap-blob".to_owned(),
            relative_path: "apk-dex/split/blob-1-1000_part00_0.dex".to_owned(),
            bytes: 1024,
            magic: "dex".to_owned(),
            pid: Some(1),
            vma_start: Some(0x1000),
            vma_end: Some(0x2000),
            map_path: Some("[anon:scudo:secondary]".to_owned()),
            dex_offset: Some(0),
            sha256: None,
        };
        let mut graph = SessionGraph::from_package_dump(
            Uuid::nil(),
            "demo.pkg",
            &[1],
            std::slice::from_ref(&artifact),
        );
        graph.correlate_dump_vmas(
            Uuid::nil(),
            std::slice::from_ref(&artifact),
            &[crate::ObservedMapping {
                process_id: 1,
                start: 0x1000,
                end: 0x2000,
                backing_path: Some("[anon:scudo:secondary]".to_owned()),
                source: crate::MappingSource::Mmap,
                mapping_generation: 0,
            }],
        );
        let overlap = graph
            .edges
            .iter()
            .find(|edge| edge.relation == "overlaps_mmap")
            .expect("overlap");
        assert_eq!(overlap.strength, EdgeStrength::Correlated);
        assert_eq!(overlap.from, "vma:1:1000-2000");
        assert_eq!(overlap.to, "mmap:1:1000-2000");
        assert!(graph
            .edges
            .iter()
            .filter(|edge| edge.relation == "overlaps_mmap")
            .all(|edge| edge.strength == EdgeStrength::Correlated));

        graph.correlate_dump_vmas(
            Uuid::nil(),
            std::slice::from_ref(&artifact),
            &[crate::ObservedMapping {
                process_id: 1,
                start: 0x9000,
                end: 0xa000,
                backing_path: None,
                source: crate::MappingSource::Mmap,
                mapping_generation: 0,
            }],
        );
        assert_eq!(
            graph
                .edges
                .iter()
                .filter(|edge| edge.relation == "overlaps_mmap")
                .count(),
            1
        );
    }

    #[test]
    fn dump_vma_keeps_one_best_overlap_not_every_fragment() {
        let artifact = crate::DumpArtifact {
            kind: "dex".to_owned(),
            source: "heap-blob".to_owned(),
            relative_path: "apk-dex/split/blob-3-1000_part00_0.dex".to_owned(),
            bytes: 4096,
            magic: "dex".to_owned(),
            pid: Some(3),
            vma_start: Some(0x1000),
            vma_end: Some(0x3000),
            map_path: Some("[anon:scudo:secondary]".to_owned()),
            dex_offset: Some(0),
            sha256: None,
        };
        let mut graph = SessionGraph::from_package_dump(
            Uuid::nil(),
            "com.icbc",
            &[3],
            std::slice::from_ref(&artifact),
        );
        graph.correlate_dump_vmas(
            Uuid::nil(),
            std::slice::from_ref(&artifact),
            &[
                crate::ObservedMapping {
                    process_id: 3,
                    start: 0,
                    end: 0x4000,
                    backing_path: None,
                    source: crate::MappingSource::ProcMaps,
                    mapping_generation: 0,
                },
                crate::ObservedMapping {
                    process_id: 3,
                    start: 0x1000,
                    end: 0x3000,
                    backing_path: Some("[anon:scudo:secondary]".to_owned()),
                    source: crate::MappingSource::ProcMaps,
                    mapping_generation: 0,
                },
                crate::ObservedMapping {
                    process_id: 3,
                    start: 0x1800,
                    end: 0x2000,
                    backing_path: None,
                    source: crate::MappingSource::ProcMaps,
                    mapping_generation: 0,
                },
            ],
        );
        let overlaps: Vec<_> = graph
            .edges
            .iter()
            .filter(|edge| edge.relation == "overlaps_mmap")
            .collect();
        assert_eq!(overlaps.len(), 1);
        assert_eq!(overlaps[0].strength, EdgeStrength::Correlated);
        assert_eq!(overlaps[0].to, "proc_maps:3:1000-3000");
    }

    #[test]
    fn art_open_join_is_correlated_not_confirmed() {
        let mut graph = SessionGraph::from_package_dump(
            Uuid::nil(),
            "pkg",
            &[8],
            &[crate::DumpArtifact {
                kind: "dex".to_owned(),
                source: "apk-dex".to_owned(),
                relative_path: "apk-dex/classes.dex".to_owned(),
                bytes: 32,
                magic: "dex".to_owned(),
                pid: None,
                vma_start: None,
                vma_end: None,
                map_path: None,
                dex_offset: None,
                sha256: Some("dead".to_owned()),
            }],
        );
        graph.attach_art_open_joins(
            Uuid::nil(),
            "pkg",
            &[(
                8,
                "/data/app/pkg/base.apk".to_owned(),
                "artifact:sha256:dead".to_owned(),
            )],
        );
        assert!(graph.edges.iter().any(|edge| {
            edge.relation == "joined_dex" && edge.strength == EdgeStrength::Correlated
        }));
        assert!(graph.edges.iter().any(|edge| edge.relation == "art_opens"));
    }

    #[test]
    fn partial_vma_overlap_is_still_correlated() {
        let artifact = crate::DumpArtifact {
            kind: "dex".to_owned(),
            source: "heap-blob".to_owned(),
            relative_path: "apk-dex/split/blob-2-1800_part00_0.dex".to_owned(),
            bytes: 64,
            magic: "dex".to_owned(),
            pid: Some(2),
            vma_start: Some(0x1800),
            vma_end: Some(0x1c00),
            map_path: None,
            dex_offset: Some(0),
            sha256: None,
        };
        let mut graph = SessionGraph::from_package_dump(
            Uuid::nil(),
            "demo.pkg",
            &[2],
            std::slice::from_ref(&artifact),
        );
        graph.correlate_dump_vmas(
            Uuid::nil(),
            std::slice::from_ref(&artifact),
            &[crate::ObservedMapping {
                process_id: 2,
                start: 0x1000,
                end: 0x2000,
                backing_path: None,
                source: crate::MappingSource::Mmap,
                mapping_generation: 0,
            }],
        );
        assert!(graph.edges.iter().any(|edge| {
            edge.relation == "overlaps_mmap"
                && edge.strength == EdgeStrength::Correlated
                && edge.to == "mmap:2:1000-2000"
        }));
    }
}
