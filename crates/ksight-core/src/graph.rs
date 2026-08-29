//! Cross-layer analysis graph: entities and explicit edge strength.
//!
//! Observe sessions produce kernel facts. The analysis plane must not present time proximity as a
//! proven causal relationship. Edges are therefore classified as confirmed, correlated, or inferred.

use ksight_model::{ArtifactKind, ArtifactProvenance, ArtifactRef, SensorKind};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{DumpArtifact, MappingSource, ObservedMapping, ProcessActivity};

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
        if pid == 0 {
            return format!("process:{label}");
        }
        let package_key = format!("process:{label}");
        let key = format!("process:{label}:{pid}");
        if self.entities.iter().any(|entity| entity.key == key) {
            return key;
        }
        self.entities.push(GraphEntity {
            kind: GraphEntityKind::ProcessInstance,
            session_id,
            key: key.clone(),
            label: format!("{label} pid={pid}"),
            sensors: Vec::new(),
            artifact: None,
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
        for process in processes.iter().take(64) {
            graph.entities.push(GraphEntity {
                kind: GraphEntityKind::ProcessInstance,
                session_id,
                key: format!("process:{}", process.label),
                label: process.label.clone(),
                sensors: process.sensor_counts.keys().copied().collect(),
                artifact: None,
            });
        }
        for relation in binder.iter().take(128) {
            let from =
                graph.ensure_process(session_id, &relation.source, relation.source_process_id);
            let to = graph.ensure_process(
                session_id,
                &relation.target,
                relation.target_process_id.unwrap_or(0),
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
            });
            let from = graph.ensure_process(session_id, &peer.source, peer.source_process_id);
            graph.edges.push(GraphEdge {
                from,
                to: key,
                relation: "connects".to_owned(),
                strength: EdgeStrength::Confirmed,
                sensor: Some(SensorKind::Network),
            });
        }
        for wakeup in sched.iter().take(128) {
            let from = graph.ensure_process(session_id, &wakeup.waker, wakeup.waker_process_id);
            let to = format!("thread:{}", wakeup.wakee_tid);
            graph.entities.push(GraphEntity {
                kind: GraphEntityKind::Thread,
                session_id,
                key: to.clone(),
                label: format!("tid {}", wakeup.wakee_tid),
                sensors: vec![SensorKind::Sched],
                artifact: None,
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
            let from = self.ensure_process(session_id, &label, mapping.process_id);
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
                },
                GraphEntity {
                    kind: GraphEntityKind::ProcessInstance,
                    session_id,
                    key: "process:b".to_owned(),
                    label: "b".to_owned(),
                    sensors: vec![SensorKind::Binder],
                    artifact: None,
                },
                GraphEntity {
                    kind: GraphEntityKind::SocketFlow,
                    session_id,
                    key: "socket:10.0.0.1:443".to_owned(),
                    label: "10.0.0.1".to_owned(),
                    sensors: vec![SensorKind::Network],
                    artifact: None,
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
                },
                crate::ObservedMapping {
                    process_id: 3,
                    start: 0x1000,
                    end: 0x3000,
                    backing_path: Some("[anon:scudo:secondary]".to_owned()),
                    source: crate::MappingSource::ProcMaps,
                },
                crate::ObservedMapping {
                    process_id: 3,
                    start: 0x1800,
                    end: 0x2000,
                    backing_path: None,
                    source: crate::MappingSource::ProcMaps,
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
            }],
        );
        assert!(graph.edges.iter().any(|edge| {
            edge.relation == "overlaps_mmap"
                && edge.strength == EdgeStrength::Correlated
                && edge.to == "mmap:2:1000-2000"
        }));
    }
}
