//! Optional capture ancestry; absence keeps legacy CLI behavior.
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::{io::Write, path::Path};
use uuid::Uuid;
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Capture Relation retained by this evidence operation.
pub struct CaptureRelation {
    /// Schema retained by this evidence operation.
    pub schema: String,
    /// Parent id retained by this evidence operation.
    pub parent_id: Uuid,
    /// Stage id retained by this evidence operation.
    pub stage_id: Uuid,
    /// Attempt id retained by this evidence operation.
    pub attempt_id: Uuid,
    /// Attempt retained by this evidence operation.
    pub attempt: u32,
    /// Stage key retained by this evidence operation.
    pub stage_key: String,
    #[serde(default)]
    /// Stage links retained by this evidence operation.
    pub stage_links: Vec<serde_json::Value>,
}
impl CaptureRelation {
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    /// Parse retained by this evidence operation.
    pub fn parse(
        parent: Option<Uuid>,
        stage: Option<Uuid>,
        attempt_id: Option<Uuid>,
        attempt: Option<u32>,
        key: Option<String>,
    ) -> Result<Option<Self>> {
        if parent.is_none()
            && stage.is_none()
            && attempt_id.is_none()
            && attempt.is_none()
            && key.is_none()
        {
            return Ok(None);
        }
        let (Some(parent_id), Some(stage_id), Some(attempt_id), Some(attempt), Some(stage_key)) =
            (parent, stage, attempt_id, attempt, key)
        else {
            bail!("parent/stage/attempt metadata must be supplied together");
        };
        if parent_id.is_nil()
            || stage_id.is_nil()
            || attempt_id.is_nil()
            || attempt == 0
            || !["l0", "l1", "linker", "dump"].contains(&stage_key.as_str())
        {
            bail!("invalid capture ancestry");
        }
        Ok(Some(Self {
            schema: "kernsight.capture-relation/v1".into(),
            parent_id,
            stage_id,
            attempt_id,
            attempt,
            stage_key,
            stage_links: vec![],
        }))
    }
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    /// With stage links retained by this evidence operation.
    pub fn with_stage_links(mut self, text: Option<&str>) -> Result<Self> {
        if let Some(text) = text {
            if text.len() > 4096 {
                bail!("stage links exceed bound");
            }
            let links: Vec<serde_json::Value> = serde_json::from_str(text)?;
            if links.len() != 3 {
                bail!("stage links require l0/l1/linker");
            }
            let mut keys = std::collections::BTreeSet::new();
            let mut ids = std::collections::BTreeSet::new();
            for link in &links {
                let r = Self::parse(
                    link["parentId"]
                        .as_str()
                        .and_then(|v| Uuid::parse_str(v).ok()),
                    link["stageId"]
                        .as_str()
                        .and_then(|v| Uuid::parse_str(v).ok()),
                    link["attemptId"]
                        .as_str()
                        .and_then(|v| Uuid::parse_str(v).ok()),
                    link["attempt"].as_u64().and_then(|v| u32::try_from(v).ok()),
                    link["stageKey"].as_str().map(str::to_owned),
                )?
                .ok_or_else(|| anyhow::anyhow!("missing stage link identity"))?;
                if r.parent_id != self.parent_id
                    || r.stage_key == "dump"
                    || !keys.insert(r.stage_key.clone())
                    || !ids.insert(r.stage_id)
                    || !ids.insert(r.attempt_id)
                {
                    bail!("invalid stage links identity");
                }
                if r.stage_key == self.stage_key
                    && (r.stage_id != self.stage_id
                        || r.attempt_id != self.attempt_id
                        || r.attempt != self.attempt)
                {
                    bail!("primary relation mismatch");
                }
            }
            self.stage_links = links;
        }
        Ok(self)
    }
    ///
    /// # Errors
    /// Returns the validation or required operation error; no successful result is fabricated.
    /// Retain retained by this evidence operation.
    pub fn retain(&self, root: &Path, session: Option<Uuid>, package: Option<&str>) -> Result<()> {
        std::fs::create_dir_all(root)?;
        let path = root.join("capture-relation.json");
        let bytes = serde_json::to_vec_pretty(
            &serde_json::json!({"relation":self,"session_id":session,"package":package}),
        )?;
        if path.exists() {
            if std::fs::read(&path)? == bytes {
                return Ok(());
            }
            bail!("capture ancestry conflicts with retained evidence");
        }
        let temp = root.join(format!(".relation-{}.tmp", Uuid::new_v4()));
        let result = (|| {
            let mut f = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            std::fs::hard_link(&temp, &path)?;
            Ok::<_, anyhow::Error>(())
        })();
        let _ = std::fs::remove_file(temp);
        result
    }
}
