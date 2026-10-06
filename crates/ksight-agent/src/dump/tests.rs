use super::*;

#[test]
fn deduplicates_compatibility_trees_and_writes_ordered_indexes() {
    use std::os::unix::fs::MetadataExt;

    let dir = std::env::temp_dir().join(format!(
        "ksight-storage-layout-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let apk = dir.join("apk-dex/classes.dex");
    let readable = dir.join("readable-dex/runtime/classes.dex");
    std::fs::create_dir_all(apk.parent().expect("apk parent")).expect("apk dir");
    std::fs::create_dir_all(readable.parent().expect("readable parent")).expect("readable dir");
    let mut bytes = vec![0_u8; 2048];
    bytes[..8].copy_from_slice(b"dex\n035\0");
    std::fs::write(&apk, &bytes).expect("apk dex");
    std::fs::write(&readable, &bytes).expect("readable dex");

    let (linked, saved) = deduplicate_code_evidence(&dir).expect("deduplicate");
    assert_eq!(linked, 1);
    assert_eq!(saved, bytes.len() as u64);
    assert_eq!(
        apk.metadata().expect("apk metadata").ino(),
        readable.metadata().expect("readable metadata").ino()
    );

    let report = ksight_core::classify_dex_ownership("com.example.app", &[]);
    write_dex_classification_index(&dir, &report).expect("classification indexes");
    assert!(dir.join("dex-classification/manifest.json").is_file());
    for category in [
        "01-business",
        "02-internal-components",
        "03-dynamic-payloads",
        "04-third-party-sdks",
        "05-mixed",
        "06-unknown",
    ] {
        assert!(dir
            .join("dex-classification")
            .join(category)
            .join("index.json")
            .is_file());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn dex_sets_deduplicate_bytes_and_preserve_observations() {
    let dir = std::env::temp_dir().join(format!("ksight-dex-set-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("runtime")).expect("runtime");
    let mut dex = vec![0_u8; 0x70];
    dex[..8].copy_from_slice(b"dex\n035\0");
    dex[32..36].copy_from_slice(&0x70_u32.to_le_bytes());
    dex[40..44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
    std::fs::write(dir.join("runtime/a.dex"), &dex).expect("dex");
    let artifacts = vec![
        ksight_core::DumpArtifact {
            kind: "dex".to_owned(),
            source: "memory-dex".to_owned(),
            relative_path: "runtime/a.dex".to_owned(),
            bytes: 0x70,
            magic: "dex".to_owned(),
            pid: Some(7),
            vma_start: Some(0x1000),
            vma_end: Some(0x2000),
            map_path: Some("[anon:dalvik-classes.dex]".to_owned()),
            dex_offset: Some(0),
            sha256: Some("same".to_owned()),
        },
        ksight_core::DumpArtifact {
            kind: "dex".to_owned(),
            source: "apk-dex".to_owned(),
            relative_path: "apk-dex/classes.dex".to_owned(),
            bytes: 0x70,
            magic: "dex".to_owned(),
            pid: None,
            vma_start: None,
            vma_end: None,
            map_path: None,
            dex_offset: None,
            sha256: Some("same".to_owned()),
        },
    ];
    let (sets, index) = build_dex_sets(&dir, &artifacts);
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].observations.len(), 2);
    assert_eq!(sets[0].canonical_relative_path, "runtime/a.dex");
    assert!(sets[0].semantic.is_some());
    assert_eq!(index.unique_dex, 1);
    assert_eq!(index.observations, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn recatalog_accepts_legacy_dump_reports() {
    let report: PackageDumpReport = serde_json::from_str(
            r#"{"package":"com.example.app","install_dir":null,"apk_files":0,"native_libs":0,"oat_files":0,"apk_dex":0,"launched":false,"pids":[1],"memory_images":0,"vdex_images":0,"fd_images":0,"runtime_libs":0,"packer_regions":32}"#,
        )
        .expect("legacy");
    assert_eq!(report.package, "com.example.app");
    assert_eq!(report.packer_regions, 32);
    assert_eq!(report.asset_files, 0);
    assert_eq!(report.artifacts.len(), 0);
    assert_eq!(report.schema_version.len(), 0);
    assert!(!report.observation_env.hide_debug_requested);
    assert!(!report.observation_env.denylist_applied);
}

#[test]
fn sensitive_catalog_hashes_plaintext_and_key_candidates() {
    let dir = std::env::temp_dir().join(format!("ksight-sensitive-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("runtime/plaintext")).expect("plaintext dir");
    std::fs::create_dir_all(dir.join("runtime/packer-keys")).expect("key dir");
    std::fs::write(dir.join("runtime/plaintext/http.txt"), b"GET / HTTP/1.1").expect("plaintext");
    std::fs::write(dir.join("runtime/packer-keys/slot.bin"), [7_u8; 16]).expect("key");
    let files = catalog_sensitive_files(&dir);
    assert_eq!(files.len(), 2);
    assert!(files.iter().all(|file| file.sha256.len() == 64));
    assert!(files.iter().all(|file| !file.confirmed));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn catalog_parses_nul_http_response_without_fake_path() {
    let dir = std::env::temp_dir().join(format!("ksight-http-calls-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("runtime/plaintext")).expect("plaintext dir");
    let mut bytes = vec![0_u8; 0x40];
    bytes[0x28..0x2c].copy_from_slice(&[0x9d, 0xb8, 0x2f, 0x00]);
    bytes.extend_from_slice(b"HTTP/1.1 200 OK\0Content-Type: image/jpeg\0Content-Length: 73045\0");
    std::fs::write(dir.join("runtime/plaintext/mem-4321-7b00+40.txt"), &bytes).expect("window");
    let calls = catalog_plaintext_http_calls(&dir, "com.example");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].origin, "heap");
    assert_eq!(calls[0].process_id, 4321);
    assert_eq!(calls[0].status, Some(200));
    assert_eq!(calls[0].path.len(), 0);
    assert_eq!(calls[0].content_type.as_deref(), Some("image/jpeg"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn catalog_parses_http2_hpack_and_https_needles() {
    let dir = std::env::temp_dir().join(format!("ksight-h2-calls-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("runtime/plaintext")).expect("plaintext dir");
    let block = [
        0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x2e, 0x63, 0x6f, 0x6d,
    ];
    let mut frame = vec![
        0,
        0,
        u8::try_from(block.len()).unwrap(),
        0x1,
        0x04,
        0,
        0,
        0,
        1,
    ];
    frame.extend_from_slice(&block);
    std::fs::write(dir.join("runtime/plaintext/mem-99-1000+0.txt"), &frame).expect("h2");
    std::fs::write(
        dir.join("runtime/plaintext/mem-99-2000+0.txt"),
        b"https://api.example/v1/session?token=x",
    )
    .expect("https");
    let calls = catalog_plaintext_http_calls(&dir, "com.example");
    assert!(
        calls.iter().any(|call| {
            call.kind == "http2_request"
                && call.host.as_deref() == Some("www.example.com")
                && call.path == "/"
                && call.origin == "heap"
        }),
        "{calls:?}"
    );
    assert!(
        calls.iter().any(|call| {
            call.host.as_deref() == Some("api.example") && call.path == "/v1/session"
        }),
        "{calls:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn catalog_parses_private_sqlite_https_urls() {
    let dir = std::env::temp_dir().join(format!("ksight-private-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("data-private/ce/databases")).expect("db dir");
    let mut bytes = vec![0_u8; 64];
    bytes.extend_from_slice(b"https://api.example.com/AppFront/supportUNI/8");
    bytes.extend_from_slice(&[0, 0, 0]);
    bytes.extend_from_slice(b"https://wap.app.example/cs/fd5/index_2220.html");
    std::fs::write(
        dir.join("data-private/ce/databases/app_mobile_database.db"),
        &bytes,
    )
    .expect("db");
    let calls =
        ksight_core::http_calls_from_private_dir(&dir.join("data-private"), "com.example.app");
    assert!(
        calls.iter().any(|call| {
            call.origin == "private"
                && call.host.as_deref() == Some("api.example.com")
                && call.path.starts_with("/AppFront/")
        }),
        "{calls:?}"
    );
    assert!(
        calls
            .iter()
            .any(|call| call.host.as_deref() == Some("wap.app.example")),
        "{calls:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn parses_pm_path_lines() {
    let paths = parse_pm_paths(
            "package:/data/app/~~x==/com.example.grid-y==/base.apk\npackage:/data/app/~~x==/com.example.grid-y==/split_config.apk\n",
        );
    assert_eq!(paths.len(), 2);
    assert!(paths[0].ends_with("base.apk"));
}

#[test]
fn prune_install_trees_keeps_evidence_dirs() {
    let dir = std::env::temp_dir().join(format!("ksight-prune-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("apk")).expect("apk");
    std::fs::create_dir_all(dir.join("lib")).expect("lib");
    std::fs::create_dir_all(dir.join("runtime")).expect("runtime");
    std::fs::create_dir_all(dir.join("data-private")).expect("private");
    std::fs::write(dir.join("apk/base.apk"), b"apk").expect("apk file");
    std::fs::write(dir.join("runtime/maps.txt"), b"maps").expect("maps");
    prune_install_trees(&dir);
    assert!(!dir.join("apk").exists());
    assert!(!dir.join("lib").exists());
    assert!(dir.join("runtime/maps.txt").is_file());
    assert!(dir.join("data-private").is_dir());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn copies_bounded_app_private_prefs_and_skips_media() {
    let root = std::env::temp_dir().join(format!("ksight-private-{}", uuid::Uuid::new_v4()));
    let dest = std::env::temp_dir().join(format!("ksight-private-out-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(root.join("shared_prefs")).expect("prefs");
    std::fs::create_dir_all(root.join("databases")).expect("db");
    std::fs::create_dir_all(root.join("files")).expect("files");
    std::fs::write(
        root.join("shared_prefs/token.xml"),
        b"<map><string name=\"t\">x</string></map>",
    )
    .expect("xml");
    std::fs::write(root.join("databases/app.db"), b"SQLite format 3\0").expect("db");
    std::fs::write(root.join("files/photo.jpg"), b"not-a-jpeg").expect("jpg");
    let copied = copy_app_private_from(std::slice::from_ref(&root), &dest).expect("copy");
    assert_eq!(copied, 2);
    assert!(dest.join("shared_prefs/token.xml").is_file());
    assert!(dest.join("databases/app.db").is_file());
    assert!(!dest.join("files/photo.jpg").exists());
    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(dest);
}

#[test]
fn catalogs_heap_blob_sidecars_as_correlated_artifacts() {
    let dir = std::env::temp_dir().join(format!("ksight-catalog-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let split = dir.join("apk-dex").join("split");
    let blob = dir.join("runtime").join("blob-dex");
    std::fs::create_dir_all(&split).expect("split");
    std::fs::create_dir_all(&blob).expect("blob");
    let name = "blob-9-abc_part00_0.dex";
    let mut dex = vec![0_u8; 0x70];
    dex[..8].copy_from_slice(b"dex\n035\0");
    std::fs::write(split.join(name), &dex).expect("dex");
    std::fs::write(
            blob.join("9-abc.json"),
            r#"{"pid":9,"vma_start":2748,"vma_end":4096,"map_path":"[anon:scudo:secondary]","files":["blob-9-abc_part00_0.dex"]}"#,
        )
        .expect("json");
    std::fs::write(
        dir.join("runtime").join("maps-9.txt"),
        "00000abc-00001000 rw-p 00000000 00:00 0 [anon:scudo:secondary]\n",
    )
    .expect("maps");
    let artifacts = catalog_dump(&dir);
    let heap = artifacts
        .iter()
        .find(|row| row.source == "heap-blob")
        .expect("heap");
    assert_eq!(heap.pid, Some(9));
    assert_eq!(heap.vma_start, Some(2748));
    assert_eq!(heap.map_path.as_deref(), Some("[anon:scudo:secondary]"));
    assert_eq!(
        parse_blob_name("blob-17628-6e61c7b000_part00_2344.dex"),
        Some((17628, 0x006e_61c7_b000, Some(2344)))
    );
    assert_eq!(
        parse_mem_name("mem-28735-6ec9458c90.dex"),
        Some((28735, 0x006e_c945_8c90, None))
    );
    assert_eq!(
        parse_mem_name("mem-2706-6ec9587000+5cd0.dex"),
        Some((2706, 0x006e_c958_7000, Some(0x5cd0)))
    );
    let mut graph = ksight_core::SessionGraph::from_package_dump(
        uuid::Uuid::nil(),
        "demo.pkg",
        &[9],
        &artifacts,
    );
    graph.correlate_dump_vmas(
        uuid::Uuid::nil(),
        &artifacts,
        &maps_as_observed(&dir, &artifacts),
    );
    assert!(graph
        .edges
        .iter()
        .all(|edge| edge.strength == ksight_core::EdgeStrength::Correlated));
    assert!(graph
        .edges
        .iter()
        .any(|edge| edge.relation == "overlaps_mmap"
            && edge.strength == ksight_core::EdgeStrength::Correlated
            && edge.to.starts_with("proc_maps:9:")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ok_marker_survives_guard_maps_and_high_address_noise() {
    let dir = std::env::temp_dir().join(format!("ksight-ok-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let split = dir.join("apk-dex").join("split");
    let blob = dir.join("runtime").join("blob-dex");
    let so_dir = dir.join("runtime").join("runtime-so");
    std::fs::create_dir_all(&split).expect("split");
    std::fs::create_dir_all(&blob).expect("blob");
    std::fs::create_dir_all(&so_dir).expect("so");
    let name = "blob-9-6e5f3f1000_part00_40.dex";
    let mut dex = vec![0_u8; 0x70];
    dex[..8].copy_from_slice(b"dex\n035\0");
    std::fs::write(split.join(name), &dex).expect("dex");
    std::fs::write(
        blob.join("9-6e5f3f1000.ok"),
        "seq=56 bytes=53604352 slices=1\n",
    )
    .expect("ok");
    std::fs::write(
        so_dir.join("9-libexec.so"),
        [0x7f, b'E', b'L', b'F', 0, 0, 0, 0],
    )
    .expect("so");
    let mut maps = String::new();
    for index in 0..600_u32 {
        let start = index * 0x1000;
        let _ = std::fmt::Write::write_fmt(
            &mut maps,
            format_args!(
                "{start:08x}-{:08x} rw-p 00000000 00:00 0 [anon:pad]\n",
                start + 0x1000
            ),
        );
    }
    maps.push_str("6e5de00000-6e60c00000 ---p 00000000 00:00 0 \n");
    maps.push_str("6ec9464000-6ec94a4000 r-xp 00000000 fe:37 1 /data/data/demo/files/libexec.so\n");
    std::fs::write(dir.join("runtime").join("maps-9.txt"), maps).expect("maps");

    let artifacts = catalog_dump(&dir);
    let heap = artifacts
        .iter()
        .find(|row| row.source == "heap-blob")
        .expect("heap");
    assert_eq!(heap.vma_start, Some(0x006e_5f3f_1000));
    assert_eq!(heap.vma_end, Some(0x006e_5f3f_1000 + 53_604_352));
    assert_eq!(heap.map_path, None);
    let so = artifacts
        .iter()
        .find(|row| row.source == "runtime-so")
        .expect("so");
    assert_eq!(so.vma_start, Some(0x006e_c946_4000));
    assert_eq!(so.vma_end, Some(0x006e_c94a_4000));
    assert_eq!(
        so.map_path.as_deref(),
        Some("/data/data/demo/files/libexec.so")
    );

    let mut graph = ksight_core::SessionGraph::from_package_dump(
        uuid::Uuid::nil(),
        "demo.pkg",
        &[9],
        &artifacts,
    );
    graph.correlate_dump_vmas(
        uuid::Uuid::nil(),
        &artifacts,
        &maps_as_observed(&dir, &artifacts),
    );
    assert!(graph
        .edges
        .iter()
        .filter(|edge| edge.relation == "overlaps_mmap")
        .all(|edge| edge.strength == ksight_core::EdgeStrength::Correlated));
    assert!(graph.edges.iter().any(|edge| {
        edge.relation == "overlaps_mmap" && edge.from.starts_with("vma:9:6e5f3f1000-")
    }));
    assert!(graph
        .edges
        .iter()
        .any(|edge| { edge.relation == "extracted_from" && edge.from.contains("libexec.so") }));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn catalogs_live_memory_dex_with_vma() {
    let dir = std::env::temp_dir().join(format!("ksight-memdex-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let runtime = dir.join("runtime");
    std::fs::create_dir_all(&runtime).expect("runtime");
    let mut dex = vec![0_u8; 2048];
    dex[..8].copy_from_slice(b"dex\n035\0");
    std::fs::write(runtime.join("mem-11-6ec9458c90.dex"), &dex).expect("dex");
    std::fs::write(
        runtime.join("maps-11.txt"),
        "6ec9458000-6ec9460000 r--p 00000000 00:00 0 [anon:dalvik-classes.dex]\n",
    )
    .expect("maps");
    let artifacts = catalog_dump(&dir);
    let mem = artifacts
        .iter()
        .find(|row| row.source == "memory-dex")
        .expect("memory-dex");
    assert_eq!(mem.pid, Some(11));
    assert_eq!(mem.vma_start, Some(0x006e_c945_8c90));
    assert_eq!(mem.vma_end, Some(0x006e_c946_0000));
    assert_eq!(mem.map_path.as_deref(), Some("[anon:dalvik-classes.dex]"));
    let graph = ksight_core::SessionGraph::from_package_dump(
        uuid::Uuid::nil(),
        "com.example.app",
        &[11],
        &artifacts,
    );
    assert!(graph.edges.iter().any(|edge| edge.relation == "produced"));
    assert!(graph
        .edges
        .iter()
        .all(|edge| edge.strength == ksight_core::EdgeStrength::Correlated));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn catalog_skips_duplicate_apk_dex_and_file_backed_heaps() {
    let dir = std::env::temp_dir().join(format!("ksight-dedupe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let split = dir.join("apk-dex").join("split");
    let blob = dir.join("runtime").join("blob-dex");
    std::fs::create_dir_all(&split).expect("split");
    std::fs::create_dir_all(&blob).expect("blob");
    let mut dex = vec![0_u8; 2048];
    dex[..8].copy_from_slice(b"dex\n035\0");
    std::fs::write(split.join("classes.dex"), &dex).expect("split");
    std::fs::write(dir.join("apk-dex").join("classes.dex"), &dex).expect("root");
    std::fs::write(split.join("blob-8-abc_part00_0.dex"), &dex).expect("heap");
    std::fs::write(
            blob.join("8-abc.json"),
            r#"{"pid":8,"vma_start":2748,"vma_end":4096,"map_path":"/data/app/x/oat/arm64/base.vdex","files":["blob-8-abc_part00_0.dex"]}"#,
        )
        .expect("json");
    std::fs::write(
        dir.join("runtime").join("maps-8.txt"),
        "00000abc-00001000 r--p 00000000 00:00 0 /data/app/x/oat/arm64/base.vdex\n",
    )
    .expect("maps");
    std::fs::write(dir.join("runtime").join("mem-8-1000.dex"), vec![0_u8; 200]).expect("tiny");
    let artifacts = catalog_dump(&dir);
    assert_eq!(
        artifacts
            .iter()
            .filter(|row| row.source == "apk-dex")
            .count(),
        1
    );
    assert!(artifacts.iter().all(|row| row.source != "heap-blob"));
    assert!(artifacts.iter().all(|row| row.source != "memory-dex"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn catalog_keeps_writable_app_so_blobs() {
    let dir = std::env::temp_dir().join(format!("ksight-so-blob-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let split = dir.join("apk-dex").join("split");
    let blob = dir.join("runtime").join("blob-dex");
    std::fs::create_dir_all(&split).expect("split");
    std::fs::create_dir_all(&blob).expect("blob");
    let mut dex = vec![0_u8; 2048];
    dex[..8].copy_from_slice(b"dex\n035\0");
    std::fs::write(split.join("blob-8-aaa_part00_0.dex"), &dex).expect("so blob");
    std::fs::write(split.join("blob-8-bbb_part00_0.dex"), &dex).expect("vdex blob");
    std::fs::write(
            blob.join("8-aaa.json"),
            r#"{"pid":8,"vma_start":1000,"vma_end":2000,"map_path":"/data/app/x/lib/arm64/libpayload.so","files":["blob-8-aaa_part00_0.dex"]}"#,
        )
        .expect("so json");
    std::fs::write(
            blob.join("8-bbb.json"),
            r#"{"pid":8,"vma_start":3000,"vma_end":4000,"map_path":"/data/app/x/oat/arm64/base.vdex","files":["blob-8-bbb_part00_0.dex"]}"#,
        )
        .expect("vdex json");
    std::fs::write(split.join("blob-8-ccc_part00_0.dex"), &dex).expect("memfd blob");
    std::fs::write(
            blob.join("8-ccc.json"),
            r#"{"pid":8,"vma_start":5000,"vma_end":6000,"map_path":"/memfd:classes","files":["blob-8-ccc_part00_0.dex"]}"#,
        )
        .expect("memfd json");
    let artifacts = catalog_dump(&dir);
    let kept: Vec<_> = artifacts
        .iter()
        .filter(|row| row.source == "heap-blob")
        .collect();
    assert_eq!(kept.len(), 2);
    assert!(kept
        .iter()
        .any(|row| { row.map_path.as_deref() == Some("/data/app/x/lib/arm64/libpayload.so") }));
    assert!(kept
        .iter()
        .any(|row| row.map_path.as_deref() == Some("/memfd:classes")));
    assert!(kept.iter().all(|row| {
        row.map_path.as_deref().is_none_or(|path| {
            std::path::Path::new(path)
                .extension()
                .is_none_or(|ext| !ext.eq_ignore_ascii_case("vdex"))
        })
    }));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn art_file_open_joins_apk_dex_from_data_app() {
    let mut loaders = vec![CodeLoaderEntry {
        pid: 9,
        order: 1,
        role: "install".to_owned(),
        origin: "art_open".to_owned(),
        path: "/data/app/~~x==/pkg-y==/base.apk".to_owned(),
        ..CodeLoaderEntry::default()
    }];
    let artifacts = vec![ksight_core::DumpArtifact {
        kind: "dex".to_owned(),
        source: "apk-dex".to_owned(),
        relative_path: "apk-dex/classes.dex".to_owned(),
        bytes: 128,
        magic: "dex".to_owned(),
        pid: None,
        vma_start: None,
        vma_end: None,
        map_path: None,
        dex_offset: None,
        sha256: Some("abc".to_owned()),
    }];
    join_art_opens(&mut loaders, &artifacts);
    assert_eq!(
        loaders[0].joined_relative_path.as_deref(),
        Some("apk-dex/classes.dex")
    );
    assert_eq!(loaders[0].joined_sha256.as_deref(), Some("abc"));
    let joins = art_open_joins(&loaders, &artifacts);
    assert_eq!(joins[0].2, "artifact:sha256:abc");
}

#[test]
fn art_memory_open_joins_containing_vma() {
    let mut loaders = vec![CodeLoaderEntry {
        pid: 4,
        order: 1,
        role: "in_memory".to_owned(),
        origin: "art_open".to_owned(),
        path: "memory:0x1200+64".to_owned(),
        opened_bytes: Some(64),
        ..CodeLoaderEntry::default()
    }];
    let artifacts = vec![ksight_core::DumpArtifact {
        kind: "dex".to_owned(),
        source: "heap-blob".to_owned(),
        relative_path: "apk-dex/split/blob.dex".to_owned(),
        bytes: 64,
        magic: "dex".to_owned(),
        pid: Some(4),
        vma_start: Some(0x1000),
        vma_end: Some(0x2000),
        map_path: Some("[anon:scudo:secondary]".to_owned()),
        dex_offset: Some(0),
        sha256: Some("heap".to_owned()),
    }];
    join_art_opens(&mut loaders, &artifacts);
    assert_eq!(
        loaders[0].joined_relative_path.as_deref(),
        Some("apk-dex/split/blob.dex")
    );
}

#[test]
fn bound_code_container_dex_is_catalogued_as_an_inner_slice() {
    let dir = std::env::temp_dir().join(format!("ksight-bound-dex-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("runtime")).unwrap();
    let mut dex = vec![0_u8; 1024];
    dex[..8].copy_from_slice(b"dex\n035\0");
    dex[32..36].copy_from_slice(&1024_u32.to_le_bytes());
    dex[40..44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
    let mut container = b"vdex027\0........".to_vec();
    let offset = container.len() as u64;
    container.extend_from_slice(&dex);
    let name = "bound-9-1a2b-11111111-2222-3333-4444-555555555555.code";
    std::fs::write(dir.join("runtime").join(name), &container).unwrap();
    let artifacts = catalog_dump(&dir);
    let dex_rows: Vec<_> = artifacts
        .iter()
        .filter(|artifact| artifact.kind == "dex" && artifact.relative_path.ends_with(name))
        .collect();
    assert_eq!(dex_rows.len(), 1);
    assert_eq!(dex_rows[0].dex_offset, Some(offset));
    assert_eq!(dex_rows[0].bytes, 1024);
    assert_eq!(dex_rows[0].source, "memory-dex");
    let mut owned = dex_rows.into_iter().cloned().collect::<Vec<_>>();
    attach_artifact_hashes(&dir, &mut owned);
    let (sets, index) = build_dex_sets(&dir, &owned);
    assert_eq!(sets.len(), 1);
    assert_eq!(sets[0].bytes, 1024);
    assert_eq!(sets[0].observations[0].dex_offset, Some(offset));
    assert!(sets[0].semantic.is_some());
    assert_eq!(index.unique_dex, 1);
    assert_ne!(
        sets[0].sha256.as_str(),
        sha256_file(&dir.join("runtime").join(name)).unwrap()
    );
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn shell_declared_size_does_not_hide_a_later_dex() {
    let mut bytes = vec![0_u8; 400];
    let write = |buf: &mut [u8], at: usize, declared: u32, classes: u32| {
        buf[at..at + 8].copy_from_slice(b"dex\n035\0");
        buf[at + 32..at + 36].copy_from_slice(&declared.to_le_bytes());
        buf[at + 40..at + 44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        buf[at + 96..at + 100].copy_from_slice(&classes.to_le_bytes());
    };
    write(&mut bytes, 0, 400, 41);
    write(&mut bytes, 200, 112, 8489);
    let found = embedded_dex_images(&bytes);
    assert!(found.contains(&(0, 400)));
    assert!(found.contains(&(200, 112)));
}

#[test]
fn unpacked_dex_requires_a_real_class_table_inside_the_buffer() {
    assert!(!anonymous_dex_region(
        "/system/lib64/libc.so",
        "rw-p",
        2 * 1024 * 1024
    ));
    assert!(anonymous_dex_region(
        "[anon:scudo:secondary]",
        "rw-p",
        18 * 1024 * 1024
    ));
    assert!(anonymous_dex_region(
        "[anon:scudo:secondary]",
        "rw-p",
        92_168_192
    ));
    assert!(!anonymous_dex_region(
        "[anon:scudo:secondary]",
        "rw-p",
        128 * 1024 * 1024 + 1
    ));
    assert!(!anonymous_dex_region(
        "[anon:dalvik-LinearAlloc]",
        "rw-p",
        92_168_192
    ));
    let mut bytes = vec![0_u8; 8192 + 512];
    let at = 8192;
    bytes[at..at + 8].copy_from_slice(b"dex\n035\0");
    bytes[at + 32..at + 36].copy_from_slice(&512_u32.to_le_bytes());
    bytes[at + 40..at + 44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
    bytes[at + 96..at + 100].copy_from_slice(&8781_u32.to_le_bytes());
    bytes[at + 100..at + 104].copy_from_slice(&112_u32.to_le_bytes());
    assert_eq!(find_unpacked_dex(&bytes), None);
    bytes[at + 96..at + 100].copy_from_slice(&7_u32.to_le_bytes());
    assert_eq!(find_unpacked_dex(&bytes), None);
}

fn put_structural_dex(bytes: &mut [u8], at: usize, classes: u32, declared: u32) {
    bytes[at..at + 8].copy_from_slice(b"dex\n035\0");
    bytes[at + 32..at + 36].copy_from_slice(&declared.to_le_bytes());
    bytes[at + 36..at + 40].copy_from_slice(&112_u32.to_le_bytes());
    bytes[at + 40..at + 44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
    bytes[at + 96..at + 100].copy_from_slice(&classes.to_le_bytes());
    bytes[at + 100..at + 104].copy_from_slice(&112_u32.to_le_bytes());
}

#[test]
fn outer_class_count_over_200_does_not_hide_an_inner_dex() {
    let inner_classes = 200_u32;
    let inner_declared = 112 + inner_classes * 32;
    let inner_at = 8_000_usize;
    let total = inner_at + inner_declared as usize;
    let mut bytes = vec![0_u8; total];
    put_structural_dex(&mut bytes, 0, 201, total as u32);
    put_structural_dex(&mut bytes, inner_at, inner_classes, inner_declared);
    assert_eq!(
        unpacked_dex_ranges(&bytes, 4),
        vec![(0, total), (inner_at, inner_declared as usize)]
    );
}

#[test]
fn forged_class_defs_and_out_of_range_class_table_are_not_structural() {
    let mut forged = vec![0_u8; 512];
    put_structural_dex(&mut forged, 0, 8781, 512);
    assert_eq!(find_unpacked_dex(&forged), None);
    let mut shifted = vec![0_u8; 512];
    put_structural_dex(&mut shifted, 0, 2, 512);
    shifted[100..104].copy_from_slice(&500_u32.to_le_bytes());
    assert_eq!(find_unpacked_dex(&shifted), None);
}

#[test]
fn one_scudo_region_keeps_each_later_unpacked_dex() {
    let first = 112 + 200 * 32;
    let second = 112 + 220 * 32;
    let mut bytes = vec![0_u8; first + second];
    put_structural_dex(&mut bytes, 0, 200, first as u32);
    put_structural_dex(&mut bytes, first, 220, second as u32);
    assert_eq!(
        unpacked_dex_ranges(&bytes, 4),
        vec![(0, first), (first, second)]
    );
}

fn anon_identity(pid: u32, birth_ns: u64, exec_id: u64) -> AnonReadIdentity {
    AnonReadIdentity {
        package: "com.example.app".to_owned(),
        pid,
        uid: 10001,
        birth_ns,
        exec_id,
        boot_id: "boot".to_owned(),
    }
}

fn anon_request(
    expected: AnonReadIdentity,
    observed: AnonReadIdentity,
    deadline_reached: bool,
    budget_closed: bool,
) -> AnonReadRequest {
    AnonReadRequest {
        expected,
        observed,
        deadline_reached,
        budget_closed,
    }
}

#[test]
fn anonymous_read_refusals_do_not_read_or_write_payload() {
    let expected = anon_identity(10, 100, 7);
    let restart = anon_request(expected.clone(), anon_identity(11, 200, 7), false, false);
    assert_eq!(
        admit_anonymous_read(&restart),
        Err(AnonReadRefusal::RestartedInstance)
    );
    assert_eq!(anonymous_payload_effect(&restart), (0, 0));
    let exec = anon_request(expected.clone(), anon_identity(10, 100, 8), false, false);
    assert_eq!(
        admit_anonymous_read(&exec),
        Err(AnonReadRefusal::ExecChanged)
    );
    assert_eq!(anonymous_payload_effect(&exec), (0, 0));
    let budget = anon_request(expected.clone(), expected.clone(), false, true);
    assert_eq!(
        admit_anonymous_read(&budget),
        Err(AnonReadRefusal::BudgetExhausted)
    );
    assert_eq!(anonymous_payload_effect(&budget), (0, 0));
    let deadline = anon_request(expected.clone(), expected.clone(), true, false);
    assert_eq!(
        admit_anonymous_read(&deadline),
        Err(AnonReadRefusal::DeadlineReached)
    );
    assert_eq!(anonymous_payload_effect(&deadline), (0, 0));
    let admitted = anon_request(expected.clone(), expected, false, false);
    assert!(admit_anonymous_read(&admitted).is_ok());
    assert_eq!(anonymous_payload_effect(&admitted), (1, 1));
}

#[test]
fn closed_output_budget_does_not_fall_back_to_an_unbudgeted_payload_write() {
    let root = std::env::temp_dir().join(format!("ksight-budget-close-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    let _guard = ksight_core::output_budget::Guard::install(vec![root.clone()], 8, 60_000).unwrap();
    let path = root.join("payload.bin");
    assert!(write_catalog_bytes(&path, &[9_u8; 64]).is_err());
    assert!(!path.exists());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn dexhelper_bss_next_to_the_library_is_a_key_region() {
    let helper = crate::dexdump::MapRow {
        start: 0x2000_0000,
        end: 0x2010_0000,
        perms: "r-xp".to_owned(),
        path: "/data/app/pkg/lib/arm64/libDexHelper.so".to_owned(),
        inode: 1,
    };
    let bss = crate::dexdump::MapRow {
        start: 0x2010_1000,
        end: 0x2010_4000,
        perms: "rw-p".to_owned(),
        path: "[anon:.bss]".to_owned(),
        inode: 0,
    };
    let far = crate::dexdump::MapRow {
        start: 0x8000_0000,
        end: 0x8000_1000,
        perms: "rw-p".to_owned(),
        path: "[anon:.bss]".to_owned(),
        inode: 0,
    };
    let rows = [helper, bss, far];
    assert!(dexhelper_key_region(
        &rows[1].path,
        &rows[1].perms,
        rows[1].start,
        &rows
    ));
    assert!(!dexhelper_key_region(
        &rows[2].path,
        &rows[2].perms,
        rows[2].start,
        &rows
    ));
    assert!(dexhelper_key_region(
        "/data/app/pkg/lib/arm64/libDexHelper.so",
        "rw-p",
        0x3000,
        &rows
    ));
}

#[test]
fn retained_dexdata0_is_named_in_the_catalog_notes() {
    let dir = std::env::temp_dir().join(format!("ksight-dexdata-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("runtime")).unwrap();
    let mut bytes = vec![0_u8; 64];
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes.extend_from_slice(&92_192_788_u32.to_le_bytes());
    bytes.extend_from_slice(&8_u32.to_le_bytes());
    bytes.extend_from_slice(b"dexdata0");
    bytes.extend_from_slice(&[1_u8; 32]);
    std::fs::write(dir.join("runtime").join("bound-3-1000-aaaa.code"), &bytes).unwrap();
    let _ = catalog_dump(&dir);
    let notes: Vec<String> = serde_json::from_slice(
        &std::fs::read(dir.join("runtime").join("truncated-dex.json")).unwrap(),
    )
    .unwrap();
    assert!(notes.iter().any(|note| {
        note.contains("dexdata0")
            && note.contains("declared 92192788")
            && note.contains("offset 64")
    }));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn truncated_vdex_prefix_is_named_and_not_catalogued_as_dex() {
    let dir = std::env::temp_dir().join(format!("ksight-trunc-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("runtime")).unwrap();
    let mut dex = vec![0_u8; 0x70];
    dex[..8].copy_from_slice(b"dex\n035\0");
    dex[32..36].copy_from_slice(&92_319_172_u32.to_le_bytes());
    dex[40..44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
    let mut container = b"vdex027\0".to_vec();
    container.resize(64, 0);
    container.extend_from_slice(&dex);
    std::fs::write(
        dir.join("runtime")
            .join("bound-9-73e0867000-11111111-2222-3333-4444-555555555555.code"),
        &container,
    )
    .unwrap();
    let artifacts = catalog_dump(&dir);
    assert!(artifacts.iter().all(|artifact| {
        artifact.source != "memory-dex" || !artifact.relative_path.contains("73e0867000")
    }));
    let notes: Vec<String> = serde_json::from_slice(
        &std::fs::read(dir.join("runtime").join("truncated-dex.json")).unwrap(),
    )
    .unwrap();
    assert!(notes.iter().any(|note| {
        note.contains("declared 92319172")
            && note.contains("retained 112")
            && note.contains("not a complete DEX")
    }));
    std::fs::remove_dir_all(dir).unwrap();
}
