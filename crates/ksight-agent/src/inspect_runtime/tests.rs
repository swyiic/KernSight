use ksight_model::ProcessKey;

use super::*;
use std::time::Duration;

#[test]
fn parse_stat_start_ticks_skips_comm_in_parentheses() {
    let mut fields = vec!["S".to_owned()];
    fields.extend(std::iter::repeat_n("0".to_owned(), 18));
    fields.push("99999".to_owned());
    let stat = format!("21428 (helper) {}", fields.join(" "));
    assert_eq!(parse_stat_start_ticks(&stat), Some(99999));
}

#[test]
fn pid_and_memory_size_parse_from_art_open_fields() {
    assert_eq!(pid_from_detail("ART DEX Open hit pid=24056 path=/x"), 24056);
    assert_eq!(parse_open_size("memory:0x1000+4096"), Some(4096));
    assert_eq!(parse_open_size("/data/app/x/base.apk"), None);
    assert_eq!(
            symbol_from_detail(
                "ART DEX Open hit pid=1 symbol=_ZN3art13DexFileLoader10OpenCommonEPKhm layout=memory path=memory:0x1+2"
            )
            .as_deref(),
            Some("_ZN3art13DexFileLoader10OpenCommonEPKhm")
        );
}

#[test]
fn art_open_layout_follows_exported_itanium_encoding() {
    assert_eq!(
        art_open_layout("_ZNK3art16ArtDexFileLoader4OpenEPKcRKNSt3__1"),
        ArtOpenLayout::Filename { reg: 1 }
    );
    assert_eq!(
        art_open_layout("_ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNS"),
        ArtOpenLayout::Memory { base: 0, size: 1 }
    );
    assert_eq!(
        art_open_layout("_ZNK3art13DexFileLoader4OpenEPKhmRKNSt3__1"),
        ArtOpenLayout::Memory { base: 1, size: 2 }
    );
    assert_eq!(
        art_open_layout("_ZNK3art13DexFileLoader16OpenFromZipEntryERKNS_10ZipArchiveEPKc"),
        ArtOpenLayout::Filename { reg: 2 }
    );
    assert_eq!(
        art_open_layout("_ZN3art13DexFileLoader4OpenEbbbPNS_22DexFileLoaderErrorCodeE"),
        ArtOpenLayout::Probe
    );
}

#[test]
fn code_path_hints_accept_apk_and_zip_entries() {
    assert!(looks_like_code_path("/data/app/x/base.apk"));
    assert!(looks_like_code_path("classes.dex"));
    assert!(looks_like_code_path(
        "/apex/com.android.art/javalib/core-oj.jar"
    ));
    assert!(!looks_like_code_path(""));
    assert!(!looks_like_code_path("ok"));
    assert!(!looks_like_code_path("not a path"));
}

#[test]
fn art_open_package_filter_does_not_keep_other_apks() {
    assert!(art_open_belongs_to_package(
        "com.example.app",
        "com.example.app",
        "memory:0x1+2"
    ));
    assert!(art_open_belongs_to_package(
        "com.example.app",
        "com.example.app:push",
        ""
    ));
    assert!(art_open_belongs_to_package(
        "com.example.app",
        "zygote",
        "/data/app/~~x==/com.example.app-y==/base.apk"
    ));
    assert!(!art_open_belongs_to_package(
        "com.example.app",
        "zygote",
        "/data/app/~~x==/com.google.android.trichromelibrary/TrichromeLibrary.apk"
    ));
    assert!(!art_open_belongs_to_package(
        "com.example.app",
        "com.qihoo.magic",
        "/data/app/~~x==/com.example.wallet-y==/base.apk"
    ));
}

#[test]
fn art_dex_prefixes_cover_loader_and_common() {
    let names = InspectAdapterKind::ArtDexLoad.symbols();
    assert!(names.iter().any(|name| name.contains("DexFileLoader4Open")));
    assert!(names.iter().any(|name| name.contains("OpenCommon")));
    assert!(names.iter().any(|name| name.contains("OpenFromZipEntry")));
    assert!(InspectAdapterKind::ArtDexMemory
        .symbols()
        .iter()
        .all(|name| name.contains("EPKhm")));
    assert!(plausible_dex_size(0x70));
    assert!(!plausible_dex_size(1));
    assert!(plausible_user_ptr(0x1000));
    assert!(!plausible_user_ptr(0));
}

#[test]
fn mapping_path_matches_libbinder_basename() {
    assert!(mapping_path_matches(
        "/system/lib/libbinder.so",
        "libbinder.so"
    ));
    assert!(mapping_path_matches(
        "/system/lib64/libbinder.so",
        "libbinder.so"
    ));
    assert!(!mapping_path_matches(
        "/system/lib64/libbinder_ndk.so",
        "libbinder.so"
    ));
    assert!(mapping_path_matches("/system/bin/linker", "linker"));
    assert!(!mapping_path_matches("/system/bin/linker64", "linker"));
    assert!(mapping_path_matches(
        "/data/app/foo/lib/arm64/libcronet.119.0.6045.so",
        "libcronet.so"
    ));
    assert!(mapping_path_matches(
        "/apex/com.android.tethering/lib64/stable_cronet_libssl.so",
        "libssl.so"
    ));
    assert!(mapping_path_matches(
        "/data/app/~~x/com.example.app-y/lib/arm64/libopenssl.so",
        "libopenssl.so"
    ));
    assert!(!mapping_path_matches(
        "/data/app/~~x/com.example.app-y/lib/arm64/libopenssl.so",
        "libssl.so"
    ));
    assert!(mapping_path_matches(
        "/data/app/~~x/com.example.wallet-y/lib/arm64/libtnet-4.0.0.so",
        "libtnet"
    ));
    assert!(!mapping_path_matches(
        "/data/app/~~x/com.example.wallet-y/lib/arm64/libBifrost.so",
        "libtnet"
    ));
    assert!(mapping_path_matches(
        "/apex/com.android.tethering/lib64/stable_cronet_libssl.so",
        "libcronet.so"
    ));
    assert!(mapping_path_matches(
        "/data/app/foo/lib/arm64/libflutter.so",
        "libflutter.so"
    ));
    assert!(mapping_path_matches(
        "/data/app/foo/lib/arm64/libmbedtls.so",
        "mbedtls"
    ));
    assert!(mapping_path_matches(
        "/data/app/foo/lib/arm64/libwolfssl.so",
        "wolfssl"
    ));
    assert!(InspectAdapterKind::TlsSslWrite
        .symbols()
        .contains(&"mbedtls_ssl_write"));
    assert!(InspectAdapterKind::TlsSslWrite
        .symbols()
        .contains(&"sslWrite"));
    assert!(InspectAdapterKind::TlsSslRead
        .symbols()
        .contains(&"wolfSSL_read"));
    assert!(InspectAdapterKind::TlsSslRead
        .symbols()
        .contains(&"sslRead"));
    // sslWriteEx / sslReadEx are non-standard: VendorCustom, not auto-attached
    // via fixed name arrays (ProbeSpec.abi required).
    assert!(!tls_exact_names(InspectAdapterKind::TlsSslWrite)
        .iter()
        .any(|n| n == "sslWriteEx"));
    assert!(tls_exact_names(InspectAdapterKind::TlsSslWrite)
        .iter()
        .any(|n| n == "SSL_write_ex2"));
    assert!(!tls_exact_names(InspectAdapterKind::TlsSslRead)
        .iter()
        .any(|n| n == "sslReadEx"));
    assert!(tls_exact_names(InspectAdapterKind::TlsSslRead)
        .iter()
        .any(|n| n == "SSL_read_ex2"));
    assert!(tls_exact_names(InspectAdapterKind::TlsSslRead)
        .iter()
        .any(|n| n == "sslRead"));
    assert!(tls_exact_names(InspectAdapterKind::TlsSslRead)
        .iter()
        .any(|n| n == "SSL_peek"));
    assert!(tls_exact_names(InspectAdapterKind::TlsSslRead)
        .iter()
        .any(|n| n == "SLIGHT_SSL_read"));
    assert!(tls_exact_names(InspectAdapterKind::TlsSslWrite)
        .iter()
        .any(|n| n == "SLIGHT_SSL_write"));
    for banned in [
        "BIO_write",
        "BIO_read",
        "SSL_quic_read_level",
        "SSL_quic_write_level",
        "SSL_provide_quic_data",
    ] {
        assert!(
            !tls_exact_names(InspectAdapterKind::TlsSslWrite)
                .iter()
                .any(|n| n == banned),
            "{banned} must not be a default TLS write attach name"
        );
        assert!(
            !tls_exact_names(InspectAdapterKind::TlsSslRead)
                .iter()
                .any(|n| n == banned),
            "{banned} must not be a default TLS read attach name"
        );
    }
    assert_eq!(
        ksight_core::TlsAbiKind::from_exported_symbol("SSL_write_ex2")
            .layout()
            .out_len_arg,
        Some(4),
        "_ex2 actual-length pointer is x4, not the _ex x3"
    );
    assert_eq!(
        ksight_core::TlsAbiKind::from_exported_symbol("SSL_write_ex")
            .layout()
            .out_len_arg,
        Some(3)
    );
    assert!(mapping_path_matches(
        "/data/app/foo/lib/arm64/libhssl-2.1.so",
        "hssl"
    ));
    assert!(mapping_path_matches(
        "/data/app/foo/lib/arm64/libwework_framework.so",
        "wework"
    ));
    assert!(mapping_path_matches(
        "/data/app/foo/lib/arm64/libttboringssl.so",
        "ttboringssl"
    ));
    assert_eq!(tls_attach_rank("/data/app/foo/lib/arm64/libhssl-2.1.so"), 0);
    assert!(
        tls_attach_rank("/data/app/foo/lib/arm64/libhssl-2.1.so")
            < tls_attach_rank("/apex/com.android.conscrypt/lib64/libssl.so")
    );
    let libs = InspectAdapterKind::BinderUserspace.libraries();
    assert!(libs
        .iter()
        .any(|path| path.ends_with("/lib64/libbinder.so")));
    assert!(libs.iter().any(|path| path.ends_with("/lib/libbinder.so")));
}

#[test]
fn scoped_inspect_filters_tgid_in_kernel() {
    let whole = InspectPolicy {
        enabled: true,
        whole_device: true,
        package: Some("com.example".to_owned()),
        ..InspectPolicy::default()
    };
    assert_eq!(active_tgid_filter(&whole), None);
    let one = InspectPolicy {
        enabled: true,
        pid: Some(42),
        ..InspectPolicy::default()
    };
    assert_eq!(active_tgid_filter(&one), Some(vec![42]));
    assert_eq!(join_tgids(&[42, 43]), "42,43");
}

#[test]
fn disabled_policy_does_not_attach() {
    let plans = InspectPlan::evaluate(
        InspectPolicy::default(),
        InspectAdapterKind::LinkerSoLoad,
        PathBuf::from("/nonexistent"),
    );
    assert!(plans.iter().all(|plan| !plan.should_attach()));
    assert!(plans[0].observation.detail.contains("disabled"));
}

#[test]
fn art_dex_memory_is_a_named_exported_symbol_adapter() {
    let kind = "art_dex_memory"
        .parse::<InspectAdapterKind>()
        .expect("parse");
    assert_eq!(kind.as_str(), "art_dex_memory");
    assert!(kind.symbols()[0].contains("OpenEPKhm"));
}

#[test]
fn binder_userspace_also_plans_write_interface_token() {
    let policy = InspectPolicy {
        enabled: true,
        package: Some("com.example.app".to_owned()),
        ..InspectPolicy::default()
    };
    let runtime = InspectRuntime::prepare(
        &policy,
        InspectAdapterKind::BinderUserspace,
        Path::new("/nonexistent"),
    );
    let adapters: Vec<_> = runtime
        .initial_observations()
        .into_iter()
        .map(|observation| observation.adapter)
        .collect();
    assert!(adapters.iter().any(|adapter| adapter == "binder_userspace"));
    assert!(adapters
        .iter()
        .any(|adapter| adapter == "binder_interface_token"));
    assert!(adapters
        .iter()
        .any(|adapter| adapter == "binder_parcel_string"));
    assert!(adapters
        .iter()
        .any(|adapter| adapter == "binder_parcel_utf8"));
    assert!(adapters
        .iter()
        .any(|adapter| adapter == "binder_parcel_int64"));
    assert!(adapters
        .iter()
        .any(|adapter| adapter == "binder_parcel_bool"));
    assert!(adapters
        .iter()
        .any(|adapter| adapter == "binder_parcel_cstring"));
    assert!(adapters
        .iter()
        .any(|adapter| adapter == "binder_parcel_dup_fd"));
    assert!("binder_interface_token"
        .parse::<InspectAdapterKind>()
        .is_ok());
    assert!("binder_parcel_string".parse::<InspectAdapterKind>().is_ok());
    assert!("binder_parcel_int64".parse::<InspectAdapterKind>().is_ok());
    assert!(
        InspectAdapterKind::BinderInterfaceToken.symbols()[0].contains("writeInterfaceTokenEPKDsm")
    );
    assert!(InspectAdapterKind::BinderParcelString.symbols()[0].contains("writeString16EPKDsm"));
    assert!(InspectAdapterKind::BinderParcelUtf8.symbols()[0].contains("writeString8EPKcm"));
    assert!(InspectAdapterKind::BinderParcelInt64.symbols()[0].contains("writeInt64El"));
    assert!(InspectAdapterKind::BinderParcelBool.symbols()[0].contains("writeBoolEb"));
    assert!(InspectAdapterKind::BinderParcelCString.symbols()[0].contains("writeCStringEPKc"));
    assert!(InspectAdapterKind::BinderParcelDupFd.symbols()[0].contains("writeDupFileDescriptorEi"));
    assert!(adapters
        .iter()
        .any(|adapter| adapter == "binder_parcel_binder"));
    assert!(adapters
        .iter()
        .any(|adapter| adapter == "binder_parcel_byte"));
    assert!("binder_parcel_binder".parse::<InspectAdapterKind>().is_ok());
    assert!(InspectAdapterKind::BinderParcelBinder.symbols()[0].contains("writeStrongBinder"));
    assert!(InspectAdapterKind::BinderParcelByte.symbols()[0].contains("writeByteEa"));
    assert!(InspectAdapterKind::BinderParcelChar.symbols()[0].contains("writeCharEDs"));
}

#[test]
fn utf16_interface_token_rejects_noise() {
    let mut bytes = Vec::new();
    for unit in "android.os.IServiceManager".encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    assert_eq!(
        decode_utf16le(&bytes, 64).as_deref(),
        Some("android.os.IServiceManager")
    );
    assert!(looks_like_binder_interface("android.os.IServiceManager"));
    assert!(!looks_like_binder_interface("ok"));
    assert!(!looks_like_binder_interface("not a token"));
    assert!(looks_like_binder_string("activity"));
    assert!(looks_like_binder_string("/data/user/0/com.example/files/x"));
    assert!(!looks_like_binder_string("has\u{0007}bell"));
}

#[test]
fn jni_utf16_is_not_clamped_to_binder_token_cap() {
    let json = format!(
            "{{\"type\":\"network-request\",\"pad\":\"{}\",\"url\":\"https://www.us.hsbc.com/api/wpb-dsvc\"}}",
            "x".repeat(160)
        );
    assert!(json.encode_utf16().count() > BINDER_INTERFACE_UNITS_CAP);
    let mut bytes = Vec::new();
    for unit in json.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let decoded = decode_utf16le(&bytes, json.encode_utf16().count()).expect("utf16");
    assert!(decoded.contains("https://www.us.hsbc.com/api/wpb-dsvc"));
    assert_eq!(decoded, json);
}

#[test]
fn binder_transact_pairs_token_and_string16_by_tid() {
    let mut tokens = HashMap::from([(7_u32, "android.os.IServiceManager".to_owned())]);
    let mut strings = HashMap::new();
    push_binder_string(&mut strings, 7, "android.os.IServiceManager".to_owned());
    push_binder_string(&mut strings, 7, "activity".to_owned());
    let (interface, collected) = pair_binder_transact(7, &mut tokens, &mut strings);
    assert_eq!(interface.as_deref(), Some("android.os.IServiceManager"));
    assert_eq!(collected, vec!["activity".to_owned()]);
    assert!(!tokens.contains_key(&7));
    assert!(!strings.contains_key(&7));
}

#[test]
fn binder_method_names_are_aosp_table_only() {
    assert_eq!(
        binder_method_name(Some("android.os.IServiceManager"), 1),
        Some("getService")
    );
    assert_eq!(
        binder_method_name(Some("android.os.IServiceManager"), 6),
        Some("listServices")
    );
    assert_eq!(
        binder_method_name(Some("android.content.pm.IPackageManager"), 3),
        Some("getPackageInfo")
    );
    assert_eq!(
        binder_method_name(Some("android.gui.IDisplayEventConnection"), 3),
        Some("requestNextVsync")
    );
    assert_eq!(
        binder_method_name(Some("android.app.IUiModeManager"), 1),
        Some("addCallback")
    );
    assert_eq!(
        binder_method_name(Some("android.app.IUiModeManager"), 5),
        Some("getCurrentModeType")
    );
    assert_eq!(
        binder_method_name(Some("android.os.IServiceManager"), 0x5f50_4e47),
        Some("PING_TRANSACTION")
    );
    assert_eq!(
        binder_method_name(Some("com.example.IBankSession"), 1),
        None
    );
    assert_eq!(binder_method_name(None, 1), None);
}

#[test]
fn jni_adapter_refuses_without_exported_boundary() {
    let policy = InspectPolicy {
        enabled: true,
        pid: Some(1),
        ..InspectPolicy::default()
    };
    let plans = InspectPlan::evaluate(
        policy,
        InspectAdapterKind::JniRegistration,
        PathBuf::from("/nonexistent"),
    );
    assert!(plans.iter().all(|plan| !plan.should_attach()));
    assert!(
        plans[0].observation.detail.contains("GetFunctionTable")
            || plans[0].observation.detail.contains("JNINativeInterface")
    );
}

#[test]
fn tls_without_app_selector_does_not_attach() {
    let policy = InspectPolicy {
        enabled: true,
        ..InspectPolicy::default()
    };
    let plans = InspectPlan::evaluate(
        policy,
        InspectAdapterKind::TlsSslWrite,
        PathBuf::from("/nonexistent"),
    );
    assert!(plans.iter().all(|plan| !plan.should_attach()));
    assert!(plans[0].observation.detail.contains("no app selector"));
}

#[test]
fn tls_write_selection_expands_read_into_selected_adapters() {
    let policy = InspectPolicy {
        enabled: true,
        package: Some("com.example.app".to_owned()),
        ..InspectPolicy::default()
    };
    let runtime = InspectRuntime::prepare_all(
        &policy,
        &[InspectAdapterKind::TlsSslWrite],
        Path::new("/nonexistent"),
    );
    assert!(
        runtime
            .selected_adapters
            .contains(&InspectAdapterKind::TlsSslWrite),
        "TlsSslWrite must remain selected"
    );
    assert!(
        runtime
            .selected_adapters
            .contains(&InspectAdapterKind::TlsSslRead),
        "TlsSslRead companion must be promoted into selected_adapters for lazy TLS rescan"
    );
    // Selecting both write+read must not duplicate the companion entry.
    let runtime_both = InspectRuntime::prepare_all(
        &policy,
        &[
            InspectAdapterKind::TlsSslWrite,
            InspectAdapterKind::TlsSslRead,
        ],
        Path::new("/nonexistent"),
    );
    let read_count = runtime_both
        .selected_adapters
        .iter()
        .filter(|adapter| **adapter == InspectAdapterKind::TlsSslRead)
        .count();
    assert_eq!(
        read_count, 1,
        "TlsSslRead must appear once when already selected"
    );
}

#[test]
fn inspect_tls_and_binder_plan_together() {
    let policy = InspectPolicy {
        enabled: true,
        package: Some("com.example.app".to_owned()),
        ..InspectPolicy::default()
    };
    let runtime = InspectRuntime::prepare_all(
        &policy,
        &[
            InspectAdapterKind::TlsSslWrite,
            InspectAdapterKind::BinderUserspace,
        ],
        Path::new("/nonexistent"),
    );
    let adapters = runtime
        .initial_observations()
        .into_iter()
        .map(|observation| observation.adapter)
        .collect::<BTreeSet<_>>();
    assert!(adapters.contains("tls_ssl_write"));
    assert!(adapters.contains("tls_ssl_read"));
    assert!(adapters.contains("binder_userspace"));
    assert!(adapters.contains("binder_interface_token"));
    assert!(adapter_is_live(
        &[
            InspectAdapterKind::TlsSslWrite,
            InspectAdapterKind::BinderUserspace,
        ],
        InspectAdapterKind::TlsSslRead
    ));
    assert!(adapter_is_live(
        &[
            InspectAdapterKind::TlsSslWrite,
            InspectAdapterKind::BinderUserspace,
        ],
        InspectAdapterKind::BinderParcelString
    ));
}

#[test]
fn per_adapter_budget_when_max_hits_unspecified() {
    let policy = InspectPolicy {
        enabled: true,
        package: Some("com.example.app".to_owned()),
        max_hits: 0,
        ..InspectPolicy::default()
    };
    let runtime = InspectRuntime::prepare_all(
        &policy,
        &[
            InspectAdapterKind::TlsSslWrite,
            InspectAdapterKind::JniPlaintext,
        ],
        Path::new("/nonexistent"),
    );
    assert!(runtime.per_adapter_budget);
    assert_eq!(
        adapter_hit_cap(&runtime, InspectAdapterKind::TlsSslWrite),
        InspectAdapterKind::TlsSslWrite.default_max_hits()
    );
    assert_eq!(
        adapter_hit_cap(&runtime, InspectAdapterKind::JniGetStringUtfChars),
        InspectAdapterKind::JniGetStringUtfChars.default_max_hits()
    );
    assert!(!jni_bytes_worth_keeping(&[]));
    assert!(!jni_bytes_worth_keeping(&[0, 0, 0]));
    assert!(jni_bytes_worth_keeping(b"TLSv1.2"));
    let mut smeared = b"\x07\x06\x01\xef".to_vec();
    smeared.extend_from_slice(&[0_u8; 200]);
    smeared.extend_from_slice(&0x6f_1b_9a_d0_u32.to_le_bytes());
    assert!(!keep_jni_elements(clip_jni_elements(&smeared)));
    assert!(keep_jni_elements(
        b"HTTP/1.1 200 OK\r\nHost: api.example\r\n"
    ));
    assert!(keep_jni_elements(
        b"{\"host\":\"api.app.example\",\"path\":\"/v1\"}"
    ));
    assert!(!keep_jni_elements(&[
        0x7b, 0x8d, 0x01, 0xc4, 0x07, 0x01, 0xd6, 0xa1, 0x02, 0x37, 0x7e, 0x8d
    ]));
    let mut noise_padded = vec![
        0x07, 0x06, 0x01, 0xd7, 0x9f, 0x73, 0x3b, 0xba, 0x57, 0x00, 0x00, 0x00, 0xe4, 0x00, 0x00,
        0x00,
    ];
    noise_padded.extend_from_slice(&[0_u8; 480]);
    assert!(!keep_jni_elements(clip_jni_elements(trim_trailing_zeros(
        &noise_padded
    ))));
    let noise_hex = ksight_core::decode_hex_bytes(
        "f75412021214140589e10200770793ae01000c005500bb44380003000e007100f7d800000a007110",
    )
    .expect("hex");
    assert!(!keep_jni_elements(&noise_hex));
    assert!(keep_jni_plaintext(
        br#"{"url":"https://cdn.example/cd/acrossBar_v1.8.zip"}"#
    ));
    assert!(keep_jni_plaintext(
        b"https://api.example/eq/open/api/homepage_v2/v3/homepage_data"
    ));
    assert!(!keep_jni_plaintext(
        b"dth\",\"height\",\"render\"];a(3110),a(8335);var o=a(8817)"
    ));
    assert!(!keep_jni_plaintext(
        b"ComponentInfo{com.example.app/com.example.app.push.InitService}"
    ));
    assert!(!keep_jni_plaintext(
        b"/data/app/~~42Ti3pHV53fUYgIpxOEbtA==/com.example.app/base.apk"
    ));
    let mut lens = HashMap::new();
    lens.insert(
        7,
        PendingJniLen {
            obj: 0x1000,
            len: 32,
        },
    );
    assert_eq!(take_paired_len(&mut lens, 7, 0x1000), Some(32));
    assert_eq!(take_paired_len(&mut lens, 7, 0x1000), None);
    lens.insert(
        8,
        PendingJniLen {
            obj: 0x2000,
            len: 4,
        },
    );
    assert_eq!(take_paired_len(&mut lens, 8, 0x21), None);
}

#[test]
fn inspect_tls_binder_and_jni_plan_together() {
    let policy = InspectPolicy {
        enabled: true,
        package: Some("com.example.app".to_owned()),
        ..InspectPolicy::default()
    };
    let runtime = InspectRuntime::prepare_all(
        &policy,
        &[
            InspectAdapterKind::TlsSslWrite,
            InspectAdapterKind::BinderUserspace,
            InspectAdapterKind::JniPlaintext,
        ],
        Path::new("/nonexistent"),
    );
    let adapters: BTreeSet<_> = runtime
        .initial_observations()
        .into_iter()
        .map(|observation| observation.adapter)
        .collect();
    assert!(adapters.contains("tls_ssl_write"));
    assert!(adapters.contains("tls_ssl_read"));
    assert!(adapters.contains("binder_userspace"));
    assert!(
        adapters.contains("jni_plaintext")
            || adapters.contains("jni_get_string_utf_chars")
            || adapters.contains("jni_registration")
    );
    assert!(adapter_is_live(
        &[InspectAdapterKind::JniPlaintext],
        InspectAdapterKind::JniGetStringUtfChars
    ));
}

#[test]
fn skips_elf32_tls_when_elf64_symbol_exists() {
    let policy = InspectPolicy {
        enabled: true,
        package: Some("com.example.app".to_owned()),
        ..InspectPolicy::default()
    };
    let mut elf32 = InspectPlan::evaluate(
        policy.clone(),
        InspectAdapterKind::TlsSslWrite,
        PathBuf::from("/nonexistent"),
    )
    .remove(0);
    elf32.pointer_width = 4;
    elf32.offset = Some(0x10);
    let mut elf64 = elf32.clone();
    elf64.pointer_width = 8;
    elf64.offset = Some(0x20);
    let mut plans = vec![elf32, elf64];
    prune_redundant_elf32_tls(&mut plans);
    assert!(plans[0].offset.is_none());
    assert_eq!(plans[1].offset, Some(0x20));
    assert!(plans[0].observation.detail.contains("skipped ELF32 TLS"));
}

#[test]
fn inspect_tls_also_plans_ssl_read() {
    let policy = InspectPolicy {
        enabled: true,
        package: Some("com.example.app".to_owned()),
        ..InspectPolicy::default()
    };
    let runtime = InspectRuntime::prepare(
        &policy,
        InspectAdapterKind::TlsSslWrite,
        Path::new("/nonexistent"),
    );
    let adapters: Vec<_> = runtime
        .initial_observations()
        .into_iter()
        .map(|observation| observation.adapter)
        .collect();
    assert!(adapters.iter().any(|adapter| adapter == "tls_ssl_write"));
    assert!(adapters.iter().any(|adapter| adapter == "tls_ssl_read"));
    assert!(InspectAdapterKind::TlsSslWrite
        .libraries()
        .iter()
        .any(|path| path.contains("stable_cronet_libssl.so")));
    assert!(InspectAdapterKind::TlsSslWrite
        .symbols()
        .contains(&"SSL_write"));
    assert!(InspectAdapterKind::TlsSslWrite
        .symbols()
        .contains(&"SSL_write_ex"));
    assert!(InspectAdapterKind::TlsSslRead
        .symbols()
        .contains(&"SSL_read_ex"));
}

#[test]
fn tls_package_selector_is_enough_to_attach() {
    let policy = InspectPolicy {
        enabled: true,
        package: Some("com.example.app".to_owned()),
        ..InspectPolicy::default()
    };
    assert!(policy.may_attach());
    let identity = ProcessIdentity {
        key: ProcessKey {
            boot_id: Uuid::nil(),
            pid: 42,
            start_time_ns: 0,
        },
        tid: 42,
        tgid: 42,
        uid: 10_123,
        gid: 10_123,
        comm: "app".to_owned(),
        command_line: Some("com.example.app:push".to_owned()),
        selinux_context: None,
        packages: Vec::new(),
    };
    assert!(hit_matches_policy(&policy, &identity));
    let mut other = identity.clone();
    other.command_line = Some("com.other.app".to_owned());
    assert!(!hit_matches_policy(&policy, &other));
}

#[test]
fn linker_session_records_audited_stubs() {
    let policy = InspectPolicy {
        enabled: true,
        pid: Some(1),
        ..InspectPolicy::default()
    };
    let runtime = InspectRuntime::prepare(
        &policy,
        InspectAdapterKind::LinkerSoLoad,
        Path::new("/nonexistent"),
    );
    let adapters = runtime
        .initial_observations()
        .into_iter()
        .map(|observation| observation.adapter)
        .collect::<BTreeSet<_>>();
    assert!(adapters.contains("linker_so_load"));
    assert!(adapters.contains("art_dex_load"));
    assert!(adapters.contains("art_dex_memory"));
    assert!(adapters.contains("jni_registration"));
    assert!(adapters.contains("binder_userspace"));
}

#[test]
fn prefer_probe_snapshot_keeps_http_when_remote_is_tls_record() {
    let http = b"POST /v1/session HTTP/1.1\r\nHost: api.example.com\r\n\r\n";
    let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x10];
    record.extend_from_slice(&[9; 16]);
    let chosen = prefer_probe_snapshot(&record, http);
    assert!(chosen.starts_with(b"POST /v1/session"), "{chosen:?}");
    let full = prefer_probe_snapshot(http, b"POST /");
    assert_eq!(full, http);
}

#[test]
fn prefer_probe_snapshot_keeps_non_http_aux_over_empty_remote() {
    let aux = b"{\"token\":\"abc\"}";
    let chosen = prefer_probe_snapshot(&[], aux);
    assert_eq!(chosen, aux);
    let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x08];
    record.extend_from_slice(&[1; 8]);
    let chosen = prefer_probe_snapshot(&record, aux);
    assert_eq!(chosen, aux);
}

#[test]
fn prefer_probe_snapshot_ignores_all_zero_remote() {
    let aux = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    let zeros = vec![0_u8; 64];
    let chosen = prefer_probe_snapshot(&zeros, aux);
    assert_eq!(
        chosen, aux,
        "cleared SSL_read buffer must not beat aux snapshot"
    );
}

#[test]
fn tls_decode_should_attempt_empty_requested_edge_cases() {
    assert!(!tls_decode_should_attempt(0, b""));
    assert!(!tls_decode_should_attempt(-1, b""));
    assert!(tls_decode_should_attempt(0, b"HTTP/1.1 200"));
    assert!(tls_decode_should_attempt(16, b""));
    assert!(tls_decode_should_attempt(0, b"{\"a\":1}"));
}

#[test]
fn tls_only_session_does_not_plan_libart_jni() {
    let policy = InspectPolicy {
        enabled: true,
        package: Some("com.example.app".to_owned()),
        ..InspectPolicy::default()
    };
    let runtime = InspectRuntime::prepare(
        &policy,
        InspectAdapterKind::TlsSslWrite,
        Path::new("/nonexistent"),
    );
    let adapters = runtime
        .initial_observations()
        .into_iter()
        .map(|observation| observation.adapter)
        .collect::<BTreeSet<_>>();
    assert!(adapters.contains("tls_ssl_write"));
    assert!(adapters.contains("tls_ssl_read"));
    assert!(!adapters.contains("jni_registration"));
    assert!(!adapters.contains("jni_new_string_utf"));
    assert!(!adapters.contains("jni_get_string_region"));
}

#[test]
fn preview_prefers_utf8_for_http() {
    let (preview, encoding) = preview_bytes(b"GET / HTTP/1.1\r\nHost: example.com\r\n");
    assert_eq!(encoding, "utf8_lossy");
    assert!(preview.contains("example.com"));
}

#[test]
fn classifies_tls_application_data_records() {
    let mut record = vec![0x17, 0x03, 0x03, 0x00, 0x10];
    record.extend_from_slice(&[0u8; 16]);
    assert_eq!(classify_buffer(&record), "tls_record");
    assert_eq!(classify_buffer(b"GET /v1/ping HTTP/1.1\r\n"), "text");
}

#[test]
fn probe_spec_builds_plan_with_custom_buffer_arg() {
    use ksight_core::{CapturePhase, ProbeSpec, TlsAbiKind, TlsDirection};
    use std::path::Path;

    let probe = ProbeSpec {
        symbol: "vendor_ssl_copy".into(),
        file_offset: Some(0xabcd),
        direction: Some(TlsDirection::Send),
        abi: Some(TlsAbiKind::VendorCustom),
        capture_phase: Some(CapturePhase::Entry),
        buffer_arg: Some(2),
        requested_length_arg: Some(3),
        actual_length_source: Some("requested_arg".into()),
        connection_arg: Some(0),
        architecture: Some("arm64".into()),
        validation_state: "enabled".into(),
        ..ProbeSpec::default()
    };
    let policy = ksight_core::InspectPolicy {
        enabled: true,
        package: Some("com.example".into()),
        ..ksight_core::InspectPolicy::default()
    };
    let stub = crate::elf::ElfIdentity {
        path: "/tmp/libvendor.so".into(),
        build_id: Some("abcd".into()),
        bits: 64,
        symbols: Vec::new(),
    };
    let plan = inspect_plan_from_probe_spec(
        &policy,
        InspectAdapterKind::TlsSslWrite,
        Path::new("/nonexistent.bpf.o"),
        "/tmp/libvendor.so",
        &stub,
        "vendor_stack",
        &probe,
    )
    .expect("ProbeSpec with abi+offset must build a plan");
    assert_eq!(plan.offset, Some(0xabcd));
    assert_eq!(plan.abi, Some(TlsAbiKind::VendorCustom));
    assert_eq!(plan.layout_hint.buffer_arg, Some(2));
    assert_eq!(plan.layout_hint.requested_length_arg, Some(3));
    assert_eq!(plan.layout_hint.capture_phase, Some(CapturePhase::Entry));
    let layout = effective_layout(&plan);
    assert_eq!(layout.buffer_arg, 2);
    assert_eq!(layout.requested_len_arg, 3);
}

#[test]
fn pending_nested_write_entry_return_push_pop() {
    let key = ProbeCallKey {
        pid: 1,
        tid: 2,
        lib_token: 3,
        offset: 4,
        abi: 5,
    };
    let mut stacks = PendingCallStacks::default();
    stacks.push(
        key,
        PendingSslRead {
            pid: 1,
            buf: 0x1000,
            requested: 8,
            written_ptr: None,
            connection_id: Some(0x2000),
        },
    );
    stacks.push(
        key,
        PendingSslRead {
            pid: 1,
            buf: 0x3000,
            requested: 4,
            written_ptr: None,
            connection_id: Some(0x2000),
        },
    );
    let popped_inner = stacks.pop(key).expect("inner");
    assert_eq!(popped_inner.buf, 0x3000);
    assert_eq!(popped_inner.requested, 4);
    let popped_outer = stacks.pop(key).expect("outer");
    assert_eq!(popped_outer.buf, 0x1000);
    assert_eq!(popped_outer.requested, 8);
    assert!(stacks.pop(key).is_none());
}

#[test]
fn nonstandard_name_not_auto_openssl_ex() {
    assert_eq!(
        ksight_core::TlsAbiKind::from_exported_symbol("sslWriteEx"),
        ksight_core::TlsAbiKind::VendorCustom
    );
    assert!(!ksight_core::TlsAbiKind::from_exported_symbol("sslWriteEx").is_auto_attachable());
    assert_eq!(
        ksight_core::TlsAbiKind::from_exported_symbol("SSL_write_ex"),
        ksight_core::TlsAbiKind::OpensslExWrite
    );
}

#[test]
fn pending_stale_timeout_is_incomplete_not_success() {
    let key = ProbeCallKey {
        pid: 11,
        tid: 22,
        lib_token: 33,
        offset: 44,
        abi: 5,
    };
    let mut stacks = PendingCallStacks::default();
    stacks.push(
        key,
        PendingSslRead {
            pid: 11,
            buf: 0x4000,
            requested: 16,
            written_ptr: None,
            connection_id: Some(0x5000),
        },
    );
    assert_eq!(stacks.frames, 1);
    stacks.age_all(Duration::from_secs(10));
    assert_eq!(stacks.drop_stale(PENDING_STALE), 1);
    assert_eq!(stacks.incomplete, 1);
    assert!(stacks.pop(key).is_none(), "stale frame must not pop as success");
    stacks.push(
        key,
        PendingSslRead {
            pid: 11,
            buf: 0x4000,
            requested: 16,
            written_ptr: None,
            connection_id: Some(0x5000),
        },
    );
    assert_eq!(stacks.drop_tid(11, 22), 1);
    assert_eq!(stacks.incomplete, 2);
    stacks.push(
        key,
        PendingSslRead {
            pid: 11,
            buf: 0x4000,
            requested: 16,
            written_ptr: None,
            connection_id: Some(0x5000),
        },
    );
    assert_eq!(stacks.drop_all_incomplete(), 1);
    assert_eq!(stacks.incomplete, 3);
    assert_eq!(stacks.frames, 0);
}

#[test]
fn probespec_without_abi_refuses_vendor_custom_name() {
    use ksight_core::{ProbeSpec, TlsDirection};
    use std::path::Path;

    let probe = ProbeSpec {
        symbol: "sslWriteEx".into(),
        file_offset: Some(0x1000),
        direction: Some(TlsDirection::Send),
        abi: None,
        validation_state: "enabled".into(),
        ..ProbeSpec::default()
    };
    let policy = ksight_core::InspectPolicy {
        enabled: true,
        package: Some("com.example".into()),
        ..ksight_core::InspectPolicy::default()
    };
    let stub = crate::elf::ElfIdentity {
        path: "/tmp/libvendor.so".into(),
        build_id: Some("abcd".into()),
        bits: 64,
        symbols: Vec::new(),
    };
    assert!(
        inspect_plan_from_probe_spec(
            &policy,
            InspectAdapterKind::TlsSslWrite,
            Path::new("/nonexistent.bpf.o"),
            "/tmp/libvendor.so",
            &stub,
            "vendor_stack",
            &probe,
        )
        .is_none(),
        "sslWriteEx without ProbeSpec.abi must not auto-attach"
    );
}
