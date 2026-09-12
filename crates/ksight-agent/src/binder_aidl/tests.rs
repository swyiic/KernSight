
    use super::aidl_method;
    #[test]
    fn service_manager_matches_pixel_stub() {
        assert_eq!(aidl_method("android.os.IServiceManager", 1), Some("getService"));
        assert_eq!(aidl_method("android.os.IServiceManager", 2), Some("getService2"));
        assert_eq!(aidl_method("android.os.IServiceManager", 6), Some("listServices"));
        assert_eq!(aidl_method("android.content.pm.IPackageManager", 3), Some("getPackageInfo"));
        assert_eq!(aidl_method("android.net.IConnectivityManager", 3), Some("getActiveNetworkInfo"));
        assert_eq!(aidl_method("android.net.INetworkStatsService", 5), Some("getMobileIfaces"));
        assert_eq!(aidl_method("android.net.INetworkStatsService", 13), Some("getTotalStats"));
        assert_eq!(aidl_method("android.hardware.media.c2.IComponent", 7), Some("queue"));
        assert_eq!(
            aidl_method("android.hardware.graphics.allocator.IAllocator", 2),
            Some("allocate2")
        );
        assert_eq!(
            aidl_method("android.graphicsenv.IGpuService", 1),
            Some("setGpuStats")
        );
        assert_eq!(
            aidl_method("android.graphicsenv.IGpuService", 6),
            Some("setTargetStatsArray")
        );
        assert_eq!(
            aidl_method("android.graphicsenv.IGpuService", 7),
            Some("addVulkanEngineName")
        );
        assert_eq!(
            aidl_method("android.hardware.drm.IDrmFactory", 1),
            Some("createDrmPlugin")
        );
        assert_eq!(
            aidl_method("android.media.IMediaMetricsService", 1),
            Some("submitBuffer")
        );
        assert_eq!(aidl_method("android.media.IMediaCodecList", 1), None);
        assert_eq!(
            aidl_method("android.media.IMediaCodecList", 3),
            Some("getCodecInfo")
        );
        assert_eq!(
            aidl_method("android.media.IMediaCodecList", 6),
            Some("findCodecByName")
        );
        assert_eq!(aidl_method("android.content.IContentProvider", 1), Some("query"));
        assert_eq!(aidl_method("android.content.IContentProvider", 21), Some("call"));
        assert_eq!(aidl_method("android.database.IBulkCursor", 1), Some("getCursorWindow"));
        assert_eq!(aidl_method("android.ui.ISurfaceComposer", 8), Some("getSupportedFrameTimestamps"));
        assert_eq!(aidl_method("com.example.IBankSession", 1), None);
        assert_eq!(
            aidl_method("android.hardware.graphics.allocator.IAllocator", 0x00ff_ffff),
            Some("getInterfaceVersion")
        );
        assert_eq!(
            aidl_method("android.graphicsenv.IGpuService", 0x00ff_fffe),
            Some("getInterfaceHash")
        );
    }
    #[test]
    fn tables_are_sorted_for_binary_search() {
        let names: Vec<_> = super::TABLES.iter().map(|entry| entry.0).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }
