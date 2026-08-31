#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(clippy::unreadable_literal, clippy::too_many_lines)]
//! Pixel 6a Android 14 Binder `Stub.TRANSACTION_*` names from on-device framework JARs.
//! App and GMS AIDL are not included. Unknown `(interface, code)` stays unnamed.

/// Look up an AOSP AIDL method for `FIRST_CALL_TRANSACTION + n` codes.
pub fn aidl_method(interface: &str, code: u32) -> Option<&'static str> {
    if let Some(name) = ndk_meta_method(code) {
        return Some(name);
    }
    let names = extra_hal(interface).or_else(|| table(interface))?;
    let index = usize::try_from(code.checked_sub(1)?).ok()?;
    names.get(index).copied().filter(|name| !name.is_empty())
}

/// NDK AIDL `IBinder::LAST_CALL_TRANSACTION` / `- 1`. Same codes on every
/// HAL interface; not a per-app table.
fn ndk_meta_method(code: u32) -> Option<&'static str> {
    match code {
        0x00ff_fffe => Some("getInterfaceHash"),
        0x00ff_ffff => Some("getInterfaceVersion"),
        _ => None,
    }
}

/// NDK/HAL AIDL not present as Java `$Stub.TRANSACTION_*` on this image.
///
/// Tables come from Pixel 6a binaries: NDK `kTransactionNames` pointer
/// arrays, or `Bn*::onTransact` switch + Parcel shape. Methods are not
/// guessed from a mismatched AOSP tag.
fn extra_hal(interface: &str) -> Option<&'static [&'static str]> {
    match interface {
        "android.graphicsenv.IGpuService" => Some(&[
            "setGpuStats",
            "setTargetStats",
            "setUpdatableDriverPath",
            "getUpdatableDriverPath",
            "toggleAngleAsSystemDriver",
            "setTargetStatsArray",
            "addVulkanEngineName",
            "getAngleFeatureOverrides",
        ]),
        "android.hardware.drm.IDrmFactory" => Some(&[
            "createDrmPlugin",
            "createCryptoPlugin",
            "getSupportedCryptoSchemes",
        ]),
        "android.hardware.graphics.allocator.IAllocator" => Some(&[
            "allocate",
            "allocate2",
            "isSupported",
            "getIMapperLibrarySuffix",
        ]),
        "android.hardware.media.c2.IComponent" => Some(&[
            "configureVideoTunnel",
            "createBlockPool",
            "destroyBlockPool",
            "drain",
            "flush",
            "getInterface",
            "queue",
            "release",
            "reset",
            "setDecoderOutputAllocator",
            "start",
            "stop",
        ]),
        // Pixel 6a `BnMediaCodecList::onTransact`: code 1 is not a user
        // method (falls through); 2–6 match Parcel shape + vtable.
        "android.media.IMediaCodecList" => Some(&[
            "",
            "countCodecs",
            "getCodecInfo",
            "getGlobalSettings",
            "findCodecByType",
            "findCodecByName",
        ]),
        // Pixel 6a `mediametricsservice-aidl-cpp.so`: only `submitBuffer`.
        "android.media.IMediaMetricsService" => Some(&["submitBuffer"]),
        _ => None,
    }
}

fn table(interface: &str) -> Option<&'static [&'static str]> {
    let i = TABLES.binary_search_by_key(&interface, |entry| entry.0).ok()?;
    Some(TABLES[i].1)
}

const TABLES: &[(&str, &[&str])] = &[
    ("android.accessibilityservice.IAccessibilityServiceClient", &[
        "init", "onAccessibilityEvent", "onInterrupt", "onGesture",
        "clearAccessibilityCache", "onKeyEvent", "onMagnificationChanged", "onMotionEvent",
        "onTouchStateChanged", "onSoftKeyboardShowModeChanged", "onPerformGestureResult", "onFingerprintCapturingGesturesChanged",
        "onFingerprintGesture", "onAccessibilityButtonClicked", "onAccessibilityButtonAvailabilityChanged", "onSystemActionsChanged",
        "createImeSession", "setImeSessionEnabled", "bindInput", "unbindInput",
        "startInput",
    ]),
    ("android.accessibilityservice.IAccessibilityServiceConnection", &[
        "setServiceInfo", "setAttributionTag", "findAccessibilityNodeInfoByAccessibilityId", "findAccessibilityNodeInfosByText",
        "findAccessibilityNodeInfosByViewId", "findFocus", "focusSearch", "performAccessibilityAction",
        "getWindow", "getWindows", "getServiceInfo", "performGlobalAction",
        "getSystemActions", "disableSelf", "setOnKeyEventResult", "getMagnificationConfig",
        "getMagnificationScale", "getMagnificationCenterX", "getMagnificationCenterY", "getMagnificationRegion",
        "getCurrentMagnificationRegion", "resetMagnification", "resetCurrentMagnification", "setMagnificationConfig",
        "setMagnificationCallbackEnabled", "setSoftKeyboardShowMode", "getSoftKeyboardShowMode", "setSoftKeyboardCallbackEnabled",
        "switchToInputMethod", "setInputMethodEnabled", "isAccessibilityButtonAvailable", "sendGesture",
        "dispatchGesture", "isFingerprintGestureDetectionAvailable", "getOverlayWindowToken", "getWindowIdForLeashToken",
        "takeScreenshot", "takeScreenshotOfWindow", "setGestureDetectionPassthroughRegion", "setTouchExplorationPassthroughRegion",
        "setFocusAppearance", "setCacheEnabled", "logTrace", "setServiceDetectsGesturesEnabled",
        "requestTouchExploration", "requestDragging", "requestDelegating", "onDoubleTap",
        "onDoubleTapAndHold", "setAnimationScale", "setInstalledAndEnabledServices", "getInstalledAndEnabledServices",
        "attachAccessibilityOverlayToDisplay", "attachAccessibilityOverlayToWindow", "connectBluetoothBrailleDisplay", "connectUsbBrailleDisplay",
        "setTestBrailleDisplayData",
    ]),
    ("android.accessibilityservice.IBrailleDisplayConnection", &[
        "disconnect", "write",
    ]),
    ("android.accessibilityservice.IBrailleDisplayController", &[
        "onConnected", "onConnectionFailed", "onInput", "onDisconnected",
    ]),
    ("android.accounts.IAccountAuthenticator", &[
        "addAccount", "confirmCredentials", "getAuthToken", "getAuthTokenLabel",
        "updateCredentials", "editProperties", "hasFeatures", "getAccountRemovalAllowed",
        "getAccountCredentialsForCloning", "addAccountFromCredentials", "startAddAccountSession", "startUpdateCredentialsSession",
        "finishSession", "isCredentialsUpdateSuggested",
    ]),
    ("android.accounts.IAccountAuthenticatorResponse", &[
        "onResult", "onRequestContinued", "onError",
    ]),
    ("android.accounts.IAccountManager", &[
        "getPassword", "getUserData", "getAuthenticatorTypes", "getAccountsForPackage",
        "getAccountsByTypeForPackage", "getAccountsAsUser", "hasFeatures", "getAccountByTypeAndFeatures",
        "getAccountsByFeatures", "addAccountExplicitly", "removeAccountAsUser", "removeAccountExplicitly",
        "copyAccountToUser", "invalidateAuthToken", "peekAuthToken", "setAuthToken",
        "setPassword", "clearPassword", "setUserData", "updateAppPermission",
        "getAuthToken", "addAccount", "addAccountAsUser", "updateCredentials",
        "editProperties", "confirmCredentialsAsUser", "accountAuthenticated", "getAuthTokenLabel",
        "addSharedAccountsFromParentUser", "renameAccount", "getPreviousName", "startAddAccountSession",
        "startUpdateCredentialsSession", "finishSessionAsUser", "someUserHasAccount", "isCredentialsUpdateSuggested",
        "getPackagesAndVisibilityForAccount", "addAccountExplicitlyWithVisibility", "setAccountVisibility", "getAccountVisibility",
        "getAccountsAndVisibilityForPackage", "registerAccountListener", "unregisterAccountListener", "hasAccountAccess",
        "createRequestAccountAccessIntentSenderAsUser", "onAccountAccessed",
    ]),
    ("android.accounts.IAccountManagerResponse", &[
        "onResult", "onError",
    ]),
    ("android.apex.IApexService", &[
        "submitStagedSession", "markStagedSessionReady", "markStagedSessionSuccessful", "getSessions",
        "getStagedSessionInfo", "getStagedApexInfos", "getActivePackages", "getAllPackages",
        "abortStagedSession", "revertActiveSessions", "snapshotCeData", "restoreCeData",
        "destroyDeSnapshots", "destroyCeSnapshots", "destroyCeSnapshotsNotSpecified", "unstagePackages",
        "stagePackages", "resumeRevertIfNeeded", "recollectPreinstalledData", "markBootCompleted",
        "calculateSizeForCompressedApex", "reserveSpaceForCompressedApex", "installAndActivatePackage",
    ]),
    ("android.app.ActivityThread$H", &[
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "execute",
    ]),
    ("android.app.AppProtoEnums", &[
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "subreasonFreezerBinder",
    ]),
    ("android.app.ApplicationExitInfo", &[
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "subreasonFreezerBinder",
    ]),
    ("android.app.IActivityClientController", &[
        "activityIdle", "activityResumed", "activityRefreshed", "activityTopResumedStateLost",
        "activityPaused", "activityStopped", "activityDestroyed", "activityLocalRelaunch",
        "activityRelaunched", "reportSizeConfigurations", "moveActivityTaskToBack", "shouldUpRecreateTask",
        "navigateUpTo", "releaseActivityInstance", "finishActivity", "finishActivityAffinity",
        "finishSubActivity", "setForceSendResultForMediaProjection", "isTopOfTask", "willActivityBeVisible",
        "getDisplayId", "getTaskForActivity", "getTaskConfiguration", "getActivityTokenBelow",
        "getCallingActivity", "getCallingPackage", "getLaunchedFromUid", "getActivityCallerUid",
        "getLaunchedFromPackage", "getActivityCallerPackage", "checkActivityCallerContentUriPermission", "setRequestedOrientation",
        "getRequestedOrientation", "convertFromTranslucent", "convertToTranslucent", "isImmersive",
        "setImmersive", "enterPictureInPictureMode", "setPictureInPictureParams", "setShouldDockBigOverlays",
        "toggleFreeformWindowingMode", "requestMultiwindowFullscreen", "startLockTaskModeByToken", "stopLockTaskModeByToken",
        "showLockTaskEscapeMessage", "setTaskDescription", "showAssistFromActivity", "isRootVoiceInteraction",
        "startLocalVoiceInteraction", "stopLocalVoiceInteraction", "setShowWhenLocked", "setInheritShowWhenLocked",
        "setTurnScreenOn", "setAllowCrossUidActivitySwitchFromBelow", "reportActivityFullyDrawn", "overrideActivityTransition",
        "clearOverrideActivityTransition", "overridePendingTransition", "setVrMode", "setRecentsScreenshotEnabled",
        "invalidateHomeTaskSnapshot", "dismissKeyguard", "registerRemoteAnimations", "unregisterRemoteAnimations",
        "onBackPressed", "splashScreenAttached", "enableTaskLocaleOverride", "isRequestedToLaunchInTaskFragment",
        "setActivityRecordInputSinkEnabled",
    ]),
    ("android.app.IActivityController", &[
        "activityStarting", "activityResuming", "appCrashed", "appEarlyNotResponding",
        "appNotResponding", "systemNotResponding",
    ]),
    ("android.app.IActivityManager", &[
        "openContentUri", "registerUidObserver", "unregisterUidObserver", "registerUidObserverForUids",
        "addUidToObserver", "removeUidFromObserver", "isUidActive", "getUidProcessState",
        "checkPermission", "logFgsApiBegin", "logFgsApiEnd", "logFgsApiStateChanged",
        "handleApplicationCrash", "startActivity", "startActivityWithFeature", "unhandledBack",
        "finishActivity", "registerReceiver", "registerReceiverWithFeature", "unregisterReceiver",
        "getRegisteredIntentFilters", "broadcastIntent", "broadcastIntentWithFeature", "unbroadcastIntent",
        "finishReceiver", "attachApplication", "finishAttachApplication", "getTasks",
        "moveTaskToFront", "getTaskForActivity", "getContentProvider", "publishContentProviders",
        "refContentProvider", "getRunningServiceControlPanel", "startService", "stopService",
        "bindService", "bindServiceInstance", "updateServiceGroup", "unbindService",
        "publishService", "setDebugApp", "setAgentApp", "setAlwaysFinish",
        "startInstrumentation", "addInstrumentationResults", "finishInstrumentation", "getConfiguration",
        "updateConfiguration", "updateMccMncConfiguration", "stopServiceToken", "setProcessLimit",
        "getProcessLimit", "checkUriPermission", "checkContentUriPermissionFull", "checkUriPermissions",
        "grantUriPermission", "revokeUriPermission", "setActivityController", "showWaitingForDebugger",
        "signalPersistentProcesses", "getRecentTasks", "serviceDoneExecuting", "getIntentSender",
        "getIntentSenderWithFeature", "cancelIntentSender", "getInfoForIntentSender", "registerIntentSenderCancelListenerEx",
        "unregisterIntentSenderCancelListener", "enterSafeMode", "noteWakeupAlarm", "removeContentProvider",
        "setRequestedOrientation", "unbindFinished", "setProcessImportant", "setServiceForeground",
        "getForegroundServiceType", "moveActivityTaskToBack", "getMemoryInfo", "getProcessesInErrorState",
        "clearApplicationUserData", "stopAppForUser", "registerForegroundServiceObserver", "forceStopPackage",
        "forceStopPackageEvenWhenStopping", "killPids", "getServices", "getRunningAppProcesses",
        "peekService", "profileControl", "shutdown", "stopAppSwitches",
        "resumeAppSwitches", "bindBackupAgent", "backupAgentCreated", "unbindBackupAgent",
        "handleIncomingUser", "addPackageDependency", "killApplication", "closeSystemDialogs",
        "getProcessMemoryInfo", "killApplicationProcess", "handleApplicationWtf", "killBackgroundProcesses",
        "isUserAMonkey", "getRunningExternalApplications", "finishHeavyWeightApp", "handleApplicationStrictModeViolation",
        "registerStrictModeCallback", "isTopActivityImmersive", "crashApplicationWithType", "crashApplicationWithTypeWithExtras",
        "getMimeTypeFilterAsync", "dumpHeap", "isUserRunning", "setPackageScreenCompatMode",
        "switchUser", "getSwitchingFromUserMessage", "getSwitchingToUserMessage", "setStopUserOnSwitch",
        "removeTask", "registerProcessObserver", "unregisterProcessObserver", "isIntentSenderTargetedToPackage",
        "updatePersistentConfiguration", "updatePersistentConfigurationWithAttribution", "getProcessPss", "showBootMessage",
        "killAllBackgroundProcesses", "getContentProviderExternal", "removeContentProviderExternal", "removeContentProviderExternalAsUser",
        "getMyMemoryState", "killProcessesBelowForeground", "getCurrentUser", "getCurrentUserId",
        "getLaunchedFromUid", "unstableProviderDied", "isIntentSenderAnActivity", "startActivityAsUser",
        "startActivityAsUserWithFeature", "stopUser", "stopUserWithCallback", "stopUserExceptCertainProfiles",
        "stopUserWithDelayedLocking", "registerUserSwitchObserver", "unregisterUserSwitchObserver", "getRunningUserIds",
        "requestSystemServerHeapDump", "requestBugReport", "requestBugReportWithDescription", "requestTelephonyBugReport",
        "requestWifiBugReport", "requestInteractiveBugReportWithDescription", "requestInteractiveBugReport", "requestBugReportWithExtraAttachments",
        "requestFullBugReport", "requestRemoteBugReport", "launchBugReportHandlerApp", "getBugreportWhitelistedPackages",
        "getIntentForIntentSender", "getLaunchedFromPackage", "killUid", "setUserIsMonkey",
        "hang", "getAllRootTaskInfos", "moveTaskToRootTask", "setFocusedRootTask",
        "getFocusedRootTaskInfo", "restart", "performIdleMaintenance", "appNotRespondingViaProvider",
        "getTaskBounds", "setProcessMemoryTrimLevel", "getTagForIntentSender", "startUserInBackground",
        "isInLockTaskMode", "startActivityFromRecents", "startSystemLockTaskMode", "isTopOfTask",
        "bootAnimationComplete", "setThemeOverlayReady", "registerTaskStackListener", "unregisterTaskStackListener",
        "notifyCleartextNetwork", "setTaskResizeable", "resizeTask", "getLockTaskModeState",
        "setDumpHeapDebugLimit", "dumpHeapFinished", "updateLockTaskPackages", "noteAlarmStart",
        "noteAlarmFinish", "getPackageProcessState", "startBinderTracking", "stopBinderTrackingAndDump",
        "suppressResizeConfigChanges", "unlockUser", "unlockUser2", "killPackageDependents",
        "makePackageIdle", "setDeterministicUidIdle", "getMemoryTrimLevel", "isVrModePackageEnabled",
        "notifyLockedProfile", "startConfirmDeviceCredentialIntent", "sendIdleJobTrigger", "sendIntentSender",
        "isBackgroundRestricted", "setRenderThread", "setHasTopUi", "cancelTaskWindowTransition",
        "scheduleApplicationInfoChanged", "setPersistentVrThread", "waitForNetworkStateUpdate", "backgroundAllowlistUid",
        "startUserInBackgroundWithListener", "startDelegateShellPermissionIdentity", "stopDelegateShellPermissionIdentity", "getDelegatedShellPermissions",
        "getLifeMonitor", "startUserInForegroundWithListener", "appNotResponding", "getHistoricalProcessStartReasons",
        "addApplicationStartInfoCompleteListener", "removeApplicationStartInfoCompleteListener", "addStartInfoTimestamp", "reportStartInfoViewTimestamps",
        "getHistoricalProcessExitReasons", "killProcessesWhenImperceptible", "setActivityLocusContext", "setProcessStateSummary",
        "isAppFreezerSupported", "isAppFreezerEnabled", "killUidForPermissionChange", "resetAppErrors",
        "enableAppFreezer", "enableFgsNotificationRateLimit", "holdLock", "startProfile",
        "stopProfile", "queryIntentComponentsForIntentSender", "getUidProcessCapabilities", "waitForBroadcastIdle",
        "waitForBroadcastBarrier", "forceDelayBroadcastDelivery", "isProcessFrozen", "getBackgroundRestrictionExemptionReason",
        "startUserInBackgroundVisibleOnDisplay", "startProfileWithListener", "restartUserInBackground", "getDisplayIdsForStartingVisibleBackgroundUsers",
        "shouldServiceTimeOut", "hasServiceTimeLimitExceeded", "registerUidFrozenStateChangedCallback", "unregisterUidFrozenStateChangedCallback",
        "getUidFrozenState", "checkPermissionForDevice", "frozenBinderTransactionDetected", "getBindingUidProcessState",
        "getUidLastIdleElapsedTime", "addOverridePermissionState", "removeOverridePermissionState", "clearOverridePermissionStates",
        "clearAllOverridePermissionStates", "noteAppRestrictionEnabled", "refreshIntentCreatorToken",
    ]),
    ("android.app.IActivityPendingResult", &[
        "sendResult",
    ]),
    ("android.app.IActivityTaskManager", &[
        "startActivity", "startActivities", "startActivityAsUser", "startNextMatchingActivity",
        "startActivityIntentSender", "startActivityAndWait", "startActivityWithConfig", "startVoiceActivity",
        "getVoiceInteractorPackageName", "startAssistantActivity", "startActivityFromGameSession", "startActivityFromRecents",
        "startActivityAsCaller", "preloadRecentsActivity", "isActivityStartAllowedOnDisplay", "unhandledBack",
        "getActivityClientController", "getFrontActivityScreenCompatMode", "setFrontActivityScreenCompatMode", "setFocusedTask",
        "setTaskIsPerceptible", "removeTask", "removeAllVisibleRecentTasks", "getTasks",
        "moveTaskToFront", "getRecentTasks", "isTopActivityImmersive", "reportAssistContextExtras",
        "canBeUniversalResizeable", "setFocusedRootTask", "getFocusedRootTaskInfo", "getTaskBounds",
        "focusTopTask", "updateLockTaskPackages", "isInLockTaskMode", "getLockTaskModeState",
        "getAppTasks", "startSystemLockTaskMode", "stopSystemLockTaskMode", "finishVoiceTask",
        "addAppTask", "getAppTaskThumbnailSize", "releaseSomeActivities", "getTaskDescriptionIcon",
        "registerTaskStackListener", "unregisterTaskStackListener", "setTaskResizeable", "resizeTask",
        "moveRootTaskToDisplay", "moveTaskToRootTask", "removeRootTasksInWindowingModes", "removeRootTasksWithActivityTypes",
        "getAllRootTaskInfos", "getRootTaskInfo", "getAllRootTaskInfosOnDisplay", "getRootTaskInfoOnDisplay",
        "setLockScreenShown", "getAssistContextExtras", "requestAssistContextExtras", "requestAutofillData",
        "isAssistDataAllowed", "requestAssistDataForTask", "keyguardGoingAway", "suppressResizeConfigChanges",
        "getWindowOrganizerController", "supportsLocalVoiceInteraction", "requestOpenInBrowserEducation", "getDeviceConfigurationInfo",
        "cancelTaskWindowTransition", "getTaskSnapshot", "takeTaskSnapshot", "getLastResumedActivityUserId",
        "updateConfiguration", "updateLockTaskFeatures", "registerRemoteAnimationForNextActivityStart", "registerRemoteAnimationsForDisplay",
        "alwaysShowUnsupportedCompileSdkWarning", "setVrThread", "setPersistentVrThread", "stopAppSwitches",
        "resumeAppSwitches", "setActivityController", "setVoiceKeepAwake", "getPackageScreenCompatMode",
        "setPackageScreenCompatMode", "getPackageAskScreenCompat", "setPackageAskScreenCompat", "clearLaunchParamsForPackages",
        "onSplashScreenViewCopyFinished", "onPictureInPictureUiStateChanged", "detachNavigationBarFromApp", "setRunningRemoteTransitionDelegate",
        "startBackNavigation", "registerBackGestureDelegate", "registerBackgroundActivityStartCallback", "unregisterBackgroundActivityStartCallback",
        "registerScreenCaptureObserver", "unregisterScreenCaptureObserver",
    ]),
    ("android.app.IAlarmCompleteListener", &[
        "alarmComplete",
    ]),
    ("android.app.IAlarmListener", &[
        "doAlarm",
    ]),
    ("android.app.IAlarmManager", &[
        "set", "setTime", "setTimeZone", "remove",
        "removeAll", "getNextWakeFromIdleTime", "getNextAlarmClock", "canScheduleExactAlarms",
        "hasScheduleExactAlarm", "getConfigVersion",
    ]),
    ("android.app.IAppTask", &[
        "finishAndRemoveTask", "getTaskInfo", "moveToFront", "startActivity",
        "setExcludeFromRecents",
    ]),
    ("android.app.IAppTraceRetriever", &[
        "getTraceFileDescriptor",
    ]),
    ("android.app.IApplicationStartInfoCompleteListener", &[
        "onApplicationStartInfoComplete",
    ]),
    ("android.app.IApplicationThread", &[
        "scheduleReceiver", "scheduleReceiverList", "scheduleCreateService", "scheduleStopService",
        "bindApplication", "runIsolatedEntryPoint", "scheduleExit", "scheduleServiceArgs",
        "updateTimeZone", "processInBackground", "scheduleBindService", "scheduleUnbindService",
        "dumpService", "scheduleRegisteredReceiver", "scheduleLowMemory", "profilerControl",
        "setSchedulingGroup", "scheduleCreateBackupAgent", "scheduleDestroyBackupAgent", "scheduleOnNewSceneTransitionInfo",
        "scheduleSuicide", "dispatchPackageBroadcast", "scheduleCrash", "dumpHeap",
        "dumpActivity", "dumpResources", "clearDnsCache", "updateHttpProxy",
        "setCoreSettings", "updatePackageCompatibilityInfo", "scheduleTrimMemory", "dumpMemInfo",
        "dumpMemInfoProto", "dumpGfxInfo", "dumpCacheInfo", "dumpProvider",
        "dumpDbInfo", "unstableProviderDied", "requestAssistContextExtras", "scheduleTranslucentConversionComplete",
        "setProcessState", "scheduleInstallProvider", "updateTimePrefs", "scheduleEnterAnimationComplete",
        "notifyCleartextNetwork", "startBinderTracking", "stopBinderTrackingAndDump", "scheduleLocalVoiceInteractionStarted",
        "handleTrustStorageUpdate", "attachAgent", "attachStartupAgents", "scheduleApplicationInfoChanged",
        "setNetworkBlockSeq", "scheduleTransaction", "scheduleTaskFragmentTransaction", "requestDirectActions",
        "performDirectAction", "notifyContentProviderPublishStatus", "instrumentWithoutRestart", "updateUiTranslationState",
        "scheduleTimeoutService", "scheduleTimeoutServiceForType", "schedulePing", "getExecutableMethodFileOffsets",
    ]),
    ("android.app.IAssistDataReceiver", &[
        "onHandleAssistData", "onHandleAssistScreenshot",
    ]),
    ("android.app.IBackgroundActivityLaunchCallback", &[
        "onBackgroundActivityLaunchAborted",
    ]),
    ("android.app.IBackupAgent", &[
        "doBackup", "doRestore", "doRestoreWithExcludedKeys", "doFullBackup",
        "doMeasureFullBackup", "doQuotaExceeded", "doRestoreFile", "doRestoreFinished",
        "fail", "getLoggerResults", "getOperationType", "clearBackupRestoreEventLogger",
    ]),
    ("android.app.ICallNotificationEventCallback", &[
        "onCallNotificationPosted", "onCallNotificationRemoved",
    ]),
    ("android.app.IEphemeralResolver", &[
        "getEphemeralResolveInfoList", "getEphemeralIntentFilterList",
    ]),
    ("android.app.IForegroundServiceObserver", &[
        "onForegroundStateChanged",
    ]),
    ("android.app.IGameManager", &[
        "getGameMode",
    ]),
    ("android.app.IGameManagerService", &[
        "getGameMode", "setGameMode", "getAvailableGameModes", "isAngleEnabled",
        "notifyGraphicsEnvironmentSetup", "setGameState", "getGameModeInfo", "setGameServiceProvider",
        "updateResolutionScalingFactor", "getResolutionScalingFactor", "updateCustomGameModeConfiguration", "addGameModeListener",
        "removeGameModeListener", "addGameStateListener", "removeGameStateListener", "toggleGameDefaultFrameRate",
    ]),
    ("android.app.IGameModeListener", &[
        "onGameModeChanged",
    ]),
    ("android.app.IGameStateListener", &[
        "onGameStateChanged",
    ]),
    ("android.app.IGrammaticalInflectionManager", &[
        "setRequestedApplicationGrammaticalGender", "setSystemWideGrammaticalGender", "getSystemGrammaticalGender", "peekSystemGrammaticalGenderByUserId",
    ]),
    ("android.app.IInstantAppResolver", &[
        "getInstantAppResolveInfoList", "getInstantAppIntentFilterList",
    ]),
    ("android.app.IInstrumentationWatcher", &[
        "instrumentationStatus", "instrumentationFinished",
    ]),
    ("android.app.ILocalWallpaperColorConsumer", &[
        "onColorsChanged",
    ]),
    ("android.app.ILocaleManager", &[
        "setApplicationLocales", "getApplicationLocales", "getSystemLocales", "setOverrideLocaleConfig",
        "getOverrideLocaleConfig",
    ]),
    ("android.app.INotificationManager", &[
        "cancelAllNotifications", "clearData", "enqueueTextToast", "enqueueToast",
        "cancelToast", "finishToken", "enqueueNotificationWithTag", "cancelNotificationWithTag",
        "isInCall", "setShowBadge", "canShowBadge", "hasSentValidMsg",
        "isInInvalidMsgState", "hasUserDemotedInvalidMsgApp", "setInvalidMsgAppDemoted", "hasSentValidBubble",
        "setNotificationsEnabledForPackage", "setNotificationsEnabledWithImportanceLockForPackage", "areNotificationsEnabledForPackage", "areNotificationsEnabled",
        "getPackageImportance", "isImportanceLocked", "getAllowedAssistantAdjustments", "allowAssistantAdjustment",
        "disallowAssistantAdjustment", "shouldHideSilentStatusIcons", "setHideSilentStatusIcons", "setBubblesAllowed",
        "areBubblesAllowed", "areBubblesEnabled", "getBubblePreferenceForPackage", "createNotificationChannelGroups",
        "createNotificationChannels", "createNotificationChannelsForPackage", "getConversations", "getConversationsForPackage",
        "getNotificationChannelGroupsForPackage", "getNotificationChannelGroupForPackage", "getPopulatedNotificationChannelGroupForPackage", "getRecentBlockedNotificationChannelGroupsForPackage",
        "updateNotificationChannelGroupForPackage", "updateNotificationChannelForPackage", "unlockNotificationChannel", "unlockAllNotificationChannels",
        "getNotificationChannel", "getConversationNotificationChannel", "createConversationNotificationChannelForPackage", "getNotificationChannelForPackage",
        "deleteNotificationChannel", "getNotificationChannels", "getNotificationChannelsForPackage", "getNumNotificationChannelsForPackage",
        "getDeletedChannelCount", "getBlockedChannelCount", "deleteNotificationChannelGroup", "getNotificationChannelGroup",
        "getNotificationChannelGroups", "getNotificationChannelGroupsWithoutChannels", "onlyHasDefaultChannel", "areChannelsBypassingDnd",
        "getNotificationChannelsBypassingDnd", "getPackagesBypassingDnd", "getPackagesWithAnyChannels", "isPackagePaused",
        "deleteNotificationHistoryItem", "isPermissionFixed", "silenceNotificationSound", "getActiveNotifications",
        "getActiveNotificationsWithAttribution", "getHistoricalNotifications", "getHistoricalNotificationsWithAttribution", "getNotificationHistory",
        "registerListener", "unregisterListener", "cancelNotificationFromListener", "cancelNotificationsFromListener",
        "snoozeNotificationUntilContextFromListener", "snoozeNotificationUntilFromListener", "requestBindListener", "requestUnbindListener",
        "requestUnbindListenerComponent", "requestBindProvider", "requestUnbindProvider", "setNotificationsShownFromListener",
        "getActiveNotificationsFromListener", "getSnoozedNotificationsFromListener", "clearRequestedListenerHints", "requestHintsFromListener",
        "getHintsFromListener", "getHintsFromListenerNoToken", "requestInterruptionFilterFromListener", "getInterruptionFilterFromListener",
        "setOnNotificationPostedTrimFromListener", "setInterruptionFilter", "createConversationNotificationChannelForPackageFromPrivilegedListener", "updateNotificationChannelGroupFromPrivilegedListener",
        "updateNotificationChannelFromPrivilegedListener", "getNotificationChannelsFromPrivilegedListener", "getNotificationChannelGroupsFromPrivilegedListener", "applyEnqueuedAdjustmentFromAssistant",
        "applyAdjustmentFromAssistant", "applyAdjustmentsFromAssistant", "unsnoozeNotificationFromAssistant", "unsnoozeNotificationFromSystemListener",
        "getEffectsSuppressor", "matchesCallFilter", "cleanUpCallersAfter", "isSystemConditionProviderEnabled",
        "isNotificationListenerAccessGranted", "isNotificationListenerAccessGrantedForUser", "isNotificationAssistantAccessGranted", "setNotificationListenerAccessGranted",
        "setNotificationAssistantAccessGranted", "setNotificationListenerAccessGrantedForUser", "setNotificationAssistantAccessGrantedForUser", "getEnabledNotificationListenerPackages",
        "getEnabledNotificationListeners", "getAllowedNotificationAssistantForUser", "getAllowedNotificationAssistant", "getDefaultNotificationAssistant",
        "setNASMigrationDoneAndResetDefault", "hasEnabledNotificationListener", "getZenMode", "getZenModeConfig",
        "getConsolidatedNotificationPolicy", "setZenMode", "notifyConditions", "isNotificationPolicyAccessGranted",
        "getNotificationPolicy", "setNotificationPolicy", "isNotificationPolicyAccessGrantedForPackage", "setNotificationPolicyAccessGranted",
        "setNotificationPolicyAccessGrantedForUser", "getDefaultZenPolicy", "getAutomaticZenRule", "getAutomaticZenRules",
        "addAutomaticZenRule", "updateAutomaticZenRule", "removeAutomaticZenRule", "removeAutomaticZenRules",
        "getRuleInstanceCount", "getAutomaticZenRuleState", "setAutomaticZenRuleState", "setManualZenRuleDeviceEffects",
        "getBackupPayload", "applyRestore", "getAppActiveNotifications", "setNotificationDelegate",
        "getNotificationDelegate", "canNotifyAsPackage", "canUseFullScreenIntent", "setPrivateNotificationsAllowed",
        "getPrivateNotificationsAllowed", "pullStats", "getListenerFilter", "setListenerFilter",
        "migrateNotificationFilter", "setToastRateLimitingEnabled", "registerCallNotificationEventListener", "unregisterCallNotificationEventListener",
        "setCanBePromoted", "appCanBePromoted", "canBePromoted", "setAdjustmentTypeSupportedState",
        "getUnsupportedAdjustmentTypes", "getAllowedAdjustmentKeyTypes", "setAssistantAdjustmentKeyTypeState", "getAdjustmentDeniedPackages",
        "isAdjustmentSupportedForPackage", "setAdjustmentSupportedForPackage", "incrementCounter",
    ]),
    ("android.app.IOnProjectionStateChangedListener", &[
        "onProjectionStateChanged",
    ]),
    ("android.app.IParcelFileDescriptorRetriever", &[
        "getPfd",
    ]),
    ("android.app.IProcessObserver", &[
        "onProcessStarted", "onForegroundActivitiesChanged", "onForegroundServicesChanged", "onProcessDied",
    ]),
    ("android.app.IRequestFinishCallback", &[
        "requestFinish",
    ]),
    ("android.app.IScreenCaptureObserver", &[
        "onScreenCaptured",
    ]),
    ("android.app.ISearchManager", &[
        "getSearchableInfo", "getSearchablesInGlobalSearch", "getGlobalSearchActivities", "getGlobalSearchActivity",
        "getWebSearchActivity", "launchAssist",
    ]),
    ("android.app.ISearchManagerCallback", &[
        "onDismiss", "onCancel",
    ]),
    ("android.app.IServiceConnection", &[
        "connected",
    ]),
    ("android.app.IStopUserCallback", &[
        "userStopped", "userStopAborted",
    ]),
    ("android.app.ITaskStackListener", &[
        "onTaskStackChanged", "onActivityPinned", "onActivityUnpinned", "onActivityRestartAttempt",
        "onActivityForcedResizable", "onActivityDismissingDockedTask", "onActivityLaunchOnSecondaryDisplayFailed", "onActivityLaunchOnSecondaryDisplayRerouted",
        "onTaskCreated", "onTaskRemoved", "onTaskMovedToFront", "onTaskDescriptionChanged",
        "onActivityRequestedOrientationChanged", "onTaskRemovalStarted", "onTaskProfileLocked", "onTaskSnapshotChanged",
        "onTaskSnapshotInvalidated", "onBackPressedOnTaskRoot", "onTaskDisplayChanged", "onRecentTaskListUpdated",
        "onRecentTaskListFrozenChanged", "onRecentTaskRemovedForAddTask", "onTaskFocusChanged", "onTaskRequestedOrientationChanged",
        "onActivityRotation", "onTaskMovedToBack", "onLockTaskModeChanged",
    ]),
    ("android.app.ITransientNotification", &[
        "show", "hide",
    ]),
    ("android.app.ITransientNotificationCallback", &[
        "onToastShown", "onToastHidden",
    ]),
    ("android.app.IUiAutomationConnection", &[
        "connect", "disconnect", "injectInputEvent", "injectInputEventToInputFilter",
        "syncInputTransactions", "setRotation", "takeScreenshot", "takeSurfaceControlScreenshot",
        "clearWindowContentFrameStats", "getWindowContentFrameStats", "clearWindowAnimationFrameStats", "getWindowAnimationFrameStats",
        "executeShellCommand", "grantRuntimePermission", "revokeRuntimePermission", "adoptShellPermissionIdentity",
        "dropShellPermissionIdentity", "shutdown", "executeShellCommandWithStderr", "executeShellCommandArrayWithStderr",
        "getAdoptedShellPermissions", "addOverridePermissionState", "removeOverridePermissionState", "clearOverridePermissionStates",
        "clearAllOverridePermissionStates",
    ]),
    ("android.app.IUiModeManager", &[
        "addCallback", "enableCarMode", "disableCarMode", "disableCarModeByCallingPackage",
        "getCurrentModeType", "setNightMode", "getNightMode", "setNightModeCustomType",
        "getNightModeCustomType", "setAttentionModeThemeOverlay", "getAttentionModeThemeOverlay", "setApplicationNightMode",
        "isUiModeLocked", "isNightModeLocked", "setNightModeActivatedForCustomMode", "setNightModeActivated",
        "getCustomNightModeStart", "setCustomNightModeStart", "getCustomNightModeEnd", "setCustomNightModeEnd",
        "requestProjection", "releaseProjection", "addOnProjectionStateChangedListener", "removeOnProjectionStateChangedListener",
        "getProjectingPackages", "getActiveProjectionTypes", "getContrast", "getForceInvertState",
    ]),
    ("android.app.IUiModeManagerCallback", &[
        "notifyContrastChanged", "notifyForceInvertStateChanged",
    ]),
    ("android.app.IUidFrozenStateChangedCallback", &[
        "onUidFrozenStateChanged",
    ]),
    ("android.app.IUidObserver", &[
        "onUidGone", "onUidActive", "onUidIdle", "onUidStateChanged",
        "onUidProcAdjChanged", "onUidCachedChanged",
    ]),
    ("android.app.IUnsafeIntentStrictModeCallback", &[
        "onUnsafeIntent",
    ]),
    ("android.app.IUriGrantsManager", &[
        "takePersistableUriPermission", "releasePersistableUriPermission", "grantUriPermissionFromOwner", "getGrantedUriPermissions",
        "clearGrantedUriPermissions", "getUriPermissions", "checkGrantUriPermission_ignoreNonSystem",
    ]),
    ("android.app.IUserSwitchObserver", &[
        "onBeforeUserSwitching", "onUserSwitching", "onUserSwitchComplete", "onForegroundProfileSwitch",
        "onLockedBootComplete",
    ]),
    ("android.app.IWallpaperManager", &[
        "setWallpaper", "setWallpaperComponentChecked", "setWallpaperComponent", "getWallpaper",
        "getWallpaperWithFeature", "getBitmapCrops", "getCurrentBitmapCrops", "getFutureBitmapCrops",
        "getBitmapCrop", "getWallpaperIdForUser", "getWallpaperInfo", "getWallpaperInfoWithFlags",
        "getWallpaperInstance", "getWallpaperInfoFile", "clearWallpaper", "hasNamedWallpaper",
        "setDimensionHints", "getWidthHint", "getHeightHint", "setDisplayPadding",
        "getName", "settingsRestored", "isWallpaperSupported", "isSetWallpaperAllowed",
        "isWallpaperBackupEligible", "getWallpaperColors", "removeOnLocalColorsChangedListener", "addOnLocalColorsChangedListener",
        "registerWallpaperColorsCallback", "unregisterWallpaperColorsCallback", "setInAmbientMode", "notifyWakingUp",
        "notifyGoingToSleep", "setWallpaperDimAmount", "getWallpaperDimAmount", "lockScreenWallpaperExists",
        "isStaticWallpaper",
    ]),
    ("android.app.IWallpaperManagerCallback", &[
        "onWallpaperChanged", "onWallpaperColorsChanged",
    ]),
    ("android.app.admin.IAuditLogEventsCallback", &[
        "onNewAuditLogEvents",
    ]),
    ("android.app.admin.IDevicePolicyManager", &[
        "setPasswordQuality", "getPasswordQuality", "setPasswordMinimumLength", "getPasswordMinimumLength",
        "setPasswordMinimumUpperCase", "getPasswordMinimumUpperCase", "setPasswordMinimumLowerCase", "getPasswordMinimumLowerCase",
        "setPasswordMinimumLetters", "getPasswordMinimumLetters", "setPasswordMinimumNumeric", "getPasswordMinimumNumeric",
        "setPasswordMinimumSymbols", "getPasswordMinimumSymbols", "setPasswordMinimumNonLetter", "getPasswordMinimumNonLetter",
        "getPasswordMinimumMetrics", "setPasswordHistoryLength", "getPasswordHistoryLength", "setPasswordExpirationTimeout",
        "getPasswordExpirationTimeout", "getPasswordExpiration", "isActivePasswordSufficient", "isActivePasswordSufficientForDeviceRequirement",
        "isPasswordSufficientAfterProfileUnification", "getPasswordComplexity", "setRequiredPasswordComplexity", "getRequiredPasswordComplexity",
        "getAggregatedPasswordComplexityForUser", "isUsingUnifiedPassword", "getCurrentFailedPasswordAttempts", "getProfileWithMinimumFailedPasswordsForWipe",
        "setMaximumFailedPasswordsForWipe", "getMaximumFailedPasswordsForWipe", "resetPassword", "setMaximumTimeToLock",
        "getMaximumTimeToLock", "setRequiredStrongAuthTimeout", "getRequiredStrongAuthTimeout", "lockNow",
        "wipeDataWithReason", "setFactoryResetProtectionPolicy", "getFactoryResetProtectionPolicy", "isFactoryResetProtectionPolicySupported",
        "sendLostModeLocationUpdate", "setGlobalProxy", "getGlobalProxyAdmin", "setRecommendedGlobalProxy",
        "setStorageEncryption", "getStorageEncryption", "getStorageEncryptionStatus", "requestBugreport",
        "setCameraDisabled", "getCameraDisabled", "setScreenCaptureDisabled", "getScreenCaptureDisabled",
        "setNearbyNotificationStreamingPolicy", "getNearbyNotificationStreamingPolicy", "setNearbyAppStreamingPolicy", "getNearbyAppStreamingPolicy",
        "setKeyguardDisabledFeatures", "getKeyguardDisabledFeatures", "setActiveAdmin", "isAdminActive",
        "getActiveAdmins", "packageHasActiveAdmins", "getRemoveWarning", "removeActiveAdmin",
        "forceRemoveActiveAdmin", "hasGrantedPolicy", "reportPasswordChanged", "reportFailedPasswordAttempt",
        "reportSuccessfulPasswordAttempt", "reportFailedBiometricAttempt", "reportSuccessfulBiometricAttempt", "reportKeyguardDismissed",
        "reportKeyguardSecured", "setDeviceOwner", "getDeviceOwnerComponent", "getDeviceOwnerComponentOnUser",
        "hasDeviceOwner", "getDeviceOwnerName", "clearDeviceOwner", "getDeviceOwnerUserId",
        "setProfileOwner", "getProfileOwnerAsUser", "getProfileOwnerOrDeviceOwnerSupervisionComponent", "isSupervisionComponent",
        "getProfileOwnerName", "setProfileEnabled", "setProfileName", "clearProfileOwner",
        "hasUserSetupCompleted", "isOrganizationOwnedDeviceWithManagedProfile", "checkDeviceIdentifierAccess", "setDeviceOwnerLockScreenInfo",
        "getDeviceOwnerLockScreenInfo", "setPackagesSuspended", "isPackageSuspended", "listPolicyExemptApps",
        "installCaCert", "uninstallCaCerts", "enforceCanManageCaCerts", "approveCaCert",
        "isCaCertApproved", "installKeyPair", "removeKeyPair", "hasKeyPair",
        "generateKeyPair", "setKeyPairCertificate", "choosePrivateKeyAlias", "setDelegatedScopes",
        "getDelegatedScopes", "getDelegatePackages", "setCertInstallerPackage", "getCertInstallerPackage",
        "setAlwaysOnVpnPackage", "getAlwaysOnVpnPackage", "getAlwaysOnVpnPackageForUser", "isAlwaysOnVpnLockdownEnabled",
        "isAlwaysOnVpnLockdownEnabledForUser", "getAlwaysOnVpnLockdownAllowlist", "addPersistentPreferredActivity", "clearPackagePersistentPreferredActivities",
        "setDefaultSmsApplication", "setDefaultDialerApplication", "setApplicationRestrictions", "getApplicationRestrictions",
        "setApplicationRestrictionsManagingPackage", "getApplicationRestrictionsManagingPackage", "isCallerApplicationRestrictionsManagingPackage", "setRestrictionsProvider",
        "getRestrictionsProvider", "setUserRestriction", "setUserRestrictionForUser", "setUserRestrictionGlobally",
        "setUserRestrictionGloballyFromSystem", "getUserRestrictions", "getUserRestrictionsGlobally", "addCrossProfileIntentFilter",
        "clearCrossProfileIntentFilters", "setPermittedAccessibilityServices", "getPermittedAccessibilityServices", "getPermittedAccessibilityServicesForUser",
        "isAccessibilityServicePermittedByAdmin", "setPermittedInputMethods", "getPermittedInputMethods", "getPermittedInputMethodsAsUser",
        "isInputMethodPermittedByAdmin", "setPermittedCrossProfileNotificationListeners", "getPermittedCrossProfileNotificationListeners", "isNotificationListenerServicePermitted",
        "createAdminSupportIntent", "getEnforcingAdminAndUserDetails", "getEnforcingAdmin", "getEnforcingAdminsForRestriction",
        "setApplicationHidden", "isApplicationHidden", "createAndManageUser", "removeUser",
        "switchUser", "startUserInBackground", "stopUser", "logoutUser",
        "logoutUserInternal", "getLogoutUserId", "getSecondaryUsers", "acknowledgeNewUserDisclaimer",
        "isNewUserDisclaimerAcknowledged", "enableSystemApp", "enableSystemAppWithIntent", "installExistingPackage",
        "setAccountManagementDisabled", "getAccountTypesWithManagementDisabled", "getAccountTypesWithManagementDisabledAsUser", "setSecondaryLockscreenEnabled",
        "isSecondaryLockscreenEnabled", "setPreferentialNetworkServiceConfigs", "getPreferentialNetworkServiceConfigs", "setLockTaskPackages",
        "getLockTaskPackages", "isLockTaskPermitted", "setLockTaskFeatures", "getLockTaskFeatures",
        "setGlobalSetting", "setSystemSetting", "setSecureSetting", "setConfiguredNetworksLockdownState",
        "hasLockdownAdminConfiguredNetworks", "setLocationEnabled", "setTime", "setTimeZone",
        "setMasterVolumeMuted", "isMasterVolumeMuted", "notifyLockTaskModeChanged", "setUninstallBlocked",
        "isUninstallBlocked", "setCrossProfileCallerIdDisabled", "getCrossProfileCallerIdDisabled", "getCrossProfileCallerIdDisabledForUser",
        "setCrossProfileContactsSearchDisabled", "getCrossProfileContactsSearchDisabled", "getCrossProfileContactsSearchDisabledForUser", "startManagedQuickContact",
        "setManagedProfileCallerIdAccessPolicy", "getManagedProfileCallerIdAccessPolicy", "hasManagedProfileCallerIdAccess", "setCredentialManagerPolicy",
        "getCredentialManagerPolicy", "setManagedProfileContactsAccessPolicy", "getManagedProfileContactsAccessPolicy", "hasManagedProfileContactsAccess",
        "setBluetoothContactSharingDisabled", "getBluetoothContactSharingDisabled", "getBluetoothContactSharingDisabledForUser", "setTrustAgentConfiguration",
        "getTrustAgentConfiguration", "addCrossProfileWidgetProvider", "removeCrossProfileWidgetProvider", "getCrossProfileWidgetProviders",
        "setAutoTimeRequired", "getAutoTimeRequired", "setAutoTimeEnabled", "getAutoTimeEnabled",
        "setAutoTimePolicy", "getAutoTimePolicy", "setAutoTimeZoneEnabled", "getAutoTimeZoneEnabled",
        "setAutoTimeZonePolicy", "getAutoTimeZonePolicy", "setForceEphemeralUsers", "getForceEphemeralUsers",
        "isRemovingAdmin", "setUserIcon", "setSystemUpdatePolicy", "getSystemUpdatePolicy",
        "clearSystemUpdatePolicyFreezePeriodRecord", "setKeyguardDisabled", "setStatusBarDisabled", "isStatusBarDisabled",
        "getDoNotAskCredentialsOnBoot", "notifyPendingSystemUpdate", "getPendingSystemUpdate", "setPermissionPolicy",
        "getPermissionPolicy", "setPermissionGrantState", "getPermissionGrantState", "isProvisioningAllowed",
        "checkProvisioningPrecondition", "setKeepUninstalledPackages", "getKeepUninstalledPackages", "isManagedProfile",
        "getWifiMacAddress", "reboot", "setShortSupportMessage", "getShortSupportMessage",
        "setLongSupportMessage", "getLongSupportMessage", "getShortSupportMessageForUser", "getLongSupportMessageForUser",
        "setOrganizationColor", "setOrganizationColorForUser", "clearOrganizationIdForUser", "getOrganizationColor",
        "getOrganizationColorForUser", "setOrganizationName", "getOrganizationName", "getDeviceOwnerOrganizationName",
        "getOrganizationNameForUser", "getUserProvisioningState", "setUserProvisioningState", "setAffiliationIds",
        "getAffiliationIds", "isCallingUserAffiliated", "isAffiliatedUser", "setSecurityLoggingEnabled",
        "isSecurityLoggingEnabled", "retrieveSecurityLogs", "retrievePreRebootSecurityLogs", "forceNetworkLogs",
        "forceSecurityLogs", "setAuditLogEnabled", "isAuditLogEnabled", "setAuditLogEventsCallback",
        "isUninstallInQueue", "uninstallPackageWithActiveAdmins", "isDeviceProvisioned", "isDeviceProvisioningConfigApplied",
        "setDeviceProvisioningConfigApplied", "forceUpdateUserSetupComplete", "setBackupServiceEnabled", "isBackupServiceEnabled",
        "setNetworkLoggingEnabled", "isNetworkLoggingEnabled", "retrieveNetworkLogs", "bindDeviceAdminServiceAsUser",
        "getBindDeviceAdminTargetUsers", "isEphemeralUser", "getLastSecurityLogRetrievalTime", "getLastBugReportRequestTime",
        "getLastNetworkLogRetrievalTime", "setResetPasswordToken", "clearResetPasswordToken", "isResetPasswordTokenActive",
        "resetPasswordWithToken", "isCurrentInputMethodSetByOwner", "getOwnerInstalledCaCerts", "clearApplicationUserData",
        "setLogoutEnabled", "isLogoutEnabled", "getDisallowedSystemApps", "transferOwnership",
        "getTransferOwnershipBundle", "setStartUserSessionMessage", "setEndUserSessionMessage", "getStartUserSessionMessage",
        "getEndUserSessionMessage", "setMeteredDataDisabledPackages", "getMeteredDataDisabledPackages", "addOverrideApn",
        "updateOverrideApn", "removeOverrideApn", "getOverrideApns", "setOverrideApnsEnabled",
        "isOverrideApnEnabled", "isMeteredDataDisabledPackageForUser", "setGlobalPrivateDns", "getGlobalPrivateDnsMode",
        "getGlobalPrivateDnsHost", "setProfileOwnerOnOrganizationOwnedDevice", "installUpdateFromFile", "setCrossProfileCalendarPackages",
        "getCrossProfileCalendarPackages", "isPackageAllowedToAccessCalendarForUser", "getCrossProfileCalendarPackagesForUser", "setCrossProfilePackages",
        "getCrossProfilePackages", "getAllCrossProfilePackages", "getDefaultCrossProfilePackages", "isManagedKiosk",
        "isUnattendedManagedKiosk", "startViewCalendarEventInManagedProfile", "setKeyGrantForApp", "getKeyPairGrants",
        "setKeyGrantToWifiAuth", "isKeyPairGrantedToWifiAuth", "setUserControlDisabledPackages", "getUserControlDisabledPackages",
        "setCommonCriteriaModeEnabled", "isCommonCriteriaModeEnabled", "getPersonalAppsSuspendedReasons", "setPersonalAppsSuspended",
        "getManagedProfileMaximumTimeOff", "setManagedProfileMaximumTimeOff", "acknowledgeDeviceCompliant", "isComplianceAcknowledgementRequired",
        "canProfileOwnerResetPasswordWhenLocked", "setNextOperationSafety", "isSafeOperation", "getEnrollmentSpecificId",
        "setOrganizationIdForUser", "createAndProvisionManagedProfile", "createManagedProfile", "finalizeCreateManagedProfile",
        "provisionFullyManagedDevice", "finalizeWorkProfileProvisioning", "removeManagedProfile", "setDeviceOwnerType",
        "getDeviceOwnerType", "resetDefaultCrossProfileIntentFilters", "canAdminGrantSensorsPermissions", "setUsbDataSignalingEnabled",
        "isUsbDataSignalingEnabled", "canUsbDataSignalingBeDisabled", "setMinimumRequiredWifiSecurityLevel", "getMinimumRequiredWifiSecurityLevel",
        "setWifiSsidPolicy", "getWifiSsidPolicy", "isDevicePotentiallyStolen", "listForegroundAffiliatedUsers",
        "setDrawables", "resetDrawables", "getDrawable", "isDpcDownloaded",
        "setDpcDownloaded", "setStrings", "resetStrings", "getString",
        "resetShouldAllowBypassingDevicePolicyManagementRoleQualificationState", "shouldAllowBypassingDevicePolicyManagementRoleQualification", "getPolicyManagedProfiles", "setApplicationExemptions",
        "getApplicationExemptions", "setMtePolicy", "setMtePolicyBySystem", "getMtePolicy",
        "setManagedSubscriptionsPolicy", "getManagedSubscriptionsPolicy", "getDevicePolicyState", "triggerDevicePolicyEngineMigration",
        "isDeviceFinanced", "getFinancedDeviceKioskRoleHolder", "calculateHasIncompatibleAccounts", "setContentProtectionPolicy",
        "getContentProtectionPolicy", "getSubscriptionIds", "setMaxPolicyStorageLimit", "forceSetMaxPolicyStorageLimit",
        "getMaxPolicyStorageLimit", "getPolicySizeForAdmin", "getHeadlessDeviceOwnerMode", "setAppFunctionsPolicy",
        "getAppFunctionsPolicy",
    ]),
    ("android.app.admin.IKeyguardCallback", &[
        "onRemoteContentReady", "onDismiss",
    ]),
    ("android.app.admin.IKeyguardClient", &[
        "onCreateKeyguardSurface",
    ]),
    ("android.app.admin.StartInstallingUpdateCallback", &[
        "onStartInstallingUpdateError",
    ]),
    ("android.app.ambientcontext.IAmbientContextManager", &[
        "registerObserver", "registerObserverWithCallback", "unregisterObserver", "queryServiceStatus",
        "startConsentActivity",
    ]),
    ("android.app.ambientcontext.IAmbientContextObserver", &[
        "onEvents", "onRegistrationComplete",
    ]),
    ("android.app.appfunctions.IAppFunctionEnabledCallback", &[
        "onSuccess", "onError",
    ]),
    ("android.app.appfunctions.IAppFunctionManager", &[
        "executeAppFunction", "setAppFunctionEnabled",
    ]),
    ("android.app.appfunctions.IAppFunctionService", &[
        "executeAppFunction",
    ]),
    ("android.app.appfunctions.ICancellationCallback", &[
        "sendCancellationTransport",
    ]),
    ("android.app.appfunctions.IExecuteAppFunctionCallback", &[
        "onSuccess", "onError",
    ]),
    ("android.app.assist.AssistStructure", &[
        "", "XFER",
    ]),
    ("android.app.backup.IBackupCallback", &[
        "operationComplete",
    ]),
    ("android.app.backup.IBackupManager", &[
        "dataChangedForUser", "dataChanged", "clearBackupDataForUser", "clearBackupData",
        "initializeTransportsForUser", "restoreAtInstallForUser", "restoreAtInstall", "setBackupEnabledForUser",
        "setFrameworkSchedulingEnabledForUser", "setBackupEnabled", "setAutoRestoreForUser", "setAutoRestore",
        "isBackupEnabledForUser", "isBackupEnabled", "setBackupPassword", "hasBackupPassword",
        "backupNowForUser", "backupNow", "adbBackup", "fullTransportBackupForUser",
        "adbRestore", "acknowledgeFullBackupOrRestoreForUser", "acknowledgeFullBackupOrRestore", "updateTransportAttributesForUser",
        "getCurrentTransportForUser", "getCurrentTransport", "getCurrentTransportComponentForUser", "listAllTransportsForUser",
        "listAllTransports", "listAllTransportComponentsForUser", "getTransportWhitelist", "selectBackupTransportForUser",
        "selectBackupTransport", "selectBackupTransportAsyncForUser", "getConfigurationIntentForUser", "getConfigurationIntent",
        "getDestinationStringForUser", "getDestinationString", "getDataManagementIntentForUser", "getDataManagementIntent",
        "getDataManagementLabelForUser", "beginRestoreSessionForUser", "opCompleteForUser", "opComplete",
        "setBackupServiceActive", "isBackupServiceActive", "isUserReadyForBackup", "getAvailableRestoreTokenForUser",
        "isAppEligibleForBackupForUser", "filterAppsEligibleForBackupForUser", "requestBackupForUser", "requestBackup",
        "cancelBackupsForUser", "cancelBackups", "getUserForAncestralSerialNumber", "setAncestralSerialNumber",
        "excludeKeysFromRestore", "reportDelayedRestoreResult",
    ]),
    ("android.app.backup.IBackupManagerMonitor", &[
        "onEvent",
    ]),
    ("android.app.backup.IBackupObserver", &[
        "onUpdate", "onResult", "backupFinished",
    ]),
    ("android.app.backup.IFullBackupRestoreObserver", &[
        "onStartBackup", "onBackupPackage", "onEndBackup", "onStartRestore",
        "onRestorePackage", "onEndRestore", "onTimeout",
    ]),
    ("android.app.backup.IRestoreObserver", &[
        "restoreSetsAvailable", "restoreStarting", "onUpdate", "restoreFinished",
    ]),
    ("android.app.backup.IRestoreSession", &[
        "getAvailableRestoreSets", "restoreAll", "restorePackages", "restorePackage",
        "endRestoreSession",
    ]),
    ("android.app.backup.ISelectBackupTransportCallback", &[
        "onSuccess", "onFailure",
    ]),
    ("android.app.blob.IBlobCommitCallback", &[
        "onResult",
    ]),
    ("android.app.blob.IBlobStoreManager", &[
        "createSession", "openSession", "openBlob", "abandonSession",
        "acquireLease", "releaseLease", "releaseAllLeases", "getRemainingLeaseQuotaBytes",
        "waitForIdle", "queryBlobsForUser", "deleteBlob", "getLeasedBlobs",
        "getLeaseInfo",
    ]),
    ("android.app.blob.IBlobStoreSession", &[
        "openWrite", "openRead", "allowPackageAccess", "allowSameSignatureAccess",
        "allowPublicAccess", "isPackageAccessAllowed", "isSameSignatureAccessAllowed", "isPublicAccessAllowed",
        "getSize", "close", "abandon", "commit",
    ]),
    ("android.app.contentsuggestions.IClassificationsCallback", &[
        "onContentClassificationsAvailable",
    ]),
    ("android.app.contentsuggestions.IContentSuggestionsManager", &[
        "provideContextImage", "provideContextBitmap", "suggestContentSelections", "classifyContentSelections",
        "notifyInteraction", "isEnabled", "resetTemporaryService", "setTemporaryService",
        "setDefaultServiceEnabled",
    ]),
    ("android.app.contentsuggestions.ISelectionsCallback", &[
        "onContentSelectionsAvailable",
    ]),
    ("android.app.contextualsearch.IContextualSearchCallback", &[
        "onResult", "onError",
    ]),
    ("android.app.contextualsearch.IContextualSearchManager", &[
        "startContextualSearchForForegroundApp", "startContextualSearch", "getContextualSearchState",
    ]),
    ("android.app.job.IJobCallback", &[
        "acknowledgeGetTransferredDownloadBytesMessage", "acknowledgeGetTransferredUploadBytesMessage", "acknowledgeStartMessage", "acknowledgeStopMessage",
        "dequeueWork", "completeWork", "jobFinished", "handleAbandonedJob",
        "updateEstimatedNetworkBytes", "updateTransferredNetworkBytes", "setNotification",
    ]),
    ("android.app.job.IJobScheduler", &[
        "schedule", "enqueue", "scheduleAsPackage", "cancel",
        "cancelAll", "cancelAllInNamespace", "getAllPendingJobs", "getAllPendingJobsInNamespace",
        "getPendingJob", "getPendingJobReason", "getPendingJobReasons", "getPendingJobReasonsHistory",
        "canRunUserInitiatedJobs", "hasRunUserInitiatedJobsPermission", "getStartedJobs", "getAllJobSnapshots",
        "registerUserVisibleJobObserver", "unregisterUserVisibleJobObserver", "notePendingUserRequestedAppStop",
    ]),
    ("android.app.job.IJobService", &[
        "startJob", "stopJob", "onNetworkChanged", "getTransferredDownloadBytes",
        "getTransferredUploadBytes",
    ]),
    ("android.app.job.IUserVisibleJobObserver", &[
        "onUserVisibleJobStateChanged",
    ]),
    ("android.app.people.IConversationListener", &[
        "onConversationUpdate",
    ]),
    ("android.app.people.IPeopleManager", &[
        "getConversation", "getRecentConversations", "removeRecentConversation", "removeAllRecentConversations",
        "isConversation", "getLastInteraction", "addOrUpdateStatus", "clearStatus",
        "clearStatuses", "getStatuses", "registerConversationListener", "unregisterConversationListener",
    ]),
    ("android.app.pinner.IPinnerService", &[
        "getPinnerStats",
    ]),
    ("android.app.prediction.IPredictionCallback", &[
        "onResult",
    ]),
    ("android.app.prediction.IPredictionManager", &[
        "createPredictionSession", "notifyAppTargetEvent", "notifyLaunchLocationShown", "sortAppTargets",
        "registerPredictionUpdates", "unregisterPredictionUpdates", "requestPredictionUpdate", "onDestroyPredictionSession",
        "requestServiceFeatures",
    ]),
    ("android.app.search.ISearchCallback", &[
        "onResult",
    ]),
    ("android.app.search.ISearchUiManager", &[
        "createSearchSession", "query", "notifyEvent", "registerEmptyQueryResultUpdateCallback",
        "unregisterEmptyQueryResultUpdateCallback", "destroySearchSession",
    ]),
    ("android.app.slice.ISliceListener", &[
        "onSliceUpdated",
    ]),
    ("android.app.slice.ISliceManager", &[
        "pinSlice", "unpinSlice", "hasSliceAccess", "getPinnedSpecs",
        "getPinnedSlices", "getBackupPayload", "applyRestore", "grantSlicePermission",
        "revokeSlicePermission", "checkSlicePermission", "grantPermissionFromUser",
    ]),
    ("android.app.smartspace.ISmartspaceCallback", &[
        "onResult",
    ]),
    ("android.app.smartspace.ISmartspaceManager", &[
        "createSmartspaceSession", "notifySmartspaceEvent", "requestSmartspaceUpdate", "registerSmartspaceUpdates",
        "unregisterSmartspaceUpdates", "destroySmartspaceSession",
    ]),
    ("android.app.supervision.ISupervisionAppService", &[
        "onEnabled", "onDisabled",
    ]),
    ("android.app.supervision.ISupervisionManager", &[
        "createConfirmSupervisionCredentialsIntent", "isSupervisionEnabledForUser", "setSupervisionEnabledForUser", "getActiveSupervisionAppPackage",
        "shouldAllowBypassingSupervisionRoleQualification",
    ]),
    ("android.app.time.ITimeDetectorListener", &[
        "onChange",
    ]),
    ("android.app.time.ITimeZoneDetectorListener", &[
        "onChange",
    ]),
    ("android.app.timedetector.ITimeDetectorService", &[
        "getCapabilitiesAndConfig", "addListener", "removeListener", "updateConfiguration",
        "getTimeState", "confirmTime", "setManualTime", "suggestExternalTime",
        "suggestManualTime", "suggestTelephonyTime", "latestNetworkTime",
    ]),
    ("android.app.timezonedetector.ITimeZoneDetectorService", &[
        "getCapabilitiesAndConfig", "addListener", "removeListener", "updateConfiguration",
        "getTimeZoneState", "confirmTimeZone", "setManualTimeZone", "suggestManualTimeZone",
        "suggestTelephonyTimeZone",
    ]),
    ("android.app.trust.IStrongAuthTracker", &[
        "onStrongAuthRequiredChanged", "onIsNonStrongBiometricAllowedChanged",
    ]),
    ("android.app.trust.ITrustListener", &[
        "onEnabledTrustAgentsChanged", "onTrustChanged", "onTrustManagedChanged", "onTrustError",
        "onIsActiveUnlockRunningChanged",
    ]),
    ("android.app.trust.ITrustManager", &[
        "reportUnlockAttempt", "reportUserRequestedUnlock", "reportUserMayRequestUnlock", "reportUnlockLockout",
        "reportEnabledTrustAgentsChanged", "registerTrustListener", "unregisterTrustListener", "reportKeyguardShowingChanged",
        "setDeviceLockedForUser", "isDeviceLocked", "isDeviceSecure", "isTrustUsuallyManaged",
        "unlockedByBiometricForUser", "clearAllBiometricRecognized", "isActiveUnlockRunning", "isInSignificantPlace",
        "registerDeviceLockedStateListener", "unregisterDeviceLockedStateListener",
    ]),
    ("android.app.usage.ICacheQuotaService", &[
        "computeCacheQuotaHints",
    ]),
    ("android.app.usage.IStorageStatsManager", &[
        "isQuotaSupported", "isReservedSupported", "getTotalBytes", "getFreeBytes",
        "getCacheBytes", "getCacheQuotaBytes", "queryStatsForPackage", "queryArtManagedStats",
        "queryStatsForUid", "queryStatsForUser", "queryExternalStatsForUser", "queryCratesForPackage",
        "queryCratesForUid", "queryCratesForUser",
    ]),
    ("android.app.usage.IUsageStatsManager", &[
        "queryUsageStats", "queryConfigurationStats", "queryEventStats", "queryEvents",
        "queryEventsForPackage", "queryEventsForUser", "queryEventsForPackageForUser", "queryEventsWithFilter",
        "setAppInactive", "isAppStandbyEnabled", "isAppInactive", "onCarrierPrivilegedAppsChanged",
        "reportChooserSelection", "getAppStandbyBucket", "setAppStandbyBucket", "getAppStandbyBuckets",
        "setAppStandbyBuckets", "getAppMinStandbyBucket", "setEstimatedLaunchTime", "setEstimatedLaunchTimes",
        "registerAppUsageObserver", "unregisterAppUsageObserver", "registerUsageSessionObserver", "unregisterUsageSessionObserver",
        "registerAppUsageLimitObserver", "unregisterAppUsageLimitObserver", "reportUsageStart", "reportPastUsageStart",
        "reportUsageStop", "reportUserInteraction", "reportUserInteractionWithBundle", "getUsageSource",
        "forceUsageSourceSettingRead", "getLastTimeAnyComponentUsed", "queryBroadcastResponseStats", "clearBroadcastResponseStats",
        "clearBroadcastEvents", "isPackageExemptedFromBroadcastResponseStats", "getAppStandbyConstant",
    ]),
    ("android.app.wallpapereffectsgeneration.ICinematicEffectListener", &[
        "onCinematicEffectGenerated",
    ]),
    ("android.app.wallpapereffectsgeneration.IWallpaperEffectsGenerationManager", &[
        "generateCinematicEffect", "returnCinematicEffectResponse",
    ]),
    ("android.app.wearable.IWearableSensingCallback", &[
        "openFile",
    ]),
    ("android.app.wearable.IWearableSensingManager", &[
        "getAvailableConnectionCount", "provideConnection", "provideConcurrentConnection", "removeConnection",
        "removeAllConnections", "provideReadOnlyParcelFileDescriptor", "provideDataStream", "provideData",
        "registerDataRequestObserver", "unregisterDataRequestObserver", "startHotwordRecognition", "stopHotwordRecognition",
    ]),
    ("android.apphibernation.IAppHibernationService", &[
        "isHibernatingForUser", "setHibernatingForUser", "isHibernatingGlobally", "setHibernatingGlobally",
        "getHibernatingPackagesForUser", "getHibernationStatsForUser", "isOatArtifactDeletionEnabled",
    ]),
    ("android.bluetooth.BluetoothProtoEnums", &[
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "COLLISION",
        "", "", "", "RESPONSE_TIMEOUT",
    ]),
    ("android.companion.IAssociationRequestCallback", &[
        "onAssociationPending", "onAssociationCreated", "onFailure",
    ]),
    ("android.companion.ICompanionDeviceDiscoveryService", &[
        "startDiscovery", "onAssociationCreated",
    ]),
    ("android.companion.ICompanionDeviceManager", &[
        "associate", "getAssociations", "getAllAssociationsForUser", "legacyDisassociate",
        "disassociate", "hasNotificationAccess", "requestNotificationAccess", "isDeviceAssociatedForWifiConnection",
        "legacyStartObservingDevicePresence", "legacyStopObservingDevicePresence", "startObservingDevicePresence", "stopObservingDevicePresence",
        "canPairWithoutPrompt", "createAssociation", "addOnAssociationsChangedListener", "removeOnAssociationsChangedListener",
        "addOnTransportsChangedListener", "removeOnTransportsChangedListener", "sendMessage", "addOnMessageReceivedListener",
        "removeOnMessageReceivedListener", "notifySelfManagedDeviceAppeared", "notifySelfManagedDeviceDisappeared", "buildPermissionTransferUserConsentIntent",
        "isPermissionTransferUserConsented", "startSystemDataTransfer", "attachSystemDataTransport", "detachSystemDataTransport",
        "isCompanionApplicationBound", "buildAssociationCancellationIntent", "enableSystemDataSync", "disableSystemDataSync",
        "enablePermissionsSync", "disablePermissionsSync", "getPermissionSyncRequest", "enableSecureTransport",
        "setDeviceId", "getBackupPayload", "applyRestoredPayload", "removeBond",
    ]),
    ("android.companion.ICompanionDeviceService", &[
        "onDeviceAppeared", "onDeviceDisappeared", "onDevicePresenceEvent",
    ]),
    ("android.companion.IOnAssociationsChangedListener", &[
        "onAssociationsChanged",
    ]),
    ("android.companion.IOnMessageReceivedListener", &[
        "onMessageReceived",
    ]),
    ("android.companion.IOnTransportsChangedListener", &[
        "onTransportsChanged",
    ]),
    ("android.companion.ISystemDataTransferCallback", &[
        "onResult", "onError",
    ]),
    ("android.companion.virtual.IVirtualDevice", &[
        "getAssociationId", "getDeviceId", "getPersistentDeviceId", "getDisplayIds",
        "getDevicePolicy", "hasCustomAudioInputSupport", "canCreateMirrorDisplays", "goToSleep",
        "wakeUp", "close", "setDevicePolicy", "addActivityPolicyExemption",
        "removeActivityPolicyExemption", "setDevicePolicyForDisplay", "onAudioSessionStarting", "onAudioSessionEnded",
        "createVirtualDisplay", "createVirtualDpad", "createVirtualKeyboard", "createVirtualMouse",
        "createVirtualTouchscreen", "createVirtualNavigationTouchpad", "createVirtualStylus", "createVirtualRotaryEncoder",
        "unregisterInputDevice", "getInputDeviceId", "sendDpadKeyEvent", "sendKeyEvent",
        "sendButtonEvent", "sendRelativeEvent", "sendScrollEvent", "sendTouchEvent",
        "sendStylusMotionEvent", "sendStylusButtonEvent", "sendRotaryEncoderScrollEvent", "getVirtualSensorList",
        "sendSensorEvent", "sendSensorAdditionalInfo", "launchPendingIntent", "getCursorPosition",
        "setShowPointerIcon", "setDisplayImePolicy", "registerIntentInterceptor", "unregisterIntentInterceptor",
        "registerVirtualCamera", "unregisterVirtualCamera", "getVirtualCameraId", "setListeners",
    ]),
    ("android.companion.virtual.IVirtualDeviceActivityListener", &[
        "onTopActivityChanged", "onDisplayEmpty", "onActivityLaunchBlocked", "onSecureWindowShown",
        "onSecureWindowHidden",
    ]),
    ("android.companion.virtual.IVirtualDeviceIntentInterceptor", &[
        "onIntentIntercepted",
    ]),
    ("android.companion.virtual.IVirtualDeviceListener", &[
        "onVirtualDeviceCreated", "onVirtualDeviceClosed",
    ]),
    ("android.companion.virtual.IVirtualDeviceManager", &[
        "createVirtualDevice", "getVirtualDevices", "getVirtualDevice", "registerVirtualDeviceListener",
        "unregisterVirtualDeviceListener", "getDeviceIdForDisplayId", "getDisplayNameForPersistentDeviceId", "isValidVirtualDeviceId",
        "getDevicePolicy", "getAudioPlaybackSessionId", "getAudioRecordingSessionId", "playSoundEffect",
        "isVirtualDeviceOwnedMirrorDisplay", "getAllPersistentDeviceIds",
    ]),
    ("android.companion.virtual.IVirtualDeviceSoundEffectListener", &[
        "onPlaySoundEffect",
    ]),
    ("android.companion.virtual.audio.IAudioConfigChangedCallback", &[
        "onPlaybackConfigChanged", "onRecordingConfigChanged",
    ]),
    ("android.companion.virtual.audio.IAudioRoutingCallback", &[
        "onAppsNeedingAudioRoutingChanged",
    ]),
    ("android.companion.virtual.camera.IVirtualCameraCallback", &[
        "onStreamConfigured", "onProcessCaptureRequest", "onStreamClosed",
    ]),
    ("android.companion.virtual.sensor.IVirtualSensorCallback", &[
        "onConfigurationChanged", "onDirectChannelCreated", "onDirectChannelDestroyed", "onDirectChannelConfigured",
    ]),
    ("android.companion.virtualnative.IVirtualDeviceManagerNative", &[
        "getDeviceIdsForUid", "getDevicePolicy", "getDeviceIdForDisplayId",
    ]),
    ("android.content.IClipboard", &[
        "setPrimaryClip", "setPrimaryClipAsPackage", "clearPrimaryClip", "getPrimaryClip",
        "getPrimaryClipDescription", "hasPrimaryClip", "addPrimaryClipChangedListener", "removePrimaryClipChangedListener",
        "hasClipboardText", "getPrimaryClipSource", "areClipboardAccessNotificationsEnabledForUser", "setClipboardAccessNotificationsEnabledForUser",
    ]),
    ("android.content.IContentProvider", &[
        "query", "getType", "insert", "delete",
        "", "", "", "",
        "", "update", "", "",
        "bulkInsert", "openFile", "openAssetFile", "",
        "", "", "", "applyBatch",
        "call", "getStreamTypes", "openTypedAssetFile", "createCancelationSignal",
        "canonicalize", "uncanonicalize", "refresh", "checkUriPermission",
        "getTypeAsync", "canonicalizeAsync", "uncanonicalizeAsync", "getTypeAnonymousAsync",
    ]),
    ("android.content.IContentService", &[
        "unregisterContentObserver", "registerContentObserver", "notifyChange", "requestSync",
        "sync", "syncAsUser", "cancelSync", "cancelSyncAsUser",
        "cancelRequest", "getSyncAutomatically", "getSyncAutomaticallyAsUser", "setSyncAutomatically",
        "setSyncAutomaticallyAsUser", "getPeriodicSyncs", "addPeriodicSync", "removePeriodicSync",
        "getIsSyncable", "getIsSyncableAsUser", "setIsSyncable", "setIsSyncableAsUser",
        "setMasterSyncAutomatically", "setMasterSyncAutomaticallyAsUser", "getMasterSyncAutomatically", "getMasterSyncAutomaticallyAsUser",
        "getCurrentSyncs", "getCurrentSyncsAsUser", "getSyncAdapterTypes", "getSyncAdapterTypesAsUser",
        "getSyncAdapterPackagesForAuthorityAsUser", "getSyncAdapterPackageAsUser", "isSyncActive", "getSyncStatus",
        "getSyncStatusAsUser", "isSyncPending", "isSyncPendingAsUser", "addStatusChangeListener",
        "removeStatusChangeListener", "putCache", "getCache", "resetTodayStats",
        "onDbCorruption",
    ]),
    ("android.content.IIntentReceiver", &[
        "performReceive",
    ]),
    ("android.content.IIntentSender", &[
        "send",
    ]),
    ("android.content.IOnPrimaryClipChangedListener", &[
        "dispatchPrimaryClipChanged",
    ]),
    ("android.content.IRestrictionsManager", &[
        "getApplicationRestrictions", "getApplicationRestrictionsPerAdminForUser", "hasRestrictionsProvider", "requestPermission",
        "notifyPermissionResponse", "createLocalApprovalIntent",
    ]),
    ("android.content.ISyncAdapter", &[
        "onUnsyncableAccount", "startSync", "cancelSync",
    ]),
    ("android.content.ISyncAdapterUnsyncableAccountCallback", &[
        "onUnsyncableAccountDone",
    ]),
    ("android.content.ISyncContext", &[
        "sendHeartbeat", "onFinished",
    ]),
    ("android.content.ISyncServiceAdapter", &[
        "startSync", "cancelSync",
    ]),
    ("android.content.ISyncStatusObserver", &[
        "onStatusChanged",
    ]),
    ("android.content.integrity.IAppIntegrityManager", &[
        "updateRuleSet", "getCurrentRuleSetVersion", "getCurrentRuleSetProvider", "getCurrentRules",
        "getWhitelistedRuleProviders",
    ]),
    ("android.content.om.IOverlayManager", &[
        "getAllOverlays", "getOverlayInfosForTarget", "getOverlayInfo", "getOverlayInfoByIdentifier",
        "setEnabled", "enableWithConstraints", "setEnabledExclusive", "setEnabledExclusiveInCategory",
        "setPriority", "setHighestPriority", "setLowestPriority", "getDefaultOverlayPackages",
        "invalidateCachesForOverlay", "commit", "getPartitionOrder", "isDefaultPartitionOrder",
    ]),
    ("android.content.pm.IBackgroundInstallControlService", &[
        "getBackgroundInstalledPackages", "registerBackgroundInstallCallback", "unregisterBackgroundInstallCallback",
    ]),
    ("android.content.pm.ICrossProfileApps", &[
        "startActivityAsUser", "startActivityAsUserByIntent", "getTargetUserProfiles", "canInteractAcrossProfiles",
        "canRequestInteractAcrossProfiles", "setInteractAcrossProfilesAppOp", "canConfigureInteractAcrossProfiles", "canUserAttemptToConfigureInteractAcrossProfiles",
        "resetInteractAcrossProfilesAppOps", "clearInteractAcrossProfilesAppOps",
    ]),
    ("android.content.pm.IDataLoader", &[
        "create", "start", "stop", "destroy",
        "prepareImage",
    ]),
    ("android.content.pm.IDataLoaderManager", &[
        "bindToDataLoader", "getDataLoader", "unbindFromDataLoader",
    ]),
    ("android.content.pm.IDataLoaderStatusListener", &[
        "onStatusChanged",
    ]),
    ("android.content.pm.IDexModuleRegisterCallback", &[
        "onDexModuleRegistered",
    ]),
    ("android.content.pm.ILauncherApps", &[
        "addOnAppsChangedListener", "removeOnAppsChangedListener", "getLauncherActivities", "resolveLauncherActivityInternal",
        "startSessionDetailsActivityAsUser", "startActivityAsUser", "getActivityLaunchIntent", "getLauncherUserInfo",
        "getPreInstalledSystemPackages", "getAppMarketActivityIntent", "getPrivateSpaceSettingsIntent", "showAppDetailsAsUser",
        "isPackageEnabled", "getSuspendedPackageLauncherExtras", "isActivityEnabled", "getApplicationInfo",
        "getAppUsageLimit", "getShortcuts", "pinShortcuts", "startShortcut",
        "getShortcutIconResId", "getShortcutIconFd", "hasShortcutHostPermission", "shouldHideFromSuggestions",
        "getShortcutConfigActivities", "getShortcutConfigActivityIntent", "getShortcutIntent", "registerPackageInstallerCallback",
        "getAllSessions", "registerShortcutChangeCallback", "unregisterShortcutChangeCallback", "cacheShortcuts",
        "uncacheShortcuts", "getShortcutIconUri", "getActivityOverrides", "registerDumpCallback",
        "unRegisterDumpCallback", "setArchiveCompatibilityOptions", "getUserProfiles", "saveViewCaptureData",
    ]),
    ("android.content.pm.IOnAppsChangedListener", &[
        "onPackageRemoved", "onPackageAdded", "onPackageChanged", "onPackagesAvailable",
        "onPackagesUnavailable", "onPackagesSuspended", "onPackagesUnsuspended", "onShortcutChanged",
        "onPackageLoadingProgressChanged", "onUserConfigChanged",
    ]),
    ("android.content.pm.IOnChecksumsReadyListener", &[
        "onChecksumsReady",
    ]),
    ("android.content.pm.IOtaDexopt", &[
        "prepare", "cleanup", "isDone", "getProgress",
        "dexoptNextPackage", "nextDexoptCommand",
    ]),
    ("android.content.pm.IPackageDataObserver", &[
        "onRemoveCompleted",
    ]),
    ("android.content.pm.IPackageDeleteObserver", &[
        "packageDeleted",
    ]),
    ("android.content.pm.IPackageDeleteObserver2", &[
        "onUserActionRequired", "onPackageDeleted",
    ]),
    ("android.content.pm.IPackageInstallObserver2", &[
        "onUserActionRequired", "onPackageInstalled",
    ]),
    ("android.content.pm.IPackageInstaller", &[
        "createSession", "updateSessionAppIcon", "updateSessionAppLabel", "abandonSession",
        "openSession", "getSessionInfo", "getAllSessions", "getMySessions",
        "getStagedSessions", "registerCallback", "unregisterCallback", "uninstall",
        "uninstallExistingPackage", "installExistingPackage", "setPermissionsResult", "bypassNextStagedInstallerCheck",
        "bypassNextAllowedApexUpdateCheck", "disableVerificationForUid", "setAllowUnlimitedSilentUpdates", "setSilentUpdatesThrottleTime",
        "checkInstallConstraints", "waitForInstallConstraints", "requestArchive", "requestUnarchive",
        "installPackageArchived", "reportUnarchivalStatus",
    ]),
    ("android.content.pm.IPackageInstallerCallback", &[
        "onSessionCreated", "onSessionBadgingChanged", "onSessionActiveChanged", "onSessionProgressChanged",
        "onSessionFinished",
    ]),
    ("android.content.pm.IPackageInstallerSession", &[
        "setClientProgress", "addClientProgress", "getNames", "openWrite",
        "openRead", "write", "stageViaHardLink", "setChecksums",
        "requestChecksums", "removeSplit", "close", "commit",
        "transfer", "abandon", "seal", "fetchPackageNames",
        "getDataLoaderParams", "addFile", "removeFile", "isMultiPackage",
        "getChildSessionIds", "addChildSessionId", "removeChildSessionId", "getParentSessionId",
        "isStaged", "getInstallFlags", "requestUserPreapproval", "isApplicationEnabledSettingPersistent",
        "isRequestUpdateOwnership", "getAppMetadataFd", "openWriteAppMetadata", "removeAppMetadata",
        "setPreVerifiedDomains", "getPreVerifiedDomains",
    ]),
    ("android.content.pm.IPackageInstallerSessionFileSystemConnector", &[
        "writeData",
    ]),
    ("android.content.pm.IPackageLoadingProgressCallback", &[
        "onPackageLoadingProgressChanged",
    ]),
    ("android.content.pm.IPackageManager", &[
        "checkPackageStartable", "isPackageAvailable", "getPackageInfo", "getPackageInfoVersioned",
        "getPackageUid", "getPackageGids", "currentToCanonicalPackageNames", "canonicalToCurrentPackageNames",
        "getApplicationInfo", "getTargetSdkVersion", "getActivityInfo", "activitySupportsIntentAsUser",
        "getReceiverInfo", "getServiceInfo", "getProviderInfo", "isProtectedBroadcast",
        "checkSignatures", "checkUidSignatures", "getAllPackages", "getPackagesForUid",
        "getNameForUid", "getNamesForUids", "getUidForSharedUser", "getFlagsForUid",
        "getPrivateFlagsForUid", "isUidPrivileged", "resolveIntent", "findPersistentPreferredActivity",
        "canForwardTo", "queryIntentActivities", "queryIntentActivityOptions", "queryIntentReceivers",
        "resolveService", "queryIntentServices", "queryIntentContentProviders", "getInstalledPackages",
        "getAppMetadataFd", "getPackagesHoldingPermissions", "getInstalledApplications", "getPersistentApplications",
        "resolveContentProvider", "resolveContentProviderForUid", "querySyncProviders", "queryContentProviders",
        "getInstrumentationInfoAsUser", "queryInstrumentationAsUser", "finishPackageInstall", "setInstallerPackageName",
        "relinquishUpdateOwnership", "setApplicationCategoryHint", "deletePackageAsUser", "deletePackageVersioned",
        "deleteExistingPackageAsUser", "getInstallerPackageName", "getInstallSourceInfo", "resetApplicationPreferences",
        "getLastChosenActivity", "setLastChosenActivity", "addPreferredActivity", "replacePreferredActivity",
        "clearPackagePreferredActivities", "getPreferredActivities", "addPersistentPreferredActivity", "clearPackagePersistentPreferredActivities",
        "clearPersistentPreferredActivity", "addCrossProfileIntentFilter", "removeCrossProfileIntentFilter", "clearCrossProfileIntentFilters",
        "setDistractingPackageRestrictionsAsUser", "setPackagesSuspendedAsUser", "getUnsuspendablePackagesForUser", "isPackageSuspendedForUser",
        "isPackageQuarantinedForUser", "isPackageStoppedForUser", "getSuspendedPackageAppExtras", "getSuspendingPackage",
        "getPreferredActivityBackup", "restorePreferredActivities", "getDefaultAppsBackup", "restoreDefaultApps",
        "getDomainVerificationBackup", "restoreDomainVerification", "getHomeActivities", "setHomeActivity",
        "overrideLabelAndIcon", "restoreLabelAndIcon", "setComponentEnabledSetting", "setComponentEnabledSettings",
        "getComponentEnabledSetting", "setApplicationEnabledSetting", "getApplicationEnabledSetting", "logAppProcessStartIfNeeded",
        "flushPackageRestrictionsAsUser", "setPackageStoppedState", "freeStorageAndNotify", "freeStorage",
        "deleteApplicationCacheFiles", "deleteApplicationCacheFilesAsUser", "clearApplicationUserData", "clearApplicationProfileData",
        "getPackageSizeInfo", "getSystemSharedLibraryNames", "getSystemSharedLibraryNamesAndPaths", "getSystemAvailableFeatures",
        "hasSystemFeature", "getInitialNonStoppedSystemPackages", "enterSafeMode", "isSafeMode",
        "hasSystemUidErrors", "notifyPackageUse", "notifyDexLoad", "registerDexModule",
        "performDexOptMode", "performDexOptSecondary", "getMoveStatus", "registerMoveCallback",
        "unregisterMoveCallback", "movePackage", "movePrimaryStorage", "setInstallLocation",
        "getInstallLocation", "installExistingPackageAsUser", "verifyPendingInstall", "extendVerificationTimeout",
        "verifyIntentFilter", "getIntentVerificationStatus", "updateIntentVerificationStatus", "getIntentFilterVerifications",
        "getAllIntentFilters", "getVerifierDeviceIdentity", "isFirstBoot", "isDeviceUpgrading",
        "isStorageLow", "setApplicationHiddenSettingAsUser", "getApplicationHiddenSettingAsUser", "setSystemAppHiddenUntilInstalled",
        "setSystemAppInstallState", "getPackageInstaller", "setBlockUninstallForUser", "getBlockUninstallForUser",
        "getKeySetByAlias", "getSigningKeySet", "isPackageSignedByKeySet", "isPackageSignedByKeySetExactly",
        "getPermissionControllerPackageName", "getSdkSandboxPackageName", "getInstantApps", "getInstantAppCookie",
        "setInstantAppCookie", "getInstantAppIcon", "isInstantApp", "setRequiredForSystemUser",
        "setUpdateAvailable", "getServicesSystemSharedLibraryPackageName", "getSharedSystemSharedLibraryPackageName", "getChangedPackages",
        "isPackageDeviceAdminOnAnyUser", "getInstallReason", "getSharedLibraries", "getDeclaredSharedLibraries",
        "canRequestPackageInstalls", "deletePreloadsFileCache", "getInstantAppResolverComponent", "getInstantAppResolverSettingsComponent",
        "getInstantAppInstallerComponent", "getInstantAppAndroidId", "getArtManager", "setHarmfulAppWarning",
        "getHarmfulAppWarning", "hasSigningCertificate", "hasUidSigningCertificate", "getDefaultTextClassifierPackageName",
        "getSystemTextClassifierPackageName", "getAttentionServicePackageName", "getRotationResolverPackageName", "getWellbeingPackageName",
        "getAppPredictionServicePackageName", "getSystemCaptionsServicePackageName", "getSetupWizardPackageName", "getIncidentReportApproverPackageName",
        "isPackageStateProtected", "sendDeviceCustomizationReadyBroadcast", "getInstalledModules", "getModuleInfo",
        "getRuntimePermissionsVersion", "setRuntimePermissionsVersion", "notifyPackagesReplacedReceived", "requestPackageChecksums",
        "getLaunchIntentSenderForPackage", "getAppOpPermissionPackages", "getPermissionGroupInfo", "addPermission",
        "addPermissionAsync", "removePermission", "checkPermission", "grantRuntimePermission",
        "checkUidPermission", "setMimeGroup", "getSplashScreenTheme", "setSplashScreenTheme",
        "getUserMinAspectRatio", "setUserMinAspectRatio", "getMimeGroup", "isAutoRevokeWhitelisted",
        "makeProviderVisible", "makeUidVisible", "getHoldLockToken", "holdLock",
        "getPropertyAsUser", "queryProperty", "setKeepUninstalledPackages", "canPackageQuery",
        "waitForHandler", "registerPackageMonitorCallback", "unregisterPackageMonitorCallback", "getArchivedPackage",
        "getArchivedAppIcon", "isAppArchivable", "getAppMetadataSource", "getDomainVerificationAgent",
        "setPageSizeAppCompatFlagsSettingsOverride", "isPageSizeCompatEnabled", "getPageSizeCompatWarningMessage", "getAllApexDirectories",
    ]),
    ("android.content.pm.IPackageManagerNative", &[
        "getNamesForUids", "getPackageUid", "getInstallerForPackage", "getVersionCodeForPackage",
        "isAudioPlaybackCaptureAllowed", "getLocationFlags", "getTargetSdkVersionForPackage", "getModuleMetadataPackageName",
        "hasSha256SigningCertificate", "isPackageDebuggable", "hasSystemFeature", "registerStagedApexObserver",
        "unregisterStagedApexObserver", "getStagedApexInfos",
    ]),
    ("android.content.pm.IPackageMoveObserver", &[
        "onCreated", "onStatusChanged",
    ]),
    ("android.content.pm.IPackageStatsObserver", &[
        "onGetStatsCompleted",
    ]),
    ("android.content.pm.IPinItemRequest", &[
        "isValid", "accept", "getShortcutInfo", "getAppWidgetProviderInfo",
        "getExtras",
    ]),
    ("android.content.pm.IShortcutChangeCallback", &[
        "onShortcutsAddedOrUpdated", "onShortcutsRemoved",
    ]),
    ("android.content.pm.IShortcutService", &[
        "setDynamicShortcuts", "addDynamicShortcuts", "removeDynamicShortcuts", "removeAllDynamicShortcuts",
        "updateShortcuts", "requestPinShortcut", "createShortcutResultIntent", "disableShortcuts",
        "enableShortcuts", "getMaxShortcutCountPerActivity", "getRemainingCallCount", "getRateLimitResetTime",
        "getIconMaxDimensions", "reportShortcutUsed", "resetThrottling", "onApplicationActive",
        "getBackupPayload", "applyRestore", "isRequestPinItemSupported", "getShareTargets",
        "hasShareTargets", "removeLongLivedShortcuts", "getShortcuts", "pushDynamicShortcut",
    ]),
    ("android.content.pm.IStagedApexObserver", &[
        "onApexStaged",
    ]),
    ("android.content.pm.dependencyinstaller.IDependencyInstallerCallback", &[
        "onAllDependenciesResolved", "onFailureToResolveAllDependencies",
    ]),
    ("android.content.pm.dependencyinstaller.IDependencyInstallerService", &[
        "onDependenciesRequired",
    ]),
    ("android.content.pm.dex.IArtManager", &[
        "snapshotRuntimeProfile", "isRuntimeProfilingEnabled",
    ]),
    ("android.content.pm.dex.ISnapshotRuntimeProfileCallback", &[
        "onSuccess", "onError",
    ]),
    ("android.content.pm.permission.IRuntimePermissionPresenter", &[
        "getAppPermissions",
    ]),
    ("android.content.pm.verify.domain.IDomainVerificationManager", &[
        "queryValidVerificationPackageNames", "getDomainVerificationInfo", "getDomainVerificationUserState", "getOwnersForDomain",
        "setDomainVerificationStatus", "setDomainVerificationLinkHandlingAllowed", "setDomainVerificationUserSelection", "setUriRelativeFilterGroups",
        "getUriRelativeFilterGroups",
    ]),
    ("android.content.res.IResourcesManager", &[
        "dumpResources",
    ]),
    ("android.content.rollback.IRollbackManager", &[
        "getAvailableRollbacks", "getRecentlyCommittedRollbacks", "commitRollback", "snapshotAndRestoreUserData",
        "reloadPersistedData", "expireRollbackForPackage", "notifyStagedSession", "blockRollbackManager",
    ]),
    ("android.contexthub.ContextHubProtoEnums", &[
        "RESULT_FAILED_UNKNOWN", "RESULT_FAILED_BAD_PARAMS", "RESULT_FAILED_UNINITIALIZED", "RESULT_FAILED_BUSY",
        "RESULT_FAILED_AT_HUB", "RESULT_FAILED_TIMEOUT", "RESULT_FAILED_SERVICE_INTERNAL_FAILURE", "RESULT_FAILED_HAL_UNAVAILABLE",
    ]),
    ("android.credentials.IClearCredentialStateCallback", &[
        "onSuccess", "onError",
    ]),
    ("android.credentials.ICreateCredentialCallback", &[
        "onPendingIntent", "onResponse", "onError",
    ]),
    ("android.credentials.ICredentialManager", &[
        "executeGetCredential", "executePrepareGetCredential", "executeCreateCredential", "getCandidateCredentials",
        "clearCredentialState", "setEnabledProviders", "registerCredentialDescription", "unregisterCredentialDescription",
        "isEnabledCredentialProviderService", "getCredentialProviderServices", "getCredentialProviderServicesForTesting", "isServiceEnabled",
    ]),
    ("android.credentials.IGetCandidateCredentialsCallback", &[
        "onResponse", "onError",
    ]),
    ("android.credentials.IGetCredentialCallback", &[
        "onPendingIntent", "onResponse", "onError",
    ]),
    ("android.credentials.IPrepareGetCredentialCallback", &[
        "onResponse", "onError",
    ]),
    ("android.credentials.ISetEnabledProvidersCallback", &[
        "onResponse", "onError",
    ]),
    ("android.database.IBulkCursor", &[
        "getCursorWindow", "deactivate", "requery", "onMove",
        "getExtras", "respond", "close",
    ]),
    ("android.database.IContentObserver", &[
        "onChange", "onChangeEtc",
    ]),
    ("android.database.sqlite.SQLiteSession", &[
        "MODE_IMMEDIATE", "MODE_EXCLUSIVE",
    ]),
    ("android.debug.IAdbCallback", &[
        "onDebuggingChanged",
    ]),
    ("android.debug.IAdbManager", &[
        "allowDebugging", "denyDebugging", "clearDebuggingKeys", "allowWirelessDebugging",
        "denyWirelessDebugging", "getPairedDevices", "unpairDevice", "enablePairingByPairingCode",
        "enablePairingByQrCode", "getAdbWirelessPort", "disablePairing", "isAdbWifiSupported",
        "isAdbWifiQrSupported", "registerCallback", "unregisterCallback",
    ]),
    ("android.debug.IAdbTransport", &[
        "onAdbEnabled",
    ]),
    ("android.flags.IFeatureFlags", &[
        "syncFlags", "registerCallback", "unregisterCallback", "queryFlags",
        "overrideFlag", "resetFlag",
    ]),
    ("android.flags.IFeatureFlagsCallback", &[
        "onFlagChange",
    ]),
    ("android.gsi.IGsiService", &[
        "commitGsiChunkFromStream", "getInstallProgress", "setGsiAshmem", "commitGsiChunkFromAshmem",
        "enableGsi", "enableGsiAsync", "isGsiEnabled", "cancelGsiInstall",
        "isGsiInstallInProgress", "removeGsi", "removeGsiAsync", "disableGsi",
        "isGsiInstalled", "isGsiRunning", "getActiveDsuSlot", "getInstalledGsiImageDir",
        "getInstalledDsuSlots", "openInstall", "closeInstall", "createPartition",
        "closePartition", "zeroPartition", "openImageService", "dumpDeviceMapperDevices",
        "getAvbPublicKey", "suggestScratchSize",
    ]),
    ("android.gsi.IGsiServiceCallback", &[
        "onResult",
    ]),
    ("android.gsi.IImageService", &[
        "createBackingImage", "deleteBackingImage", "mapImageDevice", "unmapImageDevice",
        "backingImageExists", "isImageMapped", "getAvbPublicKey", "getAllBackingImages",
        "zeroFillNewImage", "removeAllImages", "disableImage", "removeDisabledImages",
        "isImageDisabled", "getMappedImageDevice",
    ]),
    ("android.gsi.IProgressCallback", &[
        "onProgress",
    ]),
    ("android.gui.IDisplayEventConnection", &[
        "stealReceiveChannel", "setVsyncRate", "requestNextVsync", "getLatestVsyncEventData",
    ]),
    ("android.gui.ISurfaceComposer", &[
        "bootFinished", "createDisplayEventConnection", "createConnection", "createDisplay",
        "destroyDisplay", "getPhysicalDisplayIds", "getPhysicalDisplayToken", "getSupportedFrameTimestamps",
        "setPowerMode", "getDisplayStats", "getDisplayState", "getStaticDisplayInfo",
        "getDynamicDisplayInfoFromId", "getDynamicDisplayInfoFromToken", "getDisplayNativePrimaries", "setActiveColorMode",
        "setBootDisplayMode", "clearBootDisplayMode", "getBootDisplayModeSupport", "getHdrConversionCapabilities",
        "setHdrConversionStrategy", "getHdrOutputConversionSupport", "setAutoLowLatencyMode", "setGameContentType",
        "captureDisplay", "captureDisplayById", "captureLayers", "clearAnimationFrameStats",
        "getAnimationFrameStats", "overrideHdrTypes", "onPullAtom", "getLayerDebugInfo",
        "getColorManagement", "getCompositionPreference", "getDisplayedContentSamplingAttributes", "setDisplayContentSamplingEnabled",
        "getDisplayedContentSample", "getProtectedContentSupport", "isWideColorDisplay",
    ]),
    ("android.hardware.ICamera", &[
        "disconnect",
    ]),
    ("android.hardware.ICameraService", &[
        "getNumberOfCameras", "getCameraInfo", "connect", "connectDevice",
        "addListener", "getConcurrentCameraIds", "isConcurrentSessionConfigurationSupported", "injectSessionParams",
        "removeListener", "getCameraCharacteristics", "getCameraVendorTagDescriptor", "getCameraVendorTagCache",
        "getLegacyParameters", "isHiddenPhysicalCamera", "injectCamera", "setTorchMode",
        "turnOnTorchWithStrengthLevel", "getTorchStrengthLevel", "notifySystemEvent", "notifyDisplayConfigurationChange",
        "notifyDeviceStateChange", "reportExtensionSessionStats", "createDefaultRequest", "isSessionConfigurationWithParametersSupported",
        "getSessionCharacteristics",
    ]),
    ("android.hardware.ICameraServiceListener", &[
        "onStatusChanged", "onPhysicalCameraStatusChanged", "onTorchStatusChanged", "onTorchStrengthLevelChanged",
        "onCameraAccessPrioritiesChanged", "onCameraOpened", "onCameraOpenedInSharedMode", "onCameraClosed",
    ]),
    ("android.hardware.ICameraServiceProxy", &[
        "pingForUserUpdate", "notifyCameraState", "notifyFeatureCombinationStats", "getRotateAndCropOverride",
        "getAutoframingOverride", "isCameraDisabled", "notifyWatchdog",
    ]),
    ("android.hardware.IConsumerIrService", &[
        "hasIrEmitter", "transmit", "getCarrierFrequencies",
    ]),
    ("android.hardware.ISensorPrivacyListener", &[
        "onSensorPrivacyChanged", "onSensorPrivacyStateChanged",
    ]),
    ("android.hardware.ISensorPrivacyManager", &[
        "supportsSensorToggle", "addSensorPrivacyListener", "addToggleSensorPrivacyListener", "removeSensorPrivacyListener",
        "removeToggleSensorPrivacyListener", "isSensorPrivacyEnabled", "isCombinedToggleSensorPrivacyEnabled", "isToggleSensorPrivacyEnabled",
        "setSensorPrivacy", "setToggleSensorPrivacy", "setToggleSensorPrivacyForProfileGroup", "getCameraPrivacyAllowlist",
        "getToggleSensorPrivacyState", "setToggleSensorPrivacyState", "setToggleSensorPrivacyStateForProfileGroup", "isCameraPrivacyEnabled",
        "setCameraPrivacyAllowlist", "suppressToggleSensorPrivacyReminders", "requiresAuthentication", "showSensorUseDialog",
    ]),
    ("android.hardware.ISerialManager", &[
        "getSerialPorts", "openSerialPort",
    ]),
    ("android.hardware.biometrics.AuthenticationStateListener", &[
        "onAuthenticationAcquired", "onAuthenticationError", "onAuthenticationFailed", "onAuthenticationHelp",
        "onAuthenticationStarted", "onAuthenticationStopped", "onAuthenticationSucceeded",
    ]),
    ("android.hardware.biometrics.IAuthService", &[
        "createTestSession", "getSensorProperties", "getUiPackage", "authenticate",
        "cancelAuthentication", "canAuthenticate", "getLastAuthenticationTime", "hasEnrolledBiometrics",
        "registerEnabledOnKeyguardCallback", "registerAuthenticationStateListener", "unregisterAuthenticationStateListener", "invalidateAuthenticatorIds",
        "getAuthenticatorIds", "resetLockoutTimeBound", "resetLockout", "getButtonLabel",
        "getPromptMessage", "getSettingName",
    ]),
    ("android.hardware.biometrics.IBiometricAuthenticator", &[
        "createTestSession", "getSensorProperties", "dumpSensorServiceStateProto", "prepareForAuthentication",
        "startPreparedClient", "cancelAuthenticationFromService", "isHardwareDetected", "hasEnrolledTemplates",
        "getLockoutModeForUser", "invalidateAuthenticatorId", "getAuthenticatorId", "resetLockout",
    ]),
    ("android.hardware.biometrics.IBiometricContextListener", &[
        "onFoldChanged", "onDisplayStateChanged", "onHardwareIgnoreTouchesChanged",
    ]),
    ("android.hardware.biometrics.IBiometricEnabledOnKeyguardCallback", &[
        "onChanged",
    ]),
    ("android.hardware.biometrics.IBiometricSensorReceiver", &[
        "onAuthenticationSucceeded", "onAuthenticationFailed", "onError", "onAcquired",
    ]),
    ("android.hardware.biometrics.IBiometricService", &[
        "createTestSession", "getSensorProperties", "authenticate", "cancelAuthentication",
        "canAuthenticate", "getLastAuthenticationTime", "hasEnrolledBiometrics", "registerAuthenticator",
        "registerEnabledOnKeyguardCallback", "onReadyForAuthentication", "invalidateAuthenticatorIds", "getAuthenticatorIds",
        "resetLockoutTimeBound", "resetLockout", "getCurrentStrength", "getCurrentModality",
        "getSupportedModalities",
    ]),
    ("android.hardware.biometrics.IBiometricServiceLockoutResetCallback", &[
        "onLockoutReset",
    ]),
    ("android.hardware.biometrics.IBiometricServiceReceiver", &[
        "onAuthenticationSucceeded", "onAuthenticationFailed", "onError", "onAcquired",
        "onDialogDismissed", "onSystemEvent",
    ]),
    ("android.hardware.biometrics.IBiometricStateListener", &[
        "onStateChanged", "onBiometricAction", "onEnrollmentsChanged",
    ]),
    ("android.hardware.biometrics.IBiometricSysuiReceiver", &[
        "onDialogDismissed", "onTryAgainPressed", "onDeviceCredentialPressed", "onSystemEvent",
        "onDialogAnimatedIn", "onStartFingerprintNow",
    ]),
    ("android.hardware.biometrics.IInvalidationCallback", &[
        "onCompleted",
    ]),
    ("android.hardware.biometrics.ITestSession", &[
        "setTestHalEnabled", "startEnroll", "finishEnroll", "acceptAuthentication",
        "rejectAuthentication", "notifyAcquired", "notifyError", "cleanupInternalState",
        "getSensorId",
    ]),
    ("android.hardware.biometrics.ITestSessionCallback", &[
        "onCleanupStarted", "onCleanupFinished",
    ]),
    ("android.hardware.biometrics.face.virtualhal.IVirtualHal", &[
        "setEnrollments", "setEnrollmentHit", "setNextEnrollment", "setAuthenticatorId",
        "setChallenge", "setOperationAuthenticateFails", "setOperationAuthenticateLatency", "setOperationAuthenticateDuration",
        "setOperationAuthenticateError", "setOperationAuthenticateAcquired", "setOperationEnrollLatency", "setOperationDetectInteractionLatency",
        "setOperationDetectInteractionFails", "setLockout", "setLockoutEnable", "setLockoutTimedEnable",
        "setLockoutTimedThreshold", "setLockoutTimedDuration", "setLockoutPermanentThreshold", "resetConfigurations",
        "setType", "setSensorStrength", "getFaceHal",
    ]),
    ("android.hardware.biometrics.fingerprint.virtualhal.IVirtualHal", &[
        "setEnrollments", "setEnrollmentHit", "setNextEnrollment", "setAuthenticatorId",
        "setChallenge", "setOperationAuthenticateFails", "setOperationAuthenticateLatency", "setOperationAuthenticateDuration",
        "setOperationAuthenticateError", "setOperationAuthenticateAcquired", "setOperationEnrollError", "setOperationEnrollLatency",
        "setOperationDetectInteractionLatency", "setOperationDetectInteractionError", "setOperationDetectInteractionDuration", "setOperationDetectInteractionAcquired",
        "setLockout", "setLockoutEnable", "setLockoutTimedThreshold", "setLockoutTimedDuration",
        "setLockoutPermanentThreshold", "resetConfigurations", "setType", "setSensorId",
        "setSensorStrength", "setMaxEnrollmentPerUser", "setSensorLocation", "setNavigationGesture",
        "setDetectInteraction", "setDisplayTouch", "setControlIllumination", "getFingerprintHal",
    ]),
    ("android.hardware.camera2.ICameraDeviceCallbacks", &[
        "onDeviceError", "onDeviceIdle", "onCaptureStarted", "onResultReceived",
        "onPrepared", "onRepeatingRequestError", "onRequestQueueEmpty", "onClientSharedAccessPriorityChanged",
    ]),
    ("android.hardware.camera2.ICameraDeviceUser", &[
        "disconnect", "submitRequest", "submitRequestList", "startStreaming",
        "cancelRequest", "beginConfigure", "endConfigure", "isSessionConfigurationSupported",
        "deleteStream", "createStream", "createInputStream", "getInputSurface",
        "createDefaultRequest", "getCameraInfo", "waitUntilIdle", "flush",
        "prepare", "tearDown", "prepare2", "updateOutputConfiguration",
        "finalizeOutputConfigurations", "getCaptureResultMetadataQueue", "setCameraAudioRestriction", "getGlobalAudioRestriction",
        "switchToOffline", "isPrimaryClient",
    ]),
    ("android.hardware.camera2.ICameraInjectionCallback", &[
        "onInjectionError",
    ]),
    ("android.hardware.camera2.ICameraInjectionSession", &[
        "stopInjection",
    ]),
    ("android.hardware.camera2.ICameraOfflineSession", &[
        "disconnect",
    ]),
    ("android.hardware.camera2.extension.IAdvancedExtenderImpl", &[
        "isExtensionAvailable", "init", "getEstimatedCaptureLatencyRange", "getSupportedPreviewOutputResolutions",
        "getSupportedCaptureOutputResolutions", "getSupportedPostviewResolutions", "getSessionProcessor", "getAvailableCaptureRequestKeys",
        "getAvailableCaptureResultKeys", "isCaptureProcessProgressAvailable", "isPostviewAvailable", "getAvailableCharacteristicsKeyValues",
    ]),
    ("android.hardware.camera2.extension.ICameraExtensionsProxyService", &[
        "registerClient", "unregisterClient", "advancedExtensionsSupported", "initializeSession",
        "releaseSession", "initializePreviewExtension", "initializeImageExtension", "initializeAdvancedExtension",
    ]),
    ("android.hardware.camera2.extension.ICaptureCallback", &[
        "onCaptureStarted", "onCaptureProcessStarted", "onCaptureFailed", "onCaptureSequenceCompleted",
        "onCaptureSequenceAborted", "onCaptureCompleted", "onCaptureProcessProgressed", "onCaptureProcessFailed",
    ]),
    ("android.hardware.camera2.extension.ICaptureProcessorImpl", &[
        "onOutputSurface", "onPostviewOutputSurface", "onResolutionUpdate", "onImageFormatUpdate",
        "process",
    ]),
    ("android.hardware.camera2.extension.IImageCaptureExtenderImpl", &[
        "onInit", "onDeInit", "onPresetSession", "onEnableSession",
        "onDisableSession", "getSessionType", "isExtensionAvailable", "init",
        "getCaptureProcessor", "getCaptureStages", "getMaxCaptureStage", "getSupportedResolutions",
        "getSupportedPostviewResolutions", "getEstimatedCaptureLatencyRange", "getAvailableCaptureRequestKeys", "getAvailableCaptureResultKeys",
        "isCaptureProcessProgressAvailable", "getRealtimeCaptureLatency", "isPostviewAvailable",
    ]),
    ("android.hardware.camera2.extension.IImageProcessorImpl", &[
        "onNextImageAvailable",
    ]),
    ("android.hardware.camera2.extension.IInitializeSessionCallback", &[
        "onSuccess", "onFailure",
    ]),
    ("android.hardware.camera2.extension.IOutputSurfaceConfiguration", &[
        "getPreviewOutputSurface", "getImageCaptureOutputSurface", "getImageAnalysisOutputSurface", "getPostviewOutputSurface",
    ]),
    ("android.hardware.camera2.extension.IPreviewExtenderImpl", &[
        "onInit", "onDeInit", "onPresetSession", "onEnableSession",
        "onDisableSession", "init", "isExtensionAvailable", "getCaptureStage",
        "getSessionType", "getProcessorType", "getPreviewImageProcessor", "getRequestUpdateProcessor",
        "getSupportedResolutions",
    ]),
    ("android.hardware.camera2.extension.IPreviewImageProcessorImpl", &[
        "onOutputSurface", "onResolutionUpdate", "onImageFormatUpdate", "process",
    ]),
    ("android.hardware.camera2.extension.IProcessResultImpl", &[
        "onCaptureCompleted", "onCaptureProcessProgressed",
    ]),
    ("android.hardware.camera2.extension.IRequestCallback", &[
        "onCaptureStarted", "onCaptureProgressed", "onCaptureCompleted", "onCaptureFailed",
        "onCaptureBufferLost", "onCaptureSequenceCompleted", "onCaptureSequenceAborted",
    ]),
    ("android.hardware.camera2.extension.IRequestProcessorImpl", &[
        "setImageProcessor", "submit", "submitBurst", "setRepeating",
        "abortCaptures", "stopRepeating",
    ]),
    ("android.hardware.camera2.extension.IRequestUpdateProcessorImpl", &[
        "onOutputSurface", "onResolutionUpdate", "onImageFormatUpdate", "process",
    ]),
    ("android.hardware.camera2.extension.ISessionProcessorImpl", &[
        "initSession", "deInitSession", "onCaptureSessionStart", "onCaptureSessionEnd",
        "startRepeating", "stopRepeating", "startCapture", "setParameters",
        "startTrigger", "getRealtimeCaptureLatency",
    ]),
    ("android.hardware.contexthub.IContextHubEndpoint", &[
        "getAssignedHubEndpointInfo", "openSession", "closeSession", "openSessionRequestComplete",
        "unregister", "sendMessage", "sendMessageDeliveryStatus", "onCallbackFinished",
    ]),
    ("android.hardware.contexthub.IContextHubEndpointCallback", &[
        "onSessionOpenRequest", "onSessionClosed", "onSessionOpenComplete", "onMessageReceived",
    ]),
    ("android.hardware.contexthub.IContextHubEndpointDiscoveryCallback", &[
        "onEndpointsStarted", "onEndpointsStopped",
    ]),
    ("android.hardware.contexthub.V1_0.Result", &[
        "", "", "", "FAILED",
        "PENDING",
    ]),
    ("android.hardware.devicestate.IDeviceStateManager", &[
        "getDeviceStateInfo", "registerCallback", "requestState", "cancelStateRequest",
        "requestBaseStateOverride", "cancelBaseStateOverride", "onStateRequestOverlayDismissed",
    ]),
    ("android.hardware.devicestate.IDeviceStateManagerCallback", &[
        "onDeviceStateInfoChanged", "onRequestActive", "onRequestCanceled",
    ]),
    ("android.hardware.display.IBrightnessListener", &[
        "onBrightnessChanged",
    ]),
    ("android.hardware.display.IColorDisplayManager", &[
        "isDeviceColorManaged", "setSaturationLevel", "setAppSaturationLevel", "isSaturationActivated",
        "getTransformCapabilities", "isNightDisplayActivated", "setNightDisplayActivated", "getNightDisplayColorTemperature",
        "setNightDisplayColorTemperature", "getNightDisplayAutoMode", "getNightDisplayAutoModeRaw", "setNightDisplayAutoMode",
        "getNightDisplayCustomStartTime", "setNightDisplayCustomStartTime", "getNightDisplayCustomEndTime", "setNightDisplayCustomEndTime",
        "getColorMode", "setColorMode", "isDisplayWhiteBalanceEnabled", "setDisplayWhiteBalanceEnabled",
        "isReduceBrightColorsActivated", "setReduceBrightColorsActivated", "getReduceBrightColorsStrength", "setReduceBrightColorsStrength",
        "getReduceBrightColorsOffsetFactor",
    ]),
    ("android.hardware.display.IDisplayManager", &[
        "getDisplayInfo", "getDisplayIds", "isUidPresentOnDisplay", "registerCallback",
        "registerCallbackWithEventMask", "startWifiDisplayScan", "stopWifiDisplayScan", "connectWifiDisplay",
        "disconnectWifiDisplay", "renameWifiDisplay", "forgetWifiDisplay", "pauseWifiDisplay",
        "resumeWifiDisplay", "getWifiDisplayStatus", "setUserDisabledHdrTypes", "setAreUserDisabledHdrTypesAllowed",
        "areUserDisabledHdrTypesAllowed", "getUserDisabledHdrTypes", "overrideHdrTypes", "requestColorMode",
        "createVirtualDisplay", "resizeVirtualDisplay", "setVirtualDisplaySurface", "releaseVirtualDisplay",
        "setVirtualDisplayRotation", "getStableDisplaySize", "getBrightnessEvents", "getAmbientBrightnessStats",
        "setBrightnessConfigurationForUser", "setBrightnessConfigurationForDisplay", "getBrightnessConfigurationForDisplay", "getBrightnessConfigurationForUser",
        "getDefaultBrightnessConfiguration", "isMinimalPostProcessingRequested", "setTemporaryBrightness", "setBrightness",
        "getBrightness", "setTemporaryAutoBrightnessAdjustment", "getMinimumBrightnessCurve", "getBrightnessInfo",
        "getPreferredWideGamutColorSpaceId", "setUserPreferredDisplayMode", "getUserPreferredDisplayMode", "getSystemPreferredDisplayMode",
        "setHdrConversionMode", "getHdrConversionModeSetting", "getHdrConversionMode", "getSupportedHdrOutputTypes",
        "setShouldAlwaysRespectAppRequestedMode", "shouldAlwaysRespectAppRequestedMode", "setRefreshRateSwitchingType", "getRefreshRateSwitchingType",
        "getDisplayDecorationSupport", "setDisplayIdToMirror", "getOverlaySupport", "enableConnectedDisplay",
        "disableConnectedDisplay", "requestDisplayPower", "requestDisplayModes", "getHighestHdrSdrRatio",
        "getDozeBrightnessSensorValueToBrightness", "getDefaultDozeBrightness", "getDisplayTopology", "setDisplayTopology",
    ]),
    ("android.hardware.display.IDisplayManagerCallback", &[
        "onDisplayEvent", "onTopologyChanged",
    ]),
    ("android.hardware.display.IVirtualDisplayCallback", &[
        "onPaused", "onResumed", "onStopped",
    ]),
    ("android.hardware.face.IFaceAuthenticatorsRegisteredCallback", &[
        "onAllAuthenticatorsRegistered",
    ]),
    ("android.hardware.face.IFaceService", &[
        "createTestSession", "dumpSensorServiceStateProto", "getSensorPropertiesInternal", "getSensorProperties",
        "authenticate", "detectFace", "prepareForAuthentication", "startPreparedClient",
        "cancelAuthentication", "cancelFaceDetect", "cancelAuthenticationFromService", "enroll",
        "enrollRemotely", "cancelEnrollment", "remove", "removeAll",
        "getEnrolledFaces", "isHardwareDetected", "generateChallenge", "revokeChallenge",
        "hasEnrolledFaces", "getLockoutModeForUser", "invalidateAuthenticatorId", "getAuthenticatorId",
        "resetLockout", "addLockoutResetCallback", "setFeature", "getFeature",
        "registerAuthenticators", "addAuthenticatorsRegisteredCallback", "registerAuthenticationStateListener", "unregisterAuthenticationStateListener",
        "registerBiometricStateListener", "scheduleWatchdog",
    ]),
    ("android.hardware.face.IFaceServiceReceiver", &[
        "onEnrollResult", "onAcquired", "onAuthenticationSucceeded", "onFaceDetected",
        "onAuthenticationFailed", "onError", "onRemoved", "onFeatureSet",
        "onFeatureGet", "onChallengeGenerated", "onAuthenticationFrame", "onEnrollmentFrame",
    ]),
    ("android.hardware.fingerprint.IFingerprintAuthenticatorsRegisteredCallback", &[
        "onAllAuthenticatorsRegistered",
    ]),
    ("android.hardware.fingerprint.IFingerprintClientActiveCallback", &[
        "onClientActiveChanged",
    ]),
    ("android.hardware.fingerprint.IFingerprintService", &[
        "createTestSession", "dumpSensorServiceStateProto", "getSensorPropertiesInternal", "getSensorProperties",
        "authenticate", "detectFingerprint", "prepareForAuthentication", "startPreparedClient",
        "cancelAuthentication", "cancelFingerprintDetect", "cancelAuthenticationFromService", "enroll",
        "cancelEnrollment", "remove", "removeAll", "rename",
        "getEnrolledFingerprints", "isHardwareDetectedDeprecated", "isHardwareDetected", "generateChallenge",
        "revokeChallenge", "hasEnrolledFingerprintsDeprecated", "hasEnrolledFingerprints", "getLockoutModeForUser",
        "invalidateAuthenticatorId", "getAuthenticatorId", "resetLockout", "addLockoutResetCallback",
        "isClientActive", "addClientActiveCallback", "removeClientActiveCallback", "registerAuthenticators",
        "addAuthenticatorsRegisteredCallback", "onPointerDown", "onPointerUp", "onUdfpsUiEvent",
        "setIgnoreDisplayTouches", "setUdfpsOverlayController", "registerAuthenticationStateListener", "unregisterAuthenticationStateListener",
        "registerBiometricStateListener", "onPowerPressed", "scheduleWatchdog",
    ]),
    ("android.hardware.fingerprint.IFingerprintServiceReceiver", &[
        "onEnrollResult", "onAcquired", "onAuthenticationSucceeded", "onFingerprintDetected",
        "onAuthenticationFailed", "onError", "onRemoved", "onChallengeGenerated",
        "onUdfpsPointerDown", "onUdfpsPointerUp", "onUdfpsOverlayShown",
    ]),
    ("android.hardware.fingerprint.IUdfpsOverlayController", &[
        "showUdfpsOverlay", "hideUdfpsOverlay", "onAcquired", "onEnrollmentProgress",
        "onEnrollmentHelp", "setDebugMessage",
    ]),
    ("android.hardware.fingerprint.IUdfpsOverlayControllerCallback", &[
        "onUserCanceled",
    ]),
    ("android.hardware.fingerprint.IUdfpsRefreshRateRequestCallback", &[
        "onRequestEnabled", "onRequestDisabled", "onAuthenticationPossible",
    ]),
    ("android.hardware.hdmi.IHdmiCecSettingChangeListener", &[
        "onChange",
    ]),
    ("android.hardware.hdmi.IHdmiCecVolumeControlFeatureListener", &[
        "onHdmiCecVolumeControlFeature",
    ]),
    ("android.hardware.hdmi.IHdmiControlCallback", &[
        "onComplete",
    ]),
    ("android.hardware.hdmi.IHdmiControlService", &[
        "getSupportedTypes", "getActiveSource", "oneTouchPlay", "toggleAndFollowTvPower",
        "shouldHandleTvPowerKey", "queryDisplayStatus", "addHdmiControlStatusChangeListener", "removeHdmiControlStatusChangeListener",
        "addHdmiCecVolumeControlFeatureListener", "removeHdmiCecVolumeControlFeatureListener", "addHotplugEventListener", "removeHotplugEventListener",
        "addDeviceEventListener", "deviceSelect", "portSelect", "sendKeyEvent",
        "sendVolumeKeyEvent", "getPortInfo", "canChangeSystemAudioMode", "getSystemAudioMode",
        "getPhysicalAddress", "setSystemAudioMode", "addSystemAudioModeChangeListener", "removeSystemAudioModeChangeListener",
        "setArcMode", "setProhibitMode", "setSystemAudioVolume", "setSystemAudioMute",
        "setInputChangeListener", "getInputDevices", "getDeviceList", "powerOffRemoteDevice",
        "powerOnRemoteDevice", "askRemoteDeviceToBecomeActiveSource", "sendVendorCommand", "addVendorCommandListener",
        "sendStandby", "setHdmiRecordListener", "startOneTouchRecord", "stopOneTouchRecord",
        "startTimerRecording", "clearTimerRecording", "sendMhlVendorCommand", "addHdmiMhlVendorCommandListener",
        "setStandbyMode", "reportAudioStatus", "setSystemAudioModeOnForAudioOnlySource", "setMessageHistorySize",
        "getMessageHistorySize", "addCecSettingChangeListener", "removeCecSettingChangeListener", "getUserCecSettings",
        "getAllowedCecSettingStringValues", "getAllowedCecSettingIntValues", "getCecSettingStringValue", "setCecSettingStringValue",
        "getCecSettingIntValue", "setCecSettingIntValue",
    ]),
    ("android.hardware.hdmi.IHdmiControlStatusChangeListener", &[
        "onStatusChange",
    ]),
    ("android.hardware.hdmi.IHdmiDeviceEventListener", &[
        "onStatusChanged",
    ]),
    ("android.hardware.hdmi.IHdmiHotplugEventListener", &[
        "onReceived",
    ]),
    ("android.hardware.hdmi.IHdmiInputChangeListener", &[
        "onChanged",
    ]),
    ("android.hardware.hdmi.IHdmiMhlVendorCommandListener", &[
        "onReceived",
    ]),
    ("android.hardware.hdmi.IHdmiRecordListener", &[
        "getOneTouchRecordSource", "onOneTouchRecordResult", "onTimerRecordingResult", "onClearTimerRecordingResult",
    ]),
    ("android.hardware.hdmi.IHdmiSystemAudioModeChangeListener", &[
        "onStatusChanged",
    ]),
    ("android.hardware.hdmi.IHdmiVendorCommandListener", &[
        "onReceived", "onControlStateChanged",
    ]),
    ("android.hardware.input.IInputDeviceBatteryListener", &[
        "onBatteryStateChanged",
    ]),
    ("android.hardware.input.IInputDevicesChangedListener", &[
        "onInputDevicesChanged",
    ]),
    ("android.hardware.input.IInputManager", &[
        "getVelocityTrackerStrategy", "getInputDevice", "getInputDeviceIds", "enableInputDevice",
        "disableInputDevice", "hasKeys", "getKeyCodeForKeyLocation", "getKeyCharacterMap",
        "getMousePointerSpeed", "tryPointerSpeed", "injectInputEvent", "injectInputEventToTarget",
        "verifyInputEvent", "getTouchCalibrationForInputDevice", "setTouchCalibrationForInputDevice", "getKeyboardLayouts",
        "getKeyboardLayout", "getKeyboardLayoutForInputDevice", "setKeyboardLayoutOverrideForInputDevice", "setKeyboardLayoutForInputDevice",
        "getKeyboardLayoutListForInputDevice", "remapModifierKey", "clearAllModifierKeyRemappings", "getModifierKeyRemapping",
        "registerInputDevicesChangedListener", "isInTabletMode", "registerTabletModeChangedListener", "isMicMuted",
        "vibrate", "vibrateCombined", "cancelVibrate", "getVibratorIds",
        "isVibrating", "registerVibratorStateListener", "unregisterVibratorStateListener", "getBatteryState",
        "setPointerIcon", "requestPointerCapture", "monitorGestureInput", "addPortAssociation",
        "removePortAssociation", "addUniqueIdAssociationByDescriptor", "removeUniqueIdAssociationByDescriptor", "addUniqueIdAssociationByPort",
        "removeUniqueIdAssociationByPort", "getSensorList", "registerSensorListener", "unregisterSensorListener",
        "enableSensor", "disableSensor", "flushSensor", "getLights",
        "getLightState", "setLightStates", "openLightSession", "closeLightSession",
        "cancelCurrentTouch", "registerBatteryListener", "unregisterBatteryListener", "registerKeyEventActivityListener",
        "unregisterKeyEventActivityListener", "getInputDeviceBluetoothAddress", "pilferPointers", "registerKeyboardBacklightListener",
        "unregisterKeyboardBacklightListener", "getHostUsiVersionFromDisplayConfig", "registerStickyModifierStateListener", "unregisterStickyModifierStateListener",
        "getKeyGlyphMap", "registerKeyGestureEventListener", "unregisterKeyGestureEventListener", "registerKeyGestureHandler",
        "unregisterKeyGestureHandler", "getInputGesture", "addCustomInputGesture", "removeCustomInputGesture",
        "removeAllCustomInputGestures", "getCustomInputGestures", "getAppLaunchBookmarks", "resetLockedModifierState",
    ]),
    ("android.hardware.input.IInputSensorEventListener", &[
        "onInputSensorChanged", "onInputSensorAccuracyChanged",
    ]),
    ("android.hardware.input.IKeyEventActivityListener", &[
        "onKeyEventActivity",
    ]),
    ("android.hardware.input.IKeyGestureEventListener", &[
        "onKeyGestureEvent",
    ]),
    ("android.hardware.input.IKeyGestureHandler", &[
        "handleKeyGesture",
    ]),
    ("android.hardware.input.IKeyboardBacklightListener", &[
        "onBrightnessChanged",
    ]),
    ("android.hardware.input.IStickyModifierStateListener", &[
        "onStickyModifierStateChanged",
    ]),
    ("android.hardware.input.ITabletModeChangedListener", &[
        "onTabletModeChanged",
    ]),
    ("android.hardware.iris.IIrisService", &[
        "registerAuthenticators",
    ]),
    ("android.hardware.lights.ILightsManager", &[
        "getLights", "getLightState", "openSession", "closeSession",
        "setLightStates",
    ]),
    ("android.hardware.location.IActivityRecognitionHardware", &[
        "getSupportedActivities", "isActivitySupported", "registerSink", "unregisterSink",
        "enableActivityEvent", "disableActivityEvent", "flush",
    ]),
    ("android.hardware.location.IActivityRecognitionHardwareClient", &[
        "onAvailabilityChanged",
    ]),
    ("android.hardware.location.IActivityRecognitionHardwareSink", &[
        "onActivityChanged",
    ]),
    ("android.hardware.location.IActivityRecognitionHardwareWatcher", &[
        "onInstanceChanged",
    ]),
    ("android.hardware.location.IContextHubCallback", &[
        "onMessageReceipt",
    ]),
    ("android.hardware.location.IContextHubClient", &[
        "sendMessageToNanoApp", "close", "getId", "callbackFinished",
        "reliableMessageCallbackFinished", "sendReliableMessageToNanoApp",
    ]),
    ("android.hardware.location.IContextHubClientCallback", &[
        "onMessageFromNanoApp", "onHubReset", "onNanoAppAborted", "onNanoAppLoaded",
        "onNanoAppUnloaded", "onNanoAppEnabled", "onNanoAppDisabled", "onClientAuthorizationChanged",
    ]),
    ("android.hardware.location.IContextHubService", &[
        "registerCallback", "getContextHubHandles", "getContextHubInfo", "loadNanoApp",
        "unloadNanoApp", "getNanoAppInstanceInfo", "findNanoAppOnHub", "sendMessage",
        "createClient", "createPendingIntentClient", "getContextHubs", "getHubs",
        "loadNanoAppOnHub", "unloadNanoAppFromHub", "enableNanoApp", "disableNanoApp",
        "queryNanoApps", "getPreloadedNanoAppIds", "setTestMode", "findEndpoints",
        "findEndpointsWithService", "registerEndpoint", "registerEndpointDiscoveryCallbackId", "registerEndpointDiscoveryCallbackDescriptor",
        "unregisterEndpointDiscoveryCallback", "onDiscoveryCallbackFinished",
    ]),
    ("android.hardware.location.IContextHubTransactionCallback", &[
        "onQueryResponse", "onTransactionComplete",
    ]),
    ("android.hardware.location.IGeofenceHardware", &[
        "setGpsGeofenceHardware", "setFusedGeofenceHardware", "getMonitoringTypes", "getStatusOfMonitoringType",
        "addCircularFence", "removeGeofence", "pauseGeofence", "resumeGeofence",
        "registerForMonitorStateChangeCallback", "unregisterForMonitorStateChangeCallback",
    ]),
    ("android.hardware.location.IGeofenceHardwareCallback", &[
        "onGeofenceTransition", "onGeofenceAdd", "onGeofenceRemove", "onGeofencePause",
        "onGeofenceResume",
    ]),
    ("android.hardware.location.IGeofenceHardwareMonitorCallback", &[
        "onMonitoringSystemChange",
    ]),
    ("android.hardware.location.ISignificantPlaceProvider", &[
        "setSignificantPlaceProviderManager", "onSignificantPlaceCheck",
    ]),
    ("android.hardware.location.ISignificantPlaceProviderManager", &[
        "setInSignificantPlace",
    ]),
    ("android.hardware.radio.IAnnouncementListener", &[
        "onListUpdated",
    ]),
    ("android.hardware.radio.ICloseHandle", &[
        "close",
    ]),
    ("android.hardware.radio.IRadioService", &[
        "listModules", "openTuner", "addAnnouncementListener",
    ]),
    ("android.hardware.radio.ITuner", &[
        "close", "isClosed", "setConfiguration", "getConfiguration",
        "setMuted", "isMuted", "step", "seek",
        "tune", "cancel", "cancelAnnouncement", "getImage",
        "startBackgroundScan", "startProgramListUpdates", "stopProgramListUpdates", "isConfigFlagSupported",
        "isConfigFlagSet", "setConfigFlag", "setParameters", "getParameters",
    ]),
    ("android.hardware.radio.ITunerCallback", &[
        "onError", "onTuneFailed", "onConfigurationChanged", "onCurrentProgramInfoChanged",
        "onTrafficAnnouncement", "onEmergencyAnnouncement", "onAntennaState", "onBackgroundScanAvailabilityChange",
        "onBackgroundScanComplete", "onProgramListChanged", "onProgramListUpdated", "onConfigFlagUpdated",
        "onParametersUpdated",
    ]),
    ("android.hardware.soundtrigger.IRecognitionStatusCallback", &[
        "onKeyphraseDetected", "onGenericSoundTriggerDetected", "onRecognitionPaused", "onRecognitionResumed",
        "onPreempted", "onModuleDied", "onResumeFailed", "onPauseFailed",
    ]),
    ("android.hardware.usb.IDisplayPortAltModeInfoListener", &[
        "onDisplayPortAltModeInfoChanged",
    ]),
    ("android.hardware.usb.IUsbManager", &[
        "getDeviceList", "openDevice", "getCurrentAccessory", "openAccessory",
        "setDevicePackage", "setAccessoryPackage", "addDevicePackagesToPreferenceDenied", "addAccessoryPackagesToPreferenceDenied",
        "removeDevicePackagesFromPreferenceDenied", "removeAccessoryPackagesFromPreferenceDenied", "setDevicePersistentPermission", "setAccessoryPersistentPermission",
        "hasDevicePermission", "hasDevicePermissionWithIdentity", "hasAccessoryPermission", "hasAccessoryPermissionWithIdentity",
        "requestDevicePermission", "requestAccessoryPermission", "grantDevicePermission", "grantAccessoryPermission",
        "hasDefaults", "clearDefaults", "isFunctionEnabled", "isUvcGadgetSupportEnabled",
        "setCurrentFunctions", "setCurrentFunction", "getCurrentFunctions", "getCurrentUsbSpeed",
        "getGadgetHalVersion", "setScreenUnlockedFunctions", "getScreenUnlockedFunctions", "resetUsbGadget",
        "resetUsbPort", "enableUsbData", "enableUsbDataWhileDocked", "getUsbHalVersion",
        "getControlFd", "getPorts", "getPortStatus", "isModeChangeSupported",
        "setPortRoles", "enableLimitPowerTransfer", "enableContaminantDetection", "setUsbDeviceConnectionHandler",
        "registerForDisplayPortEvents", "unregisterForDisplayPortEvents",
    ]),
    ("android.hardware.usb.IUsbManagerInternal", &[
        "enableUsbDataSignal",
    ]),
    ("android.hardware.usb.IUsbOperationInternal", &[
        "onOperationComplete",
    ]),
    ("android.hardware.usb.IUsbSerialReader", &[
        "getSerial",
    ]),
    ("android.internal.perfetto.protos.WindowmanagerConfig$WindowManagerConfig", &[
        "", "logFrequency",
    ]),
    ("android.location.ICountryDetector", &[
        "detectCountry", "addCountryListener", "removeCountryListener",
    ]),
    ("android.location.ICountryListener", &[
        "onCountryDetected",
    ]),
    ("android.location.IFusedGeofenceHardware", &[
        "isSupported", "addGeofences", "removeGeofences", "pauseMonitoringGeofence",
        "resumeMonitoringGeofence", "modifyGeofenceOptions",
    ]),
    ("android.location.IGeofenceProvider", &[
        "setGeofenceHardware",
    ]),
    ("android.location.IGnssAntennaInfoListener", &[
        "onGnssAntennaInfoChanged",
    ]),
    ("android.location.IGnssMeasurementsListener", &[
        "onGnssMeasurementsReceived", "onStatusChanged",
    ]),
    ("android.location.IGnssNavigationMessageListener", &[
        "onGnssNavigationMessageReceived", "onStatusChanged",
    ]),
    ("android.location.IGnssNmeaListener", &[
        "onNmeaReceived",
    ]),
    ("android.location.IGnssStatusListener", &[
        "onGnssStarted", "onGnssStopped", "onFirstFix", "onSvStatusChanged",
    ]),
    ("android.location.IGpsGeofenceHardware", &[
        "isHardwareGeofenceSupported", "addCircularHardwareGeofence", "removeHardwareGeofence", "pauseHardwareGeofence",
        "resumeHardwareGeofence",
    ]),
    ("android.location.ILocationCallback", &[
        "onLocation",
    ]),
    ("android.location.ILocationListener", &[
        "onLocationChanged", "onProviderEnabledChanged", "onFlushComplete",
    ]),
    ("android.location.ILocationManager", &[
        "getLastLocation", "getCurrentLocation", "registerLocationListener", "unregisterLocationListener",
        "registerLocationPendingIntent", "unregisterLocationPendingIntent", "injectLocation", "requestListenerFlush",
        "requestPendingIntentFlush", "requestGeofence", "removeGeofence", "isGeocodeAvailable",
        "reverseGeocode", "forwardGeocode", "getGnssCapabilities", "getGnssYearOfHardware",
        "getGnssHardwareModelName", "getGnssAntennaInfos", "registerGnssStatusCallback", "unregisterGnssStatusCallback",
        "registerGnssNmeaCallback", "unregisterGnssNmeaCallback", "addGnssMeasurementsListener", "removeGnssMeasurementsListener",
        "injectGnssMeasurementCorrections", "addGnssNavigationMessageListener", "removeGnssNavigationMessageListener", "addGnssAntennaInfoListener",
        "removeGnssAntennaInfoListener", "addProviderRequestListener", "removeProviderRequestListener", "getGnssBatchSize",
        "startGnssBatch", "flushGnssBatch", "stopGnssBatch", "hasProvider",
        "getAllProviders", "getProviders", "getBestProvider", "getProviderProperties",
        "isProviderPackage", "getProviderPackages", "setExtraLocationControllerPackage", "getExtraLocationControllerPackage",
        "setExtraLocationControllerPackageEnabled", "isExtraLocationControllerPackageEnabled", "isProviderEnabledForUser", "isLocationEnabledForUser",
        "setLocationEnabledForUser", "isAdasGnssLocationEnabledForUser", "setAdasGnssLocationEnabledForUser", "isAutomotiveGnssSuspended",
        "setAutomotiveGnssSuspended", "addTestProvider", "removeTestProvider", "setTestProviderLocation",
        "setTestProviderEnabled", "getGnssTimeMillis", "sendExtraCommand", "getBackgroundThrottlingWhitelist",
        "getIgnoreSettingsAllowlist", "getAdasAllowlist",
    ]),
    ("android.location.INetInitiatedListener", &[
        "sendNiResponse",
    ]),
    ("android.location.provider.IGeocodeCallback", &[
        "onError", "onResults",
    ]),
    ("android.location.provider.IGeocodeProvider", &[
        "forwardGeocode", "reverseGeocode",
    ]),
    ("android.location.provider.IGnssAssistanceCallback", &[
        "onError", "onResult",
    ]),
    ("android.location.provider.IGnssAssistanceProvider", &[
        "request",
    ]),
    ("android.location.provider.ILocationProvider", &[
        "setLocationProviderManager", "setRequest", "flush", "sendExtraCommand",
    ]),
    ("android.location.provider.ILocationProviderManager", &[
        "onInitialize", "onSetAllowed", "onSetProperties", "onReportLocation",
        "onReportLocations", "onFlushComplete",
    ]),
    ("android.location.provider.IPopulationDensityProvider", &[
        "getDefaultCoarseningLevel", "getCoarsenedS2Cells",
    ]),
    ("android.location.provider.IProviderRequestListener", &[
        "onProviderRequestChanged",
    ]),
    ("android.location.provider.IS2CellIdsCallback", &[
        "onResult", "onError",
    ]),
    ("android.location.provider.IS2LevelCallback", &[
        "onResult", "onError",
    ]),
    ("android.media.IAudioDeviceVolumeDispatcher", &[
        "dispatchDeviceVolumeChanged", "dispatchDeviceVolumeAdjusted",
    ]),
    ("android.media.IAudioFocusDispatcher", &[
        "dispatchAudioFocusChange", "dispatchFocusResultFromExtPolicy",
    ]),
    ("android.media.IAudioManagerNative", &[
        "playbackHardeningEvent", "permissionUpdateBarrier", "portMuteEvent",
    ]),
    ("android.media.IAudioModeDispatcher", &[
        "dispatchAudioModeChanged",
    ]),
    ("android.media.IAudioPolicyService", &[
        "onNewAudioModulesAvailable", "setDeviceConnectionState", "getDeviceConnectionState", "handleDeviceConfigChange",
        "setPhoneState", "setForceUse", "getForceUse", "getOutput",
        "getOutputForAttr", "startOutput", "stopOutput", "releaseOutput",
        "getInputForAttr", "startInput", "stopInput", "releaseInput",
        "setDeviceAbsoluteVolumeEnabled", "initStreamVolume", "setStreamVolumeIndex", "getStreamVolumeIndex",
        "setVolumeIndexForAttributes", "getVolumeIndexForAttributes", "getMaxVolumeIndexForAttributes", "getMinVolumeIndexForAttributes",
        "getStrategyForStream", "getDevicesForAttributes", "getOutputForEffect", "registerEffect",
        "unregisterEffect", "setEffectEnabled", "moveEffectsToIo", "isStreamActive",
        "isStreamActiveRemotely", "isSourceActive", "queryDefaultPreProcessing", "addSourceDefaultEffect",
        "addStreamDefaultEffect", "removeSourceDefaultEffect", "removeStreamDefaultEffect", "setSupportedSystemUsages",
        "setAllowedCapturePolicy", "getOffloadSupport", "isDirectOutputSupported", "listAudioPorts",
        "listDeclaredDevicePorts", "getAudioPort", "createAudioPatch", "releaseAudioPatch",
        "listAudioPatches", "setAudioPortConfig", "registerClient", "setAudioPortCallbacksEnabled",
        "setAudioVolumeGroupCallbacksEnabled", "acquireSoundTriggerSession", "releaseSoundTriggerSession", "getPhoneState",
        "registerPolicyMixes", "getRegisteredPolicyMixes", "updatePolicyMixes", "setUidDeviceAffinities",
        "removeUidDeviceAffinities", "setUserIdDeviceAffinities", "removeUserIdDeviceAffinities", "startAudioSource",
        "stopAudioSource", "setMasterMono", "getMasterMono", "getStreamVolumeDB",
        "getSurroundFormats", "getReportedSurroundFormats", "getHwOffloadFormatsSupportedForBluetoothMedia", "setSurroundFormatEnabled",
        "setAssistantServicesUids", "setActiveAssistantServicesUids", "setA11yServicesUids", "setCurrentImeUid",
        "isHapticPlaybackSupported", "isUltrasoundSupported", "isHotwordStreamSupported", "listAudioProductStrategies",
        "getProductStrategyFromAudioAttributes", "listAudioVolumeGroups", "getVolumeGroupFromAudioAttributes", "setRttEnabled",
        "isCallScreenModeSupported", "setDevicesRoleForStrategy", "removeDevicesRoleForStrategy", "clearDevicesRoleForStrategy",
        "getDevicesForRoleAndStrategy", "setDevicesRoleForCapturePreset", "addDevicesRoleForCapturePreset", "removeDevicesRoleForCapturePreset",
        "clearDevicesRoleForCapturePreset", "getDevicesForRoleAndCapturePreset", "registerSoundTriggerCaptureStateListener", "getSpatializer",
        "canBeSpatialized", "getDirectPlaybackSupport", "getDirectProfilesForAttributes", "getSupportedMixerAttributes",
        "setPreferredMixerAttributes", "getPreferredMixerAttributes", "clearPreferredMixerAttributes", "getPermissionController",
        "getMmapPolicyInfos", "getMmapPolicyForDevice", "setEnableHardening",
    ]),
    ("android.media.IAudioPolicyServiceClient", &[
        "onAudioVolumeGroupChanged", "onAudioPortListUpdate", "onAudioPatchListUpdate", "onDynamicPolicyMixStateUpdate",
        "onRecordingConfigurationUpdate", "onRoutingUpdated", "onVolumeRangeInitRequest",
    ]),
    ("android.media.IAudioRoutesObserver", &[
        "dispatchAudioRoutesChanged",
    ]),
    ("android.media.IAudioServerStateDispatcher", &[
        "dispatchAudioServerStateChange",
    ]),
    ("android.media.IAudioService", &[
        "getNativeInterface", "trackPlayer", "playerAttributes", "playerEvent",
        "releasePlayer", "trackRecorder", "recorderEvent", "releaseRecorder",
        "playerSessionId", "portEvent", "permissionUpdateBarrier", "adjustStreamVolume",
        "adjustStreamVolumeWithAttribution", "setStreamVolume", "setStreamVolumeWithAttribution", "setDeviceVolume",
        "getDeviceVolume", "handleVolumeKey", "isStreamMute", "forceRemoteSubmixFullVolume",
        "isMasterMute", "setMasterMute", "getStreamVolume", "getStreamMinVolume",
        "getStreamMaxVolume", "getAudioVolumeGroups", "setVolumeGroupVolumeIndex", "getVolumeGroupVolumeIndex",
        "getVolumeGroupMaxVolumeIndex", "getVolumeGroupMinVolumeIndex", "getLastAudibleVolumeForVolumeGroup", "isVolumeGroupMuted",
        "adjustVolumeGroupVolume", "getLastAudibleStreamVolume", "setSupportedSystemUsages", "getSupportedSystemUsages",
        "getAudioProductStrategies", "isMicrophoneMuted", "isUltrasoundSupported", "isHotwordStreamSupported",
        "setMicrophoneMute", "setInputGainIndex", "getInputGainIndex", "getMaxInputGainIndex",
        "getMinInputGainIndex", "isInputGainFixed", "setMicrophoneMuteFromSwitch", "setRingerModeExternal",
        "setRingerModeInternal", "getRingerModeExternal", "getRingerModeInternal", "isValidRingerMode",
        "setVibrateSetting", "getVibrateSetting", "shouldVibrate", "setMode",
        "getMode", "playSoundEffect", "playSoundEffectVolume", "loadSoundEffects",
        "unloadSoundEffects", "reloadAudioSettings", "getSurroundFormats", "getReportedSurroundFormats",
        "setSurroundFormatEnabled", "isSurroundFormatEnabled", "setEncodedSurroundMode", "getEncodedSurroundMode",
        "setSpeakerphoneOn", "isSpeakerphoneOn", "setBluetoothScoOn", "setA2dpSuspended",
        "setLeAudioSuspended", "isBluetoothScoOn", "setBluetoothA2dpOn", "isBluetoothA2dpOn",
        "requestAudioFocus", "abandonAudioFocus", "unregisterAudioFocusClient", "getCurrentAudioFocus",
        "startBluetoothSco", "startBluetoothScoVirtualCall", "stopBluetoothSco", "forceVolumeControlStream",
        "setRingtonePlayer", "getRingtonePlayer", "getUiSoundsStreamType", "getIndependentStreamTypes",
        "getStreamTypeAlias", "isVolumeControlUsingVolumeGroups", "registerStreamAliasingDispatcher", "setNotifAliasRingForTest",
        "setWiredDeviceConnectionState", "startWatchingRoutes", "isCameraSoundForced", "setVolumeController",
        "getVolumeController", "notifyVolumeControllerVisible", "setVolumeControllerLongPressTimeoutEnabled", "isStreamAffectedByRingerMode",
        "isStreamAffectedByMute", "isStreamMutableByUi", "disableSafeMediaVolume", "lowerVolumeToRs1",
        "getOutputRs2UpperBound", "setOutputRs2UpperBound", "getCsd", "setCsd",
        "forceUseFrameworkMel", "forceComputeCsdOnAllDevices", "isCsdEnabled", "isCsdAsAFeatureAvailable",
        "isCsdAsAFeatureEnabled", "setCsdAsAFeatureEnabled", "setBluetoothAudioDeviceCategory", "getBluetoothAudioDeviceCategory",
        "isBluetoothAudioDeviceCategoryFixed", "setHdmiSystemAudioSupported", "isHdmiSystemAudioSupported", "registerAudioPolicy",
        "unregisterAudioPolicyAsync", "getRegisteredPolicyMixes", "unregisterAudioPolicy", "addMixForPolicy",
        "removeMixForPolicy", "updateMixingRulesForPolicy", "setFocusPropertiesForPolicy", "setVolumePolicy",
        "getVolumePolicy", "hasRegisteredDynamicPolicy", "registerRecordingCallback", "unregisterRecordingCallback",
        "getActiveRecordingConfigurations", "registerPlaybackCallback", "unregisterPlaybackCallback", "getActivePlaybackConfigurations",
        "getFocusRampTimeMs", "dispatchFocusChange", "dispatchFocusChangeWithFade", "playerHasOpPlayAudio",
        "handleBluetoothActiveDeviceChanged", "setFocusRequestResultFromExtPolicy", "registerAudioServerStateDispatcher", "unregisterAudioServerStateDispatcher",
        "isAudioServerRunning", "registerAudioVolumeCallback", "unregisterAudioVolumeCallback", "setUidDeviceAffinity",
        "removeUidDeviceAffinity", "setUserIdDeviceAffinity", "removeUserIdDeviceAffinity", "hasHapticChannels",
        "isCallScreeningModeSupported", "setPreferredDevicesForStrategy", "removePreferredDevicesForStrategy", "getPreferredDevicesForStrategy",
        "setDeviceAsNonDefaultForStrategy", "removeDeviceAsNonDefaultForStrategy", "getNonDefaultDevicesForStrategy", "getDevicesForAttributes",
        "getDevicesForAttributesUnprotected", "addOnDevicesForAttributesChangedListener", "removeOnDevicesForAttributesChangedListener", "setAllowedCapturePolicy",
        "getAllowedCapturePolicy", "registerStrategyPreferredDevicesDispatcher", "unregisterStrategyPreferredDevicesDispatcher", "registerStrategyNonDefaultDevicesDispatcher",
        "unregisterStrategyNonDefaultDevicesDispatcher", "setRttEnabled", "setDeviceVolumeBehavior", "getDeviceVolumeBehavior",
        "setMultiAudioFocusEnabled", "setPreferredDevicesForCapturePreset", "clearPreferredDevicesForCapturePreset", "getPreferredDevicesForCapturePreset",
        "registerCapturePresetDevicesRoleDispatcher", "unregisterCapturePresetDevicesRoleDispatcher", "adjustStreamVolumeForUid", "adjustSuggestedStreamVolumeForUid",
        "setStreamVolumeForUid", "adjustVolume", "adjustSuggestedStreamVolume", "isMusicActive",
        "getDeviceMaskForStream", "getAvailableCommunicationDeviceIds", "setCommunicationDevice", "getCommunicationDevice",
        "registerCommunicationDeviceDispatcher", "unregisterCommunicationDeviceDispatcher", "areNavigationRepeatSoundEffectsEnabled", "setNavigationRepeatSoundEffectsEnabled",
        "isHomeSoundEffectEnabled", "setHomeSoundEffectEnabled", "setAdditionalOutputDeviceDelay", "getAdditionalOutputDeviceDelay",
        "getMaxAdditionalOutputDeviceDelay", "requestAudioFocusForTest", "abandonAudioFocusForTest", "getFadeOutDurationOnFocusLossMillis",
        "getFocusDuckedUidsForTest", "getFocusFadeOutDurationForTest", "getFocusUnmuteDelayAfterFadeOutForTest", "enterAudioFocusFreezeForTest",
        "exitAudioFocusFreezeForTest", "registerModeDispatcher", "unregisterModeDispatcher", "getSpatializerImmersiveAudioLevel",
        "isSpatializerEnabled", "isSpatializerAvailable", "isSpatializerAvailableForDevice", "hasHeadTracker",
        "setHeadTrackerEnabled", "isHeadTrackerEnabled", "isHeadTrackerAvailable", "registerSpatializerHeadTrackerAvailableCallback",
        "setSpatializerEnabled", "canBeSpatialized", "getSpatializedChannelMasks", "registerSpatializerCallback",
        "unregisterSpatializerCallback", "registerSpatializerHeadTrackingCallback", "unregisterSpatializerHeadTrackingCallback", "registerHeadToSoundstagePoseCallback",
        "unregisterHeadToSoundstagePoseCallback", "getSpatializerCompatibleAudioDevices", "addSpatializerCompatibleAudioDevice", "removeSpatializerCompatibleAudioDevice",
        "setDesiredHeadTrackingMode", "getDesiredHeadTrackingMode", "getSupportedHeadTrackingModes", "getActualHeadTrackingMode",
        "setSpatializerGlobalTransform", "recenterHeadTracker", "setSpatializerParameter", "getSpatializerParameter",
        "getSpatializerOutput", "registerSpatializerOutputCallback", "unregisterSpatializerOutputCallback", "isVolumeFixed",
        "getDefaultVolumeInfo", "isPstnCallAudioInterceptable", "muteAwaitConnection", "cancelMuteAwaitConnection",
        "getMutingExpectedDevice", "registerMuteAwaitConnectionDispatcher", "setTestDeviceConnectionState", "registerDeviceVolumeBehaviorDispatcher",
        "getFocusStack", "sendFocusLossAndUpdate", "sendFocusLoss", "addAssistantServicesUids",
        "removeAssistantServicesUids", "setActiveAssistantServiceUids", "getAssistantServicesUids", "getActiveAssistantServiceUids",
        "registerDeviceVolumeDispatcherForAbsoluteVolume", "getHalVersion", "setPreferredMixerAttributes", "clearPreferredMixerAttributes",
        "registerPreferredMixerAttributesDispatcher", "unregisterPreferredMixerAttributesDispatcher", "supportsBluetoothVariableLatency", "setBluetoothVariableLatencyEnabled",
        "isBluetoothVariableLatencyEnabled", "registerLoudnessCodecUpdatesDispatcher", "unregisterLoudnessCodecUpdatesDispatcher", "startLoudnessCodecUpdates",
        "stopLoudnessCodecUpdates", "addLoudnessCodecInfo", "removeLoudnessCodecInfo", "getLoudnessParams",
        "setFadeManagerConfigurationForFocusLoss", "clearFadeManagerConfigurationForFocusLoss", "getFadeManagerConfigurationForFocusLoss", "shouldNotificationSoundPlay",
        "setEnableHardening",
    ]),
    ("android.media.ICapturePresetDevicesRoleDispatcher", &[
        "dispatchDevicesRoleChanged",
    ]),
    ("android.media.ICaptureStateListener", &[
        "setCaptureState",
    ]),
    ("android.media.ICommunicationDeviceDispatcher", &[
        "dispatchCommunicationDeviceChanged",
    ]),
    ("android.media.IDeviceVolumeBehaviorDispatcher", &[
        "dispatchDeviceVolumeBehaviorChanged",
    ]),
    ("android.media.IDevicesForAttributesCallback", &[
        "onDevicesForAttributesChanged",
    ]),
    ("android.media.ILoudnessCodecUpdatesDispatcher", &[
        "dispatchLoudnessCodecParameterChange",
    ]),
    ("android.media.IMediaHTTPConnection", &[
        "connect", "disconnect", "readAt", "getSize",
        "getMIMEType", "getUri",
    ]),
    ("android.media.IMediaHTTPService", &[
        "makeHTTPConnection",
    ]),
    ("android.media.IMediaResourceMonitor", &[
        "notifyResourceGranted",
    ]),
    ("android.media.IMediaRoute2ProviderService", &[
        "setCallback", "updateDiscoveryPreference", "setRouteVolume", "requestCreateSession",
        "requestCreateSystemMediaSession", "selectRoute", "deselectRoute", "transferToRoute",
        "setSessionVolume", "releaseSession",
    ]),
    ("android.media.IMediaRoute2ProviderServiceCallback", &[
        "notifyProviderUpdated", "notifySessionCreated", "notifySessionsUpdated", "notifySessionReleased",
        "notifyRequestFailed",
    ]),
    ("android.media.IMediaRouter2", &[
        "notifyRouterRegistered", "notifyRoutesUpdated", "notifySessionCreated", "notifySessionInfoChanged",
        "notifySessionReleased", "requestCreateSessionByManager", "notifyDeviceSuggestionsUpdated",
    ]),
    ("android.media.IMediaRouter2Manager", &[
        "notifySessionCreated", "notifySessionUpdated", "notifySessionReleased", "notifyDiscoveryPreferenceChanged",
        "notifyRouteListingPreferenceChange", "notifyDeviceSuggestionsUpdated", "notifyRoutesUpdated", "notifyRequestFailed",
        "invalidateInstance",
    ]),
    ("android.media.IMediaRouterClient", &[
        "onStateChanged", "onRestoreRoute", "onGroupRouteSelected",
    ]),
    ("android.media.IMediaRouterService", &[
        "registerClientAsUser", "unregisterClient", "registerClientGroupId", "getState",
        "isPlaybackActive", "setBluetoothA2dpOn", "setDiscoveryRequest", "setSelectedRoute",
        "requestSetVolume", "requestUpdateVolume", "getSystemRoutes", "getSystemSessionInfo",
        "showMediaOutputSwitcherWithRouter2", "registerRouter2", "unregisterRouter2", "updateScanningStateWithRouter2",
        "setDiscoveryRequestWithRouter2", "setRouteListingPreference", "setRouteVolumeWithRouter2", "requestCreateSessionWithRouter2",
        "selectRouteWithRouter2", "deselectRouteWithRouter2", "transferToRouteWithRouter2", "setSessionVolumeWithRouter2",
        "releaseSessionWithRouter2", "setDeviceSuggestionsWithRouter2", "getDeviceSuggestionsWithRouter2", "getRemoteSessions",
        "getSystemSessionInfoForPackage", "registerManager", "registerProxyRouter", "unregisterManager",
        "setRouteVolumeWithManager", "updateScanningState", "requestCreateSessionWithManager", "selectRouteWithManager",
        "deselectRouteWithManager", "transferToRouteWithManager", "setSessionVolumeWithManager", "releaseSessionWithManager",
        "showMediaOutputSwitcherWithProxyRouter", "setDeviceSuggestionsWithManager", "getDeviceSuggestionsWithManager",
    ]),
    ("android.media.IMediaScannerListener", &[
        "scanCompleted",
    ]),
    ("android.media.IMediaScannerService", &[
        "requestScanFile", "scanFile",
    ]),
    ("android.media.IMuteAwaitConnectionCallback", &[
        "dispatchOnMutedUntilConnection", "dispatchOnUnmutedEvent",
    ]),
    ("android.media.INativeAudioVolumeGroupCallback", &[
        "onAudioVolumeGroupChanged",
    ]),
    ("android.media.INativeSpatializerCallback", &[
        "onLevelChanged", "onOutputChanged",
    ]),
    ("android.media.INearbyMediaDevicesProvider", &[
        "", "", "registerNearbyDevicesCallback", "unregisterNearbyDevicesCallback",
    ]),
    ("android.media.INearbyMediaDevicesUpdateCallback", &[
        "onDevicesUpdated",
    ]),
    ("android.media.IPlaybackConfigDispatcher", &[
        "dispatchPlaybackConfigChange",
    ]),
    ("android.media.IPlayer", &[
        "start", "pause", "stop", "setVolume",
        "setPan", "setStartDelayMs", "applyVolumeShaper",
    ]),
    ("android.media.IPreferredMixerAttributesDispatcher", &[
        "dispatchPrefMixerAttributesChanged",
    ]),
    ("android.media.IRecordingConfigDispatcher", &[
        "dispatchRecordingConfigChange",
    ]),
    ("android.media.IRemoteDisplayCallback", &[
        "onStateChanged",
    ]),
    ("android.media.IRemoteDisplayProvider", &[
        "setCallback", "setDiscoveryMode", "connect", "disconnect",
        "setVolume", "adjustVolume",
    ]),
    ("android.media.IRemoteSessionCallback", &[
        "onVolumeChanged", "onSessionChanged",
    ]),
    ("android.media.IRemoteVolumeObserver", &[
        "dispatchRemoteVolumeUpdate",
    ]),
    ("android.media.IResourceManagerClient", &[
        "reclaimResource", "getName",
    ]),
    ("android.media.IResourceManagerService", &[
        "config", "addResource", "updateResource", "removeResource",
        "removeClient", "reclaimResource", "overridePid", "overrideProcessInfo",
        "markClientForPendingRemoval", "reclaimResourcesFromClientsPendingRemoval", "notifyClientCreated", "notifyClientStarted",
        "notifyClientStopped", "notifyClientConfigChanged", "getMediaResourceUsageReport",
    ]),
    ("android.media.IRingtonePlayer", &[
        "play", "playWithVolumeShaping", "stop", "isPlaying",
        "setPlaybackProperties", "playAsync", "stopAsync", "getTitle",
        "openRingtone",
    ]),
    ("android.media.ISoundDose", &[
        "setOutputRs2UpperBound", "resetCsd", "updateAttenuation", "setCsdEnabled",
        "initCachedAudioDeviceCategories", "setAudioDeviceCategory", "getOutputRs2UpperBound", "getCsd",
        "isSoundDoseHalSupported", "forceUseFrameworkMel", "forceComputeCsdOnAllDevices",
    ]),
    ("android.media.ISoundDoseCallback", &[
        "onMomentaryExposure", "onNewCsdValue",
    ]),
    ("android.media.ISpatializer", &[
        "release", "getSupportedLevels", "setLevel", "getLevel",
        "isHeadTrackingSupported", "getSupportedHeadTrackingModes", "setDesiredHeadTrackingMode", "getActualHeadTrackingMode",
        "recenterHeadTracker", "setGlobalTransform", "setHeadSensor", "setScreenSensor",
        "setDisplayOrientation", "setHingeAngle", "setFoldState", "getSupportedModes",
        "registerHeadTrackingCallback", "setParameter", "getParameter", "getOutput",
        "getSpatializedChannelMasks",
    ]),
    ("android.media.ISpatializerCallback", &[
        "dispatchSpatializerEnabledChanged", "dispatchSpatializerAvailableChanged",
    ]),
    ("android.media.ISpatializerHeadToSoundStagePoseCallback", &[
        "dispatchPoseChanged",
    ]),
    ("android.media.ISpatializerHeadTrackerAvailableCallback", &[
        "dispatchSpatializerHeadTrackerAvailable",
    ]),
    ("android.media.ISpatializerHeadTrackingCallback", &[
        "onHeadTrackingModeChanged", "onHeadToSoundStagePoseUpdated",
    ]),
    ("android.media.ISpatializerHeadTrackingModeCallback", &[
        "dispatchSpatializerActualHeadTrackingModeChanged", "dispatchSpatializerDesiredHeadTrackingModeChanged",
    ]),
    ("android.media.ISpatializerOutputCallback", &[
        "dispatchSpatializerOutputChanged",
    ]),
    ("android.media.IStrategyNonDefaultDevicesDispatcher", &[
        "dispatchNonDefDevicesChanged",
    ]),
    ("android.media.IStrategyPreferredDevicesDispatcher", &[
        "dispatchPrefDevicesChanged",
    ]),
    ("android.media.IStreamAliasingDispatcher", &[
        "dispatchStreamAliasingChanged",
    ]),
    ("android.media.IVolumeController", &[
        "displaySafeVolumeWarning", "volumeChanged", "masterMuteChanged", "setLayoutDirection",
        "dismiss", "setA11yMode", "displayCsdWarning",
    ]),
    ("android.media.audiopolicy.IAudioPolicyCallback", &[
        "notifyAudioFocusGrant", "notifyAudioFocusLoss", "notifyAudioFocusRequest", "notifyAudioFocusAbandon",
        "notifyMixStateUpdate", "notifyVolumeAdjust", "notifyUnregistration",
    ]),
    ("android.media.audiopolicy.IAudioVolumeChangeDispatcher", &[
        "onAudioVolumeGroupChanged",
    ]),
    ("android.media.metrics.IMediaMetricsManager", &[
        "reportPlaybackMetrics", "getPlaybackSessionId", "getRecordingSessionId", "reportNetworkEvent",
        "reportPlaybackErrorEvent", "reportPlaybackStateEvent", "reportTrackChangeEvent", "reportEditingEndedEvent",
        "getTranscodingSessionId", "getEditingSessionId", "getBundleSessionId", "reportBundleMetrics",
        "releaseSessionId",
    ]),
    ("android.media.midi.IBluetoothMidiService", &[
        "addBluetoothDevice",
    ]),
    ("android.media.midi.IMidiDeviceListener", &[
        "onDeviceAdded", "onDeviceRemoved", "onDeviceStatusChanged",
    ]),
    ("android.media.midi.IMidiDeviceOpenCallback", &[
        "onDeviceOpened",
    ]),
    ("android.media.midi.IMidiDeviceServer", &[
        "openInputPort", "openOutputPort", "closePort", "closeDevice",
        "connectPorts", "getDeviceInfo", "setDeviceInfo",
    ]),
    ("android.media.midi.IMidiManager", &[
        "getDevices", "getDevicesForTransport", "registerListener", "unregisterListener",
        "openDevice", "openBluetoothDevice", "closeDevice", "registerDeviceServer",
        "unregisterDeviceServer", "getServiceDeviceInfo", "getDeviceStatus", "setDeviceStatus",
        "updateTotalBytes",
    ]),
    ("android.media.musicrecognition.IMusicRecognitionAttributionTagCallback", &[
        "onAttributionTag",
    ]),
    ("android.media.musicrecognition.IMusicRecognitionManager", &[
        "beginRecognition",
    ]),
    ("android.media.musicrecognition.IMusicRecognitionManagerCallback", &[
        "onRecognitionSucceeded", "onRecognitionFailed", "onAudioStreamClosed",
    ]),
    ("android.media.musicrecognition.IMusicRecognitionService", &[
        "onAudioStreamStarted", "getAttributionTag",
    ]),
    ("android.media.musicrecognition.IMusicRecognitionServiceCallback", &[
        "onRecognitionSucceeded", "onRecognitionFailed",
    ]),
    ("android.media.projection.IMediaProjection", &[
        "start", "stop", "canProjectAudio", "canProjectVideo",
        "canProjectSecureVideo", "applyVirtualDisplayFlags", "registerCallback", "unregisterCallback",
        "getLaunchCookie", "getTaskId", "getDisplayId", "setLaunchCookie",
        "setTaskId", "isValid", "notifyVirtualDisplayCreated",
    ]),
    ("android.media.projection.IMediaProjectionCallback", &[
        "onStop", "onCapturedContentResize", "onCapturedContentVisibilityChanged",
    ]),
    ("android.media.projection.IMediaProjectionManager", &[
        "hasProjectionPermission", "createProjection", "getProjection", "isCurrentProjection",
        "requestConsentForInvalidProjection", "getActiveProjectionInfo", "stopActiveProjection", "notifyActiveProjectionCapturedContentVisibilityChanged",
        "addCallback", "removeCallback", "setContentRecordingSession", "setUserReviewGrantedConsentResult",
        "notifyPermissionRequestInitiated", "notifyPermissionRequestDisplayed", "notifyPermissionRequestCancelled", "notifyAppSelectorDisplayed",
        "notifyWindowingModeChanged", "notifyCaptureBoundsChanged",
    ]),
    ("android.media.projection.IMediaProjectionWatcherCallback", &[
        "onStart", "onStop", "onRecordingSessionSet", "onMediaProjectionEvent",
    ]),
    ("android.media.quality.IActiveProcessingPictureListener", &[
        "onActiveProcessingPicturesChanged",
    ]),
    ("android.media.quality.IAmbientBacklightCallback", &[
        "onAmbientBacklightEvent",
    ]),
    ("android.media.quality.IMediaQualityManager", &[
        "createPictureProfile", "updatePictureProfile", "removePictureProfile", "setDefaultPictureProfile",
        "getPictureProfile", "getPictureProfilesByPackage", "getAvailablePictureProfiles", "getPictureProfilePackageNames",
        "getPictureProfileAllowList", "setPictureProfileAllowList", "getPictureProfileHandle", "getPictureProfileHandleValue",
        "getDefaultPictureProfileHandleValue", "notifyPictureProfileHandleSelection", "getPictureProfileForTvInput", "createSoundProfile",
        "updateSoundProfile", "removeSoundProfile", "setDefaultSoundProfile", "getSoundProfile",
        "getSoundProfilesByPackage", "getAvailableSoundProfiles", "getSoundProfilePackageNames", "getSoundProfileAllowList",
        "setSoundProfileAllowList", "getSoundProfileHandle", "registerPictureProfileCallback", "registerSoundProfileCallback",
        "registerAmbientBacklightCallback", "registerActiveProcessingPictureListener", "getParameterCapabilities", "isSupported",
        "setAutoPictureQualityEnabled", "isAutoPictureQualityEnabled", "setSuperResolutionEnabled", "isSuperResolutionEnabled",
        "setAutoSoundQualityEnabled", "isAutoSoundQualityEnabled", "setAmbientBacklightSettings", "setAmbientBacklightEnabled",
        "isAmbientBacklightEnabled",
    ]),
    ("android.media.quality.IPictureProfileCallback", &[
        "onPictureProfileAdded", "onPictureProfileUpdated", "onPictureProfileRemoved", "onParameterCapabilitiesChanged",
        "onError",
    ]),
    ("android.media.quality.ISoundProfileCallback", &[
        "onSoundProfileAdded", "onSoundProfileUpdated", "onSoundProfileRemoved", "onParameterCapabilitiesChanged",
        "onError",
    ]),
    ("android.media.session.IActiveSessionsListener", &[
        "onActiveSessionsChanged",
    ]),
    ("android.media.session.IOnMediaKeyEventDispatchedListener", &[
        "onMediaKeyEventDispatched",
    ]),
    ("android.media.session.IOnMediaKeyEventSessionChangedListener", &[
        "onMediaKeyEventSessionChanged",
    ]),
    ("android.media.session.IOnMediaKeyListener", &[
        "onMediaKey",
    ]),
    ("android.media.session.IOnVolumeKeyLongPressListener", &[
        "onVolumeKeyLongPress",
    ]),
    ("android.media.session.ISession", &[
        "sendEvent", "getController", "setFlags", "setActive",
        "setMediaButtonReceiver", "setMediaButtonBroadcastReceiver", "setLaunchPendingIntent", "destroySession",
        "setMetadata", "setPlaybackState", "resetQueue", "getBinderForSetQueue",
        "setQueueTitle", "setExtras", "setRatingType", "setPlaybackToLocal",
        "setPlaybackToRemote", "setCurrentVolume",
    ]),
    ("android.media.session.ISession2TokensListener", &[
        "onSession2TokensChanged",
    ]),
    ("android.media.session.ISessionCallback", &[
        "onCommand", "onMediaButton", "onMediaButtonFromController", "onPrepare",
        "onPrepareFromMediaId", "onPrepareFromSearch", "onPrepareFromUri", "onPlay",
        "onPlayFromMediaId", "onPlayFromSearch", "onPlayFromUri", "onSkipToTrack",
        "onPause", "onStop", "onNext", "onPrevious",
        "onFastForward", "onRewind", "onSeekTo", "onRate",
        "onSetPlaybackSpeed", "onCustomAction", "onAdjustVolume", "onSetVolumeTo",
    ]),
    ("android.media.session.ISessionController", &[
        "sendCommand", "sendMediaButton", "registerCallback", "unregisterCallback",
        "getPackageName", "getTag", "getSessionInfo", "getLaunchPendingIntent",
        "getFlags", "getVolumeAttributes", "adjustVolume", "setVolumeTo",
        "prepare", "prepareFromMediaId", "prepareFromSearch", "prepareFromUri",
        "play", "playFromMediaId", "playFromSearch", "playFromUri",
        "skipToQueueItem", "pause", "stop", "next",
        "previous", "fastForward", "rewind", "seekTo",
        "rate", "setPlaybackSpeed", "sendCustomAction", "getMetadata",
        "getPlaybackState", "getQueue", "getQueueTitle", "getExtras",
        "getRatingType",
    ]),
    ("android.media.session.ISessionControllerCallback", &[
        "onEvent", "onSessionDestroyed", "onPlaybackStateChanged", "onMetadataChanged",
        "onQueueChanged", "onQueueTitleChanged", "onExtrasChanged", "onVolumeInfoChanged",
    ]),
    ("android.media.session.ISessionManager", &[
        "createSession", "getSessions", "getMediaKeyEventSession", "getMediaKeyEventSessionPackageName",
        "dispatchMediaKeyEvent", "dispatchMediaKeyEventToSessionAsSystemService", "dispatchVolumeKeyEvent", "dispatchVolumeKeyEventToSessionAsSystemService",
        "dispatchAdjustVolume", "addSessionsListener", "removeSessionsListener", "addSession2TokensListener",
        "removeSession2TokensListener", "registerRemoteSessionCallback", "unregisterRemoteSessionCallback", "isGlobalPriorityActive",
        "addOnMediaKeyEventDispatchedListener", "removeOnMediaKeyEventDispatchedListener", "addOnMediaKeyEventSessionChangedListener", "removeOnMediaKeyEventSessionChangedListener",
        "setOnVolumeKeyLongPressListener", "setOnMediaKeyListener", "isTrusted", "setCustomMediaKeyDispatcher",
        "setCustomMediaSessionPolicyProvider", "hasCustomMediaKeyDispatcher", "hasCustomMediaSessionPolicyProvider", "getSessionPolicies",
        "setSessionPolicies", "expireTempEngagedSessions",
    ]),
    ("android.media.soundtrigger.ISoundTriggerDetectionService", &[
        "setClient", "removeClient", "onGenericRecognitionEvent", "onError",
        "onStopOperation",
    ]),
    ("android.media.soundtrigger.ISoundTriggerDetectionServiceClient", &[
        "onOpFinished",
    ]),
    ("android.media.soundtrigger_middleware.IAcknowledgeEvent", &[
        "eventReceived",
    ]),
    ("android.media.soundtrigger_middleware.IInjectGlobalEvent", &[
        "triggerRestart", "setResourceContention", "triggerOnResourcesAvailable",
    ]),
    ("android.media.soundtrigger_middleware.IInjectModelEvent", &[
        "triggerUnloadModel",
    ]),
    ("android.media.soundtrigger_middleware.IInjectRecognitionEvent", &[
        "triggerRecognitionEvent", "triggerAbortRecognition",
    ]),
    ("android.media.soundtrigger_middleware.ISoundTriggerCallback", &[
        "onRecognition", "onPhraseRecognition", "onResourcesAvailable", "onModelUnloaded",
        "onModuleDied",
    ]),
    ("android.media.soundtrigger_middleware.ISoundTriggerInjection", &[
        "registerGlobalEventInjection", "onRestarted", "onFrameworkDetached", "onClientAttached",
        "onClientDetached", "onSoundModelLoaded", "onParamSet", "onRecognitionStarted",
        "onRecognitionStopped", "onSoundModelUnloaded", "onPreempted",
    ]),
    ("android.media.soundtrigger_middleware.ISoundTriggerMiddlewareService", &[
        "listModulesAsOriginator", "listModulesAsMiddleman", "attachAsOriginator", "attachAsMiddleman",
        "attachFakeHalInjection",
    ]),
    ("android.media.soundtrigger_middleware.ISoundTriggerModule", &[
        "loadModel", "loadPhraseModel", "unloadModel", "startRecognition",
        "stopRecognition", "forceRecognitionEvent", "setModelParameter", "getModelParameter",
        "queryModelParameterSupport", "detach",
    ]),
    ("android.media.tv.ITvInputClient", &[
        "onSessionCreated", "onSessionReleased", "onSessionEvent", "onChannelRetuned",
        "onAudioPresentationsChanged", "onAudioPresentationSelected", "onTracksChanged", "onTrackSelected",
        "onVideoAvailable", "onVideoUnavailable", "onVideoFreezeUpdated", "onContentAllowed",
        "onContentBlocked", "onLayoutSurface", "onTimeShiftStatusChanged", "onTimeShiftStartPositionChanged",
        "onTimeShiftCurrentPositionChanged", "onAitInfoUpdated", "onSignalStrength", "onCueingMessageAvailability",
        "onTimeShiftMode", "onAvailableSpeeds", "onTvMessage", "onTuned",
        "onRecordingStopped", "onError", "onBroadcastInfoResponse", "onAdResponse",
        "onAdBufferConsumed", "onTvInputSessionData",
    ]),
    ("android.media.tv.ITvInputHardware", &[
        "setSurface", "setStreamVolume", "overrideAudioSink",
    ]),
    ("android.media.tv.ITvInputHardwareCallback", &[
        "onReleased", "onStreamConfigChanged",
    ]),
    ("android.media.tv.ITvInputManager", &[
        "getTvInputList", "getTvInputInfo", "updateTvInputInfo", "getTvInputState",
        "getAvailableExtensionInterfaceNames", "getExtensionInterface", "getTvContentRatingSystemList", "registerCallback",
        "unregisterCallback", "isParentalControlsEnabled", "setParentalControlsEnabled", "isRatingBlocked",
        "getBlockedRatings", "addBlockedRating", "removeBlockedRating", "createSession",
        "releaseSession", "getClientPid", "getClientPriority", "getClientUserId",
        "setMainSession", "setSurface", "dispatchSurfaceChanged", "setVolume",
        "tune", "setCaptionEnabled", "selectTrack", "selectAudioPresentation",
        "setInteractiveAppNotificationEnabled", "sendAppPrivateCommand", "createOverlayView", "relayoutOverlayView",
        "removeOverlayView", "unblockContent", "timeShiftPlay", "timeShiftPause",
        "timeShiftResume", "timeShiftSeekTo", "timeShiftSetPlaybackParams", "timeShiftSetMode",
        "timeShiftEnablePositionTracking", "getCurrentTunedInfos", "startRecording", "stopRecording",
        "pauseRecording", "resumeRecording", "resumePlayback", "stopPlayback",
        "requestBroadcastInfo", "removeBroadcastInfo", "requestAd", "notifyAdBufferReady",
        "notifyTvMessage", "setTvMessageEnabled", "getHardwareList", "acquireTvInputHardware",
        "releaseTvInputHardware", "getAvailableTvStreamConfigList", "captureFrame", "isSingleSessionActive",
        "getDvbDeviceList", "openDvbDevice", "sendTvInputNotifyIntent", "requestChannelBrowsable",
        "addHardwareDevice", "removeHardwareDevice", "setVideoFrozen", "notifyTvAdSessionData",
    ]),
    ("android.media.tv.ITvInputManagerCallback", &[
        "onInputAdded", "onInputRemoved", "onInputUpdated", "onInputStateChanged",
        "onTvInputInfoUpdated", "onCurrentTunedInfosUpdated",
    ]),
    ("android.media.tv.ITvInputService", &[
        "registerCallback", "unregisterCallback", "createSession", "createRecordingSession",
        "getAvailableExtensionInterfaceNames", "getExtensionInterface", "getExtensionInterfacePermission", "notifyHardwareAdded",
        "notifyHardwareRemoved", "notifyHdmiDeviceAdded", "notifyHdmiDeviceRemoved", "notifyHdmiDeviceUpdated",
    ]),
    ("android.media.tv.ITvInputServiceCallback", &[
        "addHardwareInput", "addHdmiInput", "removeHardwareInput",
    ]),
    ("android.media.tv.ITvInputSession", &[
        "release", "setMain", "setSurface", "dispatchSurfaceChanged",
        "setVolume", "tune", "setCaptionEnabled", "selectAudioPresentation",
        "selectTrack", "setInteractiveAppNotificationEnabled", "appPrivateCommand", "createOverlayView",
        "relayoutOverlayView", "removeOverlayView", "unblockContent", "timeShiftPlay",
        "timeShiftPause", "timeShiftResume", "timeShiftSeekTo", "timeShiftSetPlaybackParams",
        "timeShiftSetMode", "timeShiftEnablePositionTracking", "resumePlayback", "stopPlayback",
        "startRecording", "stopRecording", "pauseRecording", "resumeRecording",
        "requestBroadcastInfo", "removeBroadcastInfo", "requestAd", "notifyAdBufferReady",
        "notifyTvMessage", "setTvMessageEnabled", "setVideoFrozen", "notifyTvAdSessionData",
    ]),
    ("android.media.tv.ITvInputSessionCallback", &[
        "onSessionCreated", "onSessionEvent", "onChannelRetuned", "onAudioPresentationsChanged",
        "onAudioPresentationSelected", "onTracksChanged", "onTrackSelected", "onVideoAvailable",
        "onVideoUnavailable", "onVideoFreezeUpdated", "onContentAllowed", "onContentBlocked",
        "onLayoutSurface", "onTimeShiftStatusChanged", "onTimeShiftStartPositionChanged", "onTimeShiftCurrentPositionChanged",
        "onAitInfoUpdated", "onSignalStrength", "onCueingMessageAvailability", "onTimeShiftMode",
        "onAvailableSpeeds", "onTuned", "onRecordingStopped", "onError",
        "onBroadcastInfoResponse", "onAdResponse", "onAdBufferConsumed", "onTvMessage",
        "onTvInputSessionData",
    ]),
    ("android.media.tv.ITvRemoteProvider", &[
        "setRemoteServiceInputSink", "onInputBridgeConnected",
    ]),
    ("android.media.tv.ITvRemoteServiceInput", &[
        "openInputBridge", "closeInputBridge", "clearInputBridge", "sendTimestamp",
        "sendKeyDown", "sendKeyUp", "sendPointerDown", "sendPointerUp",
        "sendPointerSync", "openGamepadBridge", "sendGamepadKeyDown", "sendGamepadKeyUp",
        "sendGamepadAxisValue",
    ]),
    ("android.media.tv.ad.ITvAdClient", &[
        "onSessionCreated", "onSessionReleased", "onLayoutSurface", "onRequestCurrentVideoBounds",
        "onRequestCurrentChannelUri", "onRequestTrackInfoList", "onRequestCurrentTvInputId", "onRequestSigning",
        "onTvAdSessionData",
    ]),
    ("android.media.tv.ad.ITvAdManager", &[
        "getTvAdServiceList", "sendAppLinkCommand", "createSession", "releaseSession",
        "startAdService", "stopAdService", "resetAdService", "setSurface",
        "dispatchSurfaceChanged", "sendCurrentVideoBounds", "sendCurrentChannelUri", "sendTrackInfoList",
        "sendCurrentTvInputId", "sendSigningResult", "notifyError", "notifyTvMessage",
        "registerCallback", "unregisterCallback", "createMediaView", "relayoutMediaView",
        "removeMediaView", "notifyTvInputSessionData",
    ]),
    ("android.media.tv.ad.ITvAdManagerCallback", &[
        "onAdServiceAdded", "onAdServiceRemoved", "onAdServiceUpdated",
    ]),
    ("android.media.tv.ad.ITvAdService", &[
        "registerCallback", "unregisterCallback", "createSession", "sendAppLinkCommand",
    ]),
    ("android.media.tv.ad.ITvAdSession", &[
        "release", "startAdService", "stopAdService", "resetAdService",
        "setSurface", "dispatchSurfaceChanged", "sendCurrentVideoBounds", "sendCurrentChannelUri",
        "sendTrackInfoList", "sendCurrentTvInputId", "sendSigningResult", "notifyError",
        "notifyTvMessage", "createMediaView", "relayoutMediaView", "removeMediaView",
        "notifyTvInputSessionData",
    ]),
    ("android.media.tv.ad.ITvAdSessionCallback", &[
        "onSessionCreated", "onLayoutSurface", "onRequestCurrentVideoBounds", "onRequestCurrentChannelUri",
        "onRequestTrackInfoList", "onRequestCurrentTvInputId", "onRequestSigning", "onTvAdSessionData",
    ]),
    ("android.media.tv.extension.analog.IAnalogAttributeInterface", &[
        "getVersion", "setColorSystemCapability", "getColorSystemCapability",
    ]),
    ("android.media.tv.extension.cam.ICamAppInfoListener", &[
        "onCamAppInfoChanged",
    ]),
    ("android.media.tv.extension.cam.ICamAppInfoService", &[
        "addCamAppInfoListener", "removeCamAppInfoListener", "getCamAppInfo",
    ]),
    ("android.media.tv.extension.cam.ICamDrmInfoListener", &[
        "onCamDrmInfoChanged",
    ]),
    ("android.media.tv.extension.cam.ICamHostControlAskReleaseReplyCallback", &[
        "onAskReleaseReply",
    ]),
    ("android.media.tv.extension.cam.ICamHostControlInfoListener", &[
        "onCamHostControlInfoChanged",
    ]),
    ("android.media.tv.extension.cam.ICamHostControlService", &[
        "addCamHostcontrolInfoListener", "removeCamHostcontrolInfoListener", "sendCamHostControlAskRelease", "setHostControlMode",
    ]),
    ("android.media.tv.extension.cam.ICamHostControlTuneQuietlyFlag", &[
        "addHcTuneQuietlyFlagListener", "removeHcTuneQuietlyFlagListener", "getHcTuneQuietlyFlag",
    ]),
    ("android.media.tv.extension.cam.ICamHostControlTuneQuietlyFlagListener", &[
        "onHcTuneQuietlyFlagChanged",
    ]),
    ("android.media.tv.extension.cam.ICamInfoListener", &[
        "onCamInfoChanged", "onSlotInfoChanged", "onNewTypeCamInsert",
    ]),
    ("android.media.tv.extension.cam.ICamMonitoringService", &[
        "addCamInfoListener", "removeCamInfoListener", "getCamInfo", "getSlotInfo",
        "getSlotIds", "isCamSupported",
    ]),
    ("android.media.tv.extension.cam.ICamPinCapabilityListener", &[
        "onCamPinCapabilityChanged",
    ]),
    ("android.media.tv.extension.cam.ICamPinService", &[
        "addCamPinCapabilityListener", "removeCamPinCapabilityListener", "requestCamPinValidation", "getCamPinCapability",
    ]),
    ("android.media.tv.extension.cam.ICamPinStatusListener", &[
        "onCamPinValidationReply",
    ]),
    ("android.media.tv.extension.cam.ICamProfileInterface", &[
        "getCamServiceUpdateInfo", "requestResendProfileInfoBroadcastACON",
    ]),
    ("android.media.tv.extension.cam.IContentControlService", &[
        "addCamDrmInfoListener", "removeCamDrmInfoListener", "getCamDrmInfo",
    ]),
    ("android.media.tv.extension.cam.IEnterMenuErrorCallback", &[
        "onAppInfoEnterMenuError",
    ]),
    ("android.media.tv.extension.cam.IMmiInterface", &[
        "openSession", "appInfoEnterMenu",
    ]),
    ("android.media.tv.extension.cam.IMmiSession", &[
        "setMenuListAnswer", "setEnquiryAnswer", "closeMmi", "close",
    ]),
    ("android.media.tv.extension.cam.IMmiStatusCallback", &[
        "onMmiEnq", "onMmiListMenu", "onMmiClose",
    ]),
    ("android.media.tv.extension.clienttoken.IClientToken", &[
        "generateClientToken",
    ]),
    ("android.media.tv.extension.event.IEventDownload", &[
        "createSession",
    ]),
    ("android.media.tv.extension.event.IEventDownloadListener", &[
        "onCompleted",
    ]),
    ("android.media.tv.extension.event.IEventDownloadSession", &[
        "isBarkerOrSequentialDownloadByServiceType", "isBarkerOrSequentialDownloadByServiceRecord", "startTuningMultiplex", "setActiveWindowChannelInfo",
        "cancel", "release",
    ]),
    ("android.media.tv.extension.event.IEventMonitor", &[
        "getPresentEventInfo", "addPresentEventInfoListener", "removePresentEventInfoListener", "getFollowingEventInfo",
        "addFollowingEventInfoListener", "removeFollowingEventInfoListener", "getSdtGuidanceInfo", "setBgmTuneChannelInfo",
    ]),
    ("android.media.tv.extension.event.IEventMonitorListener", &[
        "onInfoChanged",
    ]),
    ("android.media.tv.extension.oad.IOadUpdateInterface", &[
        "setOadStatus", "getOadStatus", "startScan", "stopScan",
        "startDetect", "stopDetect", "startDownload", "stopDownload",
        "getSoftwareVersion",
    ]),
    ("android.media.tv.extension.pvr.IDeleteRecordedContentsCallback", &[
        "onRecordedContentsDeleted",
    ]),
    ("android.media.tv.extension.pvr.IGetInfoRecordedContentsCallback", &[
        "onRecordedContentsGetInfo",
    ]),
    ("android.media.tv.extension.pvr.IRecordedContents", &[
        "deleteRecordedContents", "getRecordedContentsLockInfoSync", "getRecordedContentsLockInfoAsync",
    ]),
    ("android.media.tv.extension.rating.IDownloadableRatingTableMonitor", &[
        "getTable",
    ]),
    ("android.media.tv.extension.rating.IPmtRatingInterface", &[
        "getPmtRating", "addPmtRatingListener", "removePmtRatingListener",
    ]),
    ("android.media.tv.extension.rating.IPmtRatingListener", &[
        "onPmtRatingChanged",
    ]),
    ("android.media.tv.extension.rating.IProgramRatingInfo", &[
        "addProgramRatingInfoListener", "removeProgramRatingInfoListener", "getProgramRatingInfo",
    ]),
    ("android.media.tv.extension.rating.IProgramRatingInfoListener", &[
        "onProgramInfoChanged",
    ]),
    ("android.media.tv.extension.rating.IRatingInterface", &[
        "getRRTRatingInfo", "setRRTRatingInfo", "setResetRrt5",
    ]),
    ("android.media.tv.extension.rating.IVbiRatingInterface", &[
        "getVbiRating", "addVbiRatingListener", "removeVbiRatingListener",
    ]),
    ("android.media.tv.extension.rating.IVbiRatingListener", &[
        "onVbiRatingChanged",
    ]),
    ("android.media.tv.extension.scan.IFavoriteNetwork", &[
        "getFavoriteNetworks", "setFavoriteNetwork", "setListener",
    ]),
    ("android.media.tv.extension.scan.IFavoriteNetworkListener", &[
        "onDetectFavoriteNetwork",
    ]),
    ("android.media.tv.extension.scan.IHDPlusInfo", &[
        "setHDPlusInfo",
    ]),
    ("android.media.tv.extension.scan.ILcnConflict", &[
        "getLcnConflictGroups", "resolveLcnConflict", "setListener",
    ]),
    ("android.media.tv.extension.scan.ILcnConflictListener", &[
        "onDetectLcnConflict",
    ]),
    ("android.media.tv.extension.scan.ILcnV2ChannelList", &[
        "getLcnV2ChannelLists", "setLcnV2ChannelList", "setListener",
    ]),
    ("android.media.tv.extension.scan.ILcnV2ChannelListListener", &[
        "onDetectLcnV2ChannelList",
    ]),
    ("android.media.tv.extension.scan.IOperatorDetection", &[
        "setOperatorDetection", "setListener",
    ]),
    ("android.media.tv.extension.scan.IOperatorDetectionListener", &[
        "onDetectOperatorDetectionList",
    ]),
    ("android.media.tv.extension.scan.IRegionChannelList", &[
        "setRegionChannelList", "setListener",
    ]),
    ("android.media.tv.extension.scan.IRegionChannelListListener", &[
        "onDetectRegionChannelList",
    ]),
    ("android.media.tv.extension.scan.IScanInterface", &[
        "createSession", "getParameters",
    ]),
    ("android.media.tv.extension.scan.IScanListener", &[
        "onEvent", "onScanProgress", "onScanCompleted", "onStoreCompleted",
    ]),
    ("android.media.tv.extension.scan.IScanSatSearch", &[
        "setCustomizedLnb",
    ]),
    ("android.media.tv.extension.scan.IScanSession", &[
        "startScan", "resetScan", "cancelScan", "getAvailableExtensionInterfaceNames",
        "getExtensionInterface", "clearServiceList", "storeServiceList", "getServiceInfo",
        "getServiceInfoIdList", "getServiceInfoList", "updateServiceInfo", "updateServiceInfoByList",
        "getServiceLists", "setServiceList", "getPackageData", "setPackage",
        "getCountryRegionData", "setCountryRegion", "getRegionData", "setRegion",
        "getSessionToken", "release",
    ]),
    ("android.media.tv.extension.scan.ITargetRegion", &[
        "getTargetRegions", "setTargetRegion", "setListener",
    ]),
    ("android.media.tv.extension.scan.ITargetRegionListener", &[
        "onDetectTargetRegion",
    ]),
    ("android.media.tv.extension.scan.ITkgsInfo", &[
        "setPrefServiceList", "setTkgsInfoListener",
    ]),
    ("android.media.tv.extension.scan.ITkgsInfoListener", &[
        "onServiceList", "onTableVersionUpdate", "onUserMessage",
    ]),
    ("android.media.tv.extension.scanbsu.IScanBackgroundServiceUpdate", &[
        "addBackgroundServiceUpdateListener", "removeBackgroundServiceUpdateListener",
    ]),
    ("android.media.tv.extension.scanbsu.IScanBackgroundServiceUpdateListener", &[
        "onChannelListUpdate", "onNetworkListUpdate", "onTransportStreamingListUpdate",
    ]),
    ("android.media.tv.extension.screenmode.IScreenModeSettings", &[
        "setScreenModeSettings", "getOverScanIndex", "getSupportApplyOverScan",
    ]),
    ("android.media.tv.extension.servicedb.IChannelListTransfer", &[
        "importChannelList", "exportChannelList",
    ]),
    ("android.media.tv.extension.servicedb.IServiceList", &[
        "getServiceListIds", "getServiceListInfo",
    ]),
    ("android.media.tv.extension.servicedb.IServiceListEdit", &[
        "open", "close", "commit", "userEditCommit",
        "getServiceInfoFromDatabase", "getServiceInfoListFromDatabase", "getServiceInfoIdsFromDatabase", "updateServiceInfoFromDatabase",
        "updateServiceInfoByListFromDatabase", "removeServiceInfoFromDatabase", "removeServiceInfoByListFromDatabase", "getServiceListChannelIds",
        "getServiceListInfoByChannelId", "getTransportStreamInfoList", "getTransportStreamInfoListForce", "getNetworkInfoList",
        "getSatelliteInfoList", "toRecordInfoByType", "putRecordIdList", "addPredefinedServiceListInfo",
        "addPredefinedChannelList", "addPredefinedSatInfo", "getServiceLogoUri", "getInstalledServiceListInfo",
        "getAllInstalledServiceListInfo",
    ]),
    ("android.media.tv.extension.servicedb.IServiceListEditListener", &[
        "onCompleted",
    ]),
    ("android.media.tv.extension.servicedb.IServiceListExportListener", &[
        "onExported",
    ]),
    ("android.media.tv.extension.servicedb.IServiceListExportSession", &[
        "exportServiceList", "release",
    ]),
    ("android.media.tv.extension.servicedb.IServiceListImportListener", &[
        "onImported", "onPreloaded",
    ]),
    ("android.media.tv.extension.servicedb.IServiceListImportSession", &[
        "importServiceList", "preload", "release",
    ]),
    ("android.media.tv.extension.servicedb.IServiceListSetChannelListListener", &[
        "onCompleted",
    ]),
    ("android.media.tv.extension.servicedb.IServiceListSetChannelListSession", &[
        "setChannelList", "release",
    ]),
    ("android.media.tv.extension.servicedb.IServiceListTransferInterface", &[
        "createExportSession", "createImportSession", "createSetChannelListSession",
    ]),
    ("android.media.tv.extension.signal.IAnalogAudioInfo", &[
        "getAnalogAudioInfo",
    ]),
    ("android.media.tv.extension.signal.IAudioSignalInfo", &[
        "getAudioSignalInfo", "notifyMtsSelectTrackFlag", "getMtsSelectedTrackId", "addAudioSignalInfoListener",
        "removeAudioSignalInfoListener",
    ]),
    ("android.media.tv.extension.signal.IAudioSignalInfoListener", &[
        "onAudioSignalInfoChanged",
    ]),
    ("android.media.tv.extension.signal.IHdmiSignalInfoListener", &[
        "onSignalInfoChanged", "onLowLatencyModeChanged",
    ]),
    ("android.media.tv.extension.signal.IHdmiSignalInterface", &[
        "addHdmiSignalInfoListener", "removeHdmiSignalInfoListener", "getHdmiSignalInfo", "setLowLatency",
        "setForceVrr",
    ]),
    ("android.media.tv.extension.signal.ITunerFrontendSignalInfoInterface", &[
        "getFrontendSignalInfo", "setFrontendSignalInfoListener",
    ]),
    ("android.media.tv.extension.signal.ITunerFrontendSignalInfoListener", &[
        "onFrontendStatusChanged",
    ]),
    ("android.media.tv.extension.signal.IVideoSignalInfo", &[
        "addVideoSignalInfoListener", "removeVideoSignalInfoListener", "getVideoSignalInfo",
    ]),
    ("android.media.tv.extension.signal.IVideoSignalInfoListener", &[
        "onVideoSignalInfoChanged",
    ]),
    ("android.media.tv.extension.teletext.IDataServiceSignalInfo", &[
        "getDataServiceSignalInfo", "addDataServiceSignalInfoListener", "removeDataServiceSignalInfoListener",
    ]),
    ("android.media.tv.extension.teletext.IDataServiceSignalInfoListener", &[
        "onDataServiceSignalInfoChanged",
    ]),
    ("android.media.tv.extension.teletext.ITeletextPageSubCode", &[
        "getTeletextPageNumber", "setTeleltextPageNumber", "getTeletextPageSubCode", "setTeletextPageSubCode",
        "getTeletextHasTopInfo", "getTeletextTopBlockList", "getTeletextTopGroupList", "getTeletextTopPageList",
    ]),
    ("android.media.tv.extension.time.IBroadcastTime", &[
        "getUtcTime", "getLocalTime", "getTimeZoneInfo", "getUtcTimePerStream",
        "getLocalTimePerStream",
    ]),
    ("android.media.tv.extension.tune.IChannelTunedInterface", &[
        "addChannelTunedListener", "removeChannelTunedListener",
    ]),
    ("android.media.tv.extension.tune.IChannelTunedListener", &[
        "onChannelTuned",
    ]),
    ("android.media.tv.extension.tune.IMuxTune", &[
        "createSession",
    ]),
    ("android.media.tv.extension.tune.IMuxTuneSession", &[
        "start", "stop", "release", "getSessionToken",
    ]),
    ("android.media.tv.interactive.ITvInteractiveAppClient", &[
        "onSessionCreated", "onSessionReleased", "onLayoutSurface", "onBroadcastInfoRequest",
        "onRemoveBroadcastInfo", "onSessionStateChanged", "onBiInteractiveAppCreated", "onTeletextAppStateChanged",
        "onAdBufferReady", "onCommandRequest", "onTimeShiftCommandRequest", "onSetVideoBounds",
        "onRequestCurrentVideoBounds", "onRequestCurrentChannelUri", "onRequestCurrentChannelLcn", "onRequestStreamVolume",
        "onRequestTrackInfoList", "onRequestSelectedTrackInfo", "onRequestCurrentTvInputId", "onRequestTimeShiftMode",
        "onRequestAvailableSpeeds", "onRequestStartRecording", "onRequestStopRecording", "onRequestScheduleRecording",
        "onRequestScheduleRecording2", "onSetTvRecordingInfo", "onRequestTvRecordingInfo", "onRequestTvRecordingInfoList",
        "onRequestSigning", "onRequestSigning2", "onRequestCertificate", "onAdRequest",
    ]),
    ("android.media.tv.interactive.ITvInteractiveAppManager", &[
        "getTvInteractiveAppServiceList", "getAppLinkInfoList", "registerAppLinkInfo", "unregisterAppLinkInfo",
        "sendAppLinkCommand", "startInteractiveApp", "stopInteractiveApp", "resetInteractiveApp",
        "createBiInteractiveApp", "destroyBiInteractiveApp", "setTeletextAppEnabled", "sendCurrentVideoBounds",
        "sendCurrentChannelUri", "sendCurrentChannelLcn", "sendStreamVolume", "sendTrackInfoList",
        "sendCurrentTvInputId", "sendTimeShiftMode", "sendAvailableSpeeds", "sendSigningResult",
        "sendCertificate", "sendTvRecordingInfo", "sendTvRecordingInfoList", "notifyError",
        "notifyTimeShiftPlaybackParams", "notifyTimeShiftStatusChanged", "notifyTimeShiftStartPositionChanged", "notifyTimeShiftCurrentPositionChanged",
        "notifyRecordingConnectionFailed", "notifyRecordingDisconnected", "notifyRecordingTuned", "notifyRecordingError",
        "notifyRecordingScheduled", "createSession", "releaseSession", "notifyTuned",
        "notifyTrackSelected", "notifyTracksChanged", "notifyVideoAvailable", "notifyVideoUnavailable",
        "notifyVideoFreezeUpdated", "notifyContentAllowed", "notifyContentBlocked", "notifySignalStrength",
        "notifyRecordingStarted", "notifyRecordingStopped", "notifyTvMessage", "setSurface",
        "dispatchSurfaceChanged", "notifyBroadcastInfoResponse", "notifyAdResponse", "notifyAdBufferConsumed",
        "sendSelectedTrackInfo", "createMediaView", "relayoutMediaView", "removeMediaView",
        "registerCallback", "unregisterCallback",
    ]),
    ("android.media.tv.interactive.ITvInteractiveAppManagerCallback", &[
        "onInteractiveAppServiceAdded", "onInteractiveAppServiceRemoved", "onInteractiveAppServiceUpdated", "onTvInteractiveAppServiceInfoUpdated",
        "onStateChanged",
    ]),
    ("android.media.tv.interactive.ITvInteractiveAppService", &[
        "registerCallback", "unregisterCallback", "createSession", "registerAppLinkInfo",
        "unregisterAppLinkInfo", "sendAppLinkCommand",
    ]),
    ("android.media.tv.interactive.ITvInteractiveAppServiceCallback", &[
        "onStateChanged",
    ]),
    ("android.media.tv.interactive.ITvInteractiveAppSession", &[
        "startInteractiveApp", "stopInteractiveApp", "resetInteractiveApp", "createBiInteractiveApp",
        "destroyBiInteractiveApp", "setTeletextAppEnabled", "sendCurrentVideoBounds", "sendCurrentChannelUri",
        "sendCurrentChannelLcn", "sendStreamVolume", "sendTrackInfoList", "sendCurrentTvInputId",
        "sendTimeShiftMode", "sendAvailableSpeeds", "sendSigningResult", "sendCertificate",
        "sendTvRecordingInfo", "sendTvRecordingInfoList", "notifyError", "notifyTimeShiftPlaybackParams",
        "notifyTimeShiftStatusChanged", "notifyTimeShiftStartPositionChanged", "notifyTimeShiftCurrentPositionChanged", "notifyRecordingConnectionFailed",
        "notifyRecordingDisconnected", "notifyRecordingTuned", "notifyRecordingError", "notifyRecordingScheduled",
        "release", "notifyTuned", "notifyTrackSelected", "notifyTracksChanged",
        "notifyVideoAvailable", "notifyVideoUnavailable", "notifyVideoFreezeUpdated", "notifyContentAllowed",
        "notifyContentBlocked", "notifySignalStrength", "notifyRecordingStarted", "notifyRecordingStopped",
        "notifyTvMessage", "setSurface", "dispatchSurfaceChanged", "notifyBroadcastInfoResponse",
        "notifyAdResponse", "notifyAdBufferConsumed", "sendSelectedTrackInfo", "createMediaView",
        "relayoutMediaView", "removeMediaView",
    ]),
    ("android.media.tv.interactive.ITvInteractiveAppSessionCallback", &[
        "onSessionCreated", "onLayoutSurface", "onBroadcastInfoRequest", "onRemoveBroadcastInfo",
        "onSessionStateChanged", "onBiInteractiveAppCreated", "onTeletextAppStateChanged", "onAdBufferReady",
        "onCommandRequest", "onTimeShiftCommandRequest", "onSetVideoBounds", "onRequestCurrentVideoBounds",
        "onRequestCurrentChannelUri", "onRequestCurrentChannelLcn", "onRequestStreamVolume", "onRequestTrackInfoList",
        "onRequestCurrentTvInputId", "onRequestTimeShiftMode", "onRequestAvailableSpeeds", "onRequestSelectedTrackInfo",
        "onRequestStartRecording", "onRequestStopRecording", "onRequestScheduleRecording", "onRequestScheduleRecording2",
        "onSetTvRecordingInfo", "onRequestTvRecordingInfo", "onRequestTvRecordingInfoList", "onRequestSigning",
        "onRequestSigning2", "onRequestCertificate", "onAdRequest",
    ]),
    ("android.media.tv.tunerresourcemanager.IResourcesReclaimListener", &[
        "onReclaimResources",
    ]),
    ("android.media.tv.tunerresourcemanager.ITunerResourceManager", &[
        "registerClientProfile", "unregisterClientProfile", "updateClientPriority", "hasUnusedFrontend",
        "isLowestPriority", "setFrontendInfoList", "updateCasInfo", "setDemuxInfoList",
        "setLnbInfoList", "setResourceOwnershipRetention", "requestFrontend", "setMaxNumberOfFrontends",
        "getMaxNumberOfFrontends", "shareFrontend", "transferOwner", "requestDemux",
        "requestDescrambler", "requestCasSession", "requestCiCam", "requestLnb",
        "releaseFrontend", "releaseDemux", "releaseDescrambler", "releaseCasSession",
        "releaseCiCam", "releaseLnb", "isHigherPriority", "storeResourceMap",
        "clearResourceMap", "restoreResourceMap", "acquireLock", "releaseLock",
        "getClientPriority", "getConfigPriority",
    ]),
    ("android.nearby.IBroadcastListener", &[
        "onStatusChanged",
    ]),
    ("android.nearby.INearbyManager", &[
        "registerScanListener", "unregisterScanListener", "startBroadcast", "stopBroadcast",
        "queryOffloadCapability", "setPoweredOffFindingEphemeralIds", "setPoweredOffModeEnabled", "getPoweredOffModeEnabled",
    ]),
    ("android.nearby.IScanListener", &[
        "onDiscovered", "onUpdated", "onLost", "onError",
    ]),
    ("android.nearby.aidl.IOffloadCallback", &[
        "onQueryComplete",
    ]),
    ("android.net.ICaptivePortal", &[
        "appRequest", "appResponse", "setDelegateUid",
    ]),
    ("android.net.IConnectivityDiagnosticsCallback", &[
        "onConnectivityReportAvailable", "onDataStallSuspected", "onNetworkConnectivityReported",
    ]),
    ("android.net.IConnectivityManager", &[
        "getActiveNetwork", "getActiveNetworkForUid", "getActiveNetworkInfo", "getActiveNetworkInfoForUid",
        "getNetworkInfo", "getNetworkInfoForUid", "getAllNetworkInfo", "getNetworkForType",
        "getAllNetworks", "getDefaultNetworkCapabilitiesForUser", "isNetworkSupported", "getActiveLinkProperties",
        "getLinkPropertiesForType", "getLinkProperties", "getRedactedLinkPropertiesForPackage", "getNetworkCapabilities",
        "getRedactedNetworkCapabilitiesForPackage", "getAllNetworkState", "getAllNetworkStateSnapshots", "isActiveNetworkMetered",
        "requestRouteToHostAddress", "getLastTetherError", "getTetherableIfaces", "getTetheredIfaces",
        "getTetheringErroredIfaces", "getTetherableUsbRegexs", "getTetherableWifiRegexs", "reportInetCondition",
        "reportNetworkConnectivity", "getGlobalProxy", "setGlobalProxy", "getProxyForNetwork",
        "setRequireVpnForUids", "setLegacyLockdownVpnEnabled", "setProvisioningNotificationVisible", "setAirplaneMode",
        "requestBandwidthUpdate", "registerNetworkProvider", "unregisterNetworkProvider", "declareNetworkRequestUnfulfillable",
        "registerNetworkAgent", "requestNetwork", "pendingRequestForNetwork", "releasePendingNetworkRequest",
        "listenForNetwork", "pendingListenForNetwork", "releaseNetworkRequest", "setAcceptUnvalidated",
        "setAcceptPartialConnectivity", "setAvoidUnvalidated", "startCaptivePortalApp", "startCaptivePortalAppInternal",
        "shouldAvoidBadWifi", "getMultipathPreference", "getDefaultRequest", "getRestoreDefaultNetworkDelay",
        "factoryReset", "startNattKeepalive", "startNattKeepaliveWithFd", "startTcpKeepalive",
        "stopKeepalive", "getSupportedKeepalives", "getCaptivePortalServerUrl", "getNetworkWatchlistConfigHash",
        "getConnectionOwnerUid", "registerConnectivityDiagnosticsCallback", "unregisterConnectivityDiagnosticsCallback", "startOrGetTestNetworkService",
        "simulateDataStall", "systemReady", "registerNetworkActivityListener", "unregisterNetworkActivityListener",
        "isDefaultNetworkActive", "registerQosSocketCallback", "unregisterQosCallback", "setOemNetworkPreference",
        "setProfileNetworkPreferences", "getRestrictBackgroundStatusByCaller", "offerNetwork", "unofferNetwork",
        "setTestAllowBadWifiUntil", "setDataSaverEnabled", "setUidFirewallRule", "getUidFirewallRule",
        "setFirewallChainEnabled", "getFirewallChainEnabled", "replaceFirewallChain", "getCompanionDeviceManagerProxyService",
        "setVpnNetworkPreference", "setTestLowTcpPollingTimerForKeepalive", "getRoutingCoordinatorService", "getEnabledConnectivityManagerFeatures",
        "isConnectivityServiceFeatureEnabledForTesting",
    ]),
    ("android.net.IEthernetManager", &[
        "getAvailableInterfaces", "getConfiguration", "setConfiguration", "isAvailable",
        "addListener", "removeListener", "setIncludeTestInterfaces", "requestTetheredInterface",
        "releaseTetheredInterface", "updateConfiguration", "enableInterface", "disableInterface",
        "setEthernetEnabled", "getInterfaceList",
    ]),
    ("android.net.IEthernetServiceListener", &[
        "onEthernetStateChanged", "onInterfaceStateChanged",
    ]),
    ("android.net.IIpConnectivityMetrics", &[
        "logEvent", "logDefaultNetworkValidity", "logDefaultNetworkEvent", "addNetdEventCallback",
        "removeNetdEventCallback",
    ]),
    ("android.net.IIpSecService", &[
        "allocateSecurityParameterIndex", "releaseSecurityParameterIndex", "openUdpEncapsulationSocket", "closeUdpEncapsulationSocket",
        "createTunnelInterface", "addAddressToTunnelInterface", "removeAddressFromTunnelInterface", "setNetworkForTunnelInterface",
        "deleteTunnelInterface", "createTransform", "migrateTransform", "deleteTransform",
        "getTransformState", "applyTransportModeTransform", "applyTunnelModeTransform", "removeTransportModeTransforms",
    ]),
    ("android.net.INetdEventCallback", &[
        "onDnsEvent", "onNat64PrefixEvent", "onPrivateDnsValidationEvent", "onConnectEvent",
    ]),
    ("android.net.INetworkAgent", &[
        "onRegistered", "onDisconnected", "onBandwidthUpdateRequested", "onValidationStatusChanged",
        "onSaveAcceptUnvalidated", "onStartNattSocketKeepalive", "onStartTcpSocketKeepalive", "onStopSocketKeepalive",
        "onSignalStrengthThresholdsUpdated", "onPreventAutomaticReconnect", "onAddNattKeepalivePacketFilter", "onAddTcpKeepalivePacketFilter",
        "onRemoveKeepalivePacketFilter", "onQosFilterCallbackRegistered", "onQosCallbackUnregistered", "onNetworkCreated",
        "onNetworkDestroyed", "onDscpPolicyStatusUpdated",
    ]),
    ("android.net.INetworkAgentRegistry", &[
        "sendNetworkCapabilities", "sendLinkProperties", "sendNetworkInfo", "sendLocalNetworkConfig",
        "sendScore", "sendExplicitlySelected", "sendSocketKeepaliveEvent", "sendUnderlyingNetworks",
        "sendEpsQosSessionAvailable", "sendNrQosSessionAvailable", "sendQosSessionLost", "sendQosCallbackError",
        "sendTeardownDelayMs", "sendLingerDuration", "sendAddDscpPolicy", "sendRemoveDscpPolicy",
        "sendRemoveAllDscpPolicies", "sendUnregisterAfterReplacement",
    ]),
    ("android.net.INetworkManagementEventObserver", &[
        "interfaceStatusChanged", "interfaceLinkStateChanged", "interfaceAdded", "interfaceRemoved",
        "addressUpdated", "addressRemoved", "limitReached", "interfaceClassDataActivityChanged",
        "interfaceDnsServerInfo", "routeUpdated", "routeRemoved",
    ]),
    ("android.net.INetworkPolicyListener", &[
        "onUidRulesChanged", "onMeteredIfacesChanged", "onRestrictBackgroundChanged", "onUidPoliciesChanged",
        "onSubscriptionOverride", "onSubscriptionPlansChanged", "onBlockedReasonChanged",
    ]),
    ("android.net.INetworkPolicyManager", &[
        "setUidPolicy", "addUidPolicy", "removeUidPolicy", "getUidPolicy",
        "getUidsWithPolicy", "registerListener", "unregisterListener", "setNetworkPolicies",
        "getNetworkPolicies", "snoozeLimit", "setRestrictBackground", "getRestrictBackground",
        "getRestrictBackgroundByCaller", "getRestrictBackgroundStatus", "setDeviceIdleMode", "setWifiMeteredOverride",
        "getMultipathPreference", "getSubscriptionPlan", "notifyStatsProviderWarningOrLimitReached", "getSubscriptionPlans",
        "setSubscriptionPlans", "getSubscriptionPlansOwner", "setSubscriptionOverride", "factoryReset",
        "isUidNetworkingBlocked", "isUidRestrictedOnMeteredNetworks",
    ]),
    ("android.net.INetworkRecommendationProvider", &[
        "requestScores",
    ]),
    ("android.net.INetworkScoreCache", &[
        "updateScores", "clearScores",
    ]),
    ("android.net.INetworkScoreService", &[
        "updateScores", "clearScores", "setActiveScorer", "disableScoring",
        "registerNetworkScoreCache", "unregisterNetworkScoreCache", "requestScores", "isCallerActiveScorer",
        "getActiveScorerPackage", "getActiveScorer", "getAllValidScorers",
    ]),
    ("android.net.INetworkStatsService", &[
        "openSession", "openSessionForUsageStats", "getDataLayerSnapshotForUid", "getUidStatsForTransport",
        "getMobileIfaces", "incrementOperationCount", "notifyNetworkStatus", "forceUpdate",
        "registerUsageCallback", "unregisterUsageRequest", "getUidStats", "getIfaceStats",
        "getTotalStats", "registerNetworkStatsProvider", "noteUidForeground", "advisePersistThreshold",
        "setStatsProviderWarningAndLimitAsync", "clearTrafficStatsRateLimitCaches", "getRateLimitCacheConfig",
    ]),
    ("android.net.INetworkStatsSession", &[
        "getDeviceSummaryForNetwork", "getSummaryForNetwork", "getHistoryForNetwork", "getHistoryIntervalForNetwork",
        "getSummaryForAllUid", "getTaggedSummaryForAllUid", "getHistoryForUid", "getHistoryIntervalForUid",
        "getRelevantUids", "close",
    ]),
    ("android.net.IPacProxyInstalledListener", &[
        "onPacProxyInstalled",
    ]),
    ("android.net.IPacProxyManager", &[
        "addListener", "removeListener", "setCurrentProxyScriptUrl",
    ]),
    ("android.net.IVpnManager", &[
        "prepareVpn", "setVpnPackageAuthorization", "establishVpn", "addVpnAddress",
        "removeVpnAddress", "setUnderlyingNetworksForVpn", "provisionVpnProfile", "deleteVpnProfile",
        "startVpnProfile", "stopVpnProfile", "getProvisionedVpnProfileState", "setAppExclusionList",
        "getAppExclusionList", "isAlwaysOnVpnPackageSupported", "setAlwaysOnVpnPackage", "getAlwaysOnVpnPackage",
        "isVpnLockdownEnabled", "getVpnLockdownAllowlist", "isCallerCurrentAlwaysOnVpnApp", "isCallerCurrentAlwaysOnVpnLockdownApp",
        "startLegacyVpn", "getLegacyVpnInfo", "updateLockdownVpn", "getFromVpnProfileStore",
        "putIntoVpnProfileStore", "removeFromVpnProfileStore", "listFromVpnProfileStore", "getVpnConfig",
        "factoryReset",
    ]),
    ("android.net.connectivity.android.net.INetworkActivityListener", &[
        "onNetworkActive",
    ]),
    ("android.net.connectivity.android.net.INetworkInterfaceOutcomeReceiver", &[
        "onResult", "onError",
    ]),
    ("android.net.connectivity.android.net.INetworkOfferCallback", &[
        "onNetworkNeeded", "onNetworkUnneeded",
    ]),
    ("android.net.connectivity.android.net.IOnCompleteListener", &[
        "onComplete",
    ]),
    ("android.net.connectivity.android.net.IQosCallback", &[
        "onQosEpsBearerSessionAvailable", "onNrQosSessionAvailable", "onQosSessionLost", "onError",
    ]),
    ("android.net.connectivity.android.net.ISocketKeepaliveCallback", &[
        "onStarted", "onStopped", "onError", "onDataReceived",
        "onPaused", "onResumed",
    ]),
    ("android.net.connectivity.android.net.ITestNetworkManager", &[
        "createInterface", "setCarrierEnabled", "setupTestNetwork", "teardownTestNetwork",
    ]),
    ("android.net.connectivity.android.net.ITetheredInterfaceCallback", &[
        "onAvailable", "onUnavailable",
    ]),
    ("android.net.connectivity.android.net.netstats.IUsageCallback", &[
        "onThresholdReached", "onCallbackReleased",
    ]),
    ("android.net.connectivity.android.net.nsd.INsdManagerCallback", &[
        "onDiscoverServicesStarted", "onDiscoverServicesFailed", "onServiceFound", "onServiceLost",
        "onStopDiscoveryFailed", "onStopDiscoverySucceeded", "onRegisterServiceFailed", "onRegisterServiceSucceeded",
        "onUnregisterServiceFailed", "onUnregisterServiceSucceeded", "onResolveServiceFailed", "onResolveServiceSucceeded",
        "onStopResolutionFailed", "onStopResolutionSucceeded", "onServiceInfoCallbackRegistrationFailed", "onServiceUpdated",
        "onServiceUpdatedLost", "onServiceInfoCallbackUnregistered",
    ]),
    ("android.net.connectivity.android.net.nsd.INsdServiceConnector", &[
        "registerService", "unregisterService", "discoverServices", "stopDiscovery",
        "resolveService", "startDaemon", "stopResolution", "registerServiceInfoCallback",
        "unregisterServiceInfoCallback", "registerOffloadEngine", "unregisterOffloadEngine",
    ]),
    ("android.net.connectivity.android.net.nsd.IOffloadEngine", &[
        "onOffloadServiceUpdated", "onOffloadServiceRemoved",
    ]),
    ("android.net.connectivity.android.net.thread.IActiveOperationalDatasetReceiver", &[
        "onSuccess", "onError",
    ]),
    ("android.net.connectivity.android.net.thread.IConfigurationReceiver", &[
        "onConfigurationChanged",
    ]),
    ("android.net.connectivity.android.net.thread.IOperationReceiver", &[
        "onSuccess", "onError",
    ]),
    ("android.net.connectivity.android.net.thread.IOperationalDatasetCallback", &[
        "onActiveOperationalDatasetChanged", "onPendingOperationalDatasetChanged",
    ]),
    ("android.net.connectivity.android.net.thread.IOutputReceiver", &[
        "onOutput", "onComplete", "onError",
    ]),
    ("android.net.connectivity.android.net.thread.IScheduleMigrationReceiver", &[
        "onScheduled", "onMigrated", "onError",
    ]),
    ("android.net.connectivity.android.net.thread.IStateCallback", &[
        "onDeviceRoleChanged", "onPartitionIdChanged", "onThreadEnableStateChanged", "onEphemeralKeyStateChanged",
    ]),
    ("android.net.connectivity.android.net.thread.IThreadNetworkController", &[
        "registerStateCallback", "unregisterStateCallback", "registerOperationalDatasetCallback", "unregisterOperationalDatasetCallback",
        "join", "scheduleMigration", "leave", "setTestNetworkAsUpstream",
        "setChannelMaxPowers", "getThreadVersion", "createRandomizedDataset", "setEnabled",
        "setConfiguration", "registerConfigurationCallback", "unregisterConfigurationCallback", "activateEphemeralKeyMode",
        "deactivateEphemeralKeyMode",
    ]),
    ("android.net.connectivity.android.net.thread.IThreadNetworkManager", &[
        "getAllThreadNetworkControllers",
    ]),
    ("android.net.connectivity.com.android.metrics.NetworkNsdReported", &[
        "", "", "ID_FIELD_NUMBER",
    ]),
    ("android.net.connectivity.com.android.server.NsdService", &[
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "no",
    ]),
    ("android.net.netstats.provider.INetworkStatsProvider", &[
        "onRequestStatsUpdate", "onSetAlert", "onSetWarningAndLimit",
    ]),
    ("android.net.netstats.provider.INetworkStatsProviderCallback", &[
        "notifyStatsUpdated", "notifyAlertReached", "notifyWarningReached", "notifyLimitReached",
        "unregister",
    ]),
    ("android.net.nsd.INsdManager", &[
        "connect",
    ]),
    ("android.net.vcn.IVcnManagementService", &[
        "setVcnConfig", "clearVcnConfig", "getConfiguredSubscriptionGroups", "addVcnUnderlyingNetworkPolicyListener",
        "removeVcnUnderlyingNetworkPolicyListener", "getUnderlyingNetworkPolicy", "registerVcnStatusCallback", "unregisterVcnStatusCallback",
    ]),
    ("android.net.vcn.IVcnStatusCallback", &[
        "onVcnStatusChanged", "onGatewayConnectionError",
    ]),
    ("android.net.vcn.IVcnUnderlyingNetworkPolicyListener", &[
        "onPolicyChanged",
    ]),
    ("android.net.wifi.IActionListener", &[
        "onSuccess", "onFailure",
    ]),
    ("android.net.wifi.IBooleanListener", &[
        "onResult",
    ]),
    ("android.net.wifi.IByteArrayListener", &[
        "onResult",
    ]),
    ("android.net.wifi.ICoexCallback", &[
        "onCoexUnsafeChannelsChanged",
    ]),
    ("android.net.wifi.IDppCallback", &[
        "onSuccessConfigReceived", "onSuccess", "onFailure", "onProgress",
        "onBootstrapUriGenerated",
    ]),
    ("android.net.wifi.IIntegerListener", &[
        "onResult",
    ]),
    ("android.net.wifi.IInterfaceCreationInfoCallback", &[
        "onResults",
    ]),
    ("android.net.wifi.ILastCallerListener", &[
        "onResult",
    ]),
    ("android.net.wifi.IListListener", &[
        "onResult",
    ]),
    ("android.net.wifi.ILocalOnlyConnectionStatusListener", &[
        "onConnectionStatus",
    ]),
    ("android.net.wifi.ILocalOnlyHotspotCallback", &[
        "onHotspotStarted", "onHotspotStopped", "onHotspotFailed",
    ]),
    ("android.net.wifi.IMacAddressListListener", &[
        "onResult",
    ]),
    ("android.net.wifi.IMapListener", &[
        "onResult",
    ]),
    ("android.net.wifi.INetworkRequestMatchCallback", &[
        "onUserSelectionCallbackRegistration", "onAbort", "onMatch", "onUserSelectionConnectSuccess",
        "onUserSelectionConnectFailure",
    ]),
    ("android.net.wifi.INetworkRequestUserSelectionCallback", &[
        "select", "reject",
    ]),
    ("android.net.wifi.IOnWifiActivityEnergyInfoListener", &[
        "onWifiActivityEnergyInfo",
    ]),
    ("android.net.wifi.IOnWifiDriverCountryCodeChangedListener", &[
        "onDriverCountryCodeChanged",
    ]),
    ("android.net.wifi.IOnWifiUsabilityStatsListener", &[
        "onWifiUsabilityStats",
    ]),
    ("android.net.wifi.IPnoScanResultsCallback", &[
        "onScanResultsAvailable", "onRegisterSuccess", "onRegisterFailed", "onRemoved",
    ]),
    ("android.net.wifi.IScanDataListener", &[
        "onResult",
    ]),
    ("android.net.wifi.IScanResultsCallback", &[
        "onScanResultsAvailable",
    ]),
    ("android.net.wifi.IScanResultsListener", &[
        "onScanResultsAvailable",
    ]),
    ("android.net.wifi.IScoreUpdateObserver", &[
        "notifyScoreUpdate", "triggerUpdateOfWifiUsabilityStats", "notifyStatusUpdate", "requestNudOperation",
        "blocklistCurrentBssid",
    ]),
    ("android.net.wifi.ISoftApCallback", &[
        "onStateChanged", "onConnectedClientsOrInfoChanged", "onCapabilityChanged", "onBlockedClientConnecting",
        "onClientsDisconnected",
    ]),
    ("android.net.wifi.IStringListener", &[
        "onResult",
    ]),
    ("android.net.wifi.ISubsystemRestartCallback", &[
        "onSubsystemRestarting", "onSubsystemRestarted",
    ]),
    ("android.net.wifi.ISuggestionConnectionStatusListener", &[
        "onConnectionStatus",
    ]),
    ("android.net.wifi.ISuggestionUserApprovalStatusListener", &[
        "onUserApprovalStatusChange",
    ]),
    ("android.net.wifi.ITrafficStateCallback", &[
        "onStateChanged",
    ]),
    ("android.net.wifi.ITwtCallback", &[
        "onFailure", "onTeardown", "onCreate",
    ]),
    ("android.net.wifi.ITwtCapabilitiesListener", &[
        "onResult",
    ]),
    ("android.net.wifi.ITwtStatsListener", &[
        "onResult",
    ]),
    ("android.net.wifi.IWifiBandsListener", &[
        "onResult",
    ]),
    ("android.net.wifi.IWifiConnectedNetworkScorer", &[
        "onStart", "onStop", "onSetScoreUpdateObserver", "onNetworkSwitchAccepted",
        "onNetworkSwitchRejected",
    ]),
    ("android.net.wifi.IWifiLowLatencyLockListener", &[
        "onActivatedStateChanged", "onOwnershipChanged", "onActiveUsersChanged",
    ]),
    ("android.net.wifi.IWifiManager", &[
        "isFeatureSupported", "getWifiActivityEnergyInfoAsync", "setNetworkSelectionConfig", "getNetworkSelectionConfig",
        "setThirdPartyAppEnablingWifiConfirmationDialogEnabled", "isThirdPartyAppEnablingWifiConfirmationDialogEnabled", "setScreenOnScanSchedule", "setOneShotScreenOnConnectivityScanDelayMillis",
        "getConfiguredNetworks", "getPrivilegedConfiguredNetworks", "getPrivilegedConnectedNetwork", "setSsidsAllowlist",
        "getSsidsAllowlist", "getMatchingOsuProviders", "getMatchingPasspointConfigsForOsuProviders", "addOrUpdateNetwork",
        "addOrUpdateNetworkPrivileged", "addOrUpdatePasspointConfiguration", "removePasspointConfiguration", "getPasspointConfigurations",
        "getWifiConfigsForPasspointProfiles", "queryPasspointIcon", "matchProviderWithCurrentNetwork", "removeNetwork",
        "removeNonCallerConfiguredNetworks", "enableNetwork", "disableNetwork", "allowAutojoinGlobal",
        "queryAutojoinGlobal", "allowAutojoin", "allowAutojoinPasspoint", "setMacRandomizationSettingPasspointEnabled",
        "setPasspointMeteredOverride", "startScan", "getScanResults", "getChannelData",
        "getBssidBlocklist", "disconnect", "reconnect", "reassociate",
        "getConnectionInfo", "setWifiEnabled", "getWifiEnabledState", "addWifiStateChangedListener",
        "removeWifiStateChangedListener", "registerDriverCountryCodeChangedListener", "unregisterDriverCountryCodeChangedListener", "addWifiNetworkStateChangedListener",
        "removeWifiNetworkStateChangedListener", "getCountryCode", "setOverrideCountryCode", "clearOverrideCountryCode",
        "setDefaultCountryCode", "is24GHzBandSupported", "is5GHzBandSupported", "is6GHzBandSupported",
        "is60GHzBandSupported", "isWifiStandardSupported", "getDhcpInfo", "setScanAlwaysAvailable",
        "isScanAlwaysAvailable", "acquireWifiLock", "updateWifiLockWorkSource", "releaseWifiLock",
        "initializeMulticastFiltering", "isMulticastEnabled", "acquireMulticastLock", "releaseMulticastLock",
        "updateInterfaceIpState", "isDefaultCoexAlgorithmEnabled", "setCoexUnsafeChannels", "registerCoexCallback",
        "unregisterCoexCallback", "startSoftAp", "startTetheredHotspot", "startTetheredHotspotRequest",
        "stopSoftAp", "validateSoftApConfiguration", "startLocalOnlyHotspot", "stopLocalOnlyHotspot",
        "registerLocalOnlyHotspotSoftApCallback", "unregisterLocalOnlyHotspotSoftApCallback", "startWatchLocalOnlyHotspot", "stopWatchLocalOnlyHotspot",
        "getWifiApEnabledState", "getWifiApConfiguration", "getSoftApConfiguration", "queryLastConfiguredTetheredApPassphraseSinceBoot",
        "setWifiApConfiguration", "setSoftApConfiguration", "enableTdls", "enableTdlsWithRemoteIpAddress",
        "enableTdlsWithMacAddress", "enableTdlsWithRemoteMacAddress", "isTdlsOperationCurrentlyAvailable", "getMaxSupportedConcurrentTdlsSessions",
        "getNumberOfEnabledTdlsSessions", "getCurrentNetworkWpsNfcConfigurationToken", "enableVerboseLogging", "getVerboseLoggingLevel",
        "disableEphemeralNetwork", "factoryReset", "getCurrentNetwork", "retrieveBackupData",
        "restoreBackupData", "retrieveSoftApBackupData", "restoreSoftApBackupData", "restoreSupplicantBackupData",
        "startSubscriptionProvisioning", "registerSoftApCallback", "unregisterSoftApCallback", "addWifiVerboseLoggingStatusChangedListener",
        "removeWifiVerboseLoggingStatusChangedListener", "addOnWifiUsabilityStatsListener", "removeOnWifiUsabilityStatsListener", "registerTrafficStateCallback",
        "unregisterTrafficStateCallback", "registerNetworkRequestMatchCallback", "unregisterNetworkRequestMatchCallback", "addNetworkSuggestions",
        "removeNetworkSuggestions", "getNetworkSuggestions", "getFactoryMacAddresses", "setDeviceMobilityState",
        "startDppAsConfiguratorInitiator", "startDppAsEnrolleeInitiator", "startDppAsEnrolleeResponder", "stopDppSession",
        "updateWifiUsabilityScore", "connect", "save", "forget",
        "registerScanResultsCallback", "unregisterScanResultsCallback", "registerSuggestionConnectionStatusListener", "unregisterSuggestionConnectionStatusListener",
        "addLocalOnlyConnectionStatusListener", "removeLocalOnlyConnectionStatusListener", "calculateSignalLevel", "getWifiConfigForMatchedNetworkSuggestionsSharedWithUser",
        "setWifiConnectedNetworkScorer", "clearWifiConnectedNetworkScorer", "setExternalPnoScanRequest", "setPnoScanEnabled",
        "clearExternalPnoScanRequest", "getLastCallerInfoForApi", "getMatchingScanResults", "setScanThrottleEnabled",
        "isScanThrottleEnabled", "getAllMatchingPasspointProfilesForScanResults", "setAutoWakeupEnabled", "isAutoWakeupEnabled",
        "startRestrictingAutoJoinToSubscriptionId", "stopRestrictingAutoJoinToSubscriptionId", "setCarrierNetworkOffloadEnabled", "isCarrierNetworkOffloadEnabled",
        "registerSubsystemRestartCallback", "unregisterSubsystemRestartCallback", "restartWifiSubsystem", "addSuggestionUserApprovalStatusListener",
        "removeSuggestionUserApprovalStatusListener", "setEmergencyScanRequestInProgress", "removeAppState", "setWifiScoringEnabled",
        "flushPasspointAnqpCache", "getUsableChannels", "isWifiPasspointEnabled", "setWifiPasspointEnabled",
        "getStaConcurrencyForMultiInternetMode", "setStaConcurrencyForMultiInternetMode", "notifyMinimumRequiredWifiSecurityLevelChanged", "notifyWifiSsidPolicyChanged",
        "getOemPrivilegedWifiAdminPackages", "replyToP2pInvitationReceivedDialog", "replyToSimpleDialog", "addCustomDhcpOptions",
        "removeCustomDhcpOptions", "reportCreateInterfaceImpact", "getMaxNumberOfChannelsPerRequest", "addQosPolicies",
        "removeQosPolicies", "removeAllQosPolicies", "setLinkLayerStatsPollingInterval", "getLinkLayerStatsPollingInterval",
        "setMloMode", "getMloMode", "addWifiLowLatencyLockListener", "removeWifiLowLatencyLockListener",
        "getMaxMloAssociationLinkCount", "getMaxMloStrLinkCount", "getSupportedSimultaneousBandCombinations", "setWepAllowed",
        "queryWepAllowed", "enableMscs", "disableMscs", "setSendDhcpHostnameRestriction",
        "querySendDhcpHostnameRestriction", "setPerSsidRoamingMode", "removePerSsidRoamingMode", "getPerSsidRoamingModes",
        "getTwtCapabilities", "setupTwtSession", "getStatsTwtSession", "teardownTwtSession",
        "setD2dAllowedWhenInfraStaDisabled", "queryD2dAllowedWhenInfraStaDisabled", "retrieveWifiBackupData", "restoreWifiBackupData",
        "isPnoSupported", "setAutojoinDisallowedSecurityTypes", "getAutojoinDisallowedSecurityTypes", "disallowCurrentSuggestedNetwork",
        "storeCapturedData", "isUsdSubscriberSupported", "isUsdPublisherSupported",
    ]),
    ("android.net.wifi.IWifiNetworkSelectionConfigListener", &[
        "onResult",
    ]),
    ("android.net.wifi.IWifiNetworkStateChangedListener", &[
        "onWifiNetworkStateChanged",
    ]),
    ("android.net.wifi.IWifiScanner", &[
        "getAvailableChannels", "isScanning", "setScanningEnabled", "registerScanListener",
        "unregisterScanListener", "startBackgroundScan", "stopBackgroundScan", "getScanResults",
        "startScan", "stopScan", "getSingleScanResults", "getCachedScanData",
        "startPnoScan", "stopPnoScan", "enableVerboseLogging",
    ]),
    ("android.net.wifi.IWifiScannerListener", &[
        "onSuccess", "onFailure", "onResults", "onFullResult",
        "onSingleScanCompleted", "onPnoNetworkFound", "onFullResults",
    ]),
    ("android.net.wifi.IWifiStateChangedListener", &[
        "onWifiStateChanged",
    ]),
    ("android.net.wifi.IWifiVerboseLoggingStatusChangedListener", &[
        "onStatusChanged",
    ]),
    ("android.net.wifi.aware.IWifiAwareDiscoverySessionCallback", &[
        "onSessionStarted", "onSessionConfigSuccess", "onSessionConfigFail", "onSessionTerminated",
        "onSessionSuspendSucceeded", "onSessionSuspendFail", "onSessionResumeSucceeded", "onSessionResumeFail",
        "onMatch", "onMatchWithDistance", "onMessageSendSuccess", "onMessageSendFail",
        "onMessageReceived", "onMatchExpired", "onPairingSetupRequestReceived", "onPairingSetupConfirmed",
        "onPairingVerificationConfirmed", "onBootstrappingVerificationConfirmed", "onRangingResultsReceived",
    ]),
    ("android.net.wifi.aware.IWifiAwareEventCallback", &[
        "onConnectSuccess", "onConnectFail", "onIdentityChanged", "onAttachTerminate",
        "onClusterIdChanged",
    ]),
    ("android.net.wifi.aware.IWifiAwareMacAddressProvider", &[
        "macAddress",
    ]),
    ("android.net.wifi.aware.IWifiAwareManager", &[
        "isUsageEnabled", "getCharacteristics", "getAvailableAwareResources", "isDeviceAttached",
        "enableInstantCommunicationMode", "isInstantCommunicationModeEnabled", "isSetChannelOnDataPathSupported", "setAwareParams",
        "resetPairedDevices", "removePairedDevice", "getPairedDevices", "setOpportunisticModeEnabled",
        "isOpportunisticModeEnabled", "connect", "disconnect", "setMasterPreference",
        "getMasterPreference", "publish", "subscribe", "updatePublish",
        "updateSubscribe", "sendMessage", "terminateSession", "initiateNanPairingSetupRequest",
        "responseNanPairingSetupRequest", "initiateBootStrappingSetupRequest", "suspend", "resume",
        "requestMacAddresses",
    ]),
    ("android.net.wifi.hotspot2.IProvisioningCallback", &[
        "onProvisioningFailure", "onProvisioningStatus", "onProvisioningComplete",
    ]),
    ("android.net.wifi.nl80211.IApInterface", &[
        "registerCallback", "getInterfaceName",
    ]),
    ("android.net.wifi.nl80211.IApInterfaceEventCallback", &[
        "onConnectedClientsChanged", "onSoftApChannelSwitched",
    ]),
    ("android.net.wifi.nl80211.IClientInterface", &[
        "getPacketCounters", "signalPoll", "getMacAddress", "getInterfaceName",
        "getWifiScannerImpl", "SendMgmtFrame",
    ]),
    ("android.net.wifi.nl80211.IInterfaceEventCallback", &[
        "OnClientInterfaceReady", "OnApInterfaceReady", "OnClientTorndownEvent", "OnApTorndownEvent",
    ]),
    ("android.net.wifi.nl80211.IPnoScanEvent", &[
        "OnPnoNetworkFound", "OnPnoScanFailed",
    ]),
    ("android.net.wifi.nl80211.IScanEvent", &[
        "OnScanResultReady", "OnScanFailed", "OnScanRequestFailed",
    ]),
    ("android.net.wifi.nl80211.ISendMgmtFrameEvent", &[
        "OnAck", "OnFailure",
    ]),
    ("android.net.wifi.nl80211.IWifiScannerImpl", &[
        "getScanResults", "getPnoScanResults", "getMaxSsidsPerScan", "scan",
        "scanRequest", "subscribeScanEvents", "unsubscribeScanEvents", "subscribePnoScanEvents",
        "unsubscribePnoScanEvents", "startPnoScan", "stopPnoScan", "abortScan",
    ]),
    ("android.net.wifi.nl80211.IWificond", &[
        "createApInterface", "createClientInterface", "tearDownApInterface", "tearDownClientInterface",
        "tearDownInterfaces", "GetClientInterfaces", "GetApInterfaces", "getAvailable2gChannels",
        "getAvailable5gNonDFSChannels", "getAvailableDFSChannels", "getAvailable6gChannels", "getAvailable60gChannels",
        "RegisterCallback", "UnregisterCallback", "registerWificondEventCallback", "unregisterWificondEventCallback",
        "getDeviceWiphyCapabilities", "notifyCountryCodeChanged",
    ]),
    ("android.net.wifi.nl80211.IWificondEventCallback", &[
        "OnRegDomainChanged",
    ]),
    ("android.net.wifi.p2p.IWifiP2pListener", &[
        "onP2pStateChanged", "onDiscoveryStateChanged", "onListenStateChanged", "onDeviceConfigurationChanged",
        "onPeerListChanged", "onPersistentGroupsChanged", "onGroupCreating", "onGroupNegotiationRejectedByUser",
        "onGroupCreationFailed", "onGroupCreated", "onPeerClientJoined", "onPeerClientDisconnected",
        "onFrequencyChanged", "onGroupRemoved",
    ]),
    ("android.net.wifi.p2p.IWifiP2pManager", &[
        "getMessenger", "getP2pStateMachineMessenger", "close", "setMiracastMode",
        "checkConfigureWifiDisplayPermission", "getSupportedFeatures", "registerWifiP2pListener", "unregisterWifiP2pListener",
    ]),
    ("android.net.wifi.rtt.IRttCallback", &[
        "onRangingFailure", "onRangingResults",
    ]),
    ("android.net.wifi.rtt.IWifiRttManager", &[
        "isAvailable", "startRanging", "cancelRanging", "getRttCharacteristics",
    ]),
    ("android.net.wifi.sharedconnectivity.service.ISharedConnectivityCallback", &[
        "onHotspotNetworksUpdated", "onHotspotNetworkConnectionStatusChanged", "onKnownNetworksUpdated", "onKnownNetworkConnectionStatusChanged",
        "onSharedConnectivitySettingsChanged", "onServiceConnected", "onServiceDisconnected",
    ]),
    ("android.net.wifi.sharedconnectivity.service.ISharedConnectivityService", &[
        "registerCallback", "unregisterCallback", "connectHotspotNetwork", "disconnectHotspotNetwork",
        "connectKnownNetwork", "forgetKnownNetwork", "getHotspotNetworks", "getKnownNetworks",
        "getSettingsState", "getHotspotNetworkConnectionStatus", "getKnownNetworkConnectionStatus",
    ]),
    ("android.net.wifi.usd.IPublishSessionCallback", &[
        "onPublishFailed", "onPublishStarted", "onPublishReplied", "onPublishSessionTerminated",
        "onMessageReceived",
    ]),
    ("android.net.wifi.usd.ISubscribeSessionCallback", &[
        "onSubscribeFailed", "onSubscribeStarted", "onSubscribeDiscovered", "onSubscribeSessionTerminated",
        "onMessageReceived",
    ]),
    ("android.net.wifi.usd.IUsdManager", &[
        "getCharacteristics", "sendMessage", "cancelSubscribe", "cancelPublish",
        "updatePublish", "publish", "subscribe", "registerSubscriberStatusListener",
        "unregisterSubscriberStatusListener", "registerPublisherStatusListener", "unregisterPublisherStatusListener",
    ]),
    ("android.os.IBatteryPropertiesRegistrar", &[
        "getProperty", "scheduleUpdate",
    ]),
    ("android.os.ICancellationSignal", &[
        "cancel",
    ]),
    ("android.os.IClientCallback", &[
        "onClients",
    ]),
    ("android.os.IDeviceIdentifiersPolicyService", &[
        "getSerial", "getSerialForPackage",
    ]),
    ("android.os.IDeviceIdleController", &[
        "addPowerSaveWhitelistApp", "addPowerSaveWhitelistApps", "removePowerSaveWhitelistApp", "removeSystemPowerWhitelistApp",
        "restoreSystemPowerWhitelistApp", "getRemovedSystemPowerWhitelistApps", "getSystemPowerWhitelistExceptIdle", "getSystemPowerWhitelist",
        "getUserPowerWhitelist", "getFullPowerWhitelistExceptIdle", "getFullPowerWhitelist", "getAppIdWhitelistExceptIdle",
        "getAppIdWhitelist", "getAppIdUserWhitelist", "getAppIdTempWhitelist", "isPowerSaveWhitelistExceptIdleApp",
        "isPowerSaveWhitelistApp", "addPowerSaveTempWhitelistApp", "addPowerSaveTempWhitelistAppForMms", "addPowerSaveTempWhitelistAppForSms",
        "whitelistAppTemporarily", "exitIdle",
    ]),
    ("android.os.IDumpstate", &[
        "preDumpUiData", "startBugreport", "cancelBugreport", "retrieveBugreport",
    ]),
    ("android.os.IDumpstateListener", &[
        "onProgress", "onError", "onFinished", "onScreenshotTaken",
        "onUiIntensiveBugreportDumpsFinished",
    ]),
    ("android.os.IExternalVibrationController", &[
        "mute", "unmute",
    ]),
    ("android.os.IExternalVibratorService", &[
        "onExternalVibrationStart", "onExternalVibrationStop",
    ]),
    ("android.os.IHardwarePropertiesManager", &[
        "getDeviceTemperatures", "getCpuUsages", "getFanSpeeds",
    ]),
    ("android.os.IHintManager", &[
        "createHintSessionWithConfig", "setHintSessionThreads", "getHintSessionThreadIds", "getSessionChannel",
        "closeSessionChannel", "getCpuHeadroom", "getCpuHeadroomMinIntervalMillis", "getGpuHeadroom",
        "getGpuHeadroomMinIntervalMillis", "passSessionManagerBinder", "registerClient", "getClientData",
    ]),
    ("android.os.IHintManager$IHintManagerClient", &[
        "receiveChannelConfig",
    ]),
    ("android.os.IHintSession", &[
        "updateTargetWorkDuration", "reportActualWorkDuration", "close", "sendHint",
        "setMode", "reportActualWorkDuration2", "associateToLayers",
    ]),
    ("android.os.IIdmap2", &[
        "getIdmapPath", "removeIdmap", "verifyIdmap", "createIdmap",
        "createFabricatedOverlay", "deleteFabricatedOverlay", "acquireFabricatedOverlayIterator", "releaseFabricatedOverlayIterator",
        "nextFabricatedOverlayInfos", "dumpIdmap",
    ]),
    ("android.os.IIncidentAuthListener", &[
        "onReportApproved", "onReportDenied",
    ]),
    ("android.os.IIncidentCompanion", &[
        "authorizeReport", "cancelAuthorization", "sendReportReadyBroadcast", "getPendingReports",
        "approveReport", "denyReport", "getIncidentReportList", "getIncidentReport",
        "deleteIncidentReports", "deleteAllIncidentReports",
    ]),
    ("android.os.IIncidentDumpCallback", &[
        "onDumpSection",
    ]),
    ("android.os.IIncidentManager", &[
        "reportIncident", "reportIncidentToStream", "reportIncidentToDumpstate", "registerSection",
        "unregisterSection", "systemRunning", "getIncidentReportList", "getIncidentReport",
        "deleteIncidentReports", "deleteAllIncidentReports",
    ]),
    ("android.os.IIncidentReportStatusListener", &[
        "onReportStarted", "onReportSectionStatus", "onReportFinished", "onReportFailed",
    ]),
    ("android.os.IInstalld", &[
        "createUserData", "destroyUserData", "setFirstBoot", "createAppData",
        "createAppDataBatched", "reconcileSdkData", "restoreconAppData", "migrateAppData",
        "clearAppData", "destroyAppData", "fixupAppData", "getAppSize",
        "getUserSize", "getExternalSize", "getAppCrates", "getUserCrates",
        "setAppQuota", "moveCompleteApp", "dexopt", "controlDexOptBlocking",
        "rmdex", "mergeProfiles", "dumpProfiles", "copySystemProfile",
        "clearAppProfiles", "destroyAppProfiles", "deleteReferenceProfile", "createProfileSnapshot",
        "destroyProfileSnapshot", "rmPackageDir", "freeCache", "linkNativeLibraryDirectory",
        "createOatDir", "linkFile", "moveAb", "deleteOdex",
        "reconcileSecondaryDexFile", "hashSecondaryDexFile", "invalidateMounts", "isQuotaSupported",
        "prepareAppProfile", "snapshotAppData", "restoreAppDataSnapshot", "destroyAppDataSnapshot",
        "destroyCeSnapshotsNotSpecified", "tryMountDataMirror", "onPrivateVolumeRemoved", "migrateLegacyObbData",
        "cleanupInvalidPackageDirs", "getOdexVisibility", "createFsveritySetupAuthToken", "enableFsverity",
    ]),
    ("android.os.ILogd", &[
        "approve", "decline",
    ]),
    ("android.os.IMessenger", &[
        "send",
    ]),
    ("android.os.INetworkManagementService", &[
        "registerObserver", "unregisterObserver", "listInterfaces", "getInterfaceConfig",
        "setInterfaceConfig", "clearInterfaceAddresses", "setInterfaceDown", "setInterfaceUp",
        "setInterfaceIpv6PrivacyExtensions", "disableIpv6", "enableIpv6", "setIPv6AddrGenMode",
        "shutdown", "setInterfaceQuota", "removeInterfaceQuota", "setInterfaceAlert",
        "removeInterfaceAlert", "setUidOnMeteredNetworkDenylist", "setUidOnMeteredNetworkAllowlist", "setDataSaverModeEnabled",
        "setUidCleartextNetworkPolicy", "isBandwidthControlEnabled", "setFirewallEnabled", "isFirewallEnabled",
        "setFirewallUidRule", "setFirewallUidRules", "setFirewallChainEnabled", "allowProtect",
        "denyProtect", "isNetworkRestricted",
    ]),
    ("android.os.IPermissionController", &[
        "checkPermission", "noteOp", "getPackagesForUid", "isRuntimePermission",
        "getPackageUid",
    ]),
    ("android.os.IPowerManager", &[
        "acquireWakeLock", "acquireWakeLockWithUid", "releaseWakeLock", "updateWakeLockUids",
        "setPowerBoost", "setPowerMode", "setPowerModeChecked", "updateWakeLockWorkSource",
        "updateWakeLockCallback", "isWakeLockLevelSupported", "isWakeLockLevelSupportedWithDisplayId", "addScreenTimeoutPolicyListener",
        "removeScreenTimeoutPolicyListener", "userActivity", "wakeUp", "wakeUpWithDisplayId",
        "goToSleep", "goToSleepWithDisplayId", "nap", "getBrightnessConstraint",
        "isInteractive", "isDisplayInteractive", "areAutoPowerSaveModesEnabled", "isPowerSaveMode",
        "getPowerSaveState", "setPowerSaveModeEnabled", "isBatterySaverSupported", "getFullPowerSavePolicy",
        "setFullPowerSavePolicy", "setDynamicPowerSaveHint", "setAdaptivePowerSavePolicy", "setAdaptivePowerSaveEnabled",
        "getPowerSaveModeTrigger", "setBatteryDischargePrediction", "getBatteryDischargePrediction", "isBatteryDischargePredictionPersonalized",
        "isDeviceIdleMode", "isLightDeviceIdleMode", "isLowPowerStandbySupported", "isLowPowerStandbyEnabled",
        "setLowPowerStandbyEnabled", "setLowPowerStandbyActiveDuringMaintenance", "forceLowPowerStandbyActive", "setLowPowerStandbyPolicy",
        "getLowPowerStandbyPolicy", "isExemptFromLowPowerStandby", "isReasonAllowedInLowPowerStandby", "isFeatureAllowedInLowPowerStandby",
        "acquireLowPowerStandbyPorts", "releaseLowPowerStandbyPorts", "getActiveLowPowerStandbyPorts", "reboot",
        "rebootSafeMode", "shutdown", "crash", "getLastShutdownReason",
        "getLastSleepReason", "setStayOnSetting", "boostScreenBrightness", "acquireWakeLockAsync",
        "releaseWakeLockAsync", "updateWakeLockUidsAsync", "isScreenBrightnessBoosted", "setAttentionLight",
        "setDozeAfterScreenOff", "isAmbientDisplayAvailable", "suppressAmbientDisplay", "isAmbientDisplaySuppressedForToken",
        "isAmbientDisplaySuppressed", "isAmbientDisplaySuppressedForTokenByApp", "forceSuspend",
    ]),
    ("android.os.IPowerStatsService", &[
        "getSupportedPowerMonitors", "getPowerMonitorReadings",
    ]),
    ("android.os.IProcessInfoService", &[
        "getProcessStatesFromPids", "getProcessStatesAndOomScoresFromPids",
    ]),
    ("android.os.IProgressListener", &[
        "onStarted", "onProgress", "onFinished",
    ]),
    ("android.os.IRecoverySystem", &[
        "allocateSpaceForUpdate", "uncrypt", "setupBcb", "clearBcb",
        "rebootRecoveryWithCommand", "requestLskf", "clearLskf", "isLskfCaptured",
        "rebootWithLskfAssumeSlotSwitch", "rebootWithLskf",
    ]),
    ("android.os.IRecoverySystemProgressListener", &[
        "onProgress",
    ]),
    ("android.os.IRemoteCallback", &[
        "sendResult",
    ]),
    ("android.os.ISchedulingPolicyService", &[
        "requestPriority", "requestCpusetBoost",
    ]),
    ("android.os.IScreenTimeoutPolicyListener", &[
        "onScreenTimeoutPolicyChanged",
    ]),
    ("android.os.ISecurityStateManager", &[
        "getGlobalSecurityState",
    ]),
    ("android.os.IServiceCallback", &[
        "onRegistration",
    ]),
    ("android.os.IServiceManager", &[
        "getService", "getService2", "checkService", "checkService2",
        "addService", "listServices", "registerForNotifications", "unregisterForNotifications",
        "isDeclared", "getDeclaredInstances", "updatableViaApex", "getUpdatableNames",
        "getConnectionInfo", "registerClientCallback", "tryUnregisterService", "getServiceDebugInfo",
    ]),
    ("android.os.IStatsBootstrapAtomService", &[
        "reportBootstrapAtom",
    ]),
    ("android.os.IStoraged", &[
        "onUserStarted", "onUserStopped", "getRecentPerf",
    ]),
    ("android.os.ISystemConfig", &[
        "getDisabledUntilUsedPreinstalledCarrierApps", "getDisabledUntilUsedPreinstalledCarrierAssociatedApps", "getDisabledUntilUsedPreinstalledCarrierAssociatedAppEntries", "getSystemPermissionUids",
        "getEnabledComponentOverrides", "getDefaultVrComponents", "getPreventUserDisablePackages", "getEnhancedConfirmationTrustedPackages",
        "getEnhancedConfirmationTrustedInstallers",
    ]),
    ("android.os.ISystemUpdateManager", &[
        "retrieveSystemUpdateInfo", "updateSystemUpdateInfo",
    ]),
    ("android.os.IThermalEventListener", &[
        "notifyThrottling",
    ]),
    ("android.os.IThermalHeadroomListener", &[
        "onHeadroomChange",
    ]),
    ("android.os.IThermalService", &[
        "registerThermalEventListener", "registerThermalEventListenerWithType", "unregisterThermalEventListener", "getCurrentTemperatures",
        "getCurrentTemperaturesWithType", "registerThermalStatusListener", "unregisterThermalStatusListener", "getCurrentThermalStatus",
        "getCurrentCoolingDevices", "getCurrentCoolingDevicesWithType", "getThermalHeadroom", "getThermalHeadroomThresholds",
        "registerThermalHeadroomListener", "unregisterThermalHeadroomListener",
    ]),
    ("android.os.IThermalStatusListener", &[
        "onStatusChange",
    ]),
    ("android.os.ITradeInMode", &[
        "start", "isEvaluationModeAllowed", "enterEvaluationMode", "scheduleWipeForTesting",
        "startTesting", "stopTesting", "isTesting",
    ]),
    ("android.os.IUpdateEngine", &[
        "applyPayload", "applyPayloadFd", "bind", "unbind",
        "suspend", "resume", "cancel", "resetStatus",
        "setShouldSwitchSlotOnReboot", "resetShouldSwitchSlotOnReboot", "verifyPayloadApplicable", "allocateSpaceForPayload",
        "cleanupSuccessfulUpdate", "triggerPostinstall",
    ]),
    ("android.os.IUpdateEngineCallback", &[
        "onStatusUpdate", "onPayloadApplicationComplete",
    ]),
    ("android.os.IUpdateLock", &[
        "acquireUpdateLock", "releaseUpdateLock",
    ]),
    ("android.os.IUserManager", &[
        "getCredentialOwnerProfile", "getProfileParentId", "createUserWithThrow", "preCreateUserWithThrow",
        "createProfileForUserWithThrow", "createRestrictedProfileWithThrow", "getPreInstallableSystemPackages", "setUserEnabled",
        "setUserAdmin", "revokeUserAdmin", "evictCredentialEncryptionKey", "removeUser",
        "removeUserEvenWhenDisallowed", "setUserName", "setUserIcon", "getUserIcon",
        "getPrimaryUser", "getMainUserId", "getCommunalProfileId", "getPreviousFullUserToEnterForeground",
        "getUsers", "getProfiles", "getProfileIds", "isUserTypeEnabled",
        "canAddMoreUsersOfType", "getRemainingCreatableUserCount", "getRemainingCreatableProfileCount", "canAddMoreProfilesToUser",
        "canAddMoreManagedProfiles", "getProfileParent", "isSameProfileGroup", "isHeadlessSystemUserMode",
        "isUserOfType", "getUserInfo", "getUserPropertiesCopy", "getUserAccount",
        "setUserAccount", "getUserCreationTime", "getUserSwitchability", "isUserSwitcherEnabled",
        "getUserLogoutability", "isRestricted", "canHaveRestrictedProfile", "canAddPrivateProfile",
        "getUserSerialNumber", "getUserHandle", "getUserRestrictionSource", "getUserRestrictionSources",
        "getUserRestrictions", "hasBaseUserRestriction", "hasUserRestriction", "hasUserRestrictionOnAnyUser",
        "isSettingRestrictedForUser", "addUserRestrictionsListener", "setUserRestriction", "setApplicationRestrictions",
        "getApplicationRestrictions", "getApplicationRestrictionsForUser", "setDefaultGuestRestrictions", "getDefaultGuestRestrictions",
        "removeUserWhenPossible", "markGuestForDeletion", "getGuestUsers", "isQuietModeEnabled",
        "createUserWithAttributes", "setSeedAccountData", "getSeedAccountName", "getSeedAccountType",
        "getSeedAccountOptions", "clearSeedAccountData", "someUserHasSeedAccount", "someUserHasAccount",
        "getProfileType", "isDemoUser", "isAdminUser", "isPreCreated",
        "createProfileForUserEvenWhenDisallowedWithThrow", "isUserUnlockingOrUnlocked", "getUserIconBadgeResId", "getUserBadgeResId",
        "getUserBadgeNoBackgroundResId", "getUserBadgeLabelResId", "getUserBadgeColorResId", "getUserBadgeDarkColorResId",
        "getUserStatusBarIconResId", "hasBadge", "getProfileLabelResId", "getProfileAccessibilityLabelResId",
        "isUserUnlocked", "isUserRunning", "isUserForeground", "isUserVisible",
        "getVisibleUsers", "getMainDisplayIdAssignedToUser", "isForegroundUserAdmin", "isUserNameSet",
        "hasRestrictedProfiles", "requestQuietModeEnabled", "getUserName", "getUserStartRealtime",
        "getUserUnlockRealtime", "setUserEphemeral", "setBootUser", "getBootUser",
        "getProfileIdsExcludingHidden",
    ]),
    ("android.os.IUserRestrictionsListener", &[
        "onUserRestrictionsChanged",
    ]),
    ("android.os.IVibratorManagerService", &[
        "getVibratorIds", "getCapabilities", "getVibratorInfo", "isVibrating",
        "registerVibratorStateListener", "unregisterVibratorStateListener", "setAlwaysOnEffect", "vibrate",
        "cancelVibrate", "performHapticFeedback", "performHapticFeedbackForInputDevice", "startVendorVibrationSession",
    ]),
    ("android.os.IVibratorStateListener", &[
        "onVibrating",
    ]),
    ("android.os.IVold", &[
        "setListener", "abortFuse", "monitor", "reset",
        "shutdown", "onUserAdded", "onUserRemoved", "onUserStarted",
        "onUserStopped", "addAppIds", "addSandboxIds", "onSecureKeyguardStateChanged",
        "partition", "forgetPartition", "mount", "unmount",
        "format", "benchmark", "moveStorage", "remountUid",
        "remountAppStorageDirs", "unmountAppStorageDirs", "setupAppDir", "fixupAppDir",
        "ensureAppDirsCreated", "createObb", "destroyObb", "fstrim",
        "runIdleMaint", "abortIdleMaint", "getStorageLifeTime", "setGCUrgentPace",
        "refreshLatestWrite", "getWriteAmount", "mountAppFuse", "unmountAppFuse",
        "fbeEnable", "initUser0", "mountFstab", "encryptFstab",
        "setStorageBindingSeed", "createUserStorageKeys", "destroyUserStorageKeys", "setCeStorageProtection",
        "getUnlockedUsers", "unlockCeStorage", "lockCeStorage", "prepareUserStorage",
        "destroyUserStorage", "prepareSandboxForApp", "destroySandboxForApp", "startCheckpoint",
        "needsCheckpoint", "needsRollback", "isCheckpointing", "abortChanges",
        "commitChanges", "prepareCheckpoint", "restoreCheckpoint", "restoreCheckpointPart",
        "markBootAttempt", "supportsCheckpoint", "supportsBlockCheckpoint", "supportsFileCheckpoint",
        "resetCheckpoint", "earlyBootEnded", "createStubVolume", "destroyStubVolume",
        "openAppFuseFile", "incFsEnabled", "mountIncFs", "unmountIncFs",
        "setIncFsMountOptions", "bindMount", "destroyDsuMetadataKey", "getStorageSize",
        "getStorageRemainingLifetime", "getWriteBoosterBufferSize", "getWriteBoosterBufferAvailablePercent", "setWriteBoosterBufferFlush",
        "setWriteBoosterBufferOn", "getWriteBoosterLifeTimeEstimate",
    ]),
    ("android.os.IVoldListener", &[
        "onDiskCreated", "onDiskScanned", "onDiskMetadataChanged", "onDiskDestroyed",
        "onVolumeCreated", "onVolumeStateChanged", "onVolumeMetadataChanged", "onVolumePathChanged",
        "onVolumeInternalPathChanged", "onVolumeDestroyed",
    ]),
    ("android.os.IVoldMountCallback", &[
        "onVolumeChecking",
    ]),
    ("android.os.IVoldTaskListener", &[
        "onStatus", "onFinished",
    ]),
    ("android.os.IWakeLockCallback", &[
        "onStateChanged",
    ]),
    ("android.os.image.IDynamicSystemService", &[
        "startInstallation", "createPartition", "closePartition", "finishInstallation",
        "getInstallationProgress", "abort", "isInUse", "isInstalled",
        "isEnabled", "remove", "setEnable", "setAshmem",
        "submitFromAshmem", "getAvbPublicKey", "suggestScratchSize", "getActiveDsuSlot",
    ]),
    ("android.os.incremental.IIncrementalService", &[
        "openStorage", "createStorage", "createLinkedStorage", "startLoading",
        "onInstallationComplete", "makeBindMount", "deleteBindMount", "makeDirectory",
        "makeDirectories", "makeFile", "makeFileFromRange", "makeLink",
        "unlink", "isFileFullyLoaded", "isFullyLoaded", "getLoadingProgress",
        "getMetadataByPath", "getMetadataById", "deleteStorage", "disallowReadLogs",
        "configureNativeBinaries", "waitForNativeBinariesExtraction", "registerLoadingProgressListener", "unregisterLoadingProgressListener",
        "getMetrics",
    ]),
    ("android.os.incremental.IIncrementalServiceConnector", &[
        "setStorageParams",
    ]),
    ("android.os.incremental.IStorageHealthListener", &[
        "onHealthStatus",
    ]),
    ("android.os.incremental.IStorageLoadingProgressListener", &[
        "onStorageLoadingProgressChanged",
    ]),
    ("android.os.instrumentation.IDynamicInstrumentationManager", &[
        "getExecutableMethodFileOffsets",
    ]),
    ("android.os.instrumentation.IOffsetCallback", &[
        "onResult",
    ]),
    ("android.os.logcat.ILogcatManagerService", &[
        "startThread", "finishThread",
    ]),
    ("android.os.storage.IObbActionListener", &[
        "onObbResult",
    ]),
    ("android.os.storage.IStorageEventListener", &[
        "onUsbMassStorageConnectionChanged", "onStorageStateChanged", "onVolumeStateChanged", "onVolumeRecordChanged",
        "onVolumeForgotten", "onDiskScanned", "onDiskDestroyed",
    ]),
    ("android.os.storage.IStorageManager", &[
        "registerListener", "unregisterListener", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "shutdown",
        "", "mountObb", "unmountObb", "isObbMounted",
        "getMountedObbPath", "", "", "",
        "", "getVolumeList", "", "",
        "", "", "mkdirs", "",
        "", "", "", "",
        "", "lastMaintenance", "runMaintenance", "",
        "getDisks", "getVolumes", "getVolumeRecords", "mount",
        "unmount", "format", "partitionPublic", "partitionPrivate",
        "partitionMixed", "setVolumeNickname", "setVolumeUserFlags", "forgetVolume",
        "forgetAllVolumes", "getPrimaryStorageUuid", "setPrimaryStorageUuid", "benchmark",
        "setDebugFlags", "createUserStorageKeys", "destroyUserStorageKeys", "unlockCeStorage",
        "lockCeStorage", "isCeStorageUnlocked", "prepareUserStorage", "destroyUserStorage",
        "", "", "setCeStorageProtection", "",
        "fstrim", "mountProxyFileDescriptorBridge", "openProxyFileDescriptor", "getCacheQuotaBytes",
        "getCacheSizeBytes", "getAllocatableBytes", "allocateBytes", "runIdleMaintenance",
        "abortIdleMaintenance", "", "", "commitChanges",
        "supportsCheckpoint", "startCheckpoint", "needsCheckpoint", "abortChanges",
        "", "fixupAppDir", "disableAppDataIsolation", "getManageSpaceActivityIntent",
        "notifyAppIoBlocked", "notifyAppIoResumed", "getExternalStorageMountMode", "isAppIoBlocked",
        "setCloudMediaProvider", "getCloudMediaProvider", "getInternalStorageBlockDeviceSize", "getInternalStorageRemainingLifetime",
    ]),
    ("android.os.storage.IStorageShutdownObserver", &[
        "onShutDownComplete",
    ]),
    ("android.os.vibrator.IVibrationSession", &[
        "vibrate", "finishSession", "cancelSession",
    ]),
    ("android.os.vibrator.IVibrationSessionCallback", &[
        "onStarted", "onFinishing", "onFinished",
    ]),
    ("android.permission.ILegacyPermissionManager", &[
        "checkDeviceIdentifierAccess", "checkPhoneNumberAccess", "grantDefaultPermissionsToEnabledCarrierApps", "grantDefaultPermissionsToEnabledImsServices",
        "grantDefaultPermissionsToEnabledTelephonyDataServices", "revokeDefaultPermissionsFromDisabledTelephonyDataServices", "grantDefaultPermissionsToActiveLuiApp", "revokeDefaultPermissionsFromLuiApps",
        "grantDefaultPermissionsToCarrierServiceApp",
    ]),
    ("android.permission.IOnPermissionsChangeListener", &[
        "onPermissionsChanged",
    ]),
    ("android.permission.IPermissionChecker", &[
        "checkPermission", "finishDataDelivery", "checkOp",
    ]),
    ("android.permission.IPermissionController", &[
        "revokeRuntimePermissions", "getRuntimePermissionBackup", "stageAndApplyRuntimePermissionsBackup", "applyStagedRuntimePermissionBackup",
        "getAppPermissions", "revokeRuntimePermission", "countPermissionApps", "getPermissionUsages",
        "setRuntimePermissionGrantStateByDeviceAdminFromParams", "grantOrUpgradeDefaultRuntimePermissions", "notifyOneTimePermissionSessionTimeout", "updateUserSensitiveForApp",
        "getPrivilegesDescriptionStringForProfile", "getPlatformPermissionsForGroup", "getGroupOfPlatformPermission", "getUnusedAppCount",
        "getHibernationEligibility", "revokeSelfPermissionsOnKill",
    ]),
    ("android.permission.IPermissionManager", &[
        "getAllPermissionGroups", "getPermissionGroupInfo", "getPermissionInfo", "queryPermissionsByGroup",
        "addPermission", "removePermission", "getPermissionFlags", "updatePermissionFlags",
        "updatePermissionFlagsForAllApps", "addOnPermissionsChangeListener", "removeOnPermissionsChangeListener", "getAllowlistedRestrictedPermissions",
        "addAllowlistedRestrictedPermission", "removeAllowlistedRestrictedPermission", "grantRuntimePermission", "revokeRuntimePermission",
        "revokePostNotificationPermissionWithoutKillForTest", "shouldShowRequestPermissionRationale", "isPermissionRevokedByPolicy", "getSplitPermissions",
        "startOneTimePermissionSession", "stopOneTimePermissionSession", "getAutoRevokeExemptionRequestedPackages", "getAutoRevokeExemptionGrantedPackages",
        "setAutoRevokeExempted", "isAutoRevokeExempted", "registerAttributionSource", "getRegisteredAttributionSourceCount",
        "isRegisteredAttributionSource", "checkPermission", "checkUidPermission", "getAllPermissionStates",
        "getPermissionRequestState",
    ]),
    ("android.print.ILayoutResultCallback", &[
        "onLayoutStarted", "onLayoutFinished", "onLayoutFailed", "onLayoutCanceled",
    ]),
    ("android.print.IPrintDocumentAdapter", &[
        "setObserver", "start", "layout", "write",
        "finish",
    ]),
    ("android.print.IPrintDocumentAdapterObserver", &[
        "onDestroy",
    ]),
    ("android.print.IPrintJobStateChangeListener", &[
        "onPrintJobStateChanged",
    ]),
    ("android.print.IPrintManager", &[
        "getPrintJobInfos", "getPrintJobInfo", "print", "cancelPrintJob",
        "restartPrintJob", "addPrintJobStateChangeListener", "removePrintJobStateChangeListener", "addPrintServicesChangeListener",
        "removePrintServicesChangeListener", "getPrintServices", "setPrintServiceEnabled", "isPrintServiceEnabled",
        "addPrintServiceRecommendationsChangeListener", "removePrintServiceRecommendationsChangeListener", "getPrintServiceRecommendations", "createPrinterDiscoverySession",
        "startPrinterDiscovery", "stopPrinterDiscovery", "validatePrinters", "startPrinterStateTracking",
        "getCustomPrinterIcon", "stopPrinterStateTracking", "destroyPrinterDiscoverySession", "getBindInstantServiceAllowed",
        "setBindInstantServiceAllowed",
    ]),
    ("android.print.IPrintServicesChangeListener", &[
        "onPrintServicesChanged",
    ]),
    ("android.print.IPrintSpooler", &[
        "removeObsoletePrintJobs", "getPrintJobInfos", "getPrintJobInfo", "createPrintJob",
        "setPrintJobState", "setProgress", "setStatus", "setStatusRes",
        "onCustomPrinterIconLoaded", "getCustomPrinterIcon", "clearCustomPrinterIconCache", "setPrintJobTag",
        "writePrintJobData", "setClient", "setPrintJobCancelling", "pruneApprovedPrintServices",
    ]),
    ("android.print.IPrintSpoolerCallbacks", &[
        "onGetPrintJobInfosResult", "onCancelPrintJobResult", "onSetPrintJobStateResult", "onSetPrintJobTagResult",
        "onGetPrintJobInfoResult", "onGetCustomPrinterIconResult", "onCustomPrinterIconCached", "customPrinterIconCacheCleared",
    ]),
    ("android.print.IPrintSpoolerClient", &[
        "onPrintJobQueued", "onAllPrintJobsForServiceHandled", "onAllPrintJobsHandled", "onPrintJobStateChanged",
    ]),
    ("android.print.IPrinterDiscoveryObserver", &[
        "onPrintersAdded", "onPrintersRemoved",
    ]),
    ("android.print.IWriteResultCallback", &[
        "onWriteStarted", "onWriteFinished", "onWriteFailed", "onWriteCanceled",
    ]),
    ("android.printservice.IPrintService", &[
        "setClient", "requestCancelPrintJob", "onPrintJobQueued", "createPrinterDiscoverySession",
        "startPrinterDiscovery", "stopPrinterDiscovery", "validatePrinters", "startPrinterStateTracking",
        "requestCustomPrinterIcon", "stopPrinterStateTracking", "destroyPrinterDiscoverySession",
    ]),
    ("android.printservice.IPrintServiceClient", &[
        "getPrintJobInfos", "getPrintJobInfo", "setPrintJobState", "setPrintJobTag",
        "writePrintJobData", "setProgress", "setStatus", "setStatusRes",
        "onPrintersAdded", "onPrintersRemoved", "onCustomPrinterIconLoaded",
    ]),
    ("android.printservice.recommendation.IRecommendationService", &[
        "registerCallbacks",
    ]),
    ("android.printservice.recommendation.IRecommendationServiceCallbacks", &[
        "onRecommendationsUpdated",
    ]),
    ("android.printservice.recommendation.IRecommendationsChangeListener", &[
        "onRecommendationsChanged",
    ]),
    ("android.security.IFileIntegrityService", &[
        "createAuthToken", "setupFsverity",
    ]),
    ("android.security.IKeyChainAliasCallback", &[
        "alias",
    ]),
    ("android.security.IKeyChainService", &[
        "requestPrivateKey", "getCertificate", "getCaCertificates", "isUserSelectable",
        "setUserSelectable", "generateKeyPair", "setKeyPairCertificate", "installCaCertificate",
        "installKeyPair", "removeKeyPair", "containsKeyPair", "getGrants",
        "deleteCaCertificate", "reset", "getUserCaAliases", "getSystemCaAliases",
        "containsCaAlias", "getEncodedCaCertificate", "getCaCertificateChainAliases", "setCredentialManagementApp",
        "hasCredentialManagementApp", "getCredentialManagementAppPackageName", "getCredentialManagementAppPolicy", "getPredefinedAliasForPackageAndUri",
        "removeCredentialManagementApp", "isCredentialManagementApp", "setGrant", "hasGrant",
        "getWifiKeyGrantAsUser",
    ]),
    ("android.security.advancedprotection.IAdvancedProtectionCallback", &[
        "onAdvancedProtectionChanged",
    ]),
    ("android.security.advancedprotection.IAdvancedProtectionService", &[
        "isAdvancedProtectionEnabled", "registerAdvancedProtectionCallback", "unregisterAdvancedProtectionCallback", "setAdvancedProtectionEnabled",
        "getAdvancedProtectionFeatures", "logDialogShown",
    ]),
    ("android.security.apc.IConfirmationCallback", &[
        "onCompleted",
    ]),
    ("android.security.apc.IProtectedConfirmation", &[
        "presentPrompt", "cancelPrompt", "isSupported",
    ]),
    ("android.security.attestationverification.IAttestationVerificationManagerService", &[
        "verifyAttestation", "verifyToken",
    ]),
    ("android.security.attestationverification.IAttestationVerificationService", &[
        "onVerifyAttestation",
    ]),
    ("android.security.authenticationpolicy.IAuthenticationPolicyService", &[
        "enableSecureLockDevice", "disableSecureLockDevice",
    ]),
    ("android.security.authorization.IKeystoreAuthorization", &[
        "addAuthToken", "onDeviceUnlocked", "onDeviceLocked", "onWeakUnlockMethodsExpired",
        "onNonLskfUnlockMethodsExpired", "getAuthTokensForCredStore", "getLastAuthTime",
    ]),
    ("android.security.identity.ICredential", &[
        "createEphemeralKeyPair", "setReaderEphemeralPublicKey", "deleteCredential", "deleteWithChallenge",
        "proveOwnership", "getCredentialKeyCertificateChain", "selectAuthKey", "getEntries",
        "setAvailableAuthenticationKeys", "getAuthKeysNeedingCertification", "storeStaticAuthenticationData", "storeStaticAuthenticationDataWithExpiration",
        "getAuthenticationDataUsageCount", "getAuthenticationDataExpirations", "update",
    ]),
    ("android.security.identity.ICredentialStore", &[
        "getSecurityHardwareInfo", "createCredential", "getCredentialByName", "createPresentationSession",
    ]),
    ("android.security.identity.ICredentialStoreFactory", &[
        "getCredentialStore",
    ]),
    ("android.security.identity.ISession", &[
        "getEphemeralKeyPair", "getAuthChallenge", "setReaderEphemeralPublicKey", "setSessionTranscript",
        "getCredentialForPresentation",
    ]),
    ("android.security.identity.IWritableCredential", &[
        "getCredentialKeyCertificateChain", "personalize",
    ]),
    ("android.security.intrusiondetection.IIntrusionDetectionEventTransport", &[
        "initialize", "addData", "release",
    ]),
    ("android.security.intrusiondetection.IIntrusionDetectionService", &[
        "addStateCallback", "removeStateCallback", "enable", "disable",
    ]),
    ("android.security.intrusiondetection.IIntrusionDetectionServiceCommandCallback", &[
        "onSuccess", "onFailure",
    ]),
    ("android.security.intrusiondetection.IIntrusionDetectionServiceStateCallback", &[
        "onStateChange",
    ]),
    ("android.security.legacykeystore.ILegacyKeystore", &[
        "get", "put", "remove", "list",
    ]),
    ("android.security.maintenance.IKeystoreMaintenance", &[
        "onUserAdded", "initUserSuperKeys", "onUserRemoved", "onUserLskfRemoved",
        "clearNamespace", "earlyBootEnded", "migrateKeyNamespace", "deleteAllKeys",
        "getAppUidsAffectedBySid",
    ]),
    ("android.security.metrics.IKeystoreMetrics", &[
        "pullMetrics",
    ]),
    ("android.security.rkp.IGetKeyCallback", &[
        "onSuccess", "onCancel", "onError",
    ]),
    ("android.security.rkp.IGetRegistrationCallback", &[
        "onSuccess", "onCancel", "onError",
    ]),
    ("android.security.rkp.IRegistration", &[
        "getKey", "cancelGetKey", "storeUpgradedKeyAsync",
    ]),
    ("android.security.rkp.IRemoteProvisioning", &[
        "getRegistration",
    ]),
    ("android.security.rkp.IStoreUpgradedKeyCallback", &[
        "onSuccess", "onError",
    ]),
    ("android.service.ambientcontext.IAmbientContextDetectionService", &[
        "startDetection", "stopDetection", "queryServiceStatus",
    ]),
    ("android.service.appprediction.IPredictionService", &[
        "onCreatePredictionSession", "notifyAppTargetEvent", "notifyLaunchLocationShown", "sortAppTargets",
        "registerPredictionUpdates", "unregisterPredictionUpdates", "requestPredictionUpdate", "onDestroyPredictionSession",
        "requestServiceFeatures",
    ]),
    ("android.service.assist.classification.IFieldClassificationCallback", &[
        "onCancellable", "onSuccess", "onFailure", "isCompleted",
        "cancel",
    ]),
    ("android.service.assist.classification.IFieldClassificationService", &[
        "onConnected", "onDisconnected", "onFieldClassificationRequest",
    ]),
    ("android.service.attention.IAttentionCallback", &[
        "onSuccess", "onFailure",
    ]),
    ("android.service.attention.IAttentionService", &[
        "checkAttention", "cancelAttentionCheck", "onStartProximityUpdates", "onStopProximityUpdates",
    ]),
    ("android.service.attention.IProximityUpdateCallback", &[
        "onProximityUpdate",
    ]),
    ("android.service.autofill.IAutoFillService", &[
        "onConnectedStateChanged", "onFillRequest", "onFillCredentialRequest", "onSaveRequest",
        "onSavedPasswordCountRequest", "onConvertCredentialRequest", "onSessionDestroyed",
    ]),
    ("android.service.autofill.IAutofillFieldClassificationService", &[
        "calculateScores",
    ]),
    ("android.service.autofill.IConvertCredentialCallback", &[
        "onSuccess", "onFailure",
    ]),
    ("android.service.autofill.IFillCallback", &[
        "onCancellable", "onSuccess", "onFailure",
    ]),
    ("android.service.autofill.IInlineSuggestionRenderService", &[
        "renderSuggestion", "getInlineSuggestionsRendererInfo", "destroySuggestionViews",
    ]),
    ("android.service.autofill.IInlineSuggestionUi", &[
        "getSurfacePackage", "releaseSurfaceControlViewHost",
    ]),
    ("android.service.autofill.IInlineSuggestionUiCallback", &[
        "onClick", "onLongClick", "onContent", "onError",
        "onTransferTouchFocusToImeWindow", "onStartIntentSender",
    ]),
    ("android.service.autofill.ISaveCallback", &[
        "onSuccess", "onFailure",
    ]),
    ("android.service.autofill.ISurfacePackageResultCallback", &[
        "onResult",
    ]),
    ("android.service.autofill.augmented.IAugmentedAutofillService", &[
        "onConnected", "onDisconnected", "onFillRequest", "onDestroyAllFillWindowsRequest",
    ]),
    ("android.service.autofill.augmented.IFillCallback", &[
        "onCancellable", "onSuccess", "isCompleted", "cancel",
    ]),
    ("android.service.carrier.IApnSourceService", &[
        "getApns",
    ]),
    ("android.service.carrier.ICarrierMessagingCallback", &[
        "onFilterComplete", "onSendSmsComplete", "onSendMultipartSmsComplete", "onSendMmsComplete",
        "onDownloadMmsComplete",
    ]),
    ("android.service.carrier.ICarrierMessagingService", &[
        "filterSms", "sendTextSms", "sendDataSms", "sendMultipartTextSms",
        "sendMms", "downloadMms",
    ]),
    ("android.service.carrier.ICarrierService", &[
        "getCarrierConfig",
    ]),
    ("android.service.chooser.IChooserTargetResult", &[
        "sendResult",
    ]),
    ("android.service.chooser.IChooserTargetService", &[
        "getChooserTargets",
    ]),
    ("android.service.contentcapture.IContentCaptureService", &[
        "onConnected", "onDisconnected", "onSessionStarted", "onSessionFinished",
        "onActivitySnapshot", "onDataRemovalRequest", "onDataShared", "onActivityEvent",
    ]),
    ("android.service.contentcapture.IContentCaptureServiceCallback", &[
        "setContentCaptureWhitelist", "setContentCaptureConditions", "disableSelf", "writeSessionFlush",
    ]),
    ("android.service.contentcapture.IContentProtectionAllowlistCallback", &[
        "setAllowlist",
    ]),
    ("android.service.contentcapture.IContentProtectionService", &[
        "onLoginDetected", "onUpdateAllowlistRequest",
    ]),
    ("android.service.contentcapture.IDataShareCallback", &[
        "accept", "reject",
    ]),
    ("android.service.contentcapture.IDataShareReadAdapter", &[
        "start", "error", "finish",
    ]),
    ("android.service.contentsuggestions.IContentSuggestionsService", &[
        "provideContextImage", "suggestContentSelections", "classifyContentSelections", "notifyInteraction",
    ]),
    ("android.service.controls.IControlsActionCallback", &[
        "accept",
    ]),
    ("android.service.controls.IControlsProvider", &[
        "load", "loadSuggested", "subscribe", "action",
    ]),
    ("android.service.controls.IControlsSubscriber", &[
        "onSubscribe", "onNext", "onError", "onComplete",
    ]),
    ("android.service.controls.IControlsSubscription", &[
        "request", "cancel",
    ]),
    ("android.service.credentials.IBeginCreateCredentialCallback", &[
        "onSuccess", "onFailure", "onCancellable",
    ]),
    ("android.service.credentials.IBeginGetCredentialCallback", &[
        "onSuccess", "onFailure", "onCancellable",
    ]),
    ("android.service.credentials.IClearCredentialStateCallback", &[
        "onSuccess", "onFailure", "onCancellable",
    ]),
    ("android.service.credentials.ICredentialProviderService", &[
        "onBeginGetCredential", "onBeginCreateCredential", "onClearCredentialState",
    ]),
    ("android.service.displayhash.IDisplayHashingService", &[
        "generateDisplayHash", "verifyDisplayHash", "getDisplayHashAlgorithms", "getIntervalBetweenRequestsMillis",
    ]),
    ("android.service.dreams.IDreamManager", &[
        "dream", "awaken", "setDreamComponents", "getDreamComponents",
        "getDefaultDreamComponentForUser", "testDream", "isDreaming", "isDreamingOrInPreview",
        "canStartDreaming", "finishSelf", "startDozing", "stopDozing",
        "forceAmbientDisplayEnabled", "getDreamComponentsForUser", "setDreamComponentsForUser", "setSystemDreamComponent",
        "registerDreamOverlayService", "startDreamActivity", "setDreamIsObscured", "setDevicePostured",
        "startDozingOneway", "finishSelfOneway", "setScreensaverEnabled",
    ]),
    ("android.service.dreams.IDreamOverlay", &[
        "getClient",
    ]),
    ("android.service.dreams.IDreamOverlayCallback", &[
        "onExitRequested", "onRedirectWake",
    ]),
    ("android.service.dreams.IDreamOverlayClient", &[
        "startDream", "wakeUp", "endDream", "onWakeRequested",
        "comeToFront",
    ]),
    ("android.service.dreams.IDreamOverlayClientCallback", &[
        "onDreamOverlayClient",
    ]),
    ("android.service.dreams.IDreamService", &[
        "attach", "detach", "wakeUp", "comeToFront",
    ]),
    ("android.service.euicc.IDeleteSubscriptionCallback", &[
        "onComplete",
    ]),
    ("android.service.euicc.IDownloadSubscriptionCallback", &[
        "onComplete",
    ]),
    ("android.service.euicc.IEraseSubscriptionsCallback", &[
        "onComplete",
    ]),
    ("android.service.euicc.IEuiccService", &[
        "downloadSubscription", "getDownloadableSubscriptionMetadata", "getEid", "getOtaStatus",
        "startOtaIfNecessary", "getEuiccProfileInfoList", "getDefaultDownloadableSubscriptionList", "getEuiccInfo",
        "deleteSubscription", "switchToSubscription", "updateSubscriptionNickname", "eraseSubscriptions",
        "eraseSubscriptionsWithOptions", "retainSubscriptionsForFactoryReset", "dump", "getAvailableMemoryInBytes",
    ]),
    ("android.service.euicc.IEuiccServiceDumpResultCallback", &[
        "onComplete",
    ]),
    ("android.service.euicc.IGetAvailableMemoryInBytesCallback", &[
        "onSuccess", "onUnsupportedOperationException",
    ]),
    ("android.service.euicc.IGetDefaultDownloadableSubscriptionListCallback", &[
        "onComplete",
    ]),
    ("android.service.euicc.IGetDownloadableSubscriptionMetadataCallback", &[
        "onComplete",
    ]),
    ("android.service.euicc.IGetEidCallback", &[
        "onSuccess",
    ]),
    ("android.service.euicc.IGetEuiccInfoCallback", &[
        "onSuccess",
    ]),
    ("android.service.euicc.IGetEuiccProfileInfoListCallback", &[
        "onComplete",
    ]),
    ("android.service.euicc.IGetOtaStatusCallback", &[
        "onSuccess",
    ]),
    ("android.service.euicc.IOtaStatusChangedCallback", &[
        "onOtaStatusChanged",
    ]),
    ("android.service.euicc.IRetainSubscriptionsForFactoryResetCallback", &[
        "onComplete",
    ]),
    ("android.service.euicc.ISwitchToSubscriptionCallback", &[
        "onComplete",
    ]),
    ("android.service.euicc.IUpdateSubscriptionNicknameCallback", &[
        "onComplete",
    ]),
    ("android.service.games.IGameService", &[
        "connected", "disconnected", "gameStarted",
    ]),
    ("android.service.games.IGameServiceController", &[
        "createGameSession",
    ]),
    ("android.service.games.IGameSession", &[
        "onDestroyed", "onTransientSystemBarVisibilityFromRevealGestureChanged", "onTaskFocusChanged",
    ]),
    ("android.service.games.IGameSessionController", &[
        "takeScreenshot", "restartGame",
    ]),
    ("android.service.games.IGameSessionService", &[
        "create",
    ]),
    ("android.service.gatekeeper.IGateKeeperService", &[
        "enroll", "verify", "verifyChallenge", "getSecureUserId",
        "clearSecureUserId", "reportDeviceSetupComplete",
    ]),
    ("android.service.media.IMediaBrowserService", &[
        "connect", "disconnect", "addSubscriptionDeprecated", "removeSubscriptionDeprecated",
        "getMediaItem", "addSubscription", "removeSubscription",
    ]),
    ("android.service.media.IMediaBrowserServiceCallbacks", &[
        "onConnect", "onConnectFailed", "onLoadChildren", "onDisconnect",
    ]),
    ("android.service.notification.IConditionListener", &[
        "onConditionsReceived",
    ]),
    ("android.service.notification.IConditionProvider", &[
        "onConnected", "onSubscribe", "onUnsubscribe",
    ]),
    ("android.service.notification.INotificationListener", &[
        "onListenerConnected", "onNotificationPosted", "onNotificationPostedFull", "onStatusBarIconsBehaviorChanged",
        "onNotificationRemoved", "onNotificationRemovedFull", "onNotificationRankingUpdate", "onListenerHintsChanged",
        "onInterruptionFilterChanged", "onNotificationChannelModification", "onNotificationChannelGroupModification", "onNotificationEnqueuedWithChannel",
        "onNotificationEnqueuedWithChannelFull", "onNotificationSnoozedUntilContext", "onNotificationSnoozedUntilContextFull", "onNotificationsSeen",
        "onPanelRevealed", "onPanelHidden", "onNotificationVisibilityChanged", "onNotificationExpansionChanged",
        "onNotificationDirectReply", "onSuggestedReplySent", "onActionClicked", "onNotificationClicked",
        "onAllowedAdjustmentsChanged", "onNotificationFeedbackReceived",
    ]),
    ("android.service.notification.IStatusBarNotificationHolder", &[
        "get",
    ]),
    ("android.service.oemlock.IOemLockService", &[
        "getLockName", "setOemUnlockAllowedByCarrier", "isOemUnlockAllowedByCarrier", "setOemUnlockAllowedByUser",
        "isOemUnlockAllowedByUser", "isOemUnlockAllowed", "isDeviceOemUnlocked",
    ]),
    ("android.service.persistentdata.IPersistentDataBlockService", &[
        "write", "read", "wipe", "getDataBlockSize",
        "getMaximumDataBlockSize", "setOemUnlockEnabled", "getOemUnlockEnabled", "getFlashLockState",
        "hasFrpCredentialHandle", "getPersistentDataPackageName", "isFactoryResetProtectionActive", "deactivateFactoryResetProtection",
        "setFactoryResetProtectionSecret",
    ]),
    ("android.service.quickaccesswallet.IQuickAccessWalletService", &[
        "onWalletCardsRequested", "onWalletCardSelected", "onWalletDismissed", "registerWalletServiceEventListener",
        "unregisterWalletServiceEventListener", "onTargetActivityIntentRequested", "onGestureTargetActivityIntentRequested",
    ]),
    ("android.service.quickaccesswallet.IQuickAccessWalletServiceCallbacks", &[
        "onGetWalletCardsSuccess", "onGetWalletCardsFailure", "onWalletServiceEvent", "onTargetActivityPendingIntentReceived",
        "onGestureTargetActivityPendingIntentReceived",
    ]),
    ("android.service.quicksettings.IQSService", &[
        "getTile", "updateQsTile", "updateStatusIcon", "onShowDialog",
        "onStartActivity", "startActivity", "isLocked", "isSecure",
        "startUnlockAndRun", "onDialogHidden", "onStartSuccessful",
    ]),
    ("android.service.quicksettings.IQSTileService", &[
        "onTileAdded", "onTileRemoved", "onStartListening", "onStopListening",
        "onClick", "onUnlockComplete",
    ]),
    ("android.service.remotelockscreenvalidation.IRemoteLockscreenValidationCallback", &[
        "onSuccess", "onFailure",
    ]),
    ("android.service.remotelockscreenvalidation.IRemoteLockscreenValidationService", &[
        "validateLockscreenGuess",
    ]),
    ("android.service.resolver.IResolverRankerResult", &[
        "sendResult",
    ]),
    ("android.service.resolver.IResolverRankerService", &[
        "predict", "train",
    ]),
    ("android.service.resumeonreboot.IResumeOnRebootService", &[
        "wrapSecret", "unwrap",
    ]),
    ("android.service.rotationresolver.IRotationResolverCallback", &[
        "onCancellable", "onSuccess", "onFailure",
    ]),
    ("android.service.rotationresolver.IRotationResolverService", &[
        "resolveRotation",
    ]),
    ("android.service.search.ISearchUiService", &[
        "onCreateSearchSession", "onQuery", "onNotifyEvent", "onRegisterEmptyQueryResultUpdateCallback",
        "onUnregisterEmptyQueryResultUpdateCallback", "onDestroy",
    ]),
    ("android.service.settings.preferences.IGetValueCallback", &[
        "", "onSuccess", "onFailure",
    ]),
    ("android.service.settings.preferences.IMetadataCallback", &[
        "onSuccess", "onFailure",
    ]),
    ("android.service.settings.preferences.ISetValueCallback", &[
        "onSuccess", "onFailure",
    ]),
    ("android.service.settings.preferences.ISettingsPreferenceService", &[
        "", "getAllPreferenceMetadata", "getPreferenceValue", "setPreferenceValue",
    ]),
    ("android.service.settings.suggestions.ISuggestionService", &[
        "", "getSuggestions", "dismissSuggestion", "launchSuggestion",
    ]),
    ("android.service.smartspace.ISmartspaceService", &[
        "onCreateSmartspaceSession", "notifySmartspaceEvent", "requestSmartspaceUpdate", "registerSmartspaceUpdates",
        "unregisterSmartspaceUpdates", "onDestroySmartspaceSession",
    ]),
    ("android.service.storage.IExternalStorageService", &[
        "startSession", "endSession", "notifyVolumeStateChanged", "freeCache",
        "notifyAnrDelayStarted",
    ]),
    ("android.service.textclassifier.ITextClassifierCallback", &[
        "onSuccess", "onFailure",
    ]),
    ("android.service.textclassifier.ITextClassifierService", &[
        "onSuggestSelection", "onClassifyText", "onGenerateLinks", "onSelectionEvent",
        "onTextClassifierEvent", "onCreateTextClassificationSession", "onDestroyTextClassificationSession", "onDetectLanguage",
        "onSuggestConversationActions", "onConnectedStateChanged",
    ]),
    ("android.service.timezone.ITimeZoneProvider", &[
        "startUpdates", "stopUpdates",
    ]),
    ("android.service.timezone.ITimeZoneProviderManager", &[
        "onTimeZoneProviderEvent",
    ]),
    ("android.service.translation.ITranslationCallback", &[
        "onTranslationResponse",
    ]),
    ("android.service.translation.ITranslationService", &[
        "onConnected", "onDisconnected", "onCreateTranslationSession", "onTranslationCapabilitiesRequest",
    ]),
    ("android.service.trust.ITrustAgentService", &[
        "onUnlockAttempt", "onUserRequestedUnlock", "onUserMayRequestUnlock", "onUnlockLockout",
        "onTrustTimeout", "onDeviceLocked", "onDeviceUnlocked", "onConfigure",
        "setCallback", "onEscrowTokenAdded", "onTokenStateReceived", "onEscrowTokenRemoved",
    ]),
    ("android.service.trust.ITrustAgentServiceCallback", &[
        "grantTrust", "revokeTrust", "lockUser", "setManagingTrust",
        "onConfigureCompleted", "addEscrowToken", "isEscrowTokenActive", "removeEscrowToken",
        "unlockUserWithToken", "showKeyguardErrorMessage",
    ]),
    ("android.service.voice.IDetectorSessionStorageService", &[
        "openFile",
    ]),
    ("android.service.voice.IDetectorSessionVisualQueryDetectionCallback", &[
        "onAttentionGained", "onAttentionLost", "onQueryDetected", "onResultDetected",
        "onQueryFinished", "onQueryRejected",
    ]),
    ("android.service.voice.IDspHotwordDetectionCallback", &[
        "onDetected", "onRejected",
    ]),
    ("android.service.voice.IMicrophoneHotwordDetectionVoiceInteractionCallback", &[
        "onDetected", "onHotwordDetectionServiceFailure", "onRejected",
    ]),
    ("android.service.voice.ISandboxedDetectionService", &[
        "detectFromDspSource", "detectFromMicrophoneSource", "detectWithVisualSignals", "updateState",
        "updateAudioFlinger", "updateContentCaptureManager", "updateRecognitionServiceManager", "ping",
        "stopDetection", "registerRemoteStorageService",
    ]),
    ("android.service.voice.ISandboxedDetectionService$IPingMe", &[
        "onPing",
    ]),
    ("android.service.voice.IVisualQueryDetectionVoiceInteractionCallback", &[
        "onQueryDetected", "onResultDetected", "onQueryFinished", "onQueryRejected",
        "onVisualQueryDetectionServiceFailure",
    ]),
    ("android.service.voice.IVoiceInteractionService", &[
        "ready", "soundModelsChanged", "shutdown", "launchVoiceAssistFromKeyguard",
        "getActiveServiceSupportedActions", "prepareToShowSession", "showSessionFailed", "detectorRemoteExceptionOccurred",
    ]),
    ("android.service.voice.IVoiceInteractionSession", &[
        "show", "hide", "handleAssist", "handleScreenshot",
        "taskStarted", "taskFinished", "closeSystemDialogs", "onLockscreenShown",
        "destroy", "notifyVisibleActivityInfoChanged",
    ]),
    ("android.service.voice.IVoiceInteractionSessionService", &[
        "newSession",
    ]),
    ("android.service.vr.IPersistentVrStateCallbacks", &[
        "onPersistentVrStateChanged",
    ]),
    ("android.service.vr.IVrListener", &[
        "focusedActivityChanged",
    ]),
    ("android.service.vr.IVrManager", &[
        "registerListener", "unregisterListener", "registerPersistentVrStateListener", "unregisterPersistentVrStateListener",
        "getVrModeState", "getPersistentVrModeEnabled", "setPersistentVrModeEnabled", "setVr2dDisplayProperties",
        "getVr2dDisplayId", "setAndBindCompositor", "setStandbyEnabled",
    ]),
    ("android.service.vr.IVrStateCallbacks", &[
        "onVrStateChanged",
    ]),
    ("android.service.wallpaper.IWallpaperConnection", &[
        "attachEngine", "engineShown", "setWallpaper", "onWallpaperColorsChanged",
        "onLocalWallpaperColorsChanged",
    ]),
    ("android.service.wallpaper.IWallpaperEngine", &[
        "setDesiredSize", "setDisplayPadding", "setVisibility", "onScreenTurningOn",
        "onScreenTurnedOn", "setInAmbientMode", "dispatchPointer", "dispatchWallpaperCommand",
        "requestWallpaperColors", "destroy", "setZoomOut", "resizePreview",
        "removeLocalColorsAreas", "addLocalColorsAreas", "mirrorSurfaceControl", "applyDimming",
        "setWallpaperFlags", "onApplyWallpaper",
    ]),
    ("android.service.wallpaper.IWallpaperService", &[
        "attach", "detach",
    ]),
    ("android.service.wallpapereffectsgeneration.IWallpaperEffectsGenerationService", &[
        "onGenerateCinematicEffect",
    ]),
    ("android.service.wearable.IWearableSensingService", &[
        "provideSecureConnection", "provideConcurrentSecureConnection", "provideReadOnlyParcelFileDescriptor", "provideDataStream",
        "provideData", "registerDataRequestObserver", "unregisterDataRequestObserver", "startHotwordRecognition",
        "stopHotwordRecognition", "onValidatedByHotwordDetectionService", "stopActiveHotwordAudio", "startDetection",
        "stopDetection", "queryServiceStatus", "killProcess",
    ]),
    ("android.speech.IModelDownloadListener", &[
        "onProgress", "onSuccess", "onScheduled", "onError",
    ]),
    ("android.speech.IRecognitionListener", &[
        "onReadyForSpeech", "onBeginningOfSpeech", "onRmsChanged", "onBufferReceived",
        "onEndOfSpeech", "onError", "onResults", "onPartialResults",
        "onSegmentResults", "onEndOfSegmentedSession", "onLanguageDetection", "onEvent",
    ]),
    ("android.speech.IRecognitionService", &[
        "startListening", "stopListening", "cancel", "checkRecognitionSupport",
        "triggerModelDownload",
    ]),
    ("android.speech.IRecognitionServiceManager", &[
        "createSession", "setTemporaryComponent",
    ]),
    ("android.speech.IRecognitionServiceManagerCallback", &[
        "onSuccess", "onError",
    ]),
    ("android.speech.IRecognitionSupportCallback", &[
        "onSupportResult", "onError",
    ]),
    ("android.speech.tts.ITextToSpeechCallback", &[
        "onStart", "onSuccess", "onStop", "onError",
        "onBeginSynthesis", "onAudioAvailable", "onRangeStart",
    ]),
    ("android.speech.tts.ITextToSpeechManager", &[
        "createSession",
    ]),
    ("android.speech.tts.ITextToSpeechService", &[
        "speak", "synthesizeToFileDescriptor", "playAudio", "playSilence",
        "isSpeaking", "stop", "getLanguage", "getClientDefaultLanguage",
        "isLanguageAvailable", "getFeaturesForLanguage", "loadLanguage", "setCallback",
        "getVoices", "loadVoice", "getDefaultVoiceNameFor",
    ]),
    ("android.speech.tts.ITextToSpeechSession", &[
        "disconnect",
    ]),
    ("android.speech.tts.ITextToSpeechSessionCallback", &[
        "onConnected", "onDisconnected", "onError",
    ]),
    ("android.system.suspend.internal.ISuspendControlServiceInternal", &[
        "enableAutosuspend", "forceSuspend", "getWakeLockStats", "getWakeLockStatsFiltered",
        "getWakeupStats", "getSuspendStats",
    ]),
    ("android.telephony.IBooleanConsumer", &[
        "accept",
    ]),
    ("android.telephony.IBootstrapAuthenticationCallback", &[
        "onKeysAvailable", "onAuthenticationFailure",
    ]),
    ("android.telephony.ICellBroadcastService", &[
        "handleGsmCellBroadcastSms", "handleCdmaCellBroadcastSms", "handleCdmaScpMessage", "getCellBroadcastAreaInfo",
    ]),
    ("android.telephony.ICellInfoCallback", &[
        "onCellInfo", "onError",
    ]),
    ("android.telephony.IIntegerConsumer", &[
        "accept",
    ]),
    ("android.telephony.INetworkService", &[
        "createNetworkServiceProvider", "removeNetworkServiceProvider", "requestNetworkRegistrationInfo", "registerForNetworkRegistrationInfoChanged",
        "unregisterForNetworkRegistrationInfoChanged",
    ]),
    ("android.telephony.INetworkServiceCallback", &[
        "onRequestNetworkRegistrationInfoComplete", "onNetworkStateChanged",
    ]),
    ("android.telephony.data.IDataService", &[
        "createDataServiceProvider", "removeDataServiceProvider", "setupDataCall", "deactivateDataCall",
        "setInitialAttachApn", "setDataProfile", "requestDataCallList", "registerForDataCallListChanged",
        "unregisterForDataCallListChanged", "startHandover", "cancelHandover", "registerForUnthrottleApn",
        "unregisterForUnthrottleApn", "requestNetworkValidation",
    ]),
    ("android.telephony.data.IDataServiceCallback", &[
        "onSetupDataCallComplete", "onDeactivateDataCallComplete", "onSetInitialAttachApnComplete", "onSetDataProfileComplete",
        "onRequestDataCallListComplete", "onDataCallListChanged", "onHandoverStarted", "onHandoverCancelled",
        "onApnUnthrottled", "onDataProfileUnthrottled",
    ]),
    ("android.telephony.data.IQualifiedNetworksService", &[
        "createNetworkAvailabilityProvider", "removeNetworkAvailabilityProvider", "reportThrottleStatusChanged", "reportEmergencyDataNetworkPreferredTransportChanged",
    ]),
    ("android.telephony.data.IQualifiedNetworksServiceCallback", &[
        "onQualifiedNetworkTypesChanged", "onNetworkValidationRequested", "onReconnectQualifiedNetworkType",
    ]),
    ("android.telephony.gba.IGbaService", &[
        "authenticationRequest",
    ]),
    ("android.telephony.ims.aidl.ICapabilityExchangeEventListener", &[
        "onRequestPublishCapabilities", "onUnpublish", "onPublishUpdated", "onRemoteCapabilityRequest",
    ]),
    ("android.telephony.ims.aidl.IFeatureProvisioningCallback", &[
        "onFeatureProvisioningChanged", "onRcsFeatureProvisioningChanged",
    ]),
    ("android.telephony.ims.aidl.IImsCallSessionListener", &[
        "callSessionInitiating", "callSessionInitiatingFailed", "callSessionProgressing", "callSessionInitiated",
        "callSessionInitiatedFailed", "callSessionTerminated", "callSessionHeld", "callSessionHoldFailed",
        "callSessionHoldReceived", "callSessionResumed", "callSessionResumeFailed", "callSessionResumeReceived",
        "callSessionMergeStarted", "callSessionMergeComplete", "callSessionMergeFailed", "callSessionUpdated",
        "callSessionUpdateFailed", "callSessionUpdateReceived", "callSessionConferenceExtended", "callSessionConferenceExtendFailed",
        "callSessionConferenceExtendReceived", "callSessionInviteParticipantsRequestDelivered", "callSessionInviteParticipantsRequestFailed", "callSessionRemoveParticipantsRequestDelivered",
        "callSessionRemoveParticipantsRequestFailed", "callSessionConferenceStateUpdated", "callSessionUssdMessageReceived", "callSessionHandover",
        "callSessionHandoverFailed", "callSessionMayHandover", "callSessionTtyModeReceived", "callSessionMultipartyStateChanged",
        "callSessionSuppServiceReceived", "callSessionRttModifyRequestReceived", "callSessionRttModifyResponseReceived", "callSessionRttMessageReceived",
        "callSessionRttAudioIndicatorChanged", "callSessionTransferred", "callSessionTransferFailed", "callSessionDtmfReceived",
        "callQualityChanged", "callSessionRtpHeaderExtensionsReceived", "callSessionSendAnbrQuery",
    ]),
    ("android.telephony.ims.aidl.IImsCapabilityCallback", &[
        "onQueryCapabilityConfiguration", "onChangeCapabilityConfigurationError", "onCapabilitiesStatusChanged",
    ]),
    ("android.telephony.ims.aidl.IImsConfig", &[
        "addImsConfigCallback", "removeImsConfigCallback", "getConfigInt", "getConfigString",
        "setConfigInt", "setConfigString", "updateImsCarrierConfigs", "notifyRcsAutoConfigurationReceived",
        "notifyRcsAutoConfigurationRemoved", "addRcsConfigCallback", "removeRcsConfigCallback", "triggerRcsReconfiguration",
        "setRcsClientConfiguration", "notifyIntImsConfigChanged", "notifyStringImsConfigChanged",
    ]),
    ("android.telephony.ims.aidl.IImsConfigCallback", &[
        "onIntConfigChanged", "onStringConfigChanged",
    ]),
    ("android.telephony.ims.aidl.IImsMmTelFeature", &[
        "setListener", "getFeatureState", "createCallProfile", "changeOfferedRtpHeaderExtensionTypes",
        "createCallSession", "shouldProcessCall", "getUtInterface", "getEcbmInterface",
        "setUiTtyMode", "getMultiEndpointInterface", "queryCapabilityStatus", "setTerminalBasedCallWaitingStatus",
        "addCapabilityCallback", "removeCapabilityCallback", "changeCapabilitiesConfiguration", "queryCapabilityConfiguration",
        "notifySrvccStarted", "notifySrvccCompleted", "notifySrvccFailed", "notifySrvccCanceled",
        "setMediaQualityThreshold", "queryMediaQualityStatus", "setSmsListener", "sendSms",
        "onMemoryAvailable", "acknowledgeSms", "acknowledgeSmsWithPdu", "acknowledgeSmsReport",
        "getSmsFormat", "onSmsReady",
    ]),
    ("android.telephony.ims.aidl.IImsMmTelListener", &[
        "onIncomingCall", "onRejectedCall", "onVoiceMessageCountUpdate", "onAudioModeIsVoipChanged",
        "onTriggerEpsFallback", "onStartImsTrafficSession", "onModifyImsTrafficSession", "onStopImsTrafficSession",
        "onMediaQualityStatusChanged",
    ]),
    ("android.telephony.ims.aidl.IImsRcsController", &[
        "registerImsRegistrationCallback", "unregisterImsRegistrationCallback", "getImsRcsRegistrationState", "getImsRcsRegistrationTransportType",
        "registerRcsAvailabilityCallback", "unregisterRcsAvailabilityCallback", "isCapable", "isAvailable",
        "requestCapabilities", "requestAvailability", "getUcePublishState", "isUceSettingEnabled",
        "setUceSettingEnabled", "registerUcePublishStateCallback", "unregisterUcePublishStateCallback", "isSipDelegateSupported",
        "createSipDelegate", "destroySipDelegate", "triggerNetworkRegistration", "registerSipDialogStateCallback",
        "unregisterSipDialogStateCallback", "registerRcsFeatureCallback", "unregisterImsFeatureCallback",
    ]),
    ("android.telephony.ims.aidl.IImsRcsFeature", &[
        "queryCapabilityStatus", "getFeatureState", "addCapabilityCallback", "removeCapabilityCallback",
        "changeCapabilitiesConfiguration", "queryCapabilityConfiguration", "setCapabilityExchangeEventListener", "publishCapabilities",
        "subscribeForCapabilities", "sendOptionsCapabilityRequest",
    ]),
    ("android.telephony.ims.aidl.IImsRegistration", &[
        "getRegistrationTechnology", "addRegistrationCallback", "removeRegistrationCallback", "addEmergencyRegistrationCallback",
        "removeEmergencyRegistrationCallback", "triggerFullNetworkRegistration", "triggerUpdateSipDelegateRegistration", "triggerSipDelegateDeregistration",
        "triggerDeregistration",
    ]),
    ("android.telephony.ims.aidl.IImsRegistrationCallback", &[
        "onRegistered", "onRegistering", "onDeregistered", "onDeregisteredWithDetails",
        "onTechnologyChangeFailed", "onSubscriberAssociatedUriChanged",
    ]),
    ("android.telephony.ims.aidl.IImsServiceController", &[
        "setListener", "createMmTelFeature", "createEmergencyOnlyMmTelFeature", "createRcsFeature",
        "querySupportedImsFeatures", "getImsServiceCapabilities", "addFeatureStatusCallback", "removeFeatureStatusCallback",
        "notifyImsServiceReadyForFeatureCreation", "removeImsFeature", "getConfig", "getRegistration",
        "getSipTransport", "enableIms", "disableIms", "resetIms",
    ]),
    ("android.telephony.ims.aidl.IImsServiceControllerListener", &[
        "onUpdateSupportedImsFeatures",
    ]),
    ("android.telephony.ims.aidl.IImsSmsListener", &[
        "onSendSmsResult", "onSmsStatusReportReceived", "onSmsReceived", "onMemoryAvailableResult",
    ]),
    ("android.telephony.ims.aidl.IImsTrafficSessionCallback", &[
        "onReady", "onError",
    ]),
    ("android.telephony.ims.aidl.IOptionsRequestCallback", &[
        "respondToCapabilityRequest", "respondToCapabilityRequestWithError",
    ]),
    ("android.telephony.ims.aidl.IOptionsResponseCallback", &[
        "onCommandError", "onNetworkResponse",
    ]),
    ("android.telephony.ims.aidl.IPublishResponseCallback", &[
        "onCommandError", "onNetworkResponse",
    ]),
    ("android.telephony.ims.aidl.IRcsConfigCallback", &[
        "onConfigurationChanged", "onAutoConfigurationErrorReceived", "onConfigurationReset", "onRemoved",
        "onPreProvisioningReceived",
    ]),
    ("android.telephony.ims.aidl.IRcsUceControllerCallback", &[
        "onCapabilitiesReceived", "onComplete", "onError",
    ]),
    ("android.telephony.ims.aidl.IRcsUcePublishStateCallback", &[
        "onPublishUpdated",
    ]),
    ("android.telephony.ims.aidl.ISipDelegate", &[
        "sendMessage", "notifyMessageReceived", "notifyMessageReceiveError", "cleanupSession",
    ]),
    ("android.telephony.ims.aidl.ISipDelegateConnectionStateCallback", &[
        "onCreated", "onFeatureTagStatusChanged", "onImsConfigurationChanged", "onConfigurationChanged",
        "onDestroyed",
    ]),
    ("android.telephony.ims.aidl.ISipDelegateMessageCallback", &[
        "onMessageReceived", "onMessageSent", "onMessageSendFailure",
    ]),
    ("android.telephony.ims.aidl.ISipDelegateStateCallback", &[
        "onCreated", "onFeatureTagRegistrationChanged", "onImsConfigurationChanged", "onConfigurationChanged",
        "onDestroyed",
    ]),
    ("android.telephony.ims.aidl.ISipTransport", &[
        "createSipDelegate", "destroySipDelegate",
    ]),
    ("android.telephony.ims.aidl.ISrvccStartedCallback", &[
        "onSrvccCallNotified",
    ]),
    ("android.telephony.ims.aidl.ISubscribeResponseCallback", &[
        "onCommandError", "onNetworkResponse", "onNotifyCapabilitiesUpdate", "onResourceTerminated",
        "onTerminated",
    ]),
    ("android.telephony.mbms.IDownloadProgressListener", &[
        "onProgressUpdated",
    ]),
    ("android.telephony.mbms.IDownloadStatusListener", &[
        "onStatusUpdated",
    ]),
    ("android.telephony.mbms.IGroupCallCallback", &[
        "onError", "onGroupCallStateChanged", "onBroadcastSignalStrengthUpdated",
    ]),
    ("android.telephony.mbms.IMbmsDownloadSessionCallback", &[
        "onError", "onFileServicesUpdated", "onMiddlewareReady",
    ]),
    ("android.telephony.mbms.IMbmsGroupCallSessionCallback", &[
        "onError", "onAvailableSaisUpdated", "onServiceInterfaceAvailable", "onMiddlewareReady",
    ]),
    ("android.telephony.mbms.IMbmsStreamingSessionCallback", &[
        "onError", "onStreamingServicesUpdated", "onMiddlewareReady",
    ]),
    ("android.telephony.mbms.IStreamingServiceCallback", &[
        "onError", "onStreamStateUpdated", "onMediaDescriptionUpdated", "onBroadcastSignalStrengthUpdated",
        "onStreamMethodUpdated",
    ]),
    ("android.telephony.mbms.vendor.IMbmsDownloadService", &[
        "initialize", "requestUpdateFileServices", "setTempFileRootDirectory", "addServiceAnnouncement",
        "download", "addStatusListener", "removeStatusListener", "addProgressListener",
        "removeProgressListener", "listPendingDownloads", "cancelDownload", "requestDownloadState",
        "resetDownloadKnowledge", "dispose",
    ]),
    ("android.telephony.mbms.vendor.IMbmsGroupCallService", &[
        "initialize", "stopGroupCall", "updateGroupCall", "startGroupCall",
        "dispose",
    ]),
    ("android.telephony.mbms.vendor.IMbmsStreamingService", &[
        "initialize", "requestUpdateStreamingServices", "startStreaming", "getPlaybackUri",
        "stopStreaming", "dispose",
    ]),
    ("android.telephony.satellite.INtnSignalStrengthCallback", &[
        "onNtnSignalStrengthChanged",
    ]),
    ("android.telephony.satellite.ISatelliteCapabilitiesCallback", &[
        "onSatelliteCapabilitiesChanged",
    ]),
    ("android.telephony.satellite.ISatelliteCommunicationAccessStateCallback", &[
        "onAccessAllowedStateChanged", "onAccessConfigurationChanged",
    ]),
    ("android.telephony.satellite.ISatelliteDatagramCallback", &[
        "onSatelliteDatagramReceived",
    ]),
    ("android.telephony.satellite.ISatelliteDisallowedReasonsCallback", &[
        "onSatelliteDisallowedReasonsChanged",
    ]),
    ("android.telephony.satellite.ISatelliteModemStateCallback", &[
        "onSatelliteModemStateChanged", "onEmergencyModeChanged", "onRegistrationFailure", "onTerrestrialNetworkAvailableChanged",
    ]),
    ("android.telephony.satellite.ISatelliteProvisionStateCallback", &[
        "onSatelliteProvisionStateChanged", "onSatelliteSubscriptionProvisionStateChanged",
    ]),
    ("android.telephony.satellite.ISatelliteTransmissionUpdateCallback", &[
        "onSendDatagramStateChanged", "onReceiveDatagramStateChanged", "onSatellitePositionChanged", "onSendDatagramRequested",
    ]),
    ("android.telephony.satellite.ISelectedNbIotSatelliteSubscriptionCallback", &[
        "onSelectedNbIotSatelliteSubscriptionChanged",
    ]),
    ("android.telephony.satellite.stub.INtnSignalStrengthConsumer", &[
        "accept",
    ]),
    ("android.telephony.satellite.stub.ISatellite", &[
        "setSatelliteListener", "requestSatelliteListeningEnabled", "enableTerrestrialNetworkScanWhileSatelliteModeIsOn", "requestSatelliteEnabled",
        "requestIsSatelliteEnabled", "requestIsSatelliteSupported", "requestSatelliteCapabilities", "startSendingSatellitePointingInfo",
        "stopSendingSatellitePointingInfo", "pollPendingSatelliteDatagrams", "sendSatelliteDatagram", "requestSatelliteModemState",
        "requestTimeForNextSatelliteVisibility", "setSatellitePlmn", "setSatelliteEnabledForCarrier", "requestIsSatelliteEnabledForCarrier",
        "requestSignalStrength", "startSendingNtnSignalStrength", "stopSendingNtnSignalStrength", "abortSendingSatelliteDatagrams",
        "updateSatelliteSubscription", "updateSystemSelectionChannels",
    ]),
    ("android.telephony.satellite.stub.ISatelliteCapabilitiesConsumer", &[
        "accept",
    ]),
    ("android.telephony.satellite.stub.ISatelliteListener", &[
        "onSatelliteDatagramReceived", "onPendingDatagrams", "onSatellitePositionChanged", "onSatelliteModemStateChanged",
        "onNtnSignalStrengthChanged", "onSatelliteCapabilitiesChanged", "onSatelliteSupportedStateChanged", "onRegistrationFailure",
        "onTerrestrialNetworkAvailableChanged",
    ]),
    ("android.tracing.ITracingServiceProxy", &[
        "notifyTraceSessionEnded", "reportTrace",
    ]),
    ("android.ui.ISurfaceComposer", &[
        "bootFinished", "createDisplayEventConnection", "createConnection", "createDisplay",
        "destroyDisplay", "getPhysicalDisplayIds", "getPhysicalDisplayToken", "getSupportedFrameTimestamps",
        "setPowerMode", "getDisplayStats", "getDisplayState", "getStaticDisplayInfo",
        "getDynamicDisplayInfoFromId", "getDynamicDisplayInfoFromToken", "getDisplayNativePrimaries", "setActiveColorMode",
        "setBootDisplayMode", "clearBootDisplayMode", "getBootDisplayModeSupport", "getHdrConversionCapabilities",
        "setHdrConversionStrategy", "getHdrOutputConversionSupport", "setAutoLowLatencyMode", "setGameContentType",
        "captureDisplay", "captureDisplayById", "captureLayers", "clearAnimationFrameStats",
        "getAnimationFrameStats", "overrideHdrTypes", "onPullAtom", "getLayerDebugInfo",
        "getColorManagement", "getCompositionPreference", "getDisplayedContentSamplingAttributes", "setDisplayContentSamplingEnabled",
        "getDisplayedContentSample", "getProtectedContentSupport", "isWideColorDisplay",
    ]),
    ("android.view.IAppTransitionAnimationSpecsFuture", &[
        "get",
    ]),
    ("android.view.ICrossWindowBlurEnabledListener", &[
        "onCrossWindowBlurEnabledChanged",
    ]),
    ("android.view.IDecorViewGestureListener", &[
        "onInterceptionChanged",
    ]),
    ("android.view.IDisplayChangeWindowCallback", &[
        "continueDisplayChange",
    ]),
    ("android.view.IDisplayChangeWindowController", &[
        "onDisplayChange",
    ]),
    ("android.view.IDisplayFoldListener", &[
        "onDisplayFoldChanged",
    ]),
    ("android.view.IDisplayWindowInsetsController", &[
        "topFocusedWindowChanged", "insetsChanged", "insetsControlChanged", "showInsets",
        "hideInsets", "setImeInputTargetRequestedVisibility",
    ]),
    ("android.view.IDisplayWindowListener", &[
        "onDisplayAdded", "onDisplayConfigurationChanged", "onDisplayRemoved", "onFixedRotationStarted",
        "onFixedRotationFinished", "onKeepClearAreasChanged", "onDesktopModeEligibleChanged",
    ]),
    ("android.view.IDockedStackListener", &[
        "onDividerVisibilityChanged", "onDockedStackExistsChanged", "onDockedStackMinimizedChanged", "onAdjustedForImeChanged",
        "onDockSideChanged",
    ]),
    ("android.view.IGraphicsStats", &[
        "requestBufferForProcess",
    ]),
    ("android.view.IGraphicsStatsCallback", &[
        "onRotateGraphicsStatsBuffer",
    ]),
    ("android.view.IInputFilter", &[
        "install", "uninstall", "filterInputEvent",
    ]),
    ("android.view.IInputFilterHost", &[
        "sendInputEvent",
    ]),
    ("android.view.IInputMonitorHost", &[
        "pilferPointers", "dispose",
    ]),
    ("android.view.IOnKeyguardExitResult", &[
        "onKeyguardExitResult",
    ]),
    ("android.view.IPinnedTaskListener", &[
        "onMovementBoundsChanged", "onImeVisibilityChanged",
    ]),
    ("android.view.IRemoteAnimationFinishedCallback", &[
        "onAnimationFinished",
    ]),
    ("android.view.IRemoteAnimationRunner", &[
        "onAnimationStart", "onAnimationCancelled",
    ]),
    ("android.view.IRotationWatcher", &[
        "onRotationChanged",
    ]),
    ("android.view.IScrollCaptureCallbacks", &[
        "onCaptureStarted", "onImageRequestCompleted", "onCaptureEnded",
    ]),
    ("android.view.IScrollCaptureConnection", &[
        "startCapture", "requestImage", "endCapture", "close",
    ]),
    ("android.view.IScrollCaptureResponseListener", &[
        "onScrollCaptureResponse",
    ]),
    ("android.view.ISensitiveContentProtectionManager", &[
        "setSensitiveContentProtection",
    ]),
    ("android.view.ISurfaceControlViewHost", &[
        "onConfigurationChanged", "onDispatchDetachedFromWindow", "onInsetsChanged", "getSurfaceSyncGroup",
        "attachParentInterface",
    ]),
    ("android.view.ISurfaceControlViewHostParent", &[
        "updateParams", "forwardBackKeyToParent",
    ]),
    ("android.view.ISystemGestureExclusionListener", &[
        "onSystemGestureExclusionChanged",
    ]),
    ("android.view.IWallpaperVisibilityListener", &[
        "onWallpaperVisibilityChanged",
    ]),
    ("android.view.IWindow", &[
        "executeCommand", "resized", "insetsControlChanged", "showInsets",
        "hideInsets", "moved", "dispatchAppVisibility", "dispatchGetNewSurface",
        "closeSystemDialogs", "dispatchWallpaperOffsets", "dispatchWallpaperCommand", "dispatchDragEvent",
        "dispatchWindowShown", "requestAppKeyboardShortcuts", "requestScrollCapture", "dumpWindow",
    ]),
    ("android.view.IWindowFocusObserver", &[
        "focusGained", "focusLost",
    ]),
    ("android.view.IWindowId", &[
        "registerFocusObserver", "unregisterFocusObserver", "isFocused",
    ]),
    ("android.view.IWindowManager", &[
        "startViewServer", "stopViewServer", "isViewServerRunning", "openSession",
        "getInitialDisplaySize", "getBaseDisplaySize", "setForcedDisplaySize", "clearForcedDisplaySize",
        "getInitialDisplayDensity", "getBaseDisplayDensity", "getDisplayIdByUniqueId", "setForcedDisplayDensityForUser",
        "clearForcedDisplayDensityForUser", "setForcedDisplayDensityRatio", "setConfigurationChangeSettingsForUser", "setForcedDisplayScalingMode",
        "setEventDispatching", "isWindowToken", "addWindowToken", "removeWindowToken",
        "setDisplayChangeWindowController", "addShellRoot", "setShellRootAccessibilityWindow", "overridePendingAppTransitionMultiThumbFuture",
        "overridePendingAppTransitionRemote", "endProlongedAnimations", "disableKeyguard", "reenableKeyguard",
        "exitKeyguardSecurely", "isKeyguardLocked", "isKeyguardSecure", "dismissKeyguard",
        "addKeyguardLockedStateListener", "removeKeyguardLockedStateListener", "setSwitchingUser", "closeSystemDialogs",
        "getAnimationScale", "getAnimationScales", "setAnimationScale", "setAnimationScales",
        "getCurrentAnimatorScale", "setInTouchMode", "setInTouchModeOnAllDisplays", "isInTouchMode",
        "showStrictModeViolation", "setStrictModeVisualIndicatorPreference", "refreshScreenCaptureDisabled", "getDefaultDisplayRotation",
        "getDisplayUserRotation", "watchRotation", "removeRotationWatcher", "registerProposedRotationListener",
        "getPreferredOptionsPanelGravity", "freezeRotation", "thawRotation", "isRotationFrozen",
        "freezeDisplayRotation", "thawDisplayRotation", "isDisplayRotationFrozen", "setFixedToUserRotation",
        "setIgnoreOrientationRequest", "screenshotWallpaper", "mirrorWallpaperSurface", "registerWallpaperVisibilityListener",
        "unregisterWallpaperVisibilityListener", "registerSystemGestureExclusionListener", "unregisterSystemGestureExclusionListener", "requestAssistScreenshot",
        "hideTransientBars", "setRecentsVisibility", "updateStaticPrivacyIndicatorBounds", "setNavBarVirtualKeyHapticFeedbackEnabled",
        "hasNavigationBar", "lockNow", "isSafeModeEnabled", "clearWindowContentFrameStats",
        "getWindowContentFrameStats", "getDockedStackSide", "registerPinnedTaskListener", "requestAppKeyboardShortcuts",
        "requestImeKeyboardShortcuts", "getStableInsets", "registerShortcutKey", "createInputConsumer",
        "destroyInputConsumer", "getCurrentImeTouchRegion", "registerDisplayFoldListener", "unregisterDisplayFoldListener",
        "registerDisplayWindowListener", "unregisterDisplayWindowListener", "startWindowTrace", "stopWindowTrace",
        "saveWindowTraceToFile", "isWindowTraceEnabled", "startTransitionTrace", "stopTransitionTrace",
        "isTransitionTraceEnabled", "getWindowingMode", "setWindowingMode", "getRemoveContentMode",
        "setRemoveContentMode", "shouldShowWithInsecureKeyguard", "setShouldShowWithInsecureKeyguard", "shouldShowSystemDecors",
        "setShouldShowSystemDecors", "isEligibleForDesktopMode", "getDisplayImePolicy", "setDisplayImePolicy",
        "onNotificationShadeExpanded", "syncInputTransactions", "isLayerTracing", "setLayerTracing",
        "mirrorDisplay", "setDisplayWindowInsetsController", "updateDisplayWindowRequestedVisibleTypes", "updateDisplayWindowAnimatingTypes",
        "getWindowInsets", "getPossibleDisplayInfo", "showGlobalActions", "setLayerTracingFlags",
        "setActiveTransactionTracing", "requestScrollCapture", "holdLock", "getSupportedDisplayHashAlgorithms",
        "verifyDisplayHash", "setDisplayHashThrottlingEnabled", "attachWindowContextToDisplayArea", "attachWindowContextToWindowToken",
        "attachWindowContextToDisplayContent", "detachWindowContext", "reparentWindowContextToDisplayArea", "registerCrossWindowBlurEnabledListener",
        "unregisterCrossWindowBlurEnabledListener", "isTaskSnapshotSupported", "getImeDisplayId", "setTaskSnapshotEnabled",
        "registerTaskFpsCallback", "unregisterTaskFpsCallback", "snapshotTaskForRecents", "setRecentsAppBehindSystemBars",
        "getLetterboxBackgroundColorInArgb", "isLetterboxBackgroundMultiColored", "captureDisplay", "isGlobalKey",
        "addToSurfaceSyncGroup", "markSurfaceSyncGroupReady", "notifyScreenshotListeners", "replaceContentOnDisplay",
        "registerDecorViewGestureListener", "unregisterDecorViewGestureListener", "registerTrustedPresentationListener", "unregisterTrustedPresentationListener",
        "registerScreenRecordingCallback", "unregisterScreenRecordingCallback", "setGlobalDragListener", "transferTouchGesture",
        "getApplicationLaunchKeyboardShortcuts", "getIgnoreOrientationRequest",
    ]),
    ("android.view.IWindowSession", &[
        "addToDisplay", "addToDisplayAsUser", "addToDisplayWithoutInputChannel", "remove",
        "relayout", "relayoutAsync", "outOfMemory", "setInsets",
        "finishDrawing", "performDrag", "dropForAccessibility", "reportDropResult",
        "cancelDragAndDrop", "dragRecipientEntered", "dragRecipientExited", "setWallpaperPosition",
        "setWallpaperZoomOut", "setShouldZoomOutWallpaper", "wallpaperOffsetsComplete", "setWallpaperDisplayOffset",
        "sendWallpaperCommand", "wallpaperCommandComplete", "onRectangleOnScreenRequested", "getWindowId",
        "pokeDrawLock", "startMovingTask", "finishMovingTask", "updateTapExcludeRegion",
        "updateRequestedVisibleTypes", "updateAnimatingTypes", "reportSystemGestureExclusionChanged", "reportDecorViewGestureInterceptionChanged",
        "reportKeepClearAreasChanged", "grantInputChannel", "updateInputChannel", "grantEmbeddedWindowFocus",
        "generateDisplayHash", "setOnBackInvokedCallbackInfo", "clearTouchableRegion", "cancelDraw",
        "moveFocusToAdjacentWindow", "notifyImeWindowVisibilityChangedFromClient",
    ]),
    ("android.view.IWindowSessionCallback", &[
        "onAnimatorScaleChanged",
    ]),
    ("android.view.SyncRtSurfaceTransactionApplier", &[
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "flag",
    ]),
    ("android.view.accessibility.IAccessibilityEmbeddedConnection", &[
        "associateEmbeddedHierarchy", "disassociateEmbeddedHierarchy", "setWindowMatrix",
    ]),
    ("android.view.accessibility.IAccessibilityInteractionConnection", &[
        "findAccessibilityNodeInfoByAccessibilityId", "findAccessibilityNodeInfosByViewId", "findAccessibilityNodeInfosByText", "findFocus",
        "focusSearch", "performAccessibilityAction", "clearAccessibilityFocus", "notifyOutsideTouch",
        "takeScreenshotOfWindow", "getWindowSurfaceInfo", "attachAccessibilityOverlayToWindow",
    ]),
    ("android.view.accessibility.IAccessibilityInteractionConnectionCallback", &[
        "setFindAccessibilityNodeInfoResult", "setFindAccessibilityNodeInfosResult", "setPrefetchAccessibilityNodeInfoResult", "setPerformAccessibilityActionResult",
        "sendTakeScreenshotOfWindowError", "sendAttachOverlayResult",
    ]),
    ("android.view.accessibility.IAccessibilityManager", &[
        "interrupt", "sendAccessibilityEvent", "addClient", "removeClient",
        "getInstalledAccessibilityServiceList", "getEnabledAccessibilityServiceList", "addAccessibilityInteractionConnection", "removeAccessibilityInteractionConnection",
        "setPictureInPictureActionReplacingConnection", "registerUiTestAutomationService", "unregisterUiTestAutomationService", "getWindowToken",
        "notifyAccessibilityButtonClicked", "notifyAccessibilityButtonLongClicked", "notifyAccessibilityButtonVisibilityChanged", "performAccessibilityShortcut",
        "getAccessibilityShortcutTargets", "sendFingerprintGesture", "getAccessibilityWindowId", "getRecommendedTimeoutMillis",
        "registerSystemAction", "unregisterSystemAction", "setMagnificationConnection", "associateEmbeddedHierarchy",
        "disassociateEmbeddedHierarchy", "getFocusStrokeWidth", "getFocusColor", "isAudioDescriptionByDefaultEnabled",
        "setSystemAudioCaptioningEnabled", "isSystemAudioCaptioningUiEnabled", "setSystemAudioCaptioningUiEnabled", "setAccessibilityWindowAttributes",
        "registerProxyForDisplay", "unregisterProxyForDisplay", "injectInputEventToInputFilter", "startFlashNotificationSequence",
        "stopFlashNotificationSequence", "startFlashNotificationEvent", "isAccessibilityTargetAllowed", "sendRestrictedDialogIntent",
        "isAccessibilityServiceWarningRequired", "getWindowTransformationSpec", "attachAccessibilityOverlayToDisplay", "notifyQuickSettingsTilesChanged",
        "enableShortcutsForTargets", "getA11yFeatureToTileMap", "registerUserInitializationCompleteCallback", "unregisterUserInitializationCompleteCallback",
    ]),
    ("android.view.accessibility.IAccessibilityManagerClient", &[
        "setState", "notifyServicesStateChanged", "setRelevantEventTypes", "setFocusAppearance",
    ]),
    ("android.view.accessibility.IMagnificationConnection", &[
        "enableWindowMagnification", "setScaleForWindowMagnification", "disableWindowMagnification", "moveWindowMagnifier",
        "moveWindowMagnifierToPosition", "showMagnificationButton", "removeMagnificationButton", "removeMagnificationSettingsPanel",
        "setConnectionCallback", "onUserMagnificationScaleChanged", "onFullscreenMagnificationActivationChanged",
    ]),
    ("android.view.accessibility.IMagnificationConnectionCallback", &[
        "onWindowMagnifierBoundsChanged", "onChangeMagnificationMode", "onSourceBoundsChanged", "onPerformScaleAction",
        "onAccessibilityActionPerformed", "onMove",
    ]),
    ("android.view.accessibility.IRemoteMagnificationAnimationCallback", &[
        "onResult",
    ]),
    ("android.view.accessibility.IUserInitializationCompleteCallback", &[
        "onUserInitializationComplete",
    ]),
    ("android.view.accessibility.IWindowSurfaceInfoCallback", &[
        "provideWindowSurfaceInfo",
    ]),
    ("android.view.autofill.IAugmentedAutofillManagerClient", &[
        "getViewCoordinates", "getViewNodeParcelable", "autofill", "requestShowFillUi",
        "requestHideFillUi", "requestAutofill",
    ]),
    ("android.view.autofill.IAutoFillManager", &[
        "addClient", "removeClient", "startSession", "getFillEventHistory",
        "restoreSession", "updateSession", "setAutofillFailure", "setViewAutofilled",
        "finishSession", "cancelSession", "setAuthenticationResult", "setHasCallback",
        "disableOwnedAutofillServices", "isServiceSupported", "isServiceEnabled", "onPendingSaveUi",
        "getUserData", "getUserDataId", "setUserData", "isFieldClassificationEnabled",
        "getAutofillServiceComponentName", "getAvailableFieldClassificationAlgorithms", "getDefaultFieldClassificationAlgorithm", "setAugmentedAutofillWhitelist",
        "notifyNotExpiringResponseDuringAuth", "notifyViewEnteredIgnoredDuringAuthCount", "setAutofillIdsAttemptedForRefill", "notifyImeAnimationStart",
        "notifyImeAnimationEnd",
    ]),
    ("android.view.autofill.IAutoFillManagerClient", &[
        "setState", "autofill", "onGetCredentialResponse", "onGetCredentialException",
        "autofillContent", "authenticate", "setTrackedViews", "requestShowFillUi",
        "requestHideFillUi", "requestHideFillUiWhenDestroyed", "notifyNoFillUi", "notifyFillUiShown",
        "notifyFillUiHidden", "dispatchUnhandledKey", "startIntentSender", "setSaveUiState",
        "setSessionFinished", "getAugmentedAutofillClient", "notifyDisableAutofill", "requestShowSoftInput",
        "notifyFillDialogTriggerIds",
    ]),
    ("android.view.autofill.IAutofillWindowPresenter", &[
        "show", "hide",
    ]),
    ("android.view.contentcapture.IContentCaptureDirectManager", &[
        "sendEvents",
    ]),
    ("android.view.contentcapture.IContentCaptureManager", &[
        "startSession", "finishSession", "getServiceComponentName", "removeData",
        "shareData", "isContentCaptureFeatureEnabled", "getServiceSettingsActivity", "getContentCaptureConditions",
        "resetTemporaryService", "setTemporaryService", "setDefaultServiceEnabled", "registerContentCaptureOptionsCallback",
        "onLoginDetected",
    ]),
    ("android.view.contentcapture.IContentCaptureOptionsCallback", &[
        "setContentCaptureOptions",
    ]),
    ("android.view.contentcapture.IDataShareWriteAdapter", &[
        "write", "error", "rejected", "finish",
    ]),
    ("android.view.translation.ITranslationDirectManager", &[
        "onTranslationRequest", "onFinishTranslationSession",
    ]),
    ("android.view.translation.ITranslationManager", &[
        "onTranslationCapabilitiesRequest", "registerTranslationCapabilityCallback", "unregisterTranslationCapabilityCallback", "onSessionCreated",
        "updateUiTranslationState", "registerUiTranslationStateCallback", "unregisterUiTranslationStateCallback", "getServiceSettingsActivity",
        "onTranslationFinished",
    ]),
    ("android.view.translation.ITranslationServiceCallback", &[
        "updateTranslationCapability",
    ]),
    ("android.webkit.IWebViewUpdateService", &[
        "notifyRelroCreationCompleted", "waitForAndGetProvider", "changeProviderAndSetting", "getValidWebViewPackages",
        "getAllWebViewPackages", "getCurrentWebViewPackageName", "getCurrentWebViewPackage", "getDefaultWebViewPackage",
    ]),
    ("android.window.IBackAnimationFinishedCallback", &[
        "onAnimationFinished",
    ]),
    ("android.window.IBackAnimationHandoffHandler", &[
        "handOffAnimation",
    ]),
    ("android.window.IBackAnimationRunner", &[
        "", "onAnimationCancelled", "onAnimationStart",
    ]),
    ("android.window.IDisplayAreaOrganizer", &[
        "onDisplayAreaAppeared", "onDisplayAreaVanished", "onDisplayAreaInfoChanged",
    ]),
    ("android.window.IDisplayAreaOrganizerController", &[
        "registerOrganizer", "unregisterOrganizer", "createTaskDisplayArea", "deleteTaskDisplayArea",
    ]),
    ("android.window.IDumpCallback", &[
        "onDump",
    ]),
    ("android.window.IGlobalDragListener", &[
        "onCrossWindowDrop", "onUnhandledDrop",
    ]),
    ("android.window.IOnBackInvokedCallback", &[
        "onBackStarted", "onBackProgressed", "onBackCancelled", "onBackInvoked",
        "setTriggerBack", "setHandoffHandler",
    ]),
    ("android.window.IRemoteTransition", &[
        "startAnimation", "mergeAnimation", "takeOverAnimation", "onTransitionConsumed",
    ]),
    ("android.window.IRemoteTransitionFinishedCallback", &[
        "onTransitionFinished",
    ]),
    ("android.window.IScreenRecordingCallback", &[
        "onScreenRecordingStateChanged",
    ]),
    ("android.window.ISurfaceSyncGroup", &[
        "onAddedToSyncGroup", "addToSync",
    ]),
    ("android.window.ISurfaceSyncGroupCompletedListener", &[
        "onSurfaceSyncGroupComplete",
    ]),
    ("android.window.ITaskFpsCallback", &[
        "onFpsReported",
    ]),
    ("android.window.ITaskFragmentOrganizer", &[
        "onTransactionReady",
    ]),
    ("android.window.ITaskFragmentOrganizerController", &[
        "registerOrganizer", "unregisterOrganizer", "registerRemoteAnimations", "unregisterRemoteAnimations",
        "setSavedState", "onTransactionHandled", "applyTransaction",
    ]),
    ("android.window.ITaskOrganizer", &[
        "addStartingWindow", "removeStartingWindow", "copySplashScreenView", "onAppSplashScreenViewRemoved",
        "onTaskAppeared", "onTaskVanished", "onTaskInfoChanged", "onBackPressedOnTaskRoot",
        "onImeDrawnOnTask",
    ]),
    ("android.window.ITaskOrganizerController", &[
        "registerTaskOrganizer", "unregisterTaskOrganizer", "createRootTask", "deleteRootTask",
        "getChildTasks", "getRootTasks", "getImeTarget", "setInterceptBackPressedOnTaskRoot",
        "restartTaskTopActivityProcessIfVisible",
    ]),
    ("android.window.ITransactionReadyCallback", &[
        "onTransactionReady",
    ]),
    ("android.window.ITransitionMetricsReporter", &[
        "reportAnimationStart",
    ]),
    ("android.window.ITransitionPlayer", &[
        "onTransitionReady", "requestStartTransition",
    ]),
    ("android.window.ITrustedPresentationListener", &[
        "onTrustedPresentationChanged",
    ]),
    ("android.window.IUnhandledDragCallback", &[
        "notifyUnhandledDropComplete",
    ]),
    ("android.window.IWindowContainerTransactionCallback", &[
        "onTransactionReady",
    ]),
    ("android.window.IWindowOrganizerController", &[
        "applyTransaction", "applySyncTransaction", "startNewTransition", "startTransition",
        "finishTransition", "getTaskOrganizerController", "getDisplayAreaOrganizerController", "getTaskFragmentOrganizerController",
        "registerTransitionPlayer", "unregisterTransitionPlayer", "getTransitionMetricsReporter", "getApplyToken",
    ]),
    ("android.window.IWindowlessStartingSurfaceCallback", &[
        "onSurfaceAdded",
    ]),
    ("android.window.WindowContainerTransaction$Change", &[
        "", "changeBounds",
    ]),
    ("com.android.ims.ImsConfigListener", &[
        "onGetFeatureResponse", "onSetFeatureResponse", "onGetVideoQuality", "onSetVideoQuality",
    ]),
    ("com.android.ims.internal.IImsCallSession", &[
        "close", "getCallId", "getCallProfile", "getLocalCallProfile",
        "getRemoteCallProfile", "getProperty", "getState", "isInCall",
        "setListener", "setMute", "start", "startConference",
        "accept", "deflect", "reject", "transfer",
        "consultativeTransfer", "terminate", "hold", "resume",
        "merge", "update", "extendToConference", "inviteParticipants",
        "removeParticipants", "sendDtmf", "startDtmf", "stopDtmf",
        "sendUssd", "getVideoCallProvider", "isMultiparty", "sendRttModifyRequest",
        "sendRttModifyResponse", "sendRttMessage", "sendRtpHeaderExtensions", "callSessionNotifyAnbr",
    ]),
    ("com.android.ims.internal.IImsCallSessionListener", &[
        "callSessionProgressing", "callSessionStarted", "callSessionStartFailed", "callSessionTerminated",
        "callSessionHeld", "callSessionHoldFailed", "callSessionHoldReceived", "callSessionResumed",
        "callSessionResumeFailed", "callSessionResumeReceived", "callSessionMergeStarted", "callSessionMergeComplete",
        "callSessionMergeFailed", "callSessionUpdated", "callSessionUpdateFailed", "callSessionUpdateReceived",
        "callSessionConferenceExtended", "callSessionConferenceExtendFailed", "callSessionConferenceExtendReceived", "callSessionInviteParticipantsRequestDelivered",
        "callSessionInviteParticipantsRequestFailed", "callSessionRemoveParticipantsRequestDelivered", "callSessionRemoveParticipantsRequestFailed", "callSessionConferenceStateUpdated",
        "callSessionUssdMessageReceived", "callSessionHandover", "callSessionHandoverFailed", "callSessionMayHandover",
        "callSessionTtyModeReceived", "callSessionMultipartyStateChanged", "callSessionSuppServiceReceived", "callSessionRttModifyRequestReceived",
        "callSessionRttModifyResponseReceived", "callSessionRttMessageReceived", "callSessionRttAudioIndicatorChanged", "callSessionTransferred",
        "callSessionTransferFailed", "callQualityChanged", "callSessionSendAnbrQuery",
    ]),
    ("com.android.ims.internal.IImsConfig", &[
        "getProvisionedValue", "getProvisionedStringValue", "setProvisionedValue", "setProvisionedStringValue",
        "getFeatureValue", "setFeatureValue", "getVolteProvisioned", "getVideoQuality",
        "setVideoQuality",
    ]),
    ("com.android.ims.internal.IImsEcbm", &[
        "setListener", "exitEmergencyCallbackMode",
    ]),
    ("com.android.ims.internal.IImsEcbmListener", &[
        "enteredECBM", "exitedECBM",
    ]),
    ("com.android.ims.internal.IImsExternalCallStateListener", &[
        "onImsExternalCallStateUpdate",
    ]),
    ("com.android.ims.internal.IImsFeatureStatusCallback", &[
        "notifyImsFeatureStatus",
    ]),
    ("com.android.ims.internal.IImsMMTelFeature", &[
        "startSession", "endSession", "isConnected", "isOpened",
        "getFeatureStatus", "addRegistrationListener", "removeRegistrationListener", "createCallProfile",
        "createCallSession", "getPendingCallSession", "getUtInterface", "getConfigInterface",
        "turnOnIms", "turnOffIms", "getEcbmInterface", "setUiTTYMode",
        "getMultiEndpointInterface",
    ]),
    ("com.android.ims.internal.IImsMultiEndpoint", &[
        "setListener", "requestImsExternalCallStateInfo",
    ]),
    ("com.android.ims.internal.IImsRegistrationListener", &[
        "registrationConnected", "registrationProgressing", "registrationConnectedWithRadioTech", "registrationProgressingWithRadioTech",
        "registrationDisconnected", "registrationResumed", "registrationSuspended", "registrationServiceCapabilityChanged",
        "registrationFeatureCapabilityChanged", "voiceMessageCountUpdate", "registrationAssociatedUriChanged", "registrationChangeFailed",
    ]),
    ("com.android.ims.internal.IImsService", &[
        "open", "close", "isConnected", "isOpened",
        "setRegistrationListener", "addRegistrationListener", "createCallProfile", "createCallSession",
        "getPendingCallSession", "getUtInterface", "getConfigInterface", "turnOnIms",
        "turnOffIms", "getEcbmInterface", "setUiTTYMode", "getMultiEndpointInterface",
    ]),
    ("com.android.ims.internal.IImsServiceController", &[
        "createEmergencyMMTelFeature", "createMMTelFeature", "createRcsFeature", "removeImsFeature",
        "addFeatureStatusCallback", "removeFeatureStatusCallback",
    ]),
    ("com.android.ims.internal.IImsServiceFeatureCallback", &[
        "imsFeatureCreated", "imsFeatureRemoved", "imsStatusChanged", "updateCapabilities",
    ]),
    ("com.android.ims.internal.IImsStreamMediaSession", &[
        "close",
    ]),
    ("com.android.ims.internal.IImsUt", &[
        "close", "queryCallBarring", "queryCallForward", "queryCallWaiting",
        "queryCLIR", "queryCLIP", "queryCOLR", "queryCOLP",
        "transact", "updateCallBarring", "updateCallForward", "updateCallWaiting",
        "updateCLIR", "updateCLIP", "updateCOLR", "updateCOLP",
        "setListener", "queryCallBarringForServiceClass", "updateCallBarringForServiceClass", "updateCallBarringWithPassword",
    ]),
    ("com.android.ims.internal.IImsUtListener", &[
        "utConfigurationUpdated", "utConfigurationUpdateFailed", "utConfigurationQueried", "utConfigurationQueryFailed",
        "lineIdentificationSupplementaryServiceResponse", "utConfigurationCallBarringQueried", "utConfigurationCallForwardQueried", "utConfigurationCallWaitingQueried",
        "onSupplementaryServiceIndication",
    ]),
    ("com.android.ims.internal.IImsVideoCallCallback", &[
        "receiveSessionModifyRequest", "receiveSessionModifyResponse", "handleCallSessionEvent", "changePeerDimensions",
        "changeCallDataUsage", "changeCameraCapabilities", "changeVideoQuality",
    ]),
    ("com.android.ims.internal.IImsVideoCallProvider", &[
        "setCallback", "setCamera", "setPreviewSurface", "setDisplaySurface",
        "setDeviceOrientation", "setZoom", "sendSessionModifyRequest", "sendSessionModifyResponse",
        "requestCameraCapabilities", "requestCallDataUsage", "setPauseImage",
    ]),
    ("com.android.ims.internal.uce.options.IOptionsListener", &[
        "getVersionCb", "serviceAvailable", "serviceUnavailable", "sipResponseReceived",
        "cmdStatus", "incomingOptions",
    ]),
    ("com.android.ims.internal.uce.options.IOptionsService", &[
        "getVersion", "addListener", "removeListener", "setMyInfo",
        "getMyInfo", "getContactCap", "getContactListCap", "responseIncomingOptions",
    ]),
    ("com.android.ims.internal.uce.presence.IPresenceListener", &[
        "getVersionCb", "serviceAvailable", "serviceUnAvailable", "publishTriggering",
        "cmdStatus", "sipResponseReceived", "capInfoReceived", "listCapInfoReceived",
        "unpublishMessageSent",
    ]),
    ("com.android.ims.internal.uce.presence.IPresenceService", &[
        "getVersion", "addListener", "removeListener", "reenableService",
        "publishMyCap", "getContactCap", "getContactListCap", "setNewFeatureTag",
    ]),
    ("com.android.ims.internal.uce.uceservice.IUceListener", &[
        "setStatus",
    ]),
    ("com.android.ims.internal.uce.uceservice.IUceService", &[
        "startService", "stopService", "isServiceStarted", "createOptionsService",
        "createOptionsServiceForSubscription", "destroyOptionsService", "createPresenceService", "createPresenceServiceForSubscription",
        "destroyPresenceService", "getServiceStatus", "getPresenceService", "getPresenceServiceForSubscription",
        "getOptionsService", "getOptionsServiceForSubscription",
    ]),
    ("com.android.internal.app.IAppOpsActiveCallback", &[
        "opActiveChanged",
    ]),
    ("com.android.internal.app.IAppOpsAsyncNotedCallback", &[
        "opNoted",
    ]),
    ("com.android.internal.app.IAppOpsCallback", &[
        "opChanged",
    ]),
    ("com.android.internal.app.IAppOpsNotedCallback", &[
        "opNoted",
    ]),
    ("com.android.internal.app.IAppOpsService", &[
        "checkOperation", "noteOperation", "startOperation", "finishOperation",
        "startWatchingMode", "stopWatchingMode", "permissionToOpCode", "checkAudioOperation",
        "shouldCollectNotes", "setCameraAudioRestriction", "startWatchingModeWithFlags", "noteProxyOperation",
        "startProxyOperation", "finishProxyOperation", "checkPackage", "collectRuntimeAppOpAccessMessage",
        "reportRuntimeAppOpAccessMessageAndGetConfig", "getPackagesForOps", "getOpsForPackage", "getHistoricalOps",
        "getHistoricalOpsFromDiskRaw", "offsetHistory", "setHistoryParameters", "addHistoricalOps",
        "resetHistoryParameters", "resetPackageOpsNoHistory", "clearHistory", "rebootHistory",
        "getUidOps", "setUidMode", "setMode", "resetAllModes",
        "setAudioRestriction", "setUserRestrictions", "setUserRestriction", "removeUser",
        "startWatchingActive", "stopWatchingActive", "isOperationActive", "isProxying",
        "startWatchingStarted", "stopWatchingStarted", "startWatchingNoted", "stopWatchingNoted",
        "startWatchingAsyncNoted", "stopWatchingAsyncNoted", "extractAsyncOps", "checkOperationRaw",
        "reloadNonHistoricalState", "collectNoteOpCallsForValidation", "noteProxyOperationWithState", "startProxyOperationWithState",
        "finishProxyOperationWithState", "checkOperationRawForDevice", "checkOperationForDevice", "noteOperationForDevice",
        "startOperationForDevice", "finishOperationForDevice", "getPackagesForOpsForDevice", "noteOperationsInBatch",
    ]),
    ("com.android.internal.app.IAppOpsStartedCallback", &[
        "opStarted",
    ]),
    ("com.android.internal.app.IBatteryStats", &[
        "noteStartSensor", "noteStopSensor", "noteStartVideo", "noteStopVideo",
        "noteStartAudio", "noteStopAudio", "noteResetVideo", "noteResetAudio",
        "noteFlashlightOn", "noteFlashlightOff", "noteStartCamera", "noteStopCamera",
        "noteResetCamera", "noteResetFlashlight", "noteWakeupSensorEvent", "getBatteryUsageStats",
        "isCharging", "computeBatteryTimeRemaining", "computeChargeTimeRemaining", "computeBatteryScreenOffRealtimeMs",
        "getScreenOffDischargeMah", "noteEvent", "noteSyncStart", "noteSyncFinish",
        "noteJobStart", "noteJobFinish", "noteStartWakelock", "noteStopWakelock",
        "noteStartWakelockFromSource", "noteChangeWakelockFromSource", "noteStopWakelockFromSource", "noteLongPartialWakelockStart",
        "noteLongPartialWakelockStartFromSource", "noteLongPartialWakelockFinish", "noteLongPartialWakelockFinishFromSource", "noteVibratorOn",
        "noteVibratorOff", "noteGpsChanged", "noteGpsSignalQuality", "noteScreenState",
        "noteScreenBrightness", "noteUserActivity", "noteWakeUp", "noteInteractive",
        "noteConnectivityChanged", "noteMobileRadioPowerState", "notePhoneOn", "notePhoneOff",
        "notePhoneSignalStrength", "notePhoneDataConnectionState", "notePhoneState", "noteWifiOn",
        "noteWifiOff", "noteWifiRunning", "noteWifiRunningChanged", "noteWifiStopped",
        "noteWifiState", "noteWifiSupplicantStateChanged", "noteWifiRssiChanged", "noteFullWifiLockAcquired",
        "noteFullWifiLockReleased", "noteWifiScanStarted", "noteWifiScanStopped", "noteWifiMulticastEnabled",
        "noteWifiMulticastDisabled", "noteFullWifiLockAcquiredFromSource", "noteFullWifiLockReleasedFromSource", "noteWifiScanStartedFromSource",
        "noteWifiScanStoppedFromSource", "noteWifiBatchedScanStartedFromSource", "noteWifiBatchedScanStoppedFromSource", "noteWifiRadioPowerState",
        "noteNetworkInterfaceForTransports", "noteNetworkStatsEnabled", "noteDeviceIdleMode", "setBatteryState",
        "getAwakeTimeBattery", "getAwakeTimePlugged", "noteBleScanStarted", "noteBleScanStopped",
        "noteBleScanReset", "noteBleScanResults", "getCellularBatteryStats", "getWifiBatteryStats",
        "getGpsBatteryStats", "getWakeLockStats", "getBluetoothBatteryStats", "takeUidSnapshot",
        "takeUidSnapshots", "takeUidSnapshotsAsync", "noteBluetoothControllerActivity", "noteModemControllerActivity",
        "noteWifiControllerActivity", "setChargingStateUpdateDelayMillis", "setChargerAcOnline", "setBatteryLevel",
        "unplugBattery", "resetBattery", "suspendBatteryInput",
    ]),
    ("com.android.internal.app.IHotwordRecognitionStatusCallback", &[
        "onKeyphraseDetected", "onKeyphraseDetectedFromExternalSource", "onGenericSoundTriggerDetected", "onRejected",
        "onHotwordDetectionServiceFailure", "onVisualQueryDetectionServiceFailure", "onSoundTriggerFailure", "onUnknownFailure",
        "onRecognitionPaused", "onRecognitionResumed", "onStatusReported", "onProcessRestarted",
        "onOpenFile",
    ]),
    ("com.android.internal.app.ILogAccessDialogCallback", &[
        "approveAccessForClient", "declineAccessForClient",
    ]),
    ("com.android.internal.app.IMediaContainerService", &[
        "copyPackage", "getMinimalPackageInfo", "getObbInfo", "calculateInstalledSize",
    ]),
    ("com.android.internal.app.ISoundTriggerService", &[
        "attachAsOriginator", "attachAsMiddleman", "listModuleProperties", "attachInjection",
        "setInPhoneCallState",
    ]),
    ("com.android.internal.app.ISoundTriggerSession", &[
        "getSoundModel", "updateSoundModel", "deleteSoundModel", "startRecognition",
        "stopRecognition", "loadGenericSoundModel", "loadKeyphraseSoundModel", "startRecognitionForService",
        "stopRecognitionForService", "unloadSoundModel", "isRecognitionActive", "getModelState",
        "getModuleProperties", "setParameter", "getParameter", "queryParameter",
    ]),
    ("com.android.internal.app.IVisualQueryDetectionAttentionListener", &[
        "onAttentionGained", "onAttentionLost",
    ]),
    ("com.android.internal.app.IVisualQueryRecognitionStatusListener", &[
        "onStartPerceiving", "onStopPerceiving",
    ]),
    ("com.android.internal.app.IVoiceActionCheckCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.app.IVoiceInteractionAccessibilitySettingsListener", &[
        "onAccessibilityDetectionChanged",
    ]),
    ("com.android.internal.app.IVoiceInteractionManagerService", &[
        "showSession", "deliverNewSession", "showSessionFromSession", "hideSessionFromSession",
        "startVoiceActivity", "startAssistantActivity", "setKeepAwake", "closeSystemDialogs",
        "finish", "setDisabledShowContext", "getDisabledShowContext", "getUserDisabledShowContext",
        "getKeyphraseSoundModel", "updateKeyphraseSoundModel", "deleteKeyphraseSoundModel", "setModelDatabaseForTestEnabled",
        "isEnrolledForKeyphrase", "getEnrolledKeyphraseMetadata", "getActiveServiceComponentName", "showSessionForActiveService",
        "hideCurrentSession", "launchVoiceAssistFromKeyguard", "isSessionRunning", "activeServiceSupportsAssist",
        "activeServiceSupportsLaunchFromKeyguard", "onLockscreenShown", "registerVoiceInteractionSessionListener", "getActiveServiceSupportedActions",
        "setUiHints", "requestDirectActions", "performDirectAction", "setDisabled",
        "createSoundTriggerSessionAsOriginator", "listModuleProperties", "updateState", "initAndVerifyDetector",
        "destroyDetector", "shutdownHotwordDetectionService", "subscribeVisualQueryRecognitionStatus", "enableVisualQueryDetection",
        "disableVisualQueryDetection", "startPerceiving", "stopPerceiving", "startListeningFromMic",
        "stopListeningFromMic", "startListeningFromExternalSource", "triggerHardwareRecognitionEventForTest", "startListeningVisibleActivityChanged",
        "stopListeningVisibleActivityChanged", "setSessionWindowVisible", "notifyActivityEventChanged", "getAccessibilityDetectionEnabled",
        "registerAccessibilityDetectionSettingsListener", "unregisterAccessibilityDetectionSettingsListener",
    ]),
    ("com.android.internal.app.IVoiceInteractionSessionListener", &[
        "onVoiceSessionShown", "onVoiceSessionHidden", "onVoiceSessionWindowVisibilityChanged", "onSetUiHints",
    ]),
    ("com.android.internal.app.IVoiceInteractionSessionShowCallback", &[
        "onFailed", "onShown",
    ]),
    ("com.android.internal.app.IVoiceInteractionSoundTriggerSession", &[
        "getDspModuleProperties", "startRecognition", "stopRecognition", "setParameter",
        "getParameter", "queryParameter", "detach",
    ]),
    ("com.android.internal.app.IVoiceInteractor", &[
        "startConfirmation", "startPickOption", "startCompleteVoice", "startAbortVoice",
        "startCommand", "supportsCommands", "notifyDirectActionsChanged", "setKillCallback",
    ]),
    ("com.android.internal.app.IVoiceInteractorCallback", &[
        "deliverConfirmationResult", "deliverPickOptionResult", "deliverCompleteVoiceResult", "deliverAbortVoiceResult",
        "deliverCommandResult", "deliverCancel", "destroy",
    ]),
    ("com.android.internal.app.IVoiceInteractorRequest", &[
        "cancel",
    ]),
    ("com.android.internal.app.procstats.IProcessStats", &[
        "getCurrentStats", "getStatsOverTime", "getCurrentMemoryState", "getCommittedStats",
        "getCommittedStatsMerged", "getMinAssociationDumpDuration",
    ]),
    ("com.android.internal.appwidget.IAppWidgetHost", &[
        "updateAppWidgetDeferred", "updateAppWidget", "providerChanged", "providersChanged",
        "viewDataChanged", "appWidgetRemoved",
    ]),
    ("com.android.internal.appwidget.IAppWidgetService", &[
        "startListening", "stopListening", "allocateAppWidgetId", "deleteAppWidgetId",
        "deleteHost", "deleteAllHosts", "getAppWidgetViews", "getAppWidgetIdsForHost",
        "setAppWidgetHidden", "createAppWidgetConfigIntentSender", "updateAppWidgetIds", "updateAppWidgetOptions",
        "getAppWidgetOptions", "partiallyUpdateAppWidgetIds", "updateAppWidgetProvider", "updateAppWidgetProviderInfo",
        "notifyAppWidgetViewDataChanged", "getInstalledProvidersForProfile", "getAppWidgetInfo", "hasBindAppWidgetPermission",
        "setBindAppWidgetPermission", "bindAppWidgetId", "bindRemoteViewsService", "notifyProviderInheritance",
        "getMaxBitmapMemory", "getAppWidgetIds", "isBoundWidgetPackage", "requestPinAppWidget",
        "isRequestPinAppWidgetSupported", "noteAppWidgetTapped", "setWidgetPreview", "getWidgetPreview",
        "removeWidgetPreview",
    ]),
    ("com.android.internal.backup.IBackupTransport", &[
        "name", "configurationIntent", "currentDestinationString", "dataManagementIntent",
        "dataManagementIntentLabel", "transportDirName", "requestBackupTime", "initializeDevice",
        "performBackup", "clearBackupData", "finishBackup", "getAvailableRestoreSets",
        "getCurrentRestoreSet", "startRestore", "nextRestorePackage", "getRestoreData",
        "finishRestore", "requestFullBackupTime", "performFullBackup", "checkFullBackupSize",
        "sendBackupData", "cancelFullBackup", "isAppEligibleForBackup", "getBackupQuota",
        "getNextFullRestoreDataChunk", "abortFullRestore", "getTransportFlags", "getBackupManagerMonitor",
        "getPackagesThatShouldNotUseRestrictedMode",
    ]),
    ("com.android.internal.backup.IObbBackupService", &[
        "backupObbs", "restoreObbFile",
    ]),
    ("com.android.internal.backup.ITransportStatusCallback", &[
        "onOperationCompleteWithStatus", "onOperationComplete",
    ]),
    ("com.android.internal.compat.IOverrideValidator", &[
        "getOverrideAllowedState",
    ]),
    ("com.android.internal.compat.IPlatformCompat", &[
        "reportChange", "reportChangeByPackageName", "reportChangeByUid", "isChangeEnabled",
        "isChangeEnabledByPackageName", "isChangeEnabledByUid", "setOverrides", "putAllOverridesOnReleaseBuilds",
        "putOverridesOnReleaseBuilds", "setOverridesForTest", "clearOverride", "clearOverrideForTest",
        "removeAllOverridesOnReleaseBuilds", "removeOverridesOnReleaseBuilds", "enableTargetSdkChanges", "disableTargetSdkChanges",
        "clearOverrides", "clearOverridesForTest", "getAppConfig", "listAllChanges",
        "listUIChanges", "getOverrideValidator",
    ]),
    ("com.android.internal.compat.IPlatformCompatNative", &[
        "reportChangeByPackageName", "reportChangeByUid", "isChangeEnabledByPackageName", "isChangeEnabledByUid",
    ]),
    ("com.android.internal.graphics.fonts.IFontManager", &[
        "getFontConfig", "updateFontFamily",
    ]),
    ("com.android.internal.infra.IAndroidFuture", &[
        "complete",
    ]),
    ("com.android.internal.inputmethod.IAccessibilityInputMethodSession", &[
        "updateSelection", "finishInput", "finishSession", "invalidateInput",
    ]),
    ("com.android.internal.inputmethod.IAccessibilityInputMethodSessionCallback", &[
        "sessionCreated",
    ]),
    ("com.android.internal.inputmethod.IBooleanListener", &[
        "onResult",
    ]),
    ("com.android.internal.inputmethod.IConnectionlessHandwritingCallback", &[
        "onResult", "onError",
    ]),
    ("com.android.internal.inputmethod.IImeTracker", &[
        "onStart", "onProgress", "onFailed", "onCancelled",
        "onShown", "onHidden", "onDispatched", "hasPendingImeVisibilityRequests",
        "finishTrackingPendingImeVisibilityRequests",
    ]),
    ("com.android.internal.inputmethod.IInlineSuggestionsRequestCallback", &[
        "onInlineSuggestionsUnsupported", "onInlineSuggestionsRequest", "onInputMethodStartInput", "onInputMethodShowInputRequested",
        "onInputMethodStartInputView", "onInputMethodFinishInputView", "onInputMethodFinishInput", "onInlineSuggestionsSessionInvalidated",
    ]),
    ("com.android.internal.inputmethod.IInlineSuggestionsResponseCallback", &[
        "onInlineSuggestionsResponse",
    ]),
    ("com.android.internal.inputmethod.IInputContentUriToken", &[
        "take", "release",
    ]),
    ("com.android.internal.inputmethod.IInputMethod", &[
        "initializeInternal", "onCreateInlineSuggestionsRequest", "bindInput", "unbindInput",
        "startInput", "onNavButtonFlagsChanged", "createSession", "setSessionEnabled",
        "showSoftInput", "hideSoftInput", "updateEditorToolType", "changeInputMethodSubtype",
        "canStartStylusHandwriting", "startStylusHandwriting", "commitHandwritingDelegationTextIfAvailable", "discardHandwritingDelegationText",
        "initInkWindow", "finishStylusHandwriting", "removeStylusHandwritingWindow", "setStylusWindowIdleTimeoutForTest",
    ]),
    ("com.android.internal.inputmethod.IInputMethodClient", &[
        "onBindMethod", "onStartInputResult", "onBindAccessibilityService", "onUnbindMethod",
        "onUnbindAccessibilityService", "setActive", "setInteractive", "setImeVisibility",
        "scheduleStartInputIfNecessary", "reportFullscreenMode", "setImeTraceEnabled", "throwExceptionFromSystem",
    ]),
    ("com.android.internal.inputmethod.IInputMethodPrivilegedOperations", &[
        "setImeWindowStatusAsync", "reportStartInputAsync", "createInputContentUriToken", "reportFullscreenModeAsync",
        "setInputMethod", "setInputMethodAndSubtype", "hideMySoftInput", "showMySoftInput",
        "updateStatusIconAsync", "switchToPreviousInputMethod", "switchToNextInputMethod", "shouldOfferSwitchingToNextInputMethod",
        "onImeSwitchButtonClickFromClient", "notifyUserActionAsync", "applyImeVisibilityAsync", "onStylusHandwritingReady",
        "resetStylusHandwriting", "switchKeyboardLayoutAsync", "setHandwritingSurfaceNotTouchable", "setHandwritingTouchableRegion",
    ]),
    ("com.android.internal.inputmethod.IInputMethodSession", &[
        "updateExtractedText", "updateSelection", "viewClicked", "updateCursor",
        "displayCompletions", "appPrivateCommand", "finishSession", "updateCursorAnchorInfo",
        "removeImeSurface", "finishInput", "invalidateInput",
    ]),
    ("com.android.internal.inputmethod.IInputMethodSessionCallback", &[
        "sessionCreated",
    ]),
    ("com.android.internal.inputmethod.IRemoteAccessibilityInputConnection", &[
        "commitText", "setSelection", "getSurroundingText", "deleteSurroundingText",
        "sendKeyEvent", "performEditorAction", "performContextMenuAction", "getCursorCapsMode",
        "clearMetaKeyStates",
    ]),
    ("com.android.internal.inputmethod.IRemoteInputConnection", &[
        "getTextBeforeCursor", "getTextAfterCursor", "getCursorCapsMode", "getExtractedText",
        "deleteSurroundingText", "deleteSurroundingTextInCodePoints", "setComposingText", "setComposingTextWithTextAttribute",
        "finishComposingText", "commitText", "commitTextWithTextAttribute", "commitCompletion",
        "commitCorrection", "setSelection", "performEditorAction", "performContextMenuAction",
        "beginBatchEdit", "endBatchEdit", "sendKeyEvent", "clearMetaKeyStates",
        "performSpellCheck", "performPrivateCommand", "performHandwritingGesture", "previewHandwritingGesture",
        "setComposingRegion", "setComposingRegionWithTextAttribute", "getSelectedText", "requestCursorUpdates",
        "requestCursorUpdatesWithFilter", "requestTextBoundsInfo", "commitContent", "getSurroundingText",
        "setImeConsumesInput", "replaceText", "cancelCancellationSignal", "forgetCancellationSignal",
    ]),
    ("com.android.internal.net.INetworkWatchlistManager", &[
        "startWatchlistLogging", "stopWatchlistLogging", "reloadWatchlist", "reportWatchlistIfNecessary",
        "getWatchlistConfigHash",
    ]),
    ("com.android.internal.os.IBinaryTransparencyService", &[
        "getSignedImageInfo", "recordMeasurementsForAllPackages", "collectAllApexInfo", "collectAllUpdatedPreloadInfo",
        "collectAllSilentInstalledMbaInfo",
    ]),
    ("com.android.internal.os.IDropBoxManagerService", &[
        "addData", "addFile", "isTagEnabled", "getNextEntry",
        "getNextEntryWithAttribution",
    ]),
    ("com.android.internal.os.IParcelFileDescriptorFactory", &[
        "open",
    ]),
    ("com.android.internal.os.IResultReceiver", &[
        "send",
    ]),
    ("com.android.internal.os.IShellCallback", &[
        "openFile",
    ]),
    ("com.android.internal.policy.IDeviceLockedStateListener", &[
        "onDeviceLockedStateChanged",
    ]),
    ("com.android.internal.policy.IKeyguardDismissCallback", &[
        "onDismissError", "onDismissSucceeded", "onDismissCancelled",
    ]),
    ("com.android.internal.policy.IKeyguardDrawnCallback", &[
        "onDrawn",
    ]),
    ("com.android.internal.policy.IKeyguardExitCallback", &[
        "onKeyguardExitResult",
    ]),
    ("com.android.internal.policy.IKeyguardLockedStateListener", &[
        "onKeyguardLockedStateChanged",
    ]),
    ("com.android.internal.policy.IKeyguardService", &[
        "setOccluded", "addStateMonitorCallback", "verifyUnlock", "dismiss",
        "onDreamingStarted", "onDreamingStopped", "onStartedGoingToSleep", "onFinishedGoingToSleep",
        "onStartedWakingUp", "onFinishedWakingUp", "onScreenTurningOn", "onScreenTurnedOn",
        "onScreenTurningOff", "onScreenTurnedOff", "setKeyguardEnabled", "onSystemReady",
        "doKeyguardTimeout", "setSwitchingUser", "setCurrentUser", "onBootCompleted",
        "startKeyguardExitAnimation", "onShortPowerPressedGoHome", "dismissKeyguardToLaunch", "onSystemKeyPressed",
        "showDismissibleKeyguard",
    ]),
    ("com.android.internal.policy.IKeyguardStateCallback", &[
        "onShowingStateChanged", "onSimSecureStateChanged", "onInputRestrictedStateChanged", "onTrustedChanged",
    ]),
    ("com.android.internal.policy.IShortcutService", &[
        "notifyShortcutKeyPressed",
    ]),
    ("com.android.internal.protolog.IProtoLogClient", &[
        "toggleLogcat",
    ]),
    ("com.android.internal.protolog.IProtoLogConfigurationService", &[
        "registerClient",
    ]),
    ("com.android.internal.statusbar.IAddTileResultCallback", &[
        "onTileRequest",
    ]),
    ("com.android.internal.statusbar.IAppClipsService", &[
        "canLaunchCaptureContentActivityForNote", "canLaunchCaptureContentActivityForNoteInternal",
    ]),
    ("com.android.internal.statusbar.ISessionListener", &[
        "onSessionStarted", "onSessionEnded",
    ]),
    ("com.android.internal.statusbar.IStatusBar", &[
        "setIcon", "removeIcon", "disable", "disableForAllDisplays",
        "animateExpandNotificationsPanel", "animateExpandSettingsPanel", "animateCollapsePanels", "toggleNotificationsPanel",
        "showWirelessChargingAnimation", "setImeWindowStatus", "setWindowState", "showRecentApps",
        "hideRecentApps", "toggleRecentApps", "toggleTaskbar", "toggleSplitScreen",
        "preloadRecentApps", "cancelPreloadRecentApps", "showScreenPinningRequest", "confirmImmersivePrompt",
        "immersiveModeChanged", "dismissKeyboardShortcutsMenu", "toggleKeyboardShortcutsMenu", "appTransitionPending",
        "appTransitionCancelled", "appTransitionStarting", "appTransitionFinished", "showAssistDisclosure",
        "startAssist", "onCameraLaunchGestureDetected", "onWalletLaunchGestureDetected", "onEmergencyActionLaunchGestureDetected",
        "showPictureInPictureMenu", "showGlobalActionsMenu", "onProposedRotationChanged", "setTopAppHidesStatusBar",
        "addQsTile", "addQsTileToFrontOrEnd", "remQsTile", "setQsTiles",
        "clickQsTile", "handleSystemKey", "showPinningEnterExitToast", "showPinningEscapeToast",
        "showShutdownUi", "showAuthenticationDialog", "onBiometricAuthenticated", "onBiometricHelp",
        "onBiometricError", "hideAuthenticationDialog", "setBiometicContextListener", "setUdfpsRefreshRateCallback",
        "onDisplayAddSystemDecorations", "onDisplayRemoveSystemDecorations", "onSystemBarAttributesChanged", "showTransient",
        "abortTransient", "showInattentiveSleepWarning", "dismissInattentiveSleepWarning", "showToast",
        "hideToast", "startTracing", "stopTracing", "suppressAmbientDisplay",
        "requestMagnificationConnection", "passThroughShellCommand", "setNavigationBarLumaSamplingEnabled", "runGcForTest",
        "requestTileServiceListeningState", "requestAddTile", "cancelRequestAddTile", "updateMediaTapToTransferSenderDisplay",
        "updateMediaTapToTransferReceiverDisplay", "registerNearbyMediaDevicesProvider", "unregisterNearbyMediaDevicesProvider", "dumpProto",
        "showRearDisplayDialog", "moveFocusedTaskToFullscreen", "moveFocusedTaskToStageSplit", "setSplitscreenFocus",
        "showMediaOutputSwitcher", "moveFocusedTaskToDesktop",
    ]),
    ("com.android.internal.statusbar.IStatusBarService", &[
        "expandNotificationsPanel", "collapsePanels", "togglePanel", "disable",
        "disableForUser", "disable2", "disable2ForUser", "getDisableFlags",
        "setIcon", "setIconVisibility", "removeIcon", "setImeWindowStatus",
        "expandSettingsPanel", "registerStatusBar", "registerStatusBarForAllDisplays", "onPanelRevealed",
        "onPanelHidden", "clearNotificationEffects", "onNotificationClick", "onNotificationActionClick",
        "onNotificationError", "onClearAllNotifications", "onNotificationClear", "onNotificationVisibilityChanged",
        "onNotificationExpansionChanged", "onNotificationDirectReplied", "onNotificationSmartSuggestionsAdded", "onNotificationSmartReplySent",
        "onNotificationSettingsViewed", "onNotificationBubbleChanged", "onBubbleMetadataFlagChanged", "hideCurrentInputMethodForBubbles",
        "grantInlineReplyUriPermission", "clearInlineReplyUriPermissions", "onNotificationFeedbackReceived", "onGlobalActionsShown",
        "onGlobalActionsHidden", "shutdown", "reboot", "restart",
        "addTile", "remTile", "clickTile", "handleSystemKey",
        "getLastSystemKey", "showPinningEnterExitToast", "showPinningEscapeToast", "showAuthenticationDialog",
        "onBiometricAuthenticated", "onBiometricHelp", "onBiometricError", "hideAuthenticationDialog",
        "setBiometicContextListener", "setUdfpsRefreshRateCallback", "showInattentiveSleepWarning", "dismissInattentiveSleepWarning",
        "startTracing", "stopTracing", "isTracing", "suppressAmbientDisplay",
        "requestTileServiceListeningState", "requestAddTile", "cancelRequestAddTile", "setNavBarMode",
        "getNavBarMode", "registerSessionListener", "unregisterSessionListener", "onSessionStarted",
        "onSessionEnded", "updateMediaTapToTransferSenderDisplay", "updateMediaTapToTransferReceiverDisplay", "registerNearbyMediaDevicesProvider",
        "unregisterNearbyMediaDevicesProvider", "showRearDisplayDialog",
    ]),
    ("com.android.internal.statusbar.IUndoMediaTransferCallback", &[
        "onUndoTriggered",
    ]),
    ("com.android.internal.telecom.ICallControl", &[
        "setActive", "answer", "setInactive", "disconnect",
        "startCallStreaming", "requestCallEndpointChange", "setMuteState", "sendEvent",
        "requestVideoState",
    ]),
    ("com.android.internal.telecom.ICallDiagnosticService", &[
        "setAdapter", "initializeDiagnosticCall", "updateCall", "updateCallAudioState",
        "removeDiagnosticCall", "receiveDeviceToDeviceMessage", "callQualityChanged", "receiveBluetoothCallQualityReport",
        "notifyCallDisconnected",
    ]),
    ("com.android.internal.telecom.ICallDiagnosticServiceAdapter", &[
        "displayDiagnosticMessage", "clearDiagnosticMessage", "sendDeviceToDeviceMessage", "overrideDisconnectMessage",
    ]),
    ("com.android.internal.telecom.ICallEventCallback", &[
        "onAddCallControl", "onSetActive", "onSetInactive", "onAnswer",
        "onDisconnect", "onCallStreamingStarted", "onCallStreamingFailed", "onCallEndpointChanged",
        "onAvailableCallEndpointsChanged", "onMuteStateChanged", "onVideoStateChanged", "onEvent",
        "removeCallFromTransactionalServiceWrapper",
    ]),
    ("com.android.internal.telecom.ICallRedirectionAdapter", &[
        "cancelCall", "placeCallUnmodified", "redirectCall",
    ]),
    ("com.android.internal.telecom.ICallRedirectionService", &[
        "placeCall", "notifyTimeout",
    ]),
    ("com.android.internal.telecom.ICallScreeningAdapter", &[
        "onScreeningResponse",
    ]),
    ("com.android.internal.telecom.ICallScreeningService", &[
        "screenCall",
    ]),
    ("com.android.internal.telecom.ICallStreamingService", &[
        "setStreamingCallAdapter", "onCallStreamingStarted", "onCallStreamingStopped", "onCallStreamingStateChanged",
    ]),
    ("com.android.internal.telecom.IConnectionService", &[
        "addConnectionServiceAdapter", "removeConnectionServiceAdapter", "createConnection", "createConnectionComplete",
        "createConnectionFailed", "createConference", "createConferenceComplete", "createConferenceFailed",
        "abort", "answerVideo", "answer", "deflect",
        "reject", "rejectWithReason", "rejectWithMessage", "transfer",
        "consultativeTransfer", "disconnect", "silence", "hold",
        "unhold", "onCallAudioStateChanged", "onCallEndpointChanged", "onAvailableCallEndpointsChanged",
        "onMuteStateChanged", "playDtmfTone", "stopDtmfTone", "conference",
        "splitFromConference", "mergeConference", "swapConference", "addConferenceParticipants",
        "onPostDialContinue", "pullExternalCall", "sendCallEvent", "onCallFilteringCompleted",
        "onExtrasChanged", "startRtt", "stopRtt", "respondToRttUpgradeRequest",
        "connectionServiceFocusLost", "connectionServiceFocusGained", "handoverFailed", "handoverComplete",
        "onUsingAlternativeUi", "onTrackedByNonUiService",
    ]),
    ("com.android.internal.telecom.IConnectionServiceAdapter", &[
        "handleCreateConnectionComplete", "handleCreateConferenceComplete", "setActive", "setRinging",
        "setDialing", "setPulling", "setDisconnected", "setOnHold",
        "setRingbackRequested", "setConnectionCapabilities", "setConnectionProperties", "setIsConferenced",
        "setConferenceMergeFailed", "addConferenceCall", "removeCall", "onPostDialWait",
        "onPostDialChar", "queryRemoteConnectionServices", "setVideoProvider", "setVideoState",
        "setIsVoipAudioMode", "setStatusHints", "setAddress", "setCallerDisplayName",
        "setConferenceableConnections", "addExistingConnection", "putExtras", "removeExtras",
        "setAudioRoute", "requestCallEndpointChange", "onConnectionEvent", "onRttInitiationSuccess",
        "onRttInitiationFailure", "onRttSessionRemotelyTerminated", "onRemoteRttRequest", "onPhoneAccountChanged",
        "onConnectionServiceFocusReleased", "resetConnectionTime", "setConferenceState", "setCallDirection",
        "queryLocation",
    ]),
    ("com.android.internal.telecom.IDeviceIdleControllerAdapter", &[
        "exemptAppTemporarilyForEvent",
    ]),
    ("com.android.internal.telecom.IInCallAdapter", &[
        "answerCall", "deflectCall", "rejectCall", "rejectCallWithReason",
        "transferCall", "consultativeTransfer", "disconnectCall", "holdCall",
        "unholdCall", "mute", "setAudioRoute", "requestCallEndpointChange",
        "enterBackgroundAudioProcessing", "exitBackgroundAudioProcessing", "playDtmfTone", "stopDtmfTone",
        "postDialContinue", "phoneAccountSelected", "conference", "splitFromConference",
        "mergeConference", "swapConference", "addConferenceParticipants", "turnOnProximitySensor",
        "turnOffProximitySensor", "pullExternalCall", "sendCallEvent", "putExtras",
        "removeExtras", "sendRttRequest", "respondToRttRequest", "stopRtt",
        "setRttMode", "handoverTo",
    ]),
    ("com.android.internal.telecom.IInCallService", &[
        "setInCallAdapter", "addCall", "updateCall", "setPostDial",
        "setPostDialWait", "onCallAudioStateChanged", "onCallEndpointChanged", "onAvailableCallEndpointsChanged",
        "onMuteStateChanged", "bringToForeground", "onCanAddCallChanged", "silenceRinger",
        "onConnectionEvent", "onRttUpgradeRequest", "onRttInitiationFailure", "onHandoverFailed",
        "onHandoverComplete",
    ]),
    ("com.android.internal.telecom.IInternalServiceRetriever", &[
        "getDeviceIdleController",
    ]),
    ("com.android.internal.telecom.IPhoneAccountSuggestionCallback", &[
        "suggestPhoneAccounts",
    ]),
    ("com.android.internal.telecom.IPhoneAccountSuggestionService", &[
        "onAccountSuggestionRequest",
    ]),
    ("com.android.internal.telecom.IStreamingCallAdapter", &[
        "setStreamingState",
    ]),
    ("com.android.internal.telecom.ITelecomLoader", &[
        "createTelecomService",
    ]),
    ("com.android.internal.telecom.ITelecomService", &[
        "showInCallScreen", "getDefaultOutgoingPhoneAccount", "getUserSelectedOutgoingPhoneAccount", "setUserSelectedOutgoingPhoneAccount",
        "getCallCapablePhoneAccounts", "getSelfManagedPhoneAccounts", "getOwnSelfManagedPhoneAccounts", "getPhoneAccountsSupportingScheme",
        "getPhoneAccountsForPackage", "getPhoneAccount", "getRegisteredPhoneAccounts", "getAllPhoneAccountsCount",
        "getAllPhoneAccounts", "getAllPhoneAccountHandles", "getSimCallManager", "getSimCallManagerForUser",
        "registerPhoneAccount", "unregisterPhoneAccount", "clearAccounts", "isVoiceMailNumber",
        "getVoiceMailNumber", "getLine1Number", "getDefaultPhoneApp", "getDefaultDialerPackage",
        "getDefaultDialerPackageForUser", "getSystemDialerPackage", "dumpCallAnalytics", "silenceRinger",
        "isInCall", "hasManageOngoingCallsPermission", "isInManagedCall", "isRinging",
        "getCallState", "getCallStateUsingPackage", "endCall", "acceptRingingCall",
        "acceptRingingCallWithVideoState", "cancelMissedCallsNotification", "handlePinMmi", "handlePinMmiForPhoneAccount",
        "getAdnUriForPhoneAccount", "isTtySupported", "getCurrentTtyMode", "addNewIncomingCall",
        "addNewIncomingConference", "addNewUnknownCall", "startConference", "placeCall",
        "enablePhoneAccount", "setDefaultDialer", "stopBlockSuppression", "createManageBlockedNumbersIntent",
        "createLaunchEmergencyDialerIntent", "isIncomingCallPermitted", "isOutgoingCallPermitted", "waitOnHandlers",
        "acceptHandover", "setTestEmergencyPhoneAccountPackageNameFilter", "isInEmergencyCall", "handleCallIntent",
        "cleanupStuckCalls", "cleanupOrphanPhoneAccounts", "isNonUiInCallServiceBound", "resetCarMode",
        "setTestDefaultCallRedirectionApp", "requestLogMark", "setTestPhoneAcctSuggestionComponent", "setTestDefaultCallScreeningApp",
        "addOrRemoveTestCallCompanionApp", "setSystemDialer", "setTestDefaultDialer", "setTestCallDiagnosticService",
        "isInSelfManagedCall", "addCall", "hasForegroundServiceDelegation", "setMetricsTestMode",
        "waitForAudioToUpdate",
    ]),
    ("com.android.internal.telecom.IVideoCallback", &[
        "receiveSessionModifyRequest", "receiveSessionModifyResponse", "handleCallSessionEvent", "changePeerDimensions",
        "changeCallDataUsage", "changeCameraCapabilities", "changeVideoQuality",
    ]),
    ("com.android.internal.telecom.IVideoProvider", &[
        "addVideoCallback", "removeVideoCallback", "setCamera", "setPreviewSurface",
        "setDisplaySurface", "setDeviceOrientation", "setZoom", "sendSessionModifyRequest",
        "sendSessionModifyResponse", "requestCameraCapabilities", "requestCallDataUsage", "setPauseImage",
    ]),
    ("com.android.internal.telecom.RemoteServiceCallback", &[
        "onError", "onResult",
    ]),
    ("com.android.internal.telephony.IBooleanConsumer", &[
        "accept",
    ]),
    ("com.android.internal.telephony.ICallForwardingInfoCallback", &[
        "onCallForwardingInfoAvailable", "onError",
    ]),
    ("com.android.internal.telephony.ICarrierConfigChangeListener", &[
        "onCarrierConfigChanged",
    ]),
    ("com.android.internal.telephony.ICarrierConfigLoader", &[
        "getConfigForSubId", "getConfigForSubIdWithFeature", "overrideConfig", "notifyConfigChangedForSubId",
        "updateConfigForPhoneId", "getDefaultCarrierServicePackageName", "getConfigSubsetForSubIdWithFeature",
    ]),
    ("com.android.internal.telephony.ICarrierPrivilegesCallback", &[
        "onCarrierPrivilegesChanged", "onCarrierServiceChanged",
    ]),
    ("com.android.internal.telephony.IDomainSelectionServiceController", &[
        "selectDomain", "updateServiceState", "updateBarringInfo",
    ]),
    ("com.android.internal.telephony.IDomainSelector", &[
        "reselectDomain", "finishSelection",
    ]),
    ("com.android.internal.telephony.IImsStateCallback", &[
        "onUnavailable", "onAvailable",
    ]),
    ("com.android.internal.telephony.IIntegerConsumer", &[
        "accept",
    ]),
    ("com.android.internal.telephony.ILongConsumer", &[
        "accept",
    ]),
    ("com.android.internal.telephony.IMms", &[
        "sendMessage", "downloadMessage", "importTextMessage", "importMultimediaMessage",
        "deleteStoredMessage", "deleteStoredConversation", "updateStoredMessageStatus", "archiveStoredConversation",
        "addTextMessageDraft", "addMultimediaMessageDraft", "sendStoredMessage", "setAutoPersisting",
        "getAutoPersisting",
    ]),
    ("com.android.internal.telephony.INumberVerificationCallback", &[
        "onCallReceived", "onVerificationFailed",
    ]),
    ("com.android.internal.telephony.IOnSubscriptionsChangedListener", &[
        "onSubscriptionsChanged",
    ]),
    ("com.android.internal.telephony.IOns", &[
        "setEnable", "isEnabled", "setPreferredDataSubscriptionId", "getPreferredDataSubscriptionId",
        "updateAvailableNetworks",
    ]),
    ("com.android.internal.telephony.IPhoneStateListener", &[
        "onServiceStateChanged", "onSignalStrengthChanged", "onMessageWaitingIndicatorChanged", "onCallForwardingIndicatorChanged",
        "onCellLocationChanged", "onLegacyCallStateChanged", "onCallStateChanged", "onDataConnectionStateChanged",
        "onDataActivity", "onSignalStrengthsChanged", "onCellInfoChanged", "onPreciseCallStateChanged",
        "onPreciseDataConnectionStateChanged", "onDataConnectionRealTimeInfoChanged", "onSrvccStateChanged", "onVoiceActivationStateChanged",
        "onDataActivationStateChanged", "onOemHookRawEvent", "onCarrierNetworkChange", "onUserMobileDataStateChanged",
        "onDisplayInfoChanged", "onPhoneCapabilityChanged", "onActiveDataSubIdChanged", "onRadioPowerStateChanged",
        "onCallStatesChanged", "onEmergencyNumberListChanged", "onOutgoingEmergencyCall", "onOutgoingEmergencySms",
        "onCallDisconnectCauseChanged", "onImsCallDisconnectCauseChanged", "onRegistrationFailed", "onBarringInfoChanged",
        "onPhysicalChannelConfigChanged", "onDataEnabledChanged", "onAllowedNetworkTypesChanged", "onLinkCapacityEstimateChanged",
        "onMediaQualityStatusChanged", "onCallbackModeStarted", "onCallbackModeRestarted", "onCallbackModeStopped",
        "onSimultaneousCallingStateChanged", "onCarrierRoamingNtnModeChanged", "onCarrierRoamingNtnEligibleStateChanged", "onCarrierRoamingNtnAvailableServicesChanged",
        "onCarrierRoamingNtnSignalStrengthChanged", "onSecurityAlgorithmsChanged", "onCellularIdentifierDisclosedChanged",
    ]),
    ("com.android.internal.telephony.IPhoneSubInfo", &[
        "getDeviceId", "getDeviceIdWithFeature", "getNaiForSubscriber", "getDeviceIdForPhone",
        "getImeiForSubscriber", "getDeviceSvn", "getDeviceSvnUsingSubId", "getSubscriberId",
        "getSubscriberIdWithFeature", "getSubscriberIdForSubscriber", "getGroupIdLevel1ForSubscriber", "getGroupIdLevel2ForSubscriber",
        "getIccSerialNumber", "getIccSerialNumberWithFeature", "getIccSerialNumberForSubscriber", "getLine1Number",
        "getLine1NumberForSubscriber", "getLine1AlphaTag", "getLine1AlphaTagForSubscriber", "getMsisdn",
        "getMsisdnForSubscriber", "getVoiceMailNumber", "getVoiceMailNumberForSubscriber", "getCarrierInfoForImsiEncryption",
        "setCarrierInfoForImsiEncryption", "resetCarrierKeysForImsiEncryption", "getVoiceMailAlphaTag", "getVoiceMailAlphaTagForSubscriber",
        "getIsimImpi", "getImsPrivateUserIdentity", "getIsimDomain", "getIsimImpu",
        "getImsPublicUserIdentities", "getIsimIst", "getIsimPcscf", "getImsPcscfAddresses",
        "getIccSimChallengeResponse", "getSmscIdentity", "getSimServiceTable",
    ]),
    ("com.android.internal.telephony.ISatelliteStateChangeListener", &[
        "onSatelliteEnabledStateChanged",
    ]),
    ("com.android.internal.telephony.ISetOpportunisticDataCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.ISipDialogStateCallback", &[
        "onActiveSipDialogsChanged",
    ]),
    ("com.android.internal.telephony.ISms", &[
        "getAllMessagesFromIccEfForSubscriber", "updateMessageOnIccEfForSubscriber", "copyMessageToIccEfForSubscriber", "sendDataForSubscriber",
        "sendTextForSubscriber", "sendTextForSubscriberWithOptions", "injectSmsPduForSubscriber", "sendMultipartTextForSubscriber",
        "sendMultipartTextForSubscriberWithOptions", "enableCellBroadcastForSubscriber", "disableCellBroadcastForSubscriber", "enableCellBroadcastRangeForSubscriber",
        "disableCellBroadcastRangeForSubscriber", "getPremiumSmsPermission", "getPremiumSmsPermissionForSubscriber", "setPremiumSmsPermission",
        "setPremiumSmsPermissionForSubscriber", "isImsSmsSupportedForSubscriber", "isSmsSimPickActivityNeeded", "getPreferredSmsSubscription",
        "getImsSmsFormatForSubscriber", "isSMSPromptEnabled", "sendStoredText", "sendStoredMultipartText",
        "getCarrierConfigValuesForSubscriber", "createAppSpecificSmsToken", "createAppSpecificSmsTokenWithPackageInfo", "setStorageMonitorMemoryStatusOverride",
        "clearStorageMonitorMemoryStatusOverride", "checkSmsShortCodeDestination", "getSmscAddressFromIccEfForSubscriber", "setSmscAddressOnIccEfForSubscriber",
        "getSmsCapacityOnIccForSubscriber", "resetAllCellBroadcastRanges", "getWapMessageSize",
    ]),
    ("com.android.internal.telephony.ISub", &[
        "getAllSubInfoList", "getActiveSubscriptionInfo", "getActiveSubscriptionInfoForIccId", "getActiveSubscriptionInfoForSimSlotIndex",
        "getActiveSubscriptionInfoList", "getActiveSubInfoCount", "getActiveSubInfoCountMax", "getAvailableSubscriptionInfoList",
        "getAccessibleSubscriptionInfoList", "requestEmbeddedSubscriptionInfoListRefresh", "addSubInfo", "removeSubInfo",
        "setIconTint", "setDisplayNameUsingSrc", "setDisplayNumber", "setDataRoaming",
        "setOpportunistic", "createSubscriptionGroup", "setPreferredDataSubscriptionId", "getPreferredDataSubscriptionId",
        "getOpportunisticSubscriptions", "removeSubscriptionsFromGroup", "addSubscriptionsIntoGroup", "getSubscriptionsInGroup",
        "getSlotIndex", "getSubId", "getDefaultSubId", "getDefaultSubIdAsUser",
        "getPhoneId", "getDefaultDataSubId", "setDefaultDataSubId", "getDefaultVoiceSubId",
        "getDefaultVoiceSubIdAsUser", "setDefaultVoiceSubId", "getDefaultSmsSubId", "getDefaultSmsSubIdAsUser",
        "setDefaultSmsSubId", "getActiveSubIdList", "setSubscriptionProperty", "getSubscriptionProperty",
        "isSubscriptionEnabled", "getEnabledSubscriptionId", "isActiveSubId", "getActiveDataSubscriptionId",
        "canDisablePhysicalSubscription", "setUiccApplicationsEnabled", "setDeviceToDeviceStatusSharing", "setDeviceToDeviceStatusSharingContacts",
        "getPhoneNumber", "getPhoneNumberFromFirstAvailableSource", "setPhoneNumber", "setUsageSetting",
        "setGroupOwner", "setSubscriptionUserHandle", "getSubscriptionUserHandle", "isSubscriptionAssociatedWithCallingUser",
        "isSubscriptionAssociatedWithUser", "getSubscriptionInfoListAssociatedWithUser", "restoreAllSimSpecificSettingsFromBackup", "setTransferStatus",
    ]),
    ("com.android.internal.telephony.ITelephony", &[
        "dial", "call", "isRadioOn", "isRadioOnWithFeature",
        "isRadioOnForSubscriber", "isRadioOnForSubscriberWithFeature", "setCallComposerStatus", "getCallComposerStatus",
        "supplyPinForSubscriber", "supplyPukForSubscriber", "supplyPinReportResultForSubscriber", "supplyPukReportResultForSubscriber",
        "handlePinMmi", "handleUssdRequest", "handlePinMmiForSubscriber", "toggleRadioOnOff",
        "toggleRadioOnOffForSubscriber", "setRadio", "setRadioForSubscriber", "setRadioPower",
        "requestRadioPowerOffForReason", "clearRadioPowerOffForReason", "getRadioPowerOffReasons", "updateServiceLocation",
        "updateServiceLocationWithPackageName", "enableLocationUpdates", "disableLocationUpdates", "enableDataConnectivity",
        "disableDataConnectivity", "isDataConnectivityPossible", "getCellLocation", "getNetworkCountryIsoForPhone",
        "getNeighboringCellInfo", "getCallState", "getCallStateForSubscription", "getDataActivity",
        "getDataActivityForSubId", "getDataState", "getDataStateForSubId", "getActivePhoneType",
        "getActivePhoneTypeForSlot", "getCdmaEriIconIndex", "getCdmaEriIconIndexForSubscriber", "getCdmaEriIconMode",
        "getCdmaEriIconModeForSubscriber", "getCdmaEriText", "getCdmaEriTextForSubscriber", "needsOtaServiceProvisioning",
        "setVoiceMailNumber", "setVoiceActivationState", "setDataActivationState", "getVoiceActivationState",
        "getDataActivationState", "getVoiceMessageCountForSubscriber", "isConcurrentVoiceAndDataAllowed", "getVisualVoicemailSettings",
        "getVisualVoicemailPackageName", "enableVisualVoicemailSmsFilter", "disableVisualVoicemailSmsFilter", "getVisualVoicemailSmsFilterSettings",
        "getActiveVisualVoicemailSmsFilterSettings", "sendVisualVoicemailSmsForSubscriber", "sendDialerSpecialCode", "getNetworkTypeForSubscriber",
        "getDataNetworkType", "getDataNetworkTypeForSubscriber", "getVoiceNetworkTypeForSubscriber", "hasIccCard",
        "hasIccCardUsingSlotIndex", "getLteOnCdmaMode", "getLteOnCdmaModeForSubscriber", "getAllCellInfo",
        "requestCellInfoUpdate", "requestCellInfoUpdateWithWorkSource", "setCellInfoListRate", "iccOpenLogicalChannel",
        "iccCloseLogicalChannel", "iccTransmitApduLogicalChannelByPort", "iccTransmitApduLogicalChannel", "iccTransmitApduBasicChannelByPort",
        "iccTransmitApduBasicChannel", "iccExchangeSimIO", "sendEnvelopeWithStatus", "nvReadItem",
        "nvWriteItem", "nvWriteCdmaPrl", "resetModemConfig", "rebootModem",
        "getAllowedNetworkTypesBitmask", "isTetheringApnRequiredForSubscriber", "enableIms", "disableIms",
        "resetIms", "registerMmTelFeatureCallback", "unregisterImsFeatureCallback", "getImsRegistration",
        "getImsConfig", "setBoundImsServiceOverride", "clearCarrierImsServiceOverride", "getBoundImsServicePackage",
        "getImsMmTelFeatureState", "setNetworkSelectionModeAutomatic", "getCellNetworkScanResults", "requestNetworkScan",
        "stopNetworkScan", "setNetworkSelectionModeManual", "getAllowedNetworkTypesForReason", "setAllowedNetworkTypesForReason",
        "getDataEnabled", "isUserDataEnabled", "isDataEnabled", "setDataEnabledForReason",
        "isDataEnabledForReason", "isManualNetworkSelectionAllowed", "setImsRegistrationState", "getCdmaMdn",
        "getCdmaMin", "requestNumberVerification", "getCarrierPrivilegeStatus", "getCarrierPrivilegeStatusForUid",
        "checkCarrierPrivilegesForPackage", "checkCarrierPrivilegesForPackageAnyPhone", "getCarrierPackageNamesForIntentAndPhone", "setLine1NumberForDisplayForSubscriber",
        "getLine1NumberForDisplay", "getLine1AlphaTagForDisplay", "getMergedSubscriberIds", "getMergedImsisFromGroup",
        "setOperatorBrandOverride", "setRoamingOverride", "needMobileRadioShutdown", "shutdownMobileRadios",
        "getRadioAccessFamily", "uploadCallComposerPicture", "enableVideoCalling", "isVideoCallingEnabled",
        "canChangeDtmfToneLength", "isWorldPhone", "isTtyModeSupported", "isRttSupported",
        "isHearingAidCompatibilitySupported", "isImsRegistered", "isWifiCallingAvailable", "isVideoTelephonyAvailable",
        "getImsRegTechnologyForMmTel", "getDeviceId", "getDeviceIdWithFeature", "getImeiForSlot",
        "getPrimaryImei", "getTypeAllocationCodeForSlot", "getMeidForSlot", "getManufacturerCodeForSlot",
        "getDeviceSoftwareVersionForSlot", "getSubIdForPhoneAccountHandle", "getPhoneAccountHandleForSubscriptionId", "factoryReset",
        "getSimLocaleForSubscriber", "requestModemActivityInfo", "getServiceStateForSlot", "getVoicemailRingtoneUri",
        "setVoicemailRingtoneUri", "isVoicemailVibrationEnabled", "setVoicemailVibrationEnabled", "getPackagesWithCarrierPrivileges",
        "getPackagesWithCarrierPrivilegesForAllPhones", "getAidForAppType", "getEsn", "getCdmaPrlVersion",
        "getTelephonyHistograms", "setAllowedCarriers", "getAllowedCarriers", "getSubscriptionCarrierId",
        "getSubscriptionCarrierName", "getSubscriptionSpecificCarrierId", "getSubscriptionSpecificCarrierName", "getCarrierIdFromMccMnc",
        "carrierActionSetRadioEnabled", "carrierActionReportDefaultNetworkStatus", "carrierActionResetAll", "getCallForwarding",
        "setCallForwarding", "getCallWaitingStatus", "setCallWaitingStatus", "getClientRequestStats",
        "setSimPowerStateForSlot", "setSimPowerStateForSlotWithCallback", "getForbiddenPlmns", "setForbiddenPlmns",
        "getEmergencyCallbackMode", "getSignalStrength", "getCardIdForDefaultEuicc", "getUiccCardsInfo",
        "getUiccSlotsInfo", "switchSlots", "setSimSlotMapping", "isDataRoamingEnabled",
        "setDataRoamingEnabled", "getCdmaRoamingMode", "setCdmaRoamingMode", "getCdmaSubscriptionMode",
        "setCdmaSubscriptionMode", "setCarrierTestOverride", "setCarrierServicePackageOverride", "getCarrierIdListVersion",
        "refreshUiccProfile", "getNumberOfModemsWithSimultaneousDataConnections", "getNetworkSelectionMode", "isInEmergencySmsMode",
        "getRadioPowerState", "registerImsRegistrationCallback", "unregisterImsRegistrationCallback", "registerImsEmergencyRegistrationCallback",
        "unregisterImsEmergencyRegistrationCallback", "getImsMmTelRegistrationState", "getImsMmTelRegistrationTransportType", "registerMmTelCapabilityCallback",
        "unregisterMmTelCapabilityCallback", "isCapable", "isAvailable", "isMmTelCapabilitySupported",
        "isAdvancedCallingSettingEnabled", "setAdvancedCallingSettingEnabled", "isVtSettingEnabled", "setVtSettingEnabled",
        "isVoWiFiSettingEnabled", "setVoWiFiSettingEnabled", "isCrossSimCallingEnabledByUser", "setCrossSimCallingEnabled",
        "isVoWiFiRoamingSettingEnabled", "setVoWiFiRoamingSettingEnabled", "setVoWiFiNonPersistent", "getVoWiFiModeSetting",
        "setVoWiFiModeSetting", "getVoWiFiRoamingModeSetting", "setVoWiFiRoamingModeSetting", "setRttCapabilitySetting",
        "isTtyOverVolteEnabled", "getEmergencyNumberList", "isEmergencyNumber", "getCertsFromCarrierPrivilegeAccessRules",
        "registerImsProvisioningChangedCallback", "unregisterImsProvisioningChangedCallback", "registerFeatureProvisioningChangedCallback", "unregisterFeatureProvisioningChangedCallback",
        "setImsProvisioningStatusForCapability", "getImsProvisioningStatusForCapability", "getRcsProvisioningStatusForCapability", "setRcsProvisioningStatusForCapability",
        "getImsProvisioningInt", "getImsProvisioningString", "setImsProvisioningInt", "setImsProvisioningString",
        "startEmergencyCallbackMode", "updateEmergencyNumberListTestMode", "getEmergencyNumberListTestMode", "getEmergencyNumberDbVersion",
        "notifyOtaEmergencyNumberDbInstalled", "updateOtaEmergencyNumberDbFilePath", "resetOtaEmergencyNumberDbFilePath", "enableModemForSlot",
        "setMultiSimCarrierRestriction", "isMultiSimSupported", "switchMultiSimConfig", "doesSwitchMultiSimConfigTriggerReboot",
        "getSlotsMapping", "getRadioHalVersion", "getHalVersion", "getCurrentPackageName",
        "isApplicationOnUicc", "isModemEnabledForSlot", "isDataEnabledForApn", "isApnMetered",
        "setSystemSelectionChannels", "getSystemSelectionChannels", "isMvnoMatched", "enqueueSmsPickResult",
        "showSwitchToManagedProfileDialog", "getMmsUserAgent", "getMmsUAProfUrl", "setMobileDataPolicyEnabled",
        "isMobileDataPolicyEnabled", "setCepEnabled", "notifyRcsAutoConfigurationReceived", "isIccLockEnabled",
        "setIccLockEnabled", "changeIccLockPassword", "requestUserActivityNotification", "userActivity",
        "getManualNetworkSelectionPlmn", "canConnectTo5GInDsdsMode", "getEquivalentHomePlmns", "setVoNrEnabled",
        "isVoNrEnabled", "setNrDualConnectivityState", "isNrDualConnectivityEnabled", "isRadioInterfaceCapabilitySupported",
        "sendThermalMitigationRequest", "bootstrapAuthenticationRequest", "setBoundGbaServiceOverride", "getBoundGbaService",
        "setGbaReleaseTimeOverride", "getGbaReleaseTime", "setRcsClientConfiguration", "isRcsVolteSingleRegistrationCapable",
        "registerRcsProvisioningCallback", "unregisterRcsProvisioningCallback", "triggerRcsReconfiguration", "setRcsSingleRegistrationTestModeEnabled",
        "getRcsSingleRegistrationTestModeEnabled", "setDeviceSingleRegistrationEnabledOverride", "getDeviceSingleRegistrationEnabled", "setCarrierSingleRegistrationEnabledOverride",
        "sendDeviceToDeviceMessage", "setActiveDeviceToDeviceTransport", "setDeviceToDeviceForceEnabled", "getCarrierSingleRegistrationEnabled",
        "setImsFeatureValidationOverride", "getImsFeatureValidationOverride", "getMobileProvisioningUrl", "removeContactFromEab",
        "getContactFromEab", "getCapabilityFromEab", "getDeviceUceEnabled", "setDeviceUceEnabled",
        "addUceRegistrationOverrideShell", "removeUceRegistrationOverrideShell", "clearUceRegistrationOverrideShell", "getLatestRcsContactUceCapabilityShell",
        "getLastUcePidfXmlShell", "removeUceRequestDisallowedStatus", "setCapabilitiesRequestTimeout", "setSignalStrengthUpdateRequest",
        "clearSignalStrengthUpdateRequest", "getPhoneCapability", "prepareForUnattendedReboot", "getSlicingConfig",
        "isPremiumCapabilityAvailableForPurchase", "purchasePremiumCapability", "registerImsStateCallback", "unregisterImsStateCallback",
        "getLastKnownCellIdentity", "setModemService", "getModemService", "isProvisioningRequiredForCapability",
        "isRcsProvisioningRequiredForCapability", "setVoiceServiceStateOverride", "getCarrierServicePackageNameForLogicalSlot", "setRemovableEsimAsDefaultEuicc",
        "isRemovableEsimDefaultEuicc", "getDefaultRespondViaMessageApplication", "getSimStateForSlotIndex", "persistEmergencyCallDiagnosticData",
        "setNullCipherAndIntegrityEnabled", "isNullCipherAndIntegrityPreferenceEnabled", "getCellBroadcastIdRanges", "setCellBroadcastIdRanges",
        "isDomainSelectionSupported", "getCarrierRestrictionStatus", "requestSatelliteEnabled", "requestIsSatelliteEnabled",
        "requestIsDemoModeEnabled", "requestIsEmergencyModeEnabled", "requestIsSatelliteSupported", "requestSatelliteCapabilities",
        "startSatelliteTransmissionUpdates", "stopSatelliteTransmissionUpdates", "provisionSatelliteService", "deprovisionSatelliteService",
        "registerForSatelliteProvisionStateChanged", "unregisterForSatelliteProvisionStateChanged", "requestIsSatelliteProvisioned", "registerForSatelliteModemStateChanged",
        "unregisterForModemStateChanged", "registerForIncomingDatagram", "unregisterForIncomingDatagram", "pollPendingDatagrams",
        "sendDatagram", "getSatelliteDisallowedReasons", "registerForSatelliteDisallowedReasonsChanged", "unregisterForSatelliteDisallowedReasonsChanged",
        "requestIsCommunicationAllowedForCurrentLocation", "requestSatelliteAccessConfigurationForCurrentLocation", "requestTimeForNextSatelliteVisibility", "requestSelectedNbIotSatelliteSubscriptionId",
        "registerForSelectedNbIotSatelliteSubscriptionChanged", "unregisterForSelectedNbIotSatelliteSubscriptionChanged", "setDeviceAlignedWithSatellite", "setSatelliteServicePackageName",
        "setSatelliteGatewayServicePackageName", "setSatelliteListeningTimeoutDuration", "setSatelliteIgnoreCellularServiceState", "setSupportDisableSatelliteWhileEnableInProgress",
        "setSatellitePointingUiClassName", "setDatagramControllerTimeoutDuration", "setSatelliteControllerTimeoutDuration", "setEmergencyCallToSatelliteHandoverType",
        "setCountryCodes", "setSatelliteAccessControlOverlayConfigs", "setSatelliteAccessAllowedForSubscriptions", "setTnScanningSupport",
        "setOemEnabledSatelliteProvisionStatus", "overrideConfigDataVersion", "getShaIdFromAllowList", "addAttachRestrictionForCarrier",
        "removeAttachRestrictionForCarrier", "getAttachRestrictionReasonsForCarrier", "requestNtnSignalStrength", "registerForNtnSignalStrengthChanged",
        "unregisterForNtnSignalStrengthChanged", "registerForCapabilitiesChanged", "unregisterForCapabilitiesChanged", "setShouldSendDatagramToModemInDemoMode",
        "setDomainSelectionServiceOverride", "clearDomainSelectionServiceOverride", "isAospDomainSelectionService", "setEnableCellularIdentifierDisclosureNotifications",
        "isCellularIdentifierDisclosureNotificationsEnabled", "setNullCipherNotificationsEnabled", "isNullCipherNotificationsEnabled", "getSatellitePlmnsForCarrier",
        "registerForSatelliteSupportedStateChanged", "unregisterForSatelliteSupportedStateChanged", "registerForCommunicationAccessStateChanged", "unregisterForCommunicationAccessStateChanged",
        "setDatagramControllerBooleanConfig", "setIsSatelliteCommunicationAllowedForCurrentLocationCache", "requestSatelliteSessionStats", "requestSatelliteSubscriberProvisionStatus",
        "requestSatelliteDisplayName", "provisionSatellite", "setSatelliteSubscriberIdListChangedIntentComponent", "setTestEuiccUiComponent",
        "getTestEuiccUiComponent", "overrideCarrierRoamingNtnEligibilityChanged", "deprovisionSatellite", "setNtnSmsSupported",
        "getCarrierIdFromIdentifier", "getSatelliteDataOptimizedApps", "getSatelliteDataSupportMode", "setSatelliteIgnorePlmnListFromStorage",
    ]),
    ("com.android.internal.telephony.ITelephonyRegistry", &[
        "addOnSubscriptionsChangedListener", "addOnOpportunisticSubscriptionsChangedListener", "removeOnSubscriptionsChangedListener", "listenWithEventList",
        "notifyCallStateForAllSubs", "notifyCallState", "notifyServiceStateForPhoneId", "notifySignalStrengthForPhoneId",
        "notifyMessageWaitingChangedForPhoneId", "notifyCallForwardingChanged", "notifyCallForwardingChangedForSubscriber", "notifyDataActivityForSubscriber",
        "notifyDataActivityForSubscriberWithSlot", "notifyDataConnectionForSubscriber", "notifyCellLocationForSubscriber", "notifyCellInfo",
        "notifyPreciseCallState", "notifyDisconnectCause", "notifyCellInfoForSubscriber", "notifySrvccStateChanged",
        "notifySimActivationStateChangedForPhoneId", "notifyOemHookRawEventForSubscriber", "notifySubscriptionInfoChanged", "notifyOpportunisticSubscriptionInfoChanged",
        "notifyCarrierNetworkChange", "notifyCarrierNetworkChangeWithSubId", "notifyUserMobileDataStateChangedForPhoneId", "notifyDisplayInfoChanged",
        "notifyPhoneCapabilityChanged", "notifyActiveDataSubIdChanged", "notifyRadioPowerStateChanged", "notifyEmergencyNumberList",
        "notifyOutgoingEmergencyCall", "notifyOutgoingEmergencySms", "notifyCallQualityChanged", "notifyMediaQualityStatusChanged",
        "notifyImsDisconnectCause", "notifyRegistrationFailed", "notifyBarringInfoChanged", "notifyPhysicalChannelConfigForSubscriber",
        "notifyDataEnabled", "notifyAllowedNetworkTypesChanged", "notifyLinkCapacityEstimateChanged", "notifySimultaneousCellularCallingSubscriptionsChanged",
        "addCarrierPrivilegesCallback", "removeCarrierPrivilegesCallback", "notifyCarrierPrivilegesChanged", "notifyCarrierServiceChanged",
        "addCarrierConfigChangeListener", "removeCarrierConfigChangeListener", "notifyCarrierConfigChanged", "notifyCallbackModeStarted",
        "notifyCallbackModeRestarted", "notifyCallbackModeStopped", "notifyCarrierRoamingNtnModeChanged", "notifyCarrierRoamingNtnEligibleStateChanged",
        "notifyCarrierRoamingNtnAvailableServicesChanged", "notifyCarrierRoamingNtnSignalStrengthChanged", "addSatelliteStateChangeListener", "removeSatelliteStateChangeListener",
        "notifySatelliteStateChanged", "notifySecurityAlgorithmsChanged", "notifyCellularIdentifierDisclosedChanged",
    ]),
    ("com.android.internal.telephony.ITransportSelectorCallback", &[
        "onCreated", "onWlanSelected", "onWwanSelectedAsync", "onSelectionTerminated",
    ]),
    ("com.android.internal.telephony.ITransportSelectorResultCallback", &[
        "onCompleted",
    ]),
    ("com.android.internal.telephony.IUpdateAvailableNetworksCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.IVoidConsumer", &[
        "accept",
    ]),
    ("com.android.internal.telephony.IWapPushManager", &[
        "processMessage", "addPackage", "updatePackage", "deletePackage",
    ]),
    ("com.android.internal.telephony.IWwanSelectorCallback", &[
        "onRequestEmergencyNetworkScan", "onDomainSelected", "onCancel",
    ]),
    ("com.android.internal.telephony.IWwanSelectorResultCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IAuthenticateServerCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.ICancelSessionCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IDeleteProfileCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IDisableProfileCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IEuiccCardController", &[
        "getAllProfiles", "getProfile", "getEnabledProfile", "disableProfile",
        "switchToProfile", "setNickname", "deleteProfile", "resetMemory",
        "getDefaultSmdpAddress", "getSmdsAddress", "setDefaultSmdpAddress", "getRulesAuthTable",
        "getEuiccChallenge", "getEuiccInfo1", "getEuiccInfo2", "authenticateServer",
        "prepareDownload", "loadBoundProfilePackage", "cancelSession", "listNotifications",
        "retrieveNotificationList", "retrieveNotification", "removeNotificationFromList",
    ]),
    ("com.android.internal.telephony.euicc.IEuiccController", &[
        "continueOperation", "getDownloadableSubscriptionMetadata", "getDefaultDownloadableSubscriptionList", "getEid",
        "getOtaStatus", "downloadSubscription", "getEuiccInfo", "deleteSubscription",
        "switchToSubscription", "switchToSubscriptionWithPort", "updateSubscriptionNickname", "eraseSubscriptions",
        "eraseSubscriptionsWithOptions", "retainSubscriptionsForFactoryReset", "setSupportedCountries", "getSupportedCountries",
        "isSupportedCountry", "isSimPortAvailable", "hasCarrierPrivilegesForPackageOnAnyPhone", "isCompatChangeEnabled",
        "setPsimConversionSupportedCarriers", "isPsimConversionSupported", "getAvailableMemoryInBytes",
    ]),
    ("com.android.internal.telephony.euicc.IGetAllProfilesCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IGetDefaultSmdpAddressCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IGetEuiccChallengeCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IGetEuiccInfo1Callback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IGetEuiccInfo2Callback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IGetProfileCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IGetRulesAuthTableCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IGetSmdsAddressCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IListNotificationsCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.ILoadBoundProfilePackageCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IPrepareDownloadCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IRemoveNotificationFromListCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IResetMemoryCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IRetrieveNotificationCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.IRetrieveNotificationListCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.ISetDefaultSmdpAddressCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.ISetNicknameCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.telephony.euicc.ISwitchToProfileCallback", &[
        "onComplete",
    ]),
    ("com.android.internal.textservice.ISpellCheckerService", &[
        "getISpellCheckerSession",
    ]),
    ("com.android.internal.textservice.ISpellCheckerServiceCallback", &[
        "onSessionCreated",
    ]),
    ("com.android.internal.textservice.ISpellCheckerSession", &[
        "onGetSuggestionsMultiple", "onGetSentenceSuggestionsMultiple", "onCancel", "onClose",
    ]),
    ("com.android.internal.textservice.ISpellCheckerSessionListener", &[
        "onGetSuggestions", "onGetSentenceSuggestions",
    ]),
    ("com.android.internal.textservice.ITextServicesManager", &[
        "getCurrentSpellChecker", "getCurrentSpellCheckerSubtype", "getSpellCheckerService", "finishSpellCheckerService",
        "isSpellCheckerEnabled", "getEnabledSpellCheckers",
    ]),
    ("com.android.internal.textservice.ITextServicesSessionListener", &[
        "onServiceConnected",
    ]),
    ("com.android.internal.util.FrameworkStatsLog", &[
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "",
        "", "", "", "appProcessDiedSubReasonSubreasonFreezerBinder",
    ]),
    ("com.android.internal.view.IDragAndDropPermissions", &[
        "take", "takeTransient", "release",
    ]),
    ("com.android.internal.view.IInputMethodManager", &[
        "addClient", "getCurrentInputMethodInfoAsUser", "getInputMethodList", "getEnabledInputMethodList",
        "getInputMethodListLegacy", "getEnabledInputMethodListLegacy", "getEnabledInputMethodSubtypeList", "getLastInputMethodSubtype",
        "showSoftInput", "hideSoftInput", "hideSoftInputFromServerForTest", "startInputOrWindowGainedFocus",
        "startInputOrWindowGainedFocusAsync", "showInputMethodPickerFromClient", "showInputMethodPickerFromSystem", "isInputMethodPickerShownForTest",
        "onImeSwitchButtonClickFromSystem", "shouldShowImeSwitcherButtonForTest", "getCurrentInputMethodSubtype", "setAdditionalInputMethodSubtypes",
        "setExplicitlyEnabledInputMethodSubtypes", "getInputMethodWindowVisibleHeight", "reportPerceptibleAsync", "removeImeSurface",
        "removeImeSurfaceFromWindowAsync", "startProtoDump", "isImeTraceEnabled", "startImeTrace",
        "stopImeTrace", "startStylusHandwriting", "startConnectionlessStylusHandwriting", "prepareStylusHandwritingDelegation",
        "acceptStylusHandwritingDelegation", "acceptStylusHandwritingDelegationAsync", "isStylusHandwritingAvailableAsUser", "addVirtualStylusIdForTestSession",
        "setStylusWindowIdleTimeoutForTest", "getImeTrackerService",
    ]),
    ("com.android.internal.view.inline.IInlineContentCallback", &[
        "onContent", "onClick", "onLongClick",
    ]),
    ("com.android.internal.view.inline.IInlineContentProvider", &[
        "provideContent", "requestSurfacePackage", "onSurfacePackageReleased",
    ]),
    ("com.android.internal.widget.ICheckCredentialProgressCallback", &[
        "onCredentialVerified",
    ]),
    ("com.android.internal.widget.ILockSettings", &[
        "setBoolean", "setLong", "setString", "getBoolean",
        "getLong", "getString", "setLockCredential", "resetKeyStore",
        "checkCredential", "verifyCredential", "verifyTiedProfileChallenge", "verifyGatekeeperPasswordHandle",
        "removeGatekeeperPasswordHandle", "getCredentialType", "getPinLength", "refreshStoredPinLength",
        "getHashFactor", "setSeparateProfileChallengeEnabled", "getSeparateProfileChallengeEnabled", "registerStrongAuthTracker",
        "unregisterStrongAuthTracker", "requireStrongAuth", "reportSuccessfulBiometricUnlock", "scheduleNonStrongBiometricIdleTimeout",
        "systemReady", "userPresent", "getStrongAuthForUser", "hasPendingEscrowToken",
        "initRecoveryServiceWithSigFile", "getKeyChainSnapshot", "generateKey", "generateKeyWithMetadata",
        "importKey", "importKeyWithMetadata", "getKey", "removeKey",
        "setSnapshotCreatedPendingIntent", "setServerParams", "setRecoveryStatus", "getRecoveryStatus",
        "setRecoverySecretTypes", "getRecoverySecretTypes", "startRecoverySessionWithCertPath", "recoverKeyChainSnapshot",
        "closeSession", "startRemoteLockscreenValidation", "validateRemoteLockscreen", "hasSecureLockScreen",
        "tryUnlockWithCachedUnifiedChallenge", "removeCachedUnifiedChallenge", "registerWeakEscrowTokenRemovedListener", "unregisterWeakEscrowTokenRemovedListener",
        "addWeakEscrowToken", "removeWeakEscrowToken", "isWeakEscrowTokenActive", "isWeakEscrowTokenValid",
        "unlockUserKeyIfUnsecured", "writeRepairModeCredential",
    ]),
    ("com.android.internal.widget.IRemoteViewsFactory", &[
        "onDataSetChanged", "onDataSetChangedAsync", "onDestroy", "getCount",
        "getViewAt", "getLoadingView", "getViewTypeCount", "getItemId",
        "hasStableIds", "isCreated", "getRemoteCollectionItems",
    ]),
    ("com.android.internal.widget.IWeakEscrowTokenActivatedListener", &[
        "onWeakEscrowTokenActivated",
    ]),
    ("com.android.internal.widget.IWeakEscrowTokenRemovedListener", &[
        "onWeakEscrowTokenRemoved",
    ]),
    ("com.android.media.permission.INativePermissionController", &[
        "populatePackagesForUids", "updatePackagesForUid", "populatePermissionState",
    ]),
    ("com.android.net.IProxyCallback", &[
        "getProxyPort",
    ]),
    ("com.android.net.IProxyPortListener", &[
        "setProxyPort",
    ]),
    ("com.android.net.IProxyService", &[
        "resolvePacFile", "setPacFile",
    ]),
];

#[cfg(test)]
mod tests {
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
}
