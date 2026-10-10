# 使用指南

[返回项目首页](../README.md) · [开发与构建](development.md)

本指南区分设备端 `ksightd` 与电脑端 `ksightctl`。以下参数已按源码接口核对；命令存在不代表目标内核、应用或后端一定支持。先检查能力，再用短会话验证实际事件。

## 安装与能力检查

1. 下载适合设备/电脑架构的发布文件；CLI 压缩包内的可执行文件名为 `ksightctl`
2. 用发布页的 `SHA256SUMS` 核对对应下载文件；下载全部四个文件时可运行 `sha256sum -c SHA256SUMS`，macOS 使用 `shasum -a 256 -c SHA256SUMS`
3. 确认 ADB 已授权、设备具备 `su`，部署到 CLI 使用的固定路径

```bash
adb devices -l
adb push ksightd-android-arm64 /data/local/tmp/ksightd
adb shell su -c 'mkdir -p /data/local/tmp/ksight && cp /data/local/tmp/ksightd /data/local/tmp/ksight/ksightd && chmod 0755 /data/local/tmp/ksight/ksightd'
adb shell su -c '/data/local/tmp/ksight/ksightd --version'
adb shell su -c '/data/local/tmp/ksight/ksightd probe --json'
adb shell su -c '/data/local/tmp/ksight/ksightd code-capabilities'
```

多设备时为每条 ADB 命令增加 `-s <SERIAL>`；CLI 使用 `ksightctl device --serial <SERIAL> <子命令>`。

- `probe`：只读检查 root、内核版本、BTF、挂载点与部分 tracepoint；不执行挂载验证
- `code-capabilities`：报告构建身份和 qualified code 后端能力。后端检查可能加载并验证 BPF 对象，但不为应用建立采样授权；`supported` 也不是完整会话验收
- `ksightctl capabilities --json`：显示本机构建的能力说明，不是手机探测结果
- `ksightctl keypoints --json`：列出适配点，不会启用探针

设备版内嵌 7 个普通传感器与 2 个 qualified-code BPF 对象，以及默认配置、辅助脚本等资源。采集/服务会自动释放所需资源到运行目录。单文件分发不代表所有可选功能均不需要外部依赖：原生 TLS 注入辅助程序不在当前 Release 资产内，而且当前注入恢复检查会拒绝该路径。

## 按包采集

先手动打开自有或已获授权的应用，将示例包名换成真实目标。

设备端：

```bash
adb shell su -c '/data/local/tmp/ksight/ksightd capture \
  --package com.example.app \
  --files --network --memory --binder \
  --duration-seconds 30 \
  --spool-dir /data/local/tmp/ksight/spool --json'
```

电脑端等效入口：

```bash
ksightctl device --serial <SERIAL> capture \
  --package com.example.app \
  --files --network --memory --binder \
  --duration-seconds 30 --spool --json
```

只需要进程生命周期时，可省略四个可选传感器开关。失败时查看加载/挂载错误与报告，不要把“无事件”直接理解为目标没有相关行为。

全设备短会话：

```bash
ksightctl device capture --all --duration-seconds 15 --spool --quiet
```

`--all` 打开文件、网络连接、可执行内存映射与 Binder；它不会自动打开调度、FD 细节、网络 I/O、扩展内存或 Inspect。全设备数据量更大，优先按包测试。

### 常用 capture 参数

下表适用于两个入口，特别标明的参数除外。布尔开关默认关闭。

| 参数 | 含义 / 默认值 |
| --- | --- |
| `--package NAME` | 精确包名，包含其冒号子进程 |
| `--pid N` / `--uid N` | 按进程组 ID / UID 限定范围 |
| `--duration-seconds N` | 采集时长；默认 0，不设时长上限 |
| `--count N` | 实时内核事件上限；默认 0，不限制；基线记录不计入 |
| `--files` | 文件打开事件 |
| `--files-fd` | 增加 dup/close/fcntl 等 FD 细节；建议与 `--files` 配合，可能产生大量事件 |
| `--network` | 网络连接与已有实现覆盖的握手元数据 |
| `--network-io` | Socket 收发字节数，不代表读取完整载荷；会启用网络 I/O 模式 |
| `--memory` | 可执行内存映射变化 |
| `--memory-all` | 扩大映射事件范围，仍有内核侧大小过滤；不是复制全部内存 |
| `--binder` | Binder 内核事务事实 |
| `--sched` | 调度唤醒；要求 `--package`、`--pid` 或 `--uid` |
| `--all` | 文件、网络连接、可执行映射和 Binder 的常规组合 |
| `--include-threads` | 输出独立线程生命周期与改名事件 |
| `--sample-one-in N` | 可选传感器每 N 个合格事件取一个；默认 1，必须大于 0 |
| `--json` | 按行输出 JSON 事件 |
| `--quiet` | 不逐条打印，只保留采集/持久化摘要 |
| `--spool-dir PATH` | 设备端参数：持久化目录；省略则不指定持久化目录 |
| `--spool` | CLI 参数：使用设备端固定目录 `/data/local/tmp/ksight/spool` |
| `--spool-max-mib N` | 完整事件批次的保留容量，默认 64 MiB |
| `--batch-events N` | 每批事件数，默认 64；CLI 验证范围 1–1024 |
| `--forensics-dir PATH` | CLI 参数：采集后的取证文件下载目录，默认 `forensics` |
| `--no-pull-forensics` | CLI 参数：不自动下载取证文件 |
| `--hide-debug` | CLI 参数：临时改变调试设置并在结束后恢复；可能断开 ADB，不用于普通起步流程 |

采集时长不等于命令总耗时，初始化、收尾排空和文件传输还需要时间。应同时检查丢样、预算、partial 和终态记录。

## 按需 Inspect

Inspect 针对用户态边界，可能改变时序或触发目标检测。仅在明确范围内短时启用：

```bash
ksightctl device capture --package com.example.app \
  --network --inspect-tls --duration-seconds 15 --spool

ksightctl device capture --package com.example.app \
  --inspect-adapter binder_userspace --duration-seconds 15 --spool

ksightctl device capture --package com.example.app \
  --inspect-linker --duration-seconds 15 --spool
```

| 参数 | 含义 / 默认值 |
| --- | --- |
| `--inspect-tls` | 启用已适配 TLS 边界；依赖目标库、导出符号与 ABI |
| `--inspect-jni` | 启用已适配 JNI UTF-8 / byte-array 边界 |
| `--inspect-linker` | 启用 Linker SO 加载适配器 |
| `--inspect-adapter NAME` | 指定命名适配器，例如 `binder_userspace`、`jni_plaintext` |
| `--inspect-max-bytes N` | 每次命中载荷预算，默认 65536；硬上限 256 KiB，具体适配器可能更小 |
| `--inspect-max-hits N` | 命中上限；默认 0，采用适配器默认值 |
| `--inspect-max-secs N` | Inspect 时长上限；默认 0，跟随已设置的采集时长 |
| `--inspect-build-id ID` | 指定应匹配的 GNU build-id |
| `--inspect-elf PATH` / `--inspect-offset N` | 指定已核对的 ELF 与文件偏移，不应猜测 |
| `--inspect-all-apps` | 显式全应用 Inspect；数据量和影响较大，优先避免 |

通常必须同时指定 `--package`、`--pid` 或 `--uid`。`--inspect-linker` 不能与 TLS、JNI 或非 Linker 适配器组合。TLS 与 JNI/Binder 的接口允许组合，但实际覆盖和吞吐必须单独验收。

仅设备端支持 `--inspect-stages l0:SECONDS,l1:SECONDS,linker:SECONDS`。它需要包名或 PID、明确阶段时长；不能配合 `--count`、旧式 Inspect 选择参数或镜像参数使用。若同时传 `--duration-seconds`，其值必须为 0 或阶段总和。该参数未暴露在当前 `ksightctl device capture` 中。

### 当前不可承诺的路径

- `--mirror-http`（别名 `--mirror-burp`）虽保留参数，当前 strict mirror 后端会主动拒绝，不提供可用示例
- `--mitm-burp` 与原生 TLS 注入当前被恢复安全检查拒绝
- TLS/QUIC/Flutter/WebView/自定义加密栈不具备通用明文覆盖；支持的边界也不等于捕获全部请求
- 当前代码中的部分静态能力说明保留了历史功能描述，执行时的后端拒绝与会话证据优先

## 提取应用产物

独立 Dump 会复制目标的代码与运行时证据；`--launch` 会 force-stop 后重新启动应用，可能影响当前状态。先确认允许该操作。

设备端：

```bash
adb shell su -c '/data/local/tmp/ksight/ksightd dump-package \
  --package com.example.app \
  --dest /data/local/tmp/ksight/packages/com.example.app \
  --launch --json'
```

电脑端：

```bash
ksightctl device pull-package --package com.example.app --dest packages --launch
```

| 参数 | 设备端 dump-package | CLI pull-package |
| --- | --- | --- |
| `--package NAME` | 必填精确包名 | 相同 |
| `--dest PATH` | 必填，设备目录 | 电脑目录，默认 `packages`；结果写入其包名子目录 |
| `--launch` | 停止并重启后提取 | 相同 |
| `--runtime-only` / `--evidence-only` | 跳过安装 APK/lib/oat 的常规复制 | 相同 |
| `--json` | 输出完整 Dump 报告 | 无此参数 |
| `--hide-debug` | 配合包装流程等待调试设置切换 | 负责包装流程；会临时改变调试设置 |
| `--denylist` | 有 Magisk 时临时使用 DenyList | 相同；不保证隐藏 root/bootloader |
| `--hide-debug-secs N` | 无此参数 | 恢复看门狗时间；launch 时默认 120 秒，否则 60 秒 |

CLI `pull-package` 会先清理该包固定设备输出目录，再生成新结果，并执行保留策略。重要证据请先备份；需要保留多次设备端样本时，直接为 `ksightd dump-package --dest` 指定不同目录。

输出以 `dump-report.json` 为准。常见目录包括 `readable-dex`、`apk-dex`、`runtime` 和 SO 目录；具体是否存在取决于本次实际结果。带来源的 DEX/SO、哈希和映射关联有助于分析，不代表完整还原原始 APK 或证明某段代码执行过。

设备端另有 `--collect-keys`、`--collect-private`、`--collect-memory-windows` 等高敏感附加选项，默认关闭。仅在明确获授权且后端允许时使用；不要把代码提取当成默认复制全部私有数据的授权。

### 代码专用与预算

设备端 capture/dump-package 支持 `--code-only`。该路径要求 ARM64、可用内核 BTF 与实际通过的 qualified 后端，并非普通模式的兼容开关。

设备端两条命令均接受成对参数：

- `--output-budget-bytes N`：输出写入额度
- `--output-budget-ms N`：时间预算

必须一起提供；预算耗尽可能留下 partial 结果。父子阶段编排还涉及 `--parent-session`、`--stage-id`、`--attempt-id`、`--stage-attempt`、`--stage-key` 等成套身份参数。它们由集成方管理，不应手工伪造；隔离运行目录也有额外约束。普通入门示例不使用这些参数。

## 会话、报告与证据文件

设备端列出、回放会话：

```bash
adb shell su -c '/data/local/tmp/ksight/ksightd spool list'
adb shell su -c '/data/local/tmp/ksight/ksightd spool replay <SESSION_UUID>'
```

电脑端：

```bash
ksightctl device sessions
ksightctl device report <SESSION_UUID> --top 20
ksightctl device report <SESSION_UUID> --json
ksightctl device replay <SESSION_UUID> --after 0
ksightctl device graph <SESSION_UUID> --relation binder --limit 50 --json
ksightctl device pull-forensics <SESSION_UUID> --dest forensics
```

- `report` 支持 `--after`、`--top`（默认 10）、`--json`
- `replay` 支持 `--after`，只返回严格晚于该批次序号的数据
- `graph` 支持 `--after`、`--entity`、`--relation`、`--strength`、`--limit`（默认 50）、`--json`
- `report`、`replay` 不会自动确认或删除批次
- `acknowledge <SESSION_UUID> --through N` 会释放已确认连续批次的设备存储，仅在已接收、校验和备份后使用
- `decrypt <SESSION_UUID> --out PATH` 需要该会话已有可用 pcap/keylog 及相应电脑端依赖；不要推断普通采集一定生成这些文件

### 快照与重新编目

```bash
ksightctl device snapshot --package com.example.app --max-mib 32 --dest snapshots
ksightctl device recatalog-package --package com.example.app
```

`snapshot` 默认暂停目标进程。可用 `--pid` 替代包名，`--start`（含）与 `--end`（不含）成对限定虚拟地址；`--max-mib` 默认 32，CLI 接受 1–256。`--no-pause` 不暂停进程，读取可能撕裂，报告应保留该标记。

`recatalog-package` 重新整理已有产物，不重新进行 live dump。`cleanup-package --package NAME` 会删除该包设备端受保护与发布目录中的副本，执行前备份。

## 服务模式

```bash
ksightctl device daemon start
ksightctl device daemon status
ksightctl device daemon stop
```

默认配置为 `/data/local/tmp/ksight/ksightd.json`，示例见 [ksightd.json.example](../android/config/ksightd.json.example)。设备端对应 `run`、`status`、`stop`；`run --dry-run` 校验配置，`run` 本身在前台运行。该部署方式不等于已完成 AOSP init、独立 SELinux 域或 AVB 系统集成。

## 内核要求与验证范围

### 实际要求

- ARM64 Android，具备管理员授权；安全域允许所需 BPF、perf-event、tracefs 操作
- 基础传感器需要 BPF ring-buffer map/helper、probe-read helper，以及编译时使用的 BPF v3/原子指令
- 选定 tracepoint 必须存在且记录布局兼容；调度唤醒会检查其手写布局
- Binder 和用户态 Inspect 另依赖相应 tracepoint、kprobe/uprobe/perf 支持及目标 ABI
- 普通 tracepoint 传感器不统一要求可读取内核 BTF；qualified task-bound code 后端要求匹配 BTF/CO-RE、task iterator、task storage、pidfd 和 task helper，缺少时拒绝执行

root 身份、Android 版本或单一内核版本号均不足以证明兼容。不要将 ringbuf 的存在当作整个程序的最低版本保证。

### 历史设备记录

[现有 v0.2.12 发布说明](https://github.com/swyiic/KernSight/releases/tag/v0.2.12)记录：

```text
设备：Pixel 6a / bluejay / aarch64
内核：6.1.124-android14-11-g061a6a266b80c-ab10015560-4k
构建：#1 SMP PREEMPT Sun Dec 01 08:10:00 UTC 2024
BTF：不可用
代理：0.2.12_011492a0
代理 SHA-256：10f86a3346c212abd41fcd0eb4a24c57983d7f0e0ec00577ab5ba74e4a3e7c3d
```

这是既有发布说明中的历史记录，本轮未独立重测；不证明全部传感器或 BTF 后端可用。Actions 会重新生成发布二进制，主机测试成功不能替代手机运行验证。其他设备和内核（包括其他 6.1 构建）均需重新检查：

1. 核对 `--version`、完整提交身份和运行二进制 SHA-256
2. 读取 `probe --json` / `code-capabilities`，保留不支持原因
3. 对所需传感器验证加载、挂载和真实事件输出
4. 检查丢样、partial、未知覆盖、收尾和产物完整性

## 证据解释与安全

- `confirmed`：稳定内核标识或经过验证的探针直接证明
- `correlated`：存在关联依据，未证明运行时因果
- `inferred`：规则或分析推断，需要置信度与依据

SO 名称命中仅表示框架候选；DEX 与 VMA 重叠不自动证明其由某次 mmap 产生或执行。命令完成、文件保存和哈希校验也不等于采集完整或代码已全部分析。

仅用于获授权的分析。默认观察、选定进程 Inspect 和侵入式 Dump 应按目标与风险分别启用；设置有限时长与容量。明文、密钥候选、内存及私有目录可能含敏感数据，应控制保存位置、访问与清理。调试状态、root、bootloader、内核差异、探针与时序仍可能被应用观察到。

## 接口依据

- [设备端命令与参数](../crates/ksight-agent/src/main.rs)
- [电脑端命令与参数](../crates/ksight-cli/src/main.rs)
- [设备部署、拉取与清理行为](../crates/ksight-cli/src/device.rs)
- [能力发现](../crates/ksight-agent/src/capabilities.rs)与[实际后端门禁](../crates/ksight-core/src/capture_scope.rs)
- [能力与历史基线记录](../crates/ksight-core/src/capability.rs)

完整参数也可通过 `ksightd <子命令> --help` 和 `ksightctl device <子命令> --help` 查看。
