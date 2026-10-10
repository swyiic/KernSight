# KernSight

**从内核观察行为，从运行时提取证据。**

KernSight 因金融类和政务类App的高强度检测，希望减少分析工作对传统脱壳流程的依赖，产生思路：通过 eBPF 观察内核行为，结合按需启用的用户态探针和内存快照，提取有分析价值的代码、通信与运行证据。

设备端 `ksightd` 负责采集与持久化，电脑端 `ksightctl` 负责控制、回放和报告。可独立使用，也可接入 MobileE。

## 能做什么

- **观察运行行为**：进程与线程、文件访问、网络连接、内存映射、Binder 和调度唤醒
- **整理代码证据**：APK/DEX、已加载 SO 与部分运行时内存映像，保留哈希、进程和映射来源
- **按需检查语义边界**：在适配与权限满足时，采集 TLS、JNI、Linker 等边界上的有限证据
- **回放与关联**：保存会话、生成报告和关联图，区分直接证据、关联与推断

eBPF 提供内核观察；进程内存、DEX 和用户态明文由相应探针或 Dump 路径补充。实际覆盖以设备能力与本次证据报告为准。

## 下载与开始

1. 从 [Releases](https://github.com/swyiic/KernSight/releases) 下载对应文件：

| 用途 | 文件 |
| --- | --- |
| ARM64 Android 设备端 | `ksightd-android-arm64` |
| Apple Silicon 电脑端 | `kernsight-cli-macos-arm64.tar.gz` |
| 完整性校验 | `SHA256SUMS` |

2. 按[安装与能力检查](docs/usage.md#安装与能力检查)部署。需要 ARM64 Android、root 授权，以及允许 BPF/perf/tracefs 操作的内核与安全策略
3. 打开已获授权的目标应用，替换包名，开始一个短会话：

```bash
adb shell su -c '/data/local/tmp/ksight/ksightd capture \
  --package com.example.app \
  --files --network --memory --binder \
  --duration-seconds 30 \
  --spool-dir /data/local/tmp/ksight/spool --json'
```

仅用设备端也能采集；电脑端 CLI 可进一步查看会话：

```bash
ksightctl device sessions
ksightctl device report <SESSION_UUID> --json
```

| 常用参数 | 用途 |
| --- | --- |
| `--package NAME` | 限定目标包 |
| `--duration-seconds N` | 限定采集时长 |
| `--files --network --memory --binder` | 选择所需传感器 |
| `--spool-dir PATH` | 设备端持久化目录；CLI 对应 `--spool` |
| `--json` | 结构化输出 |

更多参数、Dump、Inspect、回放及清理见[使用指南](docs/usage.md)。编译、部署和构建身份见[开发指南](docs/development.md)。

## 历史验证记录

以下来自公开仓库中的基线记录，均有范围限制；本次 Actions 构建没有重新进行真机验证。

| 场景 | 已记录结果 | 边界 |
| --- | --- | --- |
| Pixel 6a 设备运行 | [v0.2.12 发布说明](https://github.com/swyiic/KernSight/releases/tag/v0.2.12)记录了实际使用的代理与内核 | 历史二进制，仍在开发中 |
| FD 生命周期与 Binder FD 传递 | [能力记录](crates/ksight-core/src/capability.rs)记载 clone/close_range，以及 system_server → Settings 的带来源 FD 传递 | 该能力仍为 partial，io_uring 等路径不完整，加载某些App瞬时内存超过写入速度会造成内存丢样等，持续优化中 |
| Binder 接口名称关联 | 同一[能力记录](crates/ksight-core/src/capability.rs)记载 Pixel 6a 的一次 8 秒窗口中约 97% 获得名称 | 单次历史窗口，不能推广为整体覆盖率 |

## 内核兼容性

历史记录的完整内核为 `6.1.124-android14-11-g061a6a266b80c-ab10015560-4k`，设备为 Pixel 6a；当时 BTF 不可用。

普通 tracepoint 采集和依赖 BTF 的 qualified code 后端有不同要求。其他 6.1 构建及 5.10、5.15、6.6 等版本均需逐设备验证，不能只按版本号判断支持。详见[内核要求与验证范围](docs/usage.md#内核要求与验证范围)。

## 使用边界

Inspect 和 Dump 可能影响目标执行；明文、内存和私有数据应限定范围并妥善保管。当前阶段不做隐形运行、通用 root 隐藏或反检测。报告中的 partial、丢样和未知覆盖会保留进行分析完善。

[Apache-2.0](LICENSE)
