# KernSight

KernSight 是一个面向自有或明确授权 Android 设备的内核可观测项目。
基于 eBPF 采集进程、文件、内存映射、网络、Binder 和调度事实，由设备端 `ksightd` 归一化并持久化，
再通过 `ksightctl` 或 MobileE 完成控制、回放、聚合和可视化。

当前版本为 **0.2.1**，主要开发基线是 Pixel 6a、Android 14、ARM64。项目仍处于实验
阶段，不应被视为通用的生产级 Android 监控组件。
持续开发ing....

## 测试应用
- 测试应用，网上国网，大陆四大行，同花顺，平安证劵，政务相关，花旗银行，汇丰US均可获取可观测dex/so

## 组件

- `ksightd`：运行在 Android 设备上的采集代理。
- `ksightctl`：运行在 PC 上的命令行客户端。
- `ksight-core`：报告、关联图、DEX 聚合和 SO 规则识别。
- `ksight-protocol`：MobileE 与设备端共享的版本化通信协议。
- `bpf/`：按传感器拆分的 eBPF 程序。
- `rules/native_frameworks.json`：壳、加固及密码框架候选规则库。

## 编译环境

### PC 端

推荐使用 macOS（Apple Silicon）或 Linux x86_64/ARM64：

- Git、Make
- Rust stable，最低支持版本 `1.85`
- `rustfmt`、`clippy`
- LLVM/Clang，且 Clang 必须支持 `-target bpfel`
- Android Platform Tools（`adb`）

macOS 使用 Homebrew 时可以安装：

```bash
brew install rustup-init llvm android-platform-tools make
rustup-init
rustup component add rustfmt clippy
```

Makefile 会优先使用 `/opt/homebrew/opt/llvm/bin/clang`。也可以显式指定：

```bash
make bpf BPF_CLANG=/absolute/path/to/clang
```

### Android 设备端

当前设备构建目标为 `aarch64-unknown-linux-musl`，要求：

- ARM64 Android 设备
- 已开启 USB 调试并被当前 PC 授权
- 具备管理员控制权；当前部署流程需要 `su`
- 内核支持 eBPF、BTF、tracefs、ring buffer 及所用 tracepoint
- Pixel 6a 是已验证基线；其他 Android/内核版本必须重新执行能力探测

KernSight 目前部署到 `/data/local/tmp/ksight`。AOSP init、独立 SELinux 域、AVB 签名
及锁定自定义信任根仍属于后续系统集成工作。

## 获取源码

```bash
git clone https://github.com/swyiic/KernSight.git
cd KernSight
```

## 检查与测试

```bash
cargo check --workspace --all-targets
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo run -p xtask -- architecture
```

也可以使用 `make check`、`make test`、`make fmt`、`make lint` 和 `make architecture`。

## 编译

### PC 端 CLI

```bash
cargo build --release -p ksight-cli
```

产物为 `target/release/ksightctl`。开发时可以直接运行：

```bash
cargo run -q -p ksight-cli -- capabilities
```

### eBPF 对象

```bash
make bpf
```

对象生成在 `build/bpf/`，包括进程、文件、网络、内存、Binder、调度和 uprobe 传感器。
这些是生成物，不应提交到 Git。

### Android 设备端代理

```bash
make device-target
make device
```

设备端二进制为 `target/aarch64-unknown-linux-musl/release/ksightd`。

### 一步编译并部署

先确认设备：

```bash
adb devices -l
```

只有一台设备时：

```bash
make deploy
```

有多台设备时限定序列号：

```bash
make deploy ADB="adb -s <serial>"
```

部署后执行只读能力探测：

```bash
make probe ADB="adb -s <serial>"
```

部署会更新 `/data/local/tmp/ksight`，需要设备端 `su` 授权。

## 基本用法

以下示例使用 Cargo 启动 CLI。若已编译 release 版本，可将
`cargo run -q -p ksight-cli --` 替换为 `target/release/ksightctl`。

```bash
SERIAL=<adb-serial>
```

### 查看能力

```bash
cargo run -q -p ksight-cli -- capabilities
cargo run -q -p ksight-cli -- keypoints
cargo run -q -p ksight-cli -- device --serial "$SERIAL" probe
```

`keypoints` 只列出经过审查的 ART、JNI、linker、Binder、TLS 和 QUIC 适配点，不会自动
启用探针。

### 全设备短时采集

```bash
cargo run -q -p ksight-cli -- device --serial "$SERIAL" capture \
  --all --duration-seconds 30 --spool
```

全设备模式适合建立 L0 内核事实基线。调度和高频网络 I/O 会产生较大事件量，建议先用
短时会话并观察丢失统计。

### 按包名采集

```bash
cargo run -q -p ksight-cli -- device --serial "$SERIAL" capture \
  --package com.example.app \
  --files --network --binder --memory \
  --duration-seconds 45 --spool
```

显式检查 TLS 边界属于可见性更高的 Inspect 操作，只应在授权测试中短时启用：

```bash
cargo run -q -p ksight-cli -- device --serial "$SERIAL" capture \
  --package com.example.app --inspect-tls \
  --duration-seconds 30 --spool
```

### 查看和解析会话

```bash
cargo run -q -p ksight-cli -- device --serial "$SERIAL" sessions
cargo run -q -p ksight-cli -- device --serial "$SERIAL" report <session-uuid>
cargo run -q -p ksight-cli -- device --serial "$SERIAL" report <session-uuid> --json
cargo run -q -p ksight-cli -- device --serial "$SERIAL" replay <session-uuid> --after 0
```

- `report`：面向人的确定性聚合报告。
- `report --json`：供 MobileE 或其他工具解析。
- `replay`：按批次查看原始事件证据。
- 读取报告不会自动确认或删除设备端批次。

### 拉取应用产物

```bash
cargo run -q -p ksight-cli -- device --serial "$SERIAL" pull-package \
  --package com.example.app
```

该流程编目 APK DEX、内存 DEX、Native SO、明文片段和 key candidate，并生成
`mobilee.kernsight-package-dump/v2` 报告。同内容 DEX 按 SHA-256 聚合为逻辑 DEX Set，
但原始文件和 PID、VMA、路径来源会被保留。

重新编目或显式清理某个包：

```bash
cargo run -q -p ksight-cli -- device --serial "$SERIAL" recatalog-package \
  --package com.example.app
cargo run -q -p ksight-cli -- device --serial "$SERIAL" cleanup-package \
  --package com.example.app
```

清理操作会删除对应包的设备端证据，执行前应确认已经完成所需备份。

## MobileE 联动

MobileE 通过共享的 `ksight-protocol` 和 `ksight-core` 与设备通信，可完成：

- 选择设备、目标包并点击控制采集
- 展示进程、线程、文件、Socket、Binder 和内存映射统计
- 展开 DEX Set 的 SHA-256、PID、VMA 和来源文件
- 展示壳/加固及密码框架候选规则命中
- 查看原始事件、明文片段和关联图
- 将有界、结构化会话摘要交给 AI 辅助分析

MobileE 是 KernSight 的客户端；KernSight 不依赖 MobileE，也可以完全通过 CLI 使用。

## 证据边界

- `confirmed`：由稳定内核标识或经过验证的探针直接证明。
- `correlated`：具有明确关联依据，但不能证明运行时因果。
- `inferred`：规则或分析推断，必须显示置信度和依据。

SO 文件名或路径命中只能说明壳、加固或密码框架候选，不能单独证明具体版本和行为。
DEX 与 VMA 地址重叠也不能自动证明某次 mmap 导致了对应 DEX 的执行。

## 安全与适用范围

本项目仅用于自有设备、实验设备或获得明确授权的分析环境。KernSight 不承诺隐形运行，
也不提供通用的 root 隐藏、应用完整性绕过或反检测保证。应用仍可能观察到 bootloader、
root、调试设置、内核差异、探针状态或时序变化。

默认全局 Observe 和选定进程 Inspect 应保持分离。明文、密钥候选、内存快照等敏感证据
必须限制目标、时间和大小，并由操作者负责保存、访问控制和清理。

## License

Apache-2.0
