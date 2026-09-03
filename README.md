KernSight

KernSight 是 Android 设备的内核观测项目。
基于 eBPF 采集进程、文件、内存映射、网络、Binder 和调度事实，由设备端 `ksightd` 归一化并持久化，
再通过 `ksightctl` 完成控制、回放、聚合。

开发基线是 Pixel 6a、Android 16 (SDK 36) 、arm64-v8a。

## 测试应用
- 测试应用，网上国网，大陆四大行，同花顺，平安证劵，政务相关，花旗银行，汇丰US均可获取可加密dex/so，明文信息等
- （金融类）中行部分数据图：
  <img width="895" height="924" alt="image" src="https://github.com/user-attachments/assets/dc43f886-f795-4f9d-923f-8f525fe2066a" />
- 爱存不存部分数据图：
  <img width="926" height="920" alt="image" src="https://github.com/user-attachments/assets/7dcbc276-7707-45d6-9ecb-f83848b04cba" />
- （政务类）随申办部分数据图：
  <img width="926" height="923" alt="image" src="https://github.com/user-attachments/assets/c65cb4e4-b20c-4e11-b3c9-f44d0d8f2e03" />
- 爱国网，爱国当前版本比较特殊，挂载的是arch32架构，uprobe没有等价内核钩子，需要换安装包，重新适配
  <img width="927" height="803" alt="image" src="https://github.com/user-attachments/assets/df0712bb-51a6-4eee-a746-bde1486362f6" />

- 当前仅为通用规则，针对某个App需要做深入优化和重新分析，binder对其，kprobe和uprobe等

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
- 测试环境：6.1.124-android14，其他 Android/内核版本必须重新执行能力探测

KernSight 目前部署到 `/data/local/tmp/ksight`。AOSP init、独立 SELinux 域、AVB 签名及锁定自定义信任根仍属于后续系统集成工作。

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
它是单文件设备发行版：7 个 eBPF 对象、默认服务配置、hide-debug 辅助脚本以及原生框架
规则均编译在 `ksightd` 内。第一次执行采集、Dump 或服务命令时，程序会自动在
`/data/local/tmp/ksight` 安装并校验内部运行资源；用户不需要逐个复制这些文件。

### 只使用一个设备端二进制

从 GitHub Release 下载 `ksightd-android-arm64`，或使用上面的 `make device` 自行编译。
电脑到手机只需执行一次 push：

```bash
adb push ksightd-android-arm64 /data/local/tmp/ksightd
adb shell su -c 'chmod 0755 /data/local/tmp/ksightd'
```

随后可以直接探测和采集，不依赖 PC 端 `ksightctl`：

```bash
adb shell su -c '/data/local/tmp/ksightd probe --json'
adb shell su -c '/data/local/tmp/ksightd capture --all \
  --duration-seconds 30 \
  --spool-dir /data/local/tmp/ksight/spool \
  --json'
```

按包采集：

```bash
adb shell su -c '/data/local/tmp/ksightd capture \
  --package com.example.app \
  --files --network --memory --binder \
  --duration-seconds 45 \
  --spool-dir /data/local/tmp/ksight/spool \
  --json'
```

这里的“单文件”是指安装和分发只需要 `ksightd`。eBPF 加载器仍需要把内嵌对象释放到
设备私有运行目录，这是程序自动且带内容校验完成的，不需要用户手工管理。

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

已编译 release 版本，选择android版本即可。

推送文件：
```bash
adb push ~/../ksightd-android-arm64 /data/local/tmp/ksightd
adb shell su -c 'chmod 0755 /data/local/tmp/ksightd'
```
能力检测：
```bash
adb shell su -c '/data/local/tmp/ksightd probe --json'
```
全设备采集：
```bash
adb shell su -c '/data/local/tmp/ksightd capture \
  --all \
  --duration-seconds 30 \
  --spool-dir /data/local/tmp/ksight/spool \
  --json'
```
指定应用采集：
```bash
adb shell su -c '/data/local/tmp/ksightd capture \
  --package com.example.app \
  --files --network --memory --binder \
  --duration-seconds 60 \
  --spool-dir /data/local/tmp/ksight/spool \
  --json'
```
查看 Session：
```bash
adb shell su -c '/data/local/tmp/ksightd spool replay <SESSION_UUID>'
```
回放指定 Session：
```bash
adb shell su -c '/data/local/tmp/ksightd spool replay <SESSION_UUID>'
```
采集某个包的 L2 证据：
```bash
adb shell su -c '/data/local/tmp/ksightd dump-package \
  --package com.example.app \
  --dest /data/local/tmp/ksight/packages/com.example.app \
  --launch \
  --json'
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

## 以下针对开发环境
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
# apps that check USB debugging:
cargo run -q -p ksight-cli -- device --serial "$SERIAL" pull-package \
  --package com.example.app --launch --hide-debug
# apps that check root, Magisk present:
cargo run -q -p ksight-cli -- device --serial "$SERIAL" pull-package \
  --package com.example.app --launch --denylist
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

本项目仅用于学习目的。目前不做隐形运行，也不提供通用的 root 隐藏、应用完整性绕过或反检测保证。
应用仍可能观察到 bootloader、root、调试设置、内核差异、探针状态或时序变化。

默认全局 Observe 和选定进程 Inspect 应保持分离。明文、密钥候选、内存快照等敏感证据需要限制目标、时间和大小，并由操作者负责保存、访问控制和清理。

## License

Apache-2.0
