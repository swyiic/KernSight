# 开发与构建

[返回项目首页](../README.md) · [使用指南](usage.md)

## 工具链

推荐 macOS（Apple Silicon）或 Linux x86_64/ARM64，安装 Git、Make、Rust、rustfmt、Clippy、支持 `-target bpfel` 的 LLVM/Clang，以及 Android Platform Tools（ADB）。

当前发布二进制使用 Rust 1.91.1；严格 CI 使用 stable。Cargo 清单声明的 rust-version 是 1.85，但这不是当前所有依赖与构建路径都已完成最低版本验证的结论。

macOS 可参考：

```bash
brew install rustup-init llvm android-platform-tools make
rustup-init
rustup component add rustfmt clippy
```

Makefile 优先使用 `/opt/homebrew/opt/llvm/bin/clang`，也可通过 `BPF_CLANG=/absolute/path/to/clang` 指定支持 BPF 的 Clang。

## 获取源码与检查

```bash
git clone https://github.com/swyiic/KernSight.git
cd KernSight
cargo check --workspace --all-targets
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --manifest-path vendor/aya/Cargo.toml --lib maps::perf::perf_buffer::tests
python3 scripts/test_build_identity.py
cargo run -p xtask -- architecture
```

对应快捷入口包括 `make check`、`make fmt`、`make lint`、`make test` 和 `make architecture`。这些主机检查不替代 Android 真机加载、挂载和事件验收。

## 构建

```bash
# 电脑端 CLI
cargo build --release -p ksight-cli

# eBPF 对象
make bpf

# ARM64 设备端
make device-target
make device
```

主要产物：

- `target/release/ksightctl`
- `target/aarch64-unknown-linux-musl/release/ksightd`
- `build/bpf/*.bpf.o`，包含普通传感器与 qualified-code 对象

设备端目标是 `aarch64-unknown-linux-musl`。`make device` 启用 `embedded-assets`，将 9 个 BPF 对象、默认配置和辅助脚本编入设备代理，首次需要时按内容校验释放。生成的 BPF 对象不应提交到 Git。

Makefile 还构建 `ksight-inject` 和原生 TLS 辅助库；当前 Release 只分发设备代理、三个主机 CLI 包与校验和。原生注入路径目前被恢复安全检查拒绝，不能因这些辅助文件存在就声称可用。

## 部署与能力探测

```bash
adb devices -l
make deploy ADB="adb -s <SERIAL>"
adb -s <SERIAL> shell su -c '/data/local/tmp/ksight/ksightd probe --json'
```

只有一台设备时可省略 `ADB=...`。部署会更新 `/data/local/tmp/ksight`，需要 `su` 授权。

注意：`make probe` 依赖 `deploy`，会先重新构建并部署；只想读取当前设备能力时，应直接运行上面的 `ksightd probe --json`。`ksightctl device deploy` 也会从构建时记录的源码工作区执行 Make，发布版 CLI 用户应优先采用[使用指南中的手工安装](usage.md#安装与能力检查)。

`cargo run -p ksight-cli -- ...` 只重建电脑端 CLI，不会自动更新手机上的代理。

### 构建身份

`ksightd --version` 和 `ksightctl --version` 使用 `<基础版本>_<8 位小写十六进制后缀>`，
例如 `0.2.12_011492a0`。后缀由构建脚本生成，通常读取 4 字节系统随机数；随机源不可用时
回退到构建进程 ID 的字节。它不是 Git 短提交号，也不保证全局唯一。版本信息编译在二进制中，
运行 `--version` 不需要 Git，也不会触发编译。

`ksightd code-capabilities` 保留 `kernsight.code-capabilities/v1` 和纯基础版本
`agent_version`，并提供 `agent_build_version`、`agent_git_commit`（完整 SHA 或 null）、
`agent_git_dirty`（true / false / null）、`agent_build_identity_source`（git / override / unknown）。
`agent_sha256` 是当前运行二进制的 SHA-256。精确核对部署应使用实际二进制 SHA-256 和完整
源码提交号，不能只比较随机后缀。协议握手和兼容性版本不变。
旧代理没有这些字段时应报告身份未知，不能拿本机仓库版本代替设备版本。

Git dirty 检查包含 Cargo 清单/锁文件、Makefile、工具链配置，以及 `.cargo`、`crates`、
`bpf`、`native`、`android`、`rules`、`xtask`、`scripts` 下的已跟踪修改、暂存修改和未忽略的新文件。
Markdown/reStructuredText 文档、其他本地笔记及 Git 忽略的构建产物不计入 dirty。
Cargo 监视这些源码目录和 Git 元数据；当前构建脚本另声明一个不创建的 nonce 路径，
让后续构建重新运行脚本并生成后缀。因此相同源码的重新构建也可能得到不同版本后缀和文件哈希，
不应声称二进制按字节可复现。

源码压缩包或无法读取 Git 时仍生成版本后缀，但结构化 Git 身份保持 unknown/null；
若仅 dirty 状态无法读取，该字段保持 null。发布流水线若已验证源码，可同时显式设置
`KERNSIGHT_BUILD_GIT_COMMIT=<完整提交 SHA>` 和 `KERNSIGHT_BUILD_GIT_DIRTY=false`
（有修改则 true）；来源会标记为 override。这些覆盖值不会固定随机后缀。
缺失其中一个变量、无效 SHA 或非 true/false 的 dirty 值会使构建失败。
覆盖值是发布者声明，不是脚本对源码的独立验证；常规 Git checkout 发布无需设置它们。

## MobileE 联动

MobileE 是平行客户端，KernSight 不依赖它。共享的 `ksight-protocol` 与 `ksight-core` 提供设备通信、会话回放、统计报告、DEX/SO 来源与关联图等基础。

集成时应保留：

- 设备实际版本、完整提交号与二进制哈希，不能以本机版本代替
- 父子会话与阶段身份、预算、停止和收尾结果
- 丢样、partial、未知覆盖及产物来源
- `confirmed` / `correlated` / `inferred` 的证据边界

原始事件保存、完整性校验、报告导入和深入分析是不同结果，不应合并成一个“全部成功”状态。

## 配置与扩展入口

- [服务配置示例](../android/config/ksightd.json.example)
- [普通传感器加载](../crates/ksight-agent/src/ebpf.rs)
- [BPF 传感器源码](../bpf/programs)
- [能力与适配点](../crates/ksight-core/src/capability.rs)
- [实际后端门禁](../crates/ksight-core/src/capture_scope.rs)
- [构建身份脚本](../crates/ksight-core/build.rs)

AOSP init、独立 SELinux 域、AVB 签名和锁定自定义信任根仍属于后续系统集成，不是当前临时目录部署已完成的能力。
