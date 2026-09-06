.PHONY: check test fmt lint architecture bpf device device-target deploy probe

BPF_CLANG ?= $(firstword $(wildcard /opt/homebrew/opt/llvm/bin/clang) $(shell command -v clang))
BPF_CFLAGS ?= -O2 -g -target bpfel -mcpu=v3 -Wall -Werror
BPF_OBJECTS := build/bpf/process_lifecycle.bpf.o build/bpf/file_open.bpf.o build/bpf/network_connect.bpf.o build/bpf/memory_regions.bpf.o build/bpf/binder_transaction.bpf.o build/bpf/sched_wakeup.bpf.o build/bpf/uprobe_regs.bpf.o
BPF_HEADERS := $(wildcard bpf/include/*.h)
DEVICE_TARGET := aarch64-unknown-linux-musl
HOST_TARGET := $(shell rustc -vV | sed -n 's/^host: //p')
RUST_LLD := $(shell rustc --print sysroot)/lib/rustlib/$(HOST_TARGET)/bin/rust-lld
DEVICE_DIR := /data/local/tmp/ksight
DEVICE_STAGE := /data/local/tmp/ksight-deploy
ADB ?= adb

check:
	cargo check --workspace --all-targets

test:
	cargo test --workspace

fmt:
	cargo fmt --all -- --check

lint:
	cargo clippy --workspace --all-targets -- -D warnings

architecture:
	cargo run -p xtask -- architecture

bpf: $(BPF_OBJECTS)

build/bpf/process_lifecycle.bpf.o: bpf/programs/process/lifecycle.bpf.c $(BPF_HEADERS)
	@mkdir -p $(dir $@)
	$(BPF_CLANG) $(BPF_CFLAGS) -I bpf/include -c $< -o $@

build/bpf/file_open.bpf.o: bpf/programs/file/open.bpf.c $(BPF_HEADERS)
	@mkdir -p $(dir $@)
	$(BPF_CLANG) $(BPF_CFLAGS) -I bpf/include -c $< -o $@

build/bpf/network_connect.bpf.o: bpf/programs/network/connect.bpf.c $(BPF_HEADERS)
	@mkdir -p $(dir $@)
	$(BPF_CLANG) $(BPF_CFLAGS) -I bpf/include -c $< -o $@

build/bpf/memory_regions.bpf.o: bpf/programs/memory/regions.bpf.c $(BPF_HEADERS)
	@mkdir -p $(dir $@)
	$(BPF_CLANG) $(BPF_CFLAGS) -I bpf/include -c $< -o $@

build/bpf/binder_transaction.bpf.o: bpf/programs/binder/transaction.bpf.c $(BPF_HEADERS)
	@mkdir -p $(dir $@)
	$(BPF_CLANG) $(BPF_CFLAGS) -I bpf/include -c $< -o $@

build/bpf/sched_wakeup.bpf.o: bpf/programs/sched/wakeup.bpf.c $(BPF_HEADERS)
	@mkdir -p $(dir $@)
	$(BPF_CLANG) $(BPF_CFLAGS) -I bpf/include -c $< -o $@

build/bpf/uprobe_regs.bpf.o: bpf/programs/uprobe/regs.bpf.c $(BPF_HEADERS)
	@mkdir -p $(dir $@)
	$(BPF_CLANG) $(BPF_CFLAGS) -I bpf/include -c $< -o $@

device-target:
	rustup target add $(DEVICE_TARGET)

NATIVE_CC ?= $(firstword $(wildcard /opt/homebrew/opt/llvm/bin/clang) $(shell command -v clang))
NATIVE_LLD ?= $(RUST_LLD)

build/native/libksight_tls.so: native/tls_hook.c
	@mkdir -p $(dir $@)
	$(NATIVE_CC) -target aarch64-linux-android21 -c -fPIC -nostdlib -ffreestanding -fno-builtin -fno-stack-protector -fomit-frame-pointer -fno-asynchronous-unwind-tables -fvisibility=hidden -Os $< -o build/native/tls_hook.o
	$(NATIVE_LLD) -flavor gnu -shared --soname=libpac.so -z now -z noexecstack -o $@ build/native/tls_hook.o
	$(firstword $(wildcard /opt/homebrew/opt/llvm/bin/llvm-strip) $(shell command -v llvm-strip) $(shell command -v strip)) -x $@ 2>/dev/null || true

build/native/libksight_tls32.so: native/tls_hook.c
	@mkdir -p $(dir $@)
	$(NATIVE_CC) -target armv7-linux-androideabi21 -c -fPIC -nostdlib -ffreestanding -fno-builtin -fno-stack-protector -fomit-frame-pointer -fno-asynchronous-unwind-tables -fvisibility=hidden -Os $< -o build/native/tls_hook32.o
	$(NATIVE_LLD) -flavor gnu -shared --soname=libpac.so -z now -z noexecstack -o $@ build/native/tls_hook32.o
	$(firstword $(wildcard /opt/homebrew/opt/llvm/bin/llvm-strip) $(shell command -v llvm-strip) $(shell command -v strip)) -x $@ 2>/dev/null || true

device: bpf device-target build/native/libksight_tls.so build/native/libksight_tls32.so
	RUSTFLAGS="-C linker=$(RUST_LLD)" cargo build --release --target $(DEVICE_TARGET) -p ksight-agent --bin ksightd --features embedded-assets
	RUSTFLAGS="-C linker=$(RUST_LLD)" cargo build --release --target $(DEVICE_TARGET) -p ksight-inject

deploy: device
	$(ADB) shell 'rm -rf $(DEVICE_STAGE) && mkdir -p $(DEVICE_STAGE)'
	$(ADB) push target/$(DEVICE_TARGET)/release/ksightd $(DEVICE_STAGE)/ksightd
	$(ADB) push target/$(DEVICE_TARGET)/release/ksight-inject $(DEVICE_STAGE)/ksight-inject
	$(ADB) push build/native/libksight_tls.so $(DEVICE_STAGE)/libksight_tls.so
	$(ADB) push build/native/libksight_tls32.so $(DEVICE_STAGE)/libksight_tls32.so
	$(ADB) shell 'su -c "mkdir -p $(DEVICE_DIR) && cp $(DEVICE_STAGE)/ksightd $(DEVICE_DIR)/ksightd.new && cp $(DEVICE_STAGE)/ksight-inject $(DEVICE_DIR)/ksight-inject && cp $(DEVICE_STAGE)/libksight_tls.so $(DEVICE_DIR)/libksight_tls.so && cp $(DEVICE_STAGE)/libksight_tls32.so $(DEVICE_DIR)/libksight_tls32.so && chown root:root $(DEVICE_DIR) $(DEVICE_DIR)/ksightd.new $(DEVICE_DIR)/ksight-inject $(DEVICE_DIR)/libksight_tls.so $(DEVICE_DIR)/libksight_tls32.so && chmod 0755 $(DEVICE_DIR) $(DEVICE_DIR)/ksightd.new $(DEVICE_DIR)/ksight-inject && chmod 0644 $(DEVICE_DIR)/libksight_tls.so $(DEVICE_DIR)/libksight_tls32.so && mv -f $(DEVICE_DIR)/ksightd.new $(DEVICE_DIR)/ksightd && $(DEVICE_DIR)/ksightd run --dry-run"'
	$(ADB) shell 'rm -rf $(DEVICE_STAGE)'

probe: deploy
	$(ADB) shell 'su -c "$(DEVICE_DIR)/ksightd probe --json"'
