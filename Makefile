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

device: bpf device-target
	RUSTFLAGS="-C linker=$(RUST_LLD)" cargo build --release --target $(DEVICE_TARGET) -p ksight-agent --bin ksightd --features embedded-assets

deploy: device
	$(ADB) shell 'rm -rf $(DEVICE_STAGE) && mkdir -p $(DEVICE_STAGE)'
	$(ADB) push target/$(DEVICE_TARGET)/release/ksightd $(DEVICE_STAGE)/ksightd
	$(ADB) shell 'su -c "mkdir -p $(DEVICE_DIR) && cp $(DEVICE_STAGE)/ksightd $(DEVICE_DIR)/ksightd.new && chown root:root $(DEVICE_DIR) $(DEVICE_DIR)/ksightd.new && chmod 0755 $(DEVICE_DIR) $(DEVICE_DIR)/ksightd.new && mv -f $(DEVICE_DIR)/ksightd.new $(DEVICE_DIR)/ksightd && $(DEVICE_DIR)/ksightd run --dry-run"'
	$(ADB) shell 'rm -rf $(DEVICE_STAGE)'

probe: deploy
	$(ADB) shell 'su -c "$(DEVICE_DIR)/ksightd probe --json"'
