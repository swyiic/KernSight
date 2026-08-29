.PHONY: check test fmt lint architecture bpf device device-target deploy probe

BPF_CLANG ?= $(firstword $(wildcard /opt/homebrew/opt/llvm/bin/clang) $(shell command -v clang))
BPF_CFLAGS ?= -O2 -g -target bpfel -Wall -Werror
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
	RUSTFLAGS="-C linker=$(RUST_LLD)" cargo build --release --target $(DEVICE_TARGET) -p ksight-agent

deploy: device
	$(ADB) shell 'rm -rf $(DEVICE_STAGE) && mkdir -p $(DEVICE_STAGE)'
	$(ADB) push target/$(DEVICE_TARGET)/release/ksightd $(DEVICE_STAGE)/ksightd
	$(ADB) push build/bpf/process_lifecycle.bpf.o $(DEVICE_STAGE)/process_lifecycle.bpf.o
	$(ADB) push build/bpf/file_open.bpf.o $(DEVICE_STAGE)/file_open.bpf.o
	$(ADB) push build/bpf/network_connect.bpf.o $(DEVICE_STAGE)/network_connect.bpf.o
	$(ADB) push build/bpf/memory_regions.bpf.o $(DEVICE_STAGE)/memory_regions.bpf.o
	$(ADB) push build/bpf/binder_transaction.bpf.o $(DEVICE_STAGE)/binder_transaction.bpf.o
	$(ADB) push build/bpf/sched_wakeup.bpf.o $(DEVICE_STAGE)/sched_wakeup.bpf.o
	$(ADB) push build/bpf/uprobe_regs.bpf.o $(DEVICE_STAGE)/uprobe_regs.bpf.o
	$(ADB) push android/config/ksightd.json.example $(DEVICE_STAGE)/ksightd.json
	$(ADB) push android/scripts/ksight-hide-debug.sh $(DEVICE_STAGE)/ksight-hide-debug.sh
	$(ADB) shell 'su -c "mkdir -p $(DEVICE_DIR) && cp $(DEVICE_STAGE)/ksightd $(DEVICE_DIR)/ksightd && cp $(DEVICE_STAGE)/process_lifecycle.bpf.o $(DEVICE_DIR)/process_lifecycle.bpf.o && cp $(DEVICE_STAGE)/file_open.bpf.o $(DEVICE_DIR)/file_open.bpf.o && cp $(DEVICE_STAGE)/network_connect.bpf.o $(DEVICE_DIR)/network_connect.bpf.o && cp $(DEVICE_STAGE)/memory_regions.bpf.o $(DEVICE_DIR)/memory_regions.bpf.o && cp $(DEVICE_STAGE)/binder_transaction.bpf.o $(DEVICE_DIR)/binder_transaction.bpf.o && cp $(DEVICE_STAGE)/sched_wakeup.bpf.o $(DEVICE_DIR)/sched_wakeup.bpf.o && cp $(DEVICE_STAGE)/uprobe_regs.bpf.o $(DEVICE_DIR)/uprobe_regs.bpf.o && cp $(DEVICE_STAGE)/ksightd.json $(DEVICE_DIR)/ksightd.json && cp $(DEVICE_STAGE)/ksight-hide-debug.sh $(DEVICE_DIR)/ksight-hide-debug.sh && chown root:root $(DEVICE_DIR) $(DEVICE_DIR)/ksightd $(DEVICE_DIR)/process_lifecycle.bpf.o $(DEVICE_DIR)/file_open.bpf.o $(DEVICE_DIR)/network_connect.bpf.o $(DEVICE_DIR)/memory_regions.bpf.o $(DEVICE_DIR)/binder_transaction.bpf.o $(DEVICE_DIR)/sched_wakeup.bpf.o $(DEVICE_DIR)/uprobe_regs.bpf.o $(DEVICE_DIR)/ksightd.json $(DEVICE_DIR)/ksight-hide-debug.sh && chmod 0755 $(DEVICE_DIR) $(DEVICE_DIR)/ksightd $(DEVICE_DIR)/ksight-hide-debug.sh && chmod 0644 $(DEVICE_DIR)/process_lifecycle.bpf.o $(DEVICE_DIR)/file_open.bpf.o $(DEVICE_DIR)/network_connect.bpf.o $(DEVICE_DIR)/memory_regions.bpf.o $(DEVICE_DIR)/binder_transaction.bpf.o $(DEVICE_DIR)/sched_wakeup.bpf.o $(DEVICE_DIR)/uprobe_regs.bpf.o $(DEVICE_DIR)/ksightd.json"'
	$(ADB) shell 'rm -rf $(DEVICE_STAGE)'

probe: deploy
	$(ADB) shell 'su -c "$(DEVICE_DIR)/ksightd probe --json"'
