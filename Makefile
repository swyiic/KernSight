.PHONY: check test fmt lint architecture bpf device device-target deploy probe

BPF_CLANG ?= $(firstword $(wildcard /opt/homebrew/opt/llvm/bin/clang) $(shell command -v clang))
BPF_CFLAGS ?= -O2 -g -target bpfel -Wall -Werror
BPF_OBJECT := build/bpf/process_lifecycle.bpf.o
BPF_SOURCE := bpf/programs/process/lifecycle.bpf.c
BPF_HEADERS := $(wildcard bpf/include/*.h)
DEVICE_TARGET := aarch64-unknown-linux-musl
HOST_TARGET := $(shell rustc -vV | sed -n 's/^host: //p')
RUST_LLD := $(shell rustc --print sysroot)/lib/rustlib/$(HOST_TARGET)/bin/rust-lld
DEVICE_DIR := /data/local/tmp/ksight
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

bpf: $(BPF_OBJECT)

$(BPF_OBJECT): $(BPF_SOURCE) $(BPF_HEADERS)
	@mkdir -p $(dir $@)
	$(BPF_CLANG) $(BPF_CFLAGS) -I bpf/include -c $< -o $@

device-target:
	rustup target add $(DEVICE_TARGET)

device: bpf device-target
	RUSTFLAGS="-C linker=$(RUST_LLD)" cargo build --release --target $(DEVICE_TARGET) -p ksight-agent

deploy: device
	$(ADB) shell 'mkdir -p $(DEVICE_DIR)'
	$(ADB) push target/$(DEVICE_TARGET)/release/ksightd $(DEVICE_DIR)/ksightd
	$(ADB) push $(BPF_OBJECT) $(DEVICE_DIR)/process_lifecycle.bpf.o
	$(ADB) shell 'chmod 0755 $(DEVICE_DIR)/ksightd'

probe: deploy
	$(ADB) shell 'su -c "$(DEVICE_DIR)/ksightd probe --json"'
