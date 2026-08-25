.PHONY: check test fmt lint architecture

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

