.PHONY: help prerequisites build test clean lint

help:
	@echo "hecate-lampad-core — shared agent library"
	@echo ""
	@echo "Targets:"
	@echo "  help           Show this help (default)"
	@echo "  prerequisites  Verify Rust toolchain and fetch dependencies"
	@echo "  build          Build release library"
	@echo "  test           Run unit and integration tests"
	@echo "  clean          Remove build artifacts"
	@echo "  lint           Run clippy with warnings denied"

prerequisites:
	@echo "Checking Rust toolchain..."
	@command -v cargo >/dev/null 2>&1 || { echo "Error: cargo not found. Install Rust via https://rustup.rs"; exit 1; }
	cargo fetch

build: prerequisites
	cargo build --release

test: prerequisites
	cargo test

clean:
	cargo clean

lint: prerequisites
	cargo clippy --all-targets -- -D warnings
