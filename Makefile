.PHONY: all build test lint fmt clippy check audit bench image clean

all: lint test

build:
	cargo build --release --locked

## test: unit and integration suites
test:
	cargo test --all

lint: fmt clippy

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --all-targets --all-features -- -D warnings

## check: validate the example config without starting the gateway
check:
	cargo run -- --config gateway.example.yaml --check

audit:
	cargo audit --deny warnings

## bench: criterion benchmarks
bench:
	cargo bench

image:
	docker build -t api-gateway:dev .

clean:
	cargo clean
