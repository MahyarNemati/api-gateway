# syntax=docker/dockerfile:1

FROM rust:1-slim AS build
WORKDIR /src
# Build dependencies first so edits to src/ do not invalidate the dep layer.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
 && echo '' > src/lib.rs \
 && cargo build --release --locked 2>/dev/null || true \
 && rm -rf src
COPY . .
RUN cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/api-gateway /usr/local/bin/api-gateway
USER nonroot
EXPOSE 8080 9090
ENTRYPOINT ["/usr/local/bin/api-gateway"]
CMD ["--config", "/etc/gateway.yaml"]
