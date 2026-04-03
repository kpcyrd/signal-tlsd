FROM rust:1-alpine3.23
ENV RUSTFLAGS="-C strip=debuginfo"
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/var/cache/buildkit \
    CARGO_HOME=/var/cache/buildkit/cargo \
    CARGO_TARGET_DIR=/var/cache/buildkit/target \
    cargo build --release --locked && \
    cp -v /var/cache/buildkit/target/release/signal-tlsd /

FROM alpine:3.23
RUN apk add libcap-setcap
COPY --from=0 /signal-tlsd /
RUN setcap cap_net_bind_service=+ep /signal-tlsd
USER nobody
ENV BIND_ADDR=[::]:443
ENTRYPOINT ["/signal-tlsd"]
