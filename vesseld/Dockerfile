FROM rust AS builder

RUN apt-get update && apt-get install -y libclang-dev libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*

WORKDIR /prople

COPY . . 

RUN cargo build -p prople-vesseld --release 

FROM debian:bookworm-slim 

RUN apt-get update && apt-get install -y libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*

COPY --from=builder /prople/target/release/prople-vesseld . 

# Run the binary
ENTRYPOINT ["./prople-vesseld"]