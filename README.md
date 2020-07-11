# async-tls-lite

* [Cargo package](https://crates.io/crates/async-tls-lite)

## Examples

* [smol server](demos/smol/src/server.rs) [smol client](demos/smol/src/client.rs)

## Simple Client

```rust
use std::net::TcpStream;

use async_tls_lite::TlsConnector;
use smol::Async;

// ...

let tcp_stream = Async::<TcpStream>::connect("github.com:443").await?;
let connector = TlsConnector::default();
let mut tls_stream = connector.connect("github.com", tcp_stream).await?;

// ...
```

## Dev

```
cargo test --all-features --all -- --nocapture && \
cargo clippy --all -- -D clippy::all && \
cargo fmt --all -- --check
```

```
cargo build-all-features
cargo test-all-features --all
```
