use std::{
    fs::{create_dir_all, read}, 
    net::SocketAddr, 
    path::{Path as FsPath, PathBuf}, 
    time::{Duration, Instant},
};

use tracing_subscriber::{EnvFilter, fmt};
use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, TransportAddr, 
    endpoint::{Connection, PathEvent, presets},
};
use n0_future::StreamExt;

const ALPN: &[u8] = b"thenet/ping/0";

#[derive(Parser, Debug)]
struct Cli {
    #[arg(long, global = true, env = "NET_KEY_FILE")]
    key_file: Option<PathBuf>,

    #[arg(long, global = true, env = "NET_RELAY")]
    relay: Option<RelayUrl>,

    #[arg(long, global = true, conflicts_with = "relay")]
    offline: bool,

    #[arg(long, global = true)]
    port: Option<u16>,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    Id,
    Listen,
    Dial {
        key: EndpointId,
        #[arg(long, default_value_t = 30)]
        count: u32,
        #[arg(long = "addr")]
        addrs: Vec<SocketAddr>,
    }
}

#[derive(Debug, Clone)]
struct NetOpts {
    relay: Option<RelayUrl>,
    offline: bool,
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    fmt().with_env_filter(
        EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
    ).init();

    let cli = Cli::parse();
    let key_file = cli.key_file.unwrap_or_else(default_key_file);
    let secret = load_or_create_key(&key_file)?;
    let opts = NetOpts {
        relay: cli.relay,
        offline: cli.offline,
        port: cli.port,
    };

    match cli.cmd {
        Cmd::Id => {
            println!("{}", secret.public());
            Ok(())
        }
        Cmd::Listen => listen(secret, opts).await,
        Cmd::Dial { key, count, addrs } => dial(secret, opts, key, count, addrs).await,
    }
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

fn default_key_file() -> PathBuf {
    let home   = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).unwrap_or_else(|| ".".into());

    home.join(".thenet").join("node.key")
}

fn load_or_create_key(path: &FsPath) -> Result<SecretKey> {
    if path.exists() {
        let bytes = read(path).with_context(|| format!("reading {}", path.display()))?;
        let bytes: [u8; 32] = bytes.as_slice().try_into().with_context(|| format!("{} is not 32-byte key", path.display()))?;
        return Ok(SecretKey::from_bytes(&bytes));
    }

    let secret = SecretKey::generate();

    if let Some(dir) = path.parent() {
        create_dir_all(dir)?;
    }

    write_private(path, &secret.to_bytes())?;
    eprintln!("New node key created at {}", path.display());
    Ok(secret)
}

#[cfg(unix)]
fn write_private(path: &FsPath, bytes: &[u8]) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;

    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &FsPath, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

async fn bind(secret: SecretKey, opts: &NetOpts, accept: bool) -> Result<Endpoint> {
    let mut builder = if opts.offline {
        Endpoint::builder(presets::Minimal).relay_mode(RelayMode::Disabled)
    } else {
        Endpoint::builder(presets::N0)
    };

    builder = builder.secret_key(secret);

    if let Some(url) = opts.relay.clone() {
        builder = builder.relay_mode(RelayMode::Custom(url.into()));
    }

    if let Some(port) = opts.port {
        builder = builder.bind_addr(SocketAddr::from(([0, 0, 0, 0], port))).context("bad bind address")?;
    }

    if accept {
        builder = builder.alpns(vec![ALPN.to_vec()]);
    }

    let endpoint = builder.bind().await.context("binding endpoint")?;

    if !opts.offline {
        if tokio::time::timeout(Duration::from_secs(10), endpoint.online()).await.is_err() {
            eprintln!(
                "warning: no relay reachable within 10s. Dialing by key alone won't work; \n\
                \x20         use --addr with a direct address, or --relay with your own relay."
            );
        }
    }
    Ok(endpoint)
}

fn print_self(endpoint: &Endpoint) {
    let addr = endpoint.addr();

    println!("node key : {}", endpoint.id());

    for relay in addr.relay_urls() {
        println!("relay    : {relay}");
    }

    for ip in addr.ip_addrs() {
        println!("direct    : {ip}");
    }
}

// ---------------------------------------------------------------------------
// listen
// ---------------------------------------------------------------------------

async fn listen(secret: SecretKey, opts: NetOpts) -> Result<()> {
    let endpoint = bind(secret, &opts, true).await?;

    print_self(&endpoint);

    println!("\n waiting for connections. on the other machine run:");

    if opts.offline {
        let hint = endpoint.addr().ip_addrs().next().map(|a| a.to_string()).unwrap_or_default();

        println!(" net --offline dial {} --addr {hint}\n", endpoint.id());
    } else {
        println!(" net dial {}\n", endpoint.id());
    }

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };

                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            if let Err(e) = serve(conn).await {
                                eprintln!("connection error: {e:#}");
                            }
                        }
                        Err(e) => eprintln!("handshake failed: {e:#}"),
                    }
                });
            }
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    endpoint.close().await;
    Ok(())
}

async fn serve(conn: Connection) -> Result<()> {
    let peer = conn.remote_id();
    println!("[+] {} connected", peer.fmt_short());
    watch_paths(&conn, peer.fmt_short().to_string());

    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let payload = recv.read_to_end(64).await?;
        send.write_all(&payload).await?;
        send.finish()?;
    }
    println!("[-] {} disconnected", peer.fmt_short());
    Ok(())
}

// ---------------------------------------------------------------------------
// dial
// ---------------------------------------------------------------------------

async fn dial(
    secret: SecretKey,
    opts: NetOpts,
    key: EndpointId,
    count: u32,
    addrs: Vec<SocketAddr>,
) -> Result<()> {
    let endpoint = bind(secret, &opts, false).await?;
    let result = dial_inner(&endpoint, key, count, addrs).await;
    endpoint.close().await;
    result
}

async fn dial_inner(
    endpoint: &Endpoint,
    key: EndpointId,
    count: u32,
    addrs: Vec<SocketAddr>,
) -> Result<()> {
    println!("me       : {}", endpoint.id().fmt_short());
    println!("dialing  : {key}");

    // By default we know only the key; where it lives is resolved by lookup.
    // Direct addresses are just hints: the TLS handshake still proves the key.
    let target = EndpointAddr::from_parts(key, addrs.into_iter().map(TransportAddr::Ip));

    let started = Instant::now();
    let conn = tokio::time::timeout(Duration::from_secs(20), endpoint.connect(target, ALPN))
        .await
        .context("timed out connecting (is the other node running `net listen`?)")?
        .context("connecting")?;
    println!(
        "connected in {:?} via {}\n",
        started.elapsed(),
        current_path(&conn)
    );
    watch_paths(&conn, "remote".into());

    let mut ok = 0u32;
    for seq in 0..count {
        let t = Instant::now();
        match ping(&conn, seq).await {
            Ok(()) => {
                ok += 1;
                println!(
                    "ping {seq:>3}  rtt {:>6.1} ms  via {}",
                    ms(t.elapsed()),
                    current_path(&conn)
                );
            }
            Err(e) => println!("ping {seq:>3}  failed: {e:#}"),
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    println!("\n{ok}/{count} pings answered");
    conn.close(0u32.into(), b"bye");
    if ok == 0 {
        bail!("no ping got through");
    }
    Ok(())
}

async fn ping(conn: &Connection, seq: u32) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let msg = seq.to_be_bytes();
    send.write_all(&msg).await?;
    send.finish()?;
    let reply = tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(64)).await??;
    if reply != msg {
        bail!("echo mismatch");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Path observation: the most instructive part of phase 0
// ---------------------------------------------------------------------------

fn current_path(conn: &Connection) -> String {
    let paths = conn.paths();
    match paths.iter().find(|p| p.is_selected()) {
        Some(p) => describe(p.remote_addr()),
        None => "unknown".into(),
    }
}

fn describe(addr: &TransportAddr) -> String {
    match addr {
        TransportAddr::Relay(url) => format!("RELAY {url}"),
        TransportAddr::Ip(ip) => format!("DIRECT {ip}"),
        other => format!("{other}",)
    }
}

fn watch_paths(conn: &Connection, label: String) {
    let mut events = conn.path_events();
    tokio::spawn(async move {
        while let Some(ev) = events.next().await {
            match ev {
                PathEvent::Opened { remote_addr, .. } => {
                    println!("  [{label}] path opened   {}", describe(&remote_addr))
                }
                PathEvent::Closed { remote_addr, .. } => {
                    println!("  [{label}] path closed   {}", describe(&remote_addr))
                }
                PathEvent::Selected { remote_addr, .. } => {
                    println!("  [{label}] now using  -> {}", describe(&remote_addr))
                }
                PathEvent::Lagged { missed, .. } => {
                    println!("  [{label}] ({missed} path events missed)")
                }
                _ => {}
            }
        }
    });
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}