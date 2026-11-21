use std::time::Duration;

use clap::Parser;
use gethostname::gethostname;
use log::{info, warn};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use moblink_rust::MDNS_SERVICE_TYPE;
use moblink_rust::relay::{self, create_get_status_closure};
use uuid::Uuid;

fn hostname() -> String {
    gethostname().to_str().unwrap_or("Moblink").to_string()
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Name to identify the relay
    #[arg(short, long, default_value_t = hostname())]
    name: String,

    /// Relay ID (valid UUID)
    #[arg(short, long)]
    id: Option<Uuid>,

    /// Streamer URL (websocket) - optional if using mDNS
    #[arg(short = 'u', long)]
    streamer_url: Option<String>,

    /// Password
    #[arg(short, long, default_value = "1234")]
    password: String,

    /// Bind address
    #[arg(short, long = "bind-address", default_value_t = String::new())]
    bind_address: String,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// No log timestamps
    #[arg(long)]
    no_log_timestamps: bool,

    /// Print status JSON to stdout, for example {"batteryPercentage": 93}.
    ///
    /// After 3 seconds, the relay returns empty status and kills only the direct
    /// child process. Any subprocesses it launched can continue running.
    #[arg(long)]
    status_executable: Option<String>,

    /// Status file.
    /// Contains status on format {"batteryPercentage": 93}.
    #[arg(long)]
    status_file: Option<String>,
}

fn setup_logging(timestamps: bool, log_level: &str) {
    let mut builder = env_logger::builder();
    if timestamps {
        builder.format_timestamp_millis()
    } else {
        builder.format_timestamp(None)
    }
    .parse_filters(log_level)
    .init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    setup_logging(!args.no_log_timestamps, &args.log_level);
    let relay_id = args.id.unwrap_or(Uuid::new_v4());

    if let Some(streamer_url) = args.streamer_url.clone() {
        run_manual(args, relay_id, streamer_url).await;
    } else {
        run_automatic(args, relay_id).await;
    }

    Ok(())
}

async fn run_manual(args: Args, relay_id: Uuid, streamer_url: String) {
    let relay = relay::Relay::new();

    if !args.bind_address.is_empty() {
        relay.set_bind_address(args.bind_address).await;
    }

    relay
        .setup(
            streamer_url,
            args.password,
            relay_id,
            args.name,
            |status| info!("Status: {}", status),
            create_get_status_closure(&args.status_executable, &args.status_file),
        )
        .await;
    relay.start().await;

    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

async fn run_automatic(args: Args, relay_id: Uuid) {
    let mut retries = 0;

    loop {
        let mdns = ServiceDaemon::new().expect("Failed to create mDNS daemon");
        let receiver = mdns
            .browse(MDNS_SERVICE_TYPE)
            .expect("Failed to browse services");

        info!("Searching for Moblink streamers via mDNS...");
        let relay = relay::Relay::new();

        while let Ok(event) = receiver.recv_async().await {
            match event {
                ServiceEvent::ServiceResolved(info) => {
                    if relay.is_started().await {
                        warn!("Relay already started, skipping discovery");
                        continue;
                    }
                    // Handle network interface binding
                    if !args.bind_address.is_empty() {
                        relay.set_bind_address(args.bind_address.clone()).await;
                    }

                    let port = info.get_port();
                    for ip in info.get_addresses() {
                        let ip = ip.to_ip_addr();
                        if ip.is_loopback() || ip.is_multicast() {
                            continue;
                        }

                        // Skip IPv6 for now
                        if ip.is_ipv6() {
                            continue;
                        }

                        let streamer_url = format!("ws://{}:{}", ip, port);
                        info!("Discovered Moblink streamer at {}", streamer_url);

                        relay
                            .setup(
                                streamer_url,
                                args.password.clone(),
                                relay_id,
                                args.name.clone(),
                                |status| info!("Status: {}", status),
                                create_get_status_closure(
                                    &args.status_executable,
                                    &args.status_file,
                                ),
                            )
                            .await;
                    }

                    relay.start().await;
                }
                ServiceEvent::ServiceRemoved(_, _) => {
                    warn!("Streamer service removed");
                    relay.stop().await;
                }
                _ => {}
            }
        }

        // Reconnect logic with backoff
        let delay = Duration::from_secs(2u64.pow(retries));
        warn!("No streamers found, retrying in {:?}...", delay);
        tokio::time::sleep(delay).await;
        retries = (retries + 1).min(5);
    }
}
