use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use moblink_rust::relay::create_get_status_closure;
use moblink_rust::relay_service::{RelayService, RelayServiceConfig};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Password
    #[arg(long, default_value = "1234")]
    password: String,

    /// Network interfaces to allow as a regex (^ prefix and $ suffix are added
    /// automatically). Localhost is never allowed.
    #[arg(long)]
    network_interfaces_to_allow: Vec<String>,

    /// Network interfaces to ignore as a regex (^ prefix and $ suffix are added
    /// automatically). Ignores localhost automatically.
    #[arg(long)]
    network_interfaces_to_ignore: Vec<String>,

    /// Connect to these streamer URLs directly instead of discovering streamers
    /// over mDNS. Repeatable, e.g. --streamer-url ws://192.168.1.10:7777
    #[arg(long)]
    streamer_url: Vec<String>,

    /// Override the relay name shown in the Moblin app for a given interface,
    /// as "interface=label". Repeatable, e.g. --interface-name-override
    /// eth0=WAN
    #[arg(long)]
    interface_name_override: Vec<String>,

    /// Write current relay and streamer state as JSON to this file, for
    /// external UIs to display connection status and streamer IPs.
    #[arg(long)]
    runtime_status_file: Option<PathBuf>,

    /// Log level
    #[arg(long, default_value = "info")]
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

    /// Database with relay ids
    #[arg(long, default_value = "moblink-relay-service.json")]
    database: PathBuf,
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
async fn main() {
    let args = Args::parse();
    setup_logging(!args.no_log_timestamps, &args.log_level);

    let relay_service = RelayService::new(
        RelayServiceConfig {
            password: args.password,
            network_interfaces_to_allow: args.network_interfaces_to_allow,
            network_interfaces_to_ignore: args.network_interfaces_to_ignore,
            streamer_urls: args.streamer_url,
            interface_name_overrides: args.interface_name_override,
            runtime_status_file: args.runtime_status_file,
            database: args.database,
        },
        create_get_status_closure(&args.status_executable, &args.status_file),
    )
    .await;
    relay_service.start().await;

    loop {
        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}
