use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::{error, info};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use url::Url;
use uuid::Uuid;

use crate::MDNS_SERVICE_TYPE;
use crate::relay::{ConnectionStatus, GetStatusClosure, Relay, Status};
use crate::utils::{any_address_belongs_to_this_machine, get_first_ipv4_address};

#[derive(Serialize, Deserialize, Default)]
struct DatabaseContent {
    relay_ids: HashMap<String, Uuid>,
}

struct Database {
    path: PathBuf,
    content: DatabaseContent,
}

impl Database {
    async fn new(path: PathBuf) -> Self {
        let content = Self::load(&path).await;
        Self { path, content }
    }

    async fn load(path: &PathBuf) -> DatabaseContent {
        let mut content = "".to_string();
        if let Ok(mut file) = File::open(path).await {
            let mut buffer = vec![];
            if file.read_to_end(&mut buffer).await.is_ok() {
                content = String::from_utf8(buffer).unwrap_or_default();
            }
        }
        serde_json::from_str(&content).unwrap_or_default()
    }

    async fn store(&self) {
        let content = serde_json::to_string(&self.content).unwrap_or_default();
        if let Ok(mut file) = File::create(&self.path).await {
            file.write_all(content.as_bytes()).await.ok();
        }
    }

    async fn get_relay_id(&mut self, name: &str) -> Uuid {
        if !self.content.relay_ids.contains_key(name) {
            self.content
                .relay_ids
                .insert(name.to_string(), Uuid::new_v4());
            self.store().await;
        }
        *self.content.relay_ids.get(name).unwrap()
    }
}

struct ServiceRelay {
    interface_name: String,
    interface_address: Ipv4Addr,
    streamer_name: String,
    streamer_url: String,
    relay: Relay,
}

impl ServiceRelay {
    async fn new(
        interface_name: String,
        interface_address: Ipv4Addr,
        relay_name: String,
        streamer: Streamer,
        password: String,
        get_status: Option<GetStatusClosure>,
        database: Arc<Mutex<Database>>,
    ) -> Self {
        let relay = Relay::new();
        relay.set_bind_address(interface_address.to_string()).await;
        relay
            .setup(
                streamer.url.clone(),
                password,
                database.lock().await.get_relay_id(&interface_name).await,
                relay_name,
                |_| {},
                get_status,
            )
            .await;
        relay.start().await;
        Self {
            interface_name,
            interface_address,
            streamer_name: streamer.name,
            streamer_url: streamer.url,
            relay,
        }
    }
}

#[derive(Clone)]
struct Streamer {
    name: String,
    url: String,
}

#[derive(Serialize)]
struct RuntimeStreamerStatus {
    name: String,
    url: String,
    host: String,
}

#[derive(Serialize)]
struct RuntimeRelayStatus {
    #[serde(flatten)]
    connection: ConnectionStatus,
    interface_name: String,
    interface_address: String,
    streamer_name: String,
    streamer_url: String,
    streamer_host: String,
}

#[derive(Serialize)]
struct RuntimeStatus {
    schema_version: u8,
    process_id: u32,
    updated_at: u64,
    updated_uptime: Option<u64>,
    connected: bool,
    manual_streamer: bool,
    streamers: Vec<RuntimeStreamerStatus>,
    relays: Vec<RuntimeRelayStatus>,
}

// Parses "interface=label" pairs used to give a relay a friendly name in the
// Moblin app instead of the raw interface name (e.g. "eth0=WAN").
fn parse_interface_name_overrides(values: Vec<String>) -> HashMap<String, String> {
    let mut overrides = HashMap::new();

    for value in values {
        let Some((interface, label)) = value.split_once('=') else {
            continue;
        };
        let interface = interface.trim();
        let label = label.trim();

        if !interface.is_empty() && !label.is_empty() {
            overrides.insert(interface.to_string(), label.to_string());
        }
    }

    overrides
}

fn host_from_url(url: &str) -> String {
    Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(|host| host.to_string()))
        .unwrap_or_default()
}

// Builds the streamer list from explicit URLs, bypassing mDNS discovery. Used
// where discovery is unreliable (e.g. across router uplinks behind NAT).
fn parse_manual_streamers(values: Vec<String>) -> Vec<Streamer> {
    values
        .into_iter()
        .filter_map(|value| match Url::parse(&value) {
            Ok(url) => Some(Streamer {
                name: url
                    .host_str()
                    .map(|host| host.to_string())
                    .unwrap_or_else(|| value.clone()),
                url: value,
            }),
            Err(error) => {
                error!("Invalid manual streamer URL {}: {}", value, error);
                None
            }
        })
        .collect()
}

struct NetworkInterfaceFilter {
    patterns_to_allow: Option<Regex>,
    patterns_to_ignore: Option<Regex>,
}

impl NetworkInterfaceFilter {
    fn new(patterns_to_allow: Vec<String>, patterns_to_ignore: Vec<String>) -> Self {
        Self {
            patterns_to_allow: Self::compile(patterns_to_allow),
            patterns_to_ignore: Self::compile(patterns_to_ignore),
        }
    }

    fn filter(&self, interfaces: &mut Vec<NetworkInterface>) {
        if let Some(patterns_to_allow) = &self.patterns_to_allow {
            interfaces.retain(|interface| patterns_to_allow.is_match(&interface.name));
        }
        if let Some(patterns_to_ignore) = &self.patterns_to_ignore {
            interfaces.retain(|interface| !patterns_to_ignore.is_match(&interface.name));
        }
    }

    fn compile(patterns: Vec<String>) -> Option<Regex> {
        if !patterns.is_empty() {
            let pattern = format!("^{}$", patterns.join("|"));
            match Regex::new(&pattern) {
                Ok(regex) => return Some(regex),
                Err(error) => {
                    error!("Failed to compile regex {} with error: {}", pattern, error);
                }
            }
        }
        None
    }
}

struct RelayServiceInner {
    me: Weak<Mutex<Self>>,
    password: String,
    network_interface_filter: NetworkInterfaceFilter,
    manual_streamers: Vec<Streamer>,
    interface_name_overrides: HashMap<String, String>,
    runtime_status_file: Option<PathBuf>,
    get_status: Option<GetStatusClosure>,
    status: watch::Sender<Status>,
    relays: Vec<ServiceRelay>,
    network_interfaces: Vec<NetworkInterface>,
    streamers: Vec<Streamer>,
    network_interface_monitor: Option<JoinHandle<()>>,
    streamers_monitor: Option<JoinHandle<()>>,
    get_status_updater: Option<JoinHandle<()>>,
    database: Arc<Mutex<Database>>,
}

impl RelayServiceInner {
    async fn new(
        config: RelayServiceConfig,
        get_status: Option<GetStatusClosure>,
    ) -> Arc<Mutex<Self>> {
        let database = Arc::new(Mutex::new(Database::new(config.database).await));
        Arc::new_cyclic(|me| {
            Mutex::new(Self {
                me: me.clone(),
                password: config.password,
                network_interface_filter: NetworkInterfaceFilter::new(
                    config.network_interfaces_to_allow,
                    config.network_interfaces_to_ignore,
                ),
                manual_streamers: parse_manual_streamers(config.streamer_urls),
                interface_name_overrides: parse_interface_name_overrides(
                    config.interface_name_overrides,
                ),
                runtime_status_file: config.runtime_status_file,
                get_status,
                status: watch::channel(Status::default()).0,
                relays: Vec::new(),
                network_interfaces: Vec::new(),
                streamers: Vec::new(),
                network_interface_monitor: None,
                streamers_monitor: None,
                get_status_updater: None,
                database,
            })
        })
    }

    async fn start(&mut self) {
        self.start_network_interfaces_monitor();
        if self.manual_streamers.is_empty() {
            self.start_streamers_monitor();
        } else {
            self.streamers = self.manual_streamers.clone();
            self.updated().await;
            info!(
                "Using {} manually configured streamer URL(s)",
                self.streamers.len()
            );
        }
        self.start_get_status_updater();
        self.write_runtime_status().await;
    }

    async fn stop(&mut self) {
        if let Some(network_interface_monitor) = self.network_interface_monitor.take() {
            network_interface_monitor.abort();
            network_interface_monitor.await.ok();
        }
        if let Some(streamers_finder) = self.streamers_monitor.take() {
            streamers_finder.abort();
            streamers_finder.await.ok();
        }
    }

    fn start_network_interfaces_monitor(&mut self) {
        let relay_service = self.me.clone();
        self.network_interface_monitor = Some(tokio::spawn(async move {
            while let Ok(interfaces) = NetworkInterface::show() {
                let Some(relay_service) = relay_service.upgrade() else {
                    break;
                };
                {
                    let mut relay_service = relay_service.lock().await;
                    relay_service.update_network_interfaces(interfaces);
                    relay_service.updated().await;
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        }));
    }

    fn update_network_interfaces(&mut self, mut interfaces: Vec<NetworkInterface>) {
        self.network_interface_filter.filter(&mut interfaces);
        self.network_interfaces = interfaces;
    }

    fn start_streamers_monitor(&mut self) {
        let relay_service = self.me.clone();
        self.streamers_monitor = Some(tokio::spawn(async move {
            loop {
                let Ok(browser) = ServiceDaemon::new() else {
                    return;
                };
                let Ok(receiver) = browser.browse(MDNS_SERVICE_TYPE) else {
                    return;
                };
                while let Ok(event) = receiver.recv_async().await {
                    if let ServiceEvent::ServiceResolved(info) = event {
                        info!(
                            "mDNS-SD: Found streamer {} {:?} {}",
                            info.get_fullname(),
                            info.get_addresses(),
                            info.get_port()
                        );
                        let Some(name) = info.get_property_val_str("name") else {
                            continue;
                        };
                        let addresses = info.get_addresses_v4();
                        if any_address_belongs_to_this_machine(&addresses) {
                            continue;
                        }
                        let Some(address) = addresses.iter().next().cloned() else {
                            continue;
                        };
                        let Some(relay_service) = relay_service.upgrade() else {
                            break;
                        };
                        {
                            let mut relay_service = relay_service.lock().await;
                            relay_service.add_streamer(name.to_string(), address, info.get_port());
                            relay_service.updated().await;
                        }
                    }
                }
            }
        }));
    }

    fn start_get_status_updater(&mut self) {
        let relay_service = self.me.clone();
        self.get_status_updater = Some(tokio::spawn(async move {
            loop {
                let Some(relay_service) = relay_service.upgrade() else {
                    break;
                };
                relay_service.lock().await.update_status().await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }));
    }

    async fn update_status(&mut self) {
        let status = if let Some(get_status) = &self.get_status {
            get_status().await
        } else {
            Status::default()
        };
        self.status.send_replace(status);
    }

    fn add_streamer(&mut self, name: String, address: Ipv4Addr, port: u16) {
        let url = format!("ws://{}:{}", address, port);
        self.streamers.retain(|streamer| streamer.url != url);
        self.streamers.push(Streamer { name, url });
    }

    // Writes the current relay/streamer state to a JSON file so external UIs
    // (e.g. the OpenWrt LuCI app) can show connection state and streamer IPs.
    async fn write_runtime_status(&self) {
        let Some(path) = &self.runtime_status_file else {
            return;
        };

        // OpenWrt's system.info.localtime includes the timezone offset. Uptime
        // lets consumers check freshness independently of timezone/NTP changes.
        let updated_uptime = tokio::fs::read_to_string("/proc/uptime")
            .await
            .ok()
            .and_then(|value| {
                value
                    .split_whitespace()
                    .next()?
                    .split('.')
                    .next()?
                    .parse()
                    .ok()
            });
        let relays: Vec<_> = self
            .relays
            .iter()
            .map(|relay| RuntimeRelayStatus {
                connection: relay.relay.connection_status(),
                interface_name: relay.interface_name.clone(),
                interface_address: relay.interface_address.to_string(),
                streamer_name: relay.streamer_name.clone(),
                streamer_url: relay.streamer_url.clone(),
                streamer_host: host_from_url(&relay.streamer_url),
            })
            .collect();
        let status = RuntimeStatus {
            schema_version: 2,
            process_id: std::process::id(),
            updated_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            updated_uptime,
            connected: relays.iter().any(|relay| relay.connection.connected),
            manual_streamer: !self.manual_streamers.is_empty(),
            streamers: self
                .streamers
                .iter()
                .map(|streamer| RuntimeStreamerStatus {
                    name: streamer.name.clone(),
                    url: streamer.url.clone(),
                    host: host_from_url(&streamer.url),
                })
                .collect(),
            relays,
        };

        let Ok(content) = serde_json::to_string(&status) else {
            return;
        };

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.ok();
        }

        // Write to a sibling temp file and atomically rename it over the target.
        // Readers polling this file (e.g. the LuCI UI) then always observe either
        // the previous or the new complete document, never a truncated or
        // half-written one. Writes here are already serialized by the service
        // mutex, so the fixed temp name cannot collide with itself.
        let mut temp_path = path.clone();
        temp_path.as_mut_os_string().push(".tmp");
        if let Err(error) = tokio::fs::write(&temp_path, content).await {
            error!("Failed to write runtime status file: {}", error);
            return;
        }
        if let Err(error) = tokio::fs::rename(&temp_path, path).await {
            error!("Failed to replace runtime status file: {}", error);
            tokio::fs::remove_file(&temp_path).await.ok();
        }
    }

    async fn updated(&mut self) {
        let old_number_of_relays = self.relays.len();
        self.add_relays().await;
        self.remove_relays().await;
        let new_number_of_relays = self.relays.len();
        if new_number_of_relays != old_number_of_relays {
            info!("Number of relays: {}", new_number_of_relays);
        }
        self.write_runtime_status().await;
    }

    async fn add_relays(&mut self) {
        for interface in &self.network_interfaces {
            let Some(interface_address) = get_first_ipv4_address(interface) else {
                continue;
            };
            if interface_address.is_loopback() {
                continue;
            }
            for streamer in &self.streamers {
                if self.relay_already_added(interface_address, &streamer.url) {
                    continue;
                }
                let relay_name = self
                    .interface_name_overrides
                    .get(&interface.name)
                    .cloned()
                    .unwrap_or_else(|| interface.name.clone());
                info!(
                    "Adding relay called {} with interface address {} for streamer name {} and \
                     URL {}",
                    relay_name, interface_address, streamer.name, streamer.url
                );
                self.relays.push(
                    ServiceRelay::new(
                        interface.name.clone(),
                        interface_address,
                        relay_name,
                        streamer.clone(),
                        self.password.clone(),
                        self.create_get_status_closure(),
                        self.database.clone(),
                    )
                    .await,
                );
            }
        }
    }

    pub fn create_get_status_closure(&self) -> Option<GetStatusClosure> {
        let status = self.status.subscribe();
        Some(Box::new(move || {
            let status = status.borrow().clone();
            Box::pin(async move { status })
        }))
    }

    fn relay_already_added(&self, interface_address: Ipv4Addr, streamer_url: &str) -> bool {
        self.relays.iter().any(|relay| {
            relay.interface_address == interface_address && relay.streamer_url == streamer_url
        })
    }

    async fn remove_relays(&mut self) {
        let mut relays_to_keep: Vec<ServiceRelay> = Vec::new();
        let mut relays_to_remove: Vec<ServiceRelay> = Vec::new();
        for relay in self.relays.drain(..) {
            if Self::should_keep_relay(&self.network_interfaces, relay.interface_address) {
                relays_to_keep.push(relay);
            } else {
                relays_to_remove.push(relay);
            }
        }
        self.relays = relays_to_keep;
        for relay in relays_to_remove {
            info!(
                "Removing relay called {} with interface address {} for streamer name {} and URL \
                 {}",
                relay.interface_name,
                relay.interface_address,
                relay.streamer_name,
                relay.streamer_url
            );
            relay.relay.stop().await;
        }
    }

    fn should_keep_relay(
        network_interfaces: &[NetworkInterface],
        interface_address: Ipv4Addr,
    ) -> bool {
        network_interfaces
            .iter()
            .any(|interface| get_first_ipv4_address(interface) == Some(interface_address))
    }
}

/// Configuration for a [`RelayService`].
pub struct RelayServiceConfig {
    pub password: String,
    /// Regex of interface names to allow (`^`/`$` anchors added automatically).
    pub network_interfaces_to_allow: Vec<String>,
    /// Regex of interface names to ignore (`^`/`$` anchors added
    /// automatically).
    pub network_interfaces_to_ignore: Vec<String>,
    /// Streamer URLs to connect to directly instead of discovering over mDNS.
    pub streamer_urls: Vec<String>,
    /// `"interface=label"` pairs renaming a relay as shown in the Moblin app.
    pub interface_name_overrides: Vec<String>,
    /// File to write relay/streamer state as JSON for external UIs to read.
    pub runtime_status_file: Option<PathBuf>,
    /// File storing the per-interface relay identities.
    pub database: PathBuf,
}

pub struct RelayService {
    inner: Arc<Mutex<RelayServiceInner>>,
}

#[cfg(test)]
mod runtime_tests {
    use super::*;

    #[tokio::test]
    async fn a_relay_object_does_not_mean_authenticated() {
        let path = std::env::temp_dir().join(format!("moblink-test-{}.json", Uuid::new_v4()));
        let service = RelayService::new(
            RelayServiceConfig {
                password: "test".into(),
                network_interfaces_to_allow: vec![],
                network_interfaces_to_ignore: vec![],
                streamer_urls: vec![],
                interface_name_overrides: vec![],
                runtime_status_file: Some(path.clone()),
                database: path.with_extension("database"),
            },
            None,
        )
        .await;
        let mut inner = service.inner.lock().await;
        let get_status = inner.create_get_status_closure().unwrap();
        inner.status.send_replace(Status {
            battery_percentage: Some(73),
        });
        // Connection setup may own this mutex for longer than the handler limit.
        // Status must still return promptly, with the latest cached value.
        let status = tokio::time::timeout(Duration::from_millis(100), get_status())
            .await
            .unwrap();
        assert_eq!(status.battery_percentage, Some(73));

        inner.relays.push(ServiceRelay {
            interface_name: "eth0".into(),
            interface_address: Ipv4Addr::LOCALHOST,
            streamer_name: "test".into(),
            streamer_url: "ws://localhost:7777".into(),
            relay: Relay::new(),
        });
        inner.write_runtime_status().await;
        let value: serde_json::Value =
            serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
        assert_eq!(value["schema_version"], 2);
        assert_eq!(value["process_id"], std::process::id());
        assert!(value["updated_at"].as_u64().unwrap() > 0);
        assert!(value["updated_uptime"].as_u64().unwrap() > 0);
        assert_eq!(value["connected"], false);
        assert_eq!(value["relays"][0]["connected"], false);
        // Update authentication concurrently with repeated file snapshots.
        use crate::protocol::{Identified, MessageToRelay, MoblinkResult, Present};
        use futures_util::SinkExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = &inner.relays[0].relay;
        relay
            .setup(
                format!("ws://{}", listener.local_addr().unwrap()),
                "test".into(),
                Uuid::new_v4(),
                "test".into(),
                |_| {},
                None,
            )
            .await;
        let (_, mut server) = tokio::join!(relay.start(), async {
            let (stream, _) = listener.accept().await.unwrap();
            tokio_tungstenite::accept_async(stream).await.unwrap()
        });
        let updates = tokio::spawn(async move {
            for index in 0..200 {
                let result = if index % 2 == 0 {
                    MoblinkResult::Ok(Present {})
                } else {
                    MoblinkResult::WrongPassword(Present {})
                };
                let message = MessageToRelay::Identified(Identified { result });
                server
                    .send(tokio_tungstenite::tungstenite::Message::Text(
                        serde_json::to_string(&message).unwrap().into(),
                    ))
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            server
        });
        let mut saw_connected = false;
        for _ in 0..200 {
            inner.write_runtime_status().await;
            let value: serde_json::Value =
                serde_json::from_slice(&tokio::fs::read(&path).await.unwrap()).unwrap();
            let any_connected = value["relays"]
                .as_array()
                .unwrap()
                .iter()
                .any(|relay| relay["connected"] == true);
            assert_eq!(value["connected"], any_connected);
            saw_connected |= any_connected;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let _server = updates.await.unwrap();
        assert!(saw_connected);
        inner.relays[0].relay.stop().await;
        tokio::fs::remove_file(path).await.unwrap();
    }
}

impl RelayService {
    pub async fn new(config: RelayServiceConfig, get_status: Option<GetStatusClosure>) -> Self {
        Self {
            inner: RelayServiceInner::new(config, get_status).await,
        }
    }

    pub async fn start(&self) {
        self.inner.lock().await.start().await;
    }

    pub async fn stop(&self) {
        self.inner.lock().await.stop().await;
    }
}
