use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Weak};
use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use ipnetwork::Ipv4Network;
use log::{debug, error, info};
use mdns_sd::{IfKind, ServiceDaemon, ServiceInfo};
use notify::event::AccessKind;
use notify::{self, EventKind, Watcher};
use packet::{Builder as _, Packet, ip, udp};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::select;
use tokio::sync::Mutex;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::JoinHandle;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::bytes::Bytes;
use tokio_util::codec::Framed;
use tokio_util::sync::CancellationToken;
use tun::{self, AsyncDevice, TunPacketCodec};
use uuid::Uuid;

use crate::belaui::CONFIG_JSON_PATH;
use crate::protocol::{
    API_VERSION, Authentication, Hello, Identified, Identify, MessageRequest, MessageRequestData,
    MessageResponse, MessageToRelay, MessageToStreamer, MoblinkResult, Present, ResponseData,
    StartTunnelRequest, calculate_authentication,
};
use crate::utils::{AnyError, execute_command, random_string, resolve_host};
use crate::{MDNS_SERVICE_TYPE, belaui};

type WebSocketWriter = SplitSink<WebSocketStream<TcpStream>, Message>;
type WebSocketReader = SplitStream<WebSocketStream<TcpStream>>;

type TunWriter = SplitSink<Framed<AsyncDevice, TunPacketCodec>, Vec<u8>>;
type TunReader = SplitStream<Framed<AsyncDevice, TunPacketCodec>>;

#[derive(Debug)]
struct PacketBuilder {
    source_address: Ipv4Addr,
    source_port: u16,
    destination_address: Ipv4Addr,
    destination_port: u16,
}

impl PacketBuilder {
    fn new(
        source_address: Ipv4Addr,
        source_port: u16,
        destination_address: Ipv4Addr,
        destination_port: u16,
    ) -> Self {
        Self {
            source_address,
            source_port,
            destination_address,
            destination_port,
        }
    }

    fn pack(&self, payload: &[u8]) -> Result<Vec<u8>, AnyError> {
        Ok(ip::v4::Builder::default()
            .source(self.source_address)?
            .destination(self.destination_address)?
            .udp()?
            .source(self.source_port)?
            .destination(self.destination_port)?
            .payload(payload)?
            .build()?)
    }
}

struct Relay {
    me: Weak<Mutex<Self>>,
    streamer: Weak<Mutex<StreamerInner>>,
    relay_address: SocketAddr,
    writer: Option<WebSocketWriter>,
    challenge: String,
    salt: String,
    identified: bool,
    relay_id: Uuid,
    relay_name: String,
    relay_tunnel_port: Option<u16>,
    tun_ip_address: String,
    relay_receiver: Option<JoinHandle<()>>,
    tun_receiver: Option<JoinHandle<()>>,
    unique_index: u32,
    pong_received: bool,
    websocket_receiver_cancellation_token: Option<CancellationToken>,
}

impl Relay {
    pub fn new(
        streamer: Weak<Mutex<StreamerInner>>,
        relay_address: SocketAddr,
        writer: WebSocketWriter,
        tun_ip_address: String,
        unique_index: u32,
    ) -> Arc<Mutex<Self>> {
        Arc::new_cyclic(|me| {
            Mutex::new(Self {
                me: me.clone(),
                streamer,
                relay_address,
                writer: Some(writer),
                challenge: String::new(),
                salt: String::new(),
                identified: false,
                relay_id: Uuid::new_v4(),
                relay_name: "".into(),
                relay_tunnel_port: None,
                tun_ip_address,
                relay_receiver: None,
                tun_receiver: None,
                unique_index,
                pong_received: true,
                websocket_receiver_cancellation_token: None,
            })
        })
    }

    fn start(&mut self, reader: WebSocketReader) {
        self.start_websocket_receiver(reader);
        self.start_pinger();
    }

    fn stop(&mut self) {
        if let Some(websocket_receiver_cancellation_token) =
            self.websocket_receiver_cancellation_token.take()
        {
            websocket_receiver_cancellation_token.cancel();
        }
    }

    fn start_websocket_receiver(&mut self, mut reader: WebSocketReader) {
        let relay = self.me.clone();
        let cancellation_token = CancellationToken::new();
        self.websocket_receiver_cancellation_token = Some(cancellation_token.clone());

        tokio::spawn(async move {
            let Some(relay) = relay.upgrade() else {
                return;
            };

            relay.lock().await.start_handshake().await;

            loop {
                select! {
                    result = tokio::time::timeout(Duration::from_secs(20), reader.next()) => {
                        match result {
                            Ok(Some(Ok(message))) => {
                                if let Err(error) =
                                    relay.lock().await.handle_websocket_message(message).await
                                {
                                    error!("Relay error: {}", error);
                                    break;
                                }
                            }
                            Ok(Some(Err(error))) => {
                                info!("Websocket error {}", error);
                                break;
                            }
                            Ok(None) => {
                                info!("No more websocket messages to receive");
                                break;
                            }
                            Err(_) => {
                                info!("Websocket read timeout");
                                if relay.lock().await.writer.is_none() {
                                    break;
                                }
                            }
                        }
                    }
                    _ = cancellation_token.cancelled() => {
                        info!("Websocket cancelled");
                        break;
                    }
                }
            }
            let streamer = {
                let mut relay = relay.lock().await;
                info!("Relay disconnected: {}", relay.relay_address);
                relay.tunnel_destroyed().await;
                relay.streamer.upgrade()
            };
            if let Some(streamer) = streamer {
                streamer.lock().await.remove_relay(&relay).await;
            }
        });
    }

    fn start_pinger(&mut self) {
        let relay = self.me.clone();

        tokio::spawn(async move {
            loop {
                {
                    let Some(relay) = relay.upgrade() else {
                        break;
                    };
                    let mut relay = relay.lock().await;
                    if !relay.pong_received {
                        info!("Pong not received.");
                        relay.writer = None;
                        break;
                    } else {
                        relay.pong_received = false;
                        relay.send_websocket(Message::Ping(Bytes::new())).await.ok();
                    }
                }
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        });
    }

    async fn handle_websocket_message(&mut self, message: Message) -> Result<(), AnyError> {
        debug!("Websocket got: {:?}", message);
        match message {
            Message::Text(text) => match serde_json::from_str(&text) {
                Ok(message) => self.handle_message(message).await,
                Err(error) => {
                    Err(format!("Failed to deserialize message with error: {}", error).into())
                }
            },
            Message::Ping(data) => Ok(self.send_websocket(Message::Pong(data)).await?),
            Message::Pong(_) => {
                self.pong_received = true;
                Ok(())
            }
            _ => Err(format!("Unsupported websocket message: {:?}", message).into()),
        }
    }

    async fn handle_message(&mut self, message: MessageToStreamer) -> Result<(), AnyError> {
        match message {
            MessageToStreamer::Identify(identify) => self.handle_message_identify(identify).await,
            MessageToStreamer::Response(response) => self.handle_message_response(response).await,
        }
    }

    async fn handle_message_identify(&mut self, identify: Identify) -> Result<(), AnyError> {
        let Some(streamer) = self.streamer.upgrade() else {
            return Err("No streamer".into());
        };
        if identify.authentication
            == calculate_authentication(
                &streamer.lock().await.password,
                &self.salt,
                &self.challenge,
            )
        {
            self.identified = true;
            self.relay_id = identify.id;
            self.relay_name = identify.name;
            let identified = Identified {
                result: MoblinkResult::Ok(Present {}),
            };
            self.send(MessageToRelay::Identified(identified)).await?;
            self.start_tunnel().await
        } else {
            let identified = Identified {
                result: MoblinkResult::WrongPassword(Present {}),
            };
            self.send(MessageToRelay::Identified(identified)).await?;
            Err("Relay sent wrong password".into())
        }
    }

    async fn handle_message_response(&mut self, response: MessageResponse) -> Result<(), AnyError> {
        match response.data {
            ResponseData::StartTunnel(data) => {
                self.relay_tunnel_port = Some(data.port);
                self.tunnel_created().await?;
            }
            message => {
                info!("Ignoring message {:?}", message);
            }
        }
        Ok(())
    }

    async fn tunnel_created(&mut self) -> Result<(), AnyError> {
        let Some(relay_tunnel_port) = self.relay_tunnel_port else {
            return Ok(());
        };
        info!(
            "Tunnel created: {}:{} ({}, {})",
            self.relay_address.ip(),
            relay_tunnel_port,
            self.relay_name,
            self.relay_id
        );
        self.start_udp_networking(relay_tunnel_port).await?;
        Ok(())
    }

    async fn tunnel_destroyed(&mut self) {
        let Some(relay_tunnel_port) = self.relay_tunnel_port.take() else {
            return;
        };
        info!(
            "Tunnel destroyed: {}:{} ({}, {})",
            self.relay_address.ip(),
            relay_tunnel_port,
            self.relay_name,
            self.relay_id
        );
        self.stop_udp_networking().await;
    }

    async fn start_udp_networking(&mut self, relay_tunnel_port: u16) -> Result<(), AnyError> {
        let (tun_writer, tun_reader) = self.create_tun_device()?;
        let relay_socket = self.create_relay_socket(relay_tunnel_port).await?;
        self.setup_os_networking().await;
        let (tun_port_writer, tun_port_reader) = channel(1);
        self.start_relay_receiver(relay_socket.clone(), tun_writer, tun_port_reader)
            .await?;
        self.start_tun_receiver(tun_reader, relay_socket, tun_port_writer)
            .await;

        Ok(())
    }

    async fn stop_udp_networking(&mut self) {
        if let Some(relay_receiver) = self.relay_receiver.take() {
            relay_receiver.abort();
            relay_receiver.await.ok();
        }
        if let Some(tun_receiver) = self.tun_receiver.take() {
            tun_receiver.abort();
            tun_receiver.await.ok();
        }
        self.teardown_os_networking().await;
    }

    async fn create_relay_socket(
        &self,
        relay_tunnel_port: u16,
    ) -> Result<Arc<UdpSocket>, AnyError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let tunnel_address = format!("{}:{}", self.relay_address.ip(), relay_tunnel_port);
        socket.connect(tunnel_address).await?;
        Ok(Arc::new(socket))
    }

    fn create_tun_device(&self) -> Result<(TunWriter, TunReader), AnyError> {
        let mut config = tun::Configuration::default();
        config
            .address(&self.tun_ip_address)
            .tun_name(self.tun_device_name())
            .up();
        let device = tun::create_as_async(&config)?;
        Ok(device.into_framed().split())
    }

    #[cfg(not(target_os = "macos"))]
    fn tun_device_name(&self) -> String {
        format!("mob-{}", self.relay_name.replace(" ", "-"))
    }

    #[cfg(target_os = "macos")]
    fn tun_device_name(&self) -> String {
        format!("utun{}", 99 + self.unique_index)
    }

    async fn setup_os_networking(&self) {
        #[cfg(target_os = "linux")]
        self.setup_linux_networking().await;
    }

    #[allow(dead_code)]
    async fn setup_linux_networking(&self) {
        let Some(streamer) = self.streamer.upgrade() else {
            return;
        };
        let destination_address = &streamer.lock().await.destination_address;
        let table = self.get_linux_networking_table();
        self.teardown_linux_networking().await;
        execute_command(
            "ip",
            &[
                "route",
                "add",
                destination_address,
                "dev",
                &self.tun_device_name(),
                "proto",
                "kernel",
                "scope",
                "link",
                "src",
                &self.tun_ip_address,
                "table",
                &table,
            ],
        )
        .await;
        execute_command(
            "ip",
            &[
                "route",
                "add",
                "default",
                "via",
                &self.tun_ip_address,
                "dev",
                &self.tun_device_name(),
                "table",
                &table,
            ],
        )
        .await;
        execute_command(
            "ip",
            &[
                "rule",
                "add",
                "from",
                &self.tun_ip_address,
                "lookup",
                &table,
            ],
        )
        .await;
    }

    async fn teardown_os_networking(&self) {
        #[cfg(target_os = "linux")]
        self.teardown_linux_networking().await;
    }

    #[allow(dead_code)]
    async fn teardown_linux_networking(&self) {
        let table = self.get_linux_networking_table();
        execute_command("ip", &["rule", "del", "lookup", &table]).await;
        execute_command("ip", &["route", "flush", "table", &table]).await;
    }

    fn get_linux_networking_table(&self) -> String {
        format!("{}", 300 + self.unique_index)
    }

    async fn start_tun_receiver(
        &mut self,
        mut tun_reader: TunReader,
        relay_socket: Arc<UdpSocket>,
        tun_port_writer: Sender<u16>,
    ) {
        let Some(streamer) = self.streamer.upgrade() else {
            return;
        };
        let streamer = streamer.lock().await;
        let Ok(destination_address) = Ipv4Addr::from_str(&streamer.destination_address) else {
            return;
        };
        self.tun_receiver = Some(tokio::spawn(async move {
            let mut tun_port = 0u16;
            while let Some(packet) = tun_reader.next().await {
                if let Err(error) = Self::handle_tun_packet(
                    packet,
                    &relay_socket,
                    destination_address,
                    &tun_port_writer,
                    &mut tun_port,
                )
                .await
                {
                    error!("TUN receiver: {}", error);
                    break;
                }
            }
        }));
    }

    async fn handle_tun_packet(
        packet: Result<Vec<u8>, std::io::Error>,
        relay_socket: &Arc<UdpSocket>,
        destination_address: Ipv4Addr,
        tun_port_writer: &Sender<u16>,
        tun_port: &mut u16,
    ) -> Result<(), AnyError> {
        match packet {
            Ok(packet) => match ip::Packet::new(packet) {
                Ok(ip::Packet::V4(packet)) => {
                    if packet.protocol() == ip::Protocol::Udp
                        && packet.destination() == destination_address
                    {
                        Self::handle_tun_udp_packet(
                            packet.payload(),
                            relay_socket,
                            tun_port_writer,
                            tun_port,
                        )
                        .await?;
                    }
                }
                Ok(ip::Packet::V6(_)) => {
                    debug!("TUN receiver: Discarding IPv6 packet");
                }
                Err(error) => {
                    return Err(format!("Invalid IP packet: {}", error).into());
                }
            },
            Err(error) => {
                return Err(format!("TUN receiver: Read failed with: {}", error).into());
            }
        }
        Ok(())
    }

    async fn handle_tun_udp_packet(
        packet: &[u8],
        relay_socket: &Arc<UdpSocket>,
        tun_port_writer: &Sender<u16>,
        tun_port: &mut u16,
    ) -> Result<(), AnyError> {
        match udp::Packet::new(packet) {
            Ok(packet) => {
                let new_tun_port = packet.source();
                if new_tun_port != *tun_port {
                    tun_port_writer.send(new_tun_port).await.ok();
                    *tun_port = new_tun_port;
                }
                if let Err(error) = relay_socket.send(packet.payload()).await {
                    return Err(format!("Send error {}", error).into());
                }
            }
            Err(error) => {
                return Err(format!("Invalid UDP packet: {}", error).into());
            }
        }
        Ok(())
    }

    async fn start_relay_receiver(
        &mut self,
        relay_socket: Arc<UdpSocket>,
        mut tun_writer: TunWriter,
        mut tun_port_reader: Receiver<u16>,
    ) -> Result<(), AnyError> {
        let Some(streamer) = self.streamer.upgrade() else {
            return Err("No streamer".into());
        };
        let streamer = streamer.lock().await;
        let destination_address = streamer.destination_address.clone();
        let destination_port = streamer.destination_port;
        let tun_ip_address = self.tun_ip_address.clone();

        self.relay_receiver = Some(tokio::spawn(async move {
            let Ok(destination_address) = Ipv4Addr::from_str(&destination_address) else {
                return;
            };
            let Ok(tun_ip_address) = Ipv4Addr::from_str(&tun_ip_address) else {
                return;
            };
            let mut buffer = vec![0; 2048];
            let mut packet_builder =
                PacketBuilder::new(destination_address, destination_port, tun_ip_address, 10000);
            loop {
                if let Err(error) = select! {
                    result = relay_socket.recv(&mut buffer) => {
                        Self::handle_relay_packet(&mut tun_writer, &packet_builder, result, &buffer).await
                    }
                    tun_port = tun_port_reader.recv() => {
                        Self::handle_tun_port(&mut packet_builder, tun_port)
                    }
                } {
                    error!("Relay receiver: Error {}", error);
                    break;
                }
            }
        }));
        Ok(())
    }

    async fn handle_relay_packet(
        tun_writer: &mut TunWriter,
        packet_builder: &PacketBuilder,
        result: Result<usize, std::io::Error>,
        buffer: &[u8],
    ) -> Result<(), AnyError> {
        match result {
            Ok(length) => {
                debug!("Relay receiver: Got {:?}", &buffer[..length]);
                let Ok(packet) = packet_builder.pack(&buffer[..length]) else {
                    return Err("Relay receiver: IP create error".into());
                };
                if let Err(error) = tun_writer.send(packet).await {
                    Err(format!("Relay receiver: Send error {}", error).into())
                } else {
                    Ok(())
                }
            }
            Err(error) => Err(format!("Relay receiver: Error {}", error).into()),
        }
    }

    fn handle_tun_port(
        packet_builder: &mut PacketBuilder,
        tun_port: Option<u16>,
    ) -> Result<(), AnyError> {
        let Some(tun_port) = tun_port else {
            return Err("TUN port missing".into());
        };
        packet_builder.destination_port = tun_port;
        info!("Relay receiver: Ready with {:?}", packet_builder);
        Ok(())
    }

    async fn start_handshake(&mut self) {
        self.challenge = random_string();
        self.salt = random_string();
        self.send_hello().await;
        self.identified = false;
    }

    async fn start_tunnel(&mut self) -> Result<(), AnyError> {
        let Some(streamer) = self.streamer.upgrade() else {
            return Err("No streamer".into());
        };
        let streamer = streamer.lock().await;
        if streamer.destination_address.is_empty() {
            // TODO: Should not be an error, but start the tunnel when the
            //       destination address is known (read from BelaUI).
            return Err("Destination address not available".into());
        }
        let start_tunnel = StartTunnelRequest {
            address: streamer.destination_address.clone(),
            port: streamer.destination_port,
        };
        let request = MessageRequest {
            id: 1,
            data: MessageRequestData::StartTunnel(start_tunnel),
        };
        self.send(MessageToRelay::Request(request)).await
    }

    async fn send_hello(&mut self) {
        let hello = MessageToRelay::Hello(Hello {
            api_version: API_VERSION.into(),
            authentication: Authentication {
                challenge: self.challenge.clone(),
                salt: self.salt.clone(),
            },
        });
        self.send(hello).await.ok();
    }

    async fn send(&mut self, message: MessageToRelay) -> Result<(), AnyError> {
        let text = serde_json::to_string(&message)?;
        self.send_websocket(Message::Text(text.into())).await
    }

    async fn send_websocket(&mut self, message: Message) -> Result<(), AnyError> {
        match self.writer.as_mut() {
            Some(writer) => {
                debug!("Websocket sending: {:?}", message);
                writer.send(message).await?;
            }
            _ => {
                return Err("No websocket writer".into());
            }
        }
        Ok(())
    }
}

struct StreamerInner {
    me: Weak<Mutex<Self>>,
    id: String,
    name: String,
    address: String,
    port: u16,
    password: String,
    destination_address: String,
    destination_port: u16,
    belabox: bool,
    relays: Vec<Arc<Mutex<Relay>>>,
    unique_indexes: Vec<u32>,
    tun_ip_network: Ipv4Network,
    service_daemon: ServiceDaemon,
}

impl StreamerInner {
    pub fn new(
        id: String,
        name: String,
        address: String,
        port: u16,
        tun_ip_network: String,
        password: String,
        destination_address: String,
        destination_port: u16,
        belabox: bool,
    ) -> Result<Arc<Mutex<Self>>, Box<dyn std::error::Error + Send + Sync>> {
        let tun_ip_network = parse_tun_ip_network(&tun_ip_network)?;
        Ok(Arc::new_cyclic(|me| {
            Mutex::new(Self {
                me: me.clone(),
                id,
                name,
                address,
                port,
                password,
                destination_address,
                destination_port,
                belabox,
                relays: Vec::new(),
                unique_indexes: (0..tun_ip_network.size() - 1).collect(),
                tun_ip_network,
                service_daemon: Self::create_service_daemon(),
            })
        }))
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.belabox {
            if let Err(error) = self.read_belaui_config_file().await {
                error!("Read BELABOX config error: {}", error);
            }
            self.start_belaui_config_watcher();
        } else {
            self.destination_address = resolve_host(&self.destination_address).await?;
        }
        self.start_relay_listener().await?;
        self.start_mdns_daemon();
        Ok(())
    }

    fn create_service_daemon() -> ServiceDaemon {
        let service_daemon = ServiceDaemon::new().unwrap();
        service_daemon
            .disable_interface(Vec::from([IfKind::IPv6]))
            .ok();
        service_daemon
    }

    async fn start_relay_listener(
        &mut self,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener_address = format!("{}:{}", self.address, self.port);
        let listener = TcpListener::bind(&listener_address).await?;
        info!("WebSocket server listening on '{}'", listener_address);
        let streamer = self.me.clone();

        tokio::spawn(async move {
            while let Ok((tcp_stream, relay_address)) = listener.accept().await {
                match streamer.upgrade() {
                    Some(streamer) => {
                        streamer
                            .lock()
                            .await
                            .handle_relay_connection(tcp_stream, relay_address)
                            .await;
                    }
                    _ => {
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    fn start_belaui_config_watcher(&mut self) {
        let (async_events_writer, mut async_events_reader) = tokio::sync::mpsc::channel(1);
        std::thread::spawn(move || {
            let (events_writer, events_reader) =
                std::sync::mpsc::channel::<notify::Result<notify::Event>>();
            let Ok(mut watcher) = notify::recommended_watcher(events_writer) else {
                error!("Failed to create watcher");
                return;
            };
            if let Err(error) = watcher.watch(
                Path::new(CONFIG_JSON_PATH),
                notify::RecursiveMode::NonRecursive,
            ) {
                error!("Watch failed with error: {}", error);
                return;
            }
            for result in events_reader {
                if async_events_writer.blocking_send(result).is_err() {
                    break;
                }
            }
        });

        let streamer = self.me.clone();
        tokio::spawn(async move {
            while let Some(result) = async_events_reader.recv().await {
                match result {
                    Ok(event) => {
                        let EventKind::Access(AccessKind::Close(_)) = event.kind else {
                            continue;
                        };
                        if let Some(streamer) = streamer.upgrade() {
                            let mut streamer = streamer.lock().await;
                            match streamer.read_belaui_config_file().await {
                                Ok(destination_changed) => {
                                    if destination_changed {
                                        for relay in &streamer.relays {
                                            relay.lock().await.stop();
                                        }
                                    }
                                }
                                Err(error) => {
                                    error!("Read BELABOX config error: {}", error)
                                }
                            }
                        }
                    }
                    Err(error) => error!("Config error: {:?}", error),
                }
            }
        });
    }

    fn start_mdns_daemon(&mut self) {
        match self.create_mdns_service_info() {
            Ok(service_info) => {
                if let Err(error) = self.service_daemon.register(service_info) {
                    error!("Failed to register mDNS service with error: {}", error);
                }
            }
            Err(error) => {
                error!("Failed to create mDNS service info with error: {}", error);
            }
        }
    }

    async fn read_belaui_config_file(&mut self) -> Result<bool, AnyError> {
        let config = belaui::Config::new_from_file().await?;
        let mut destination_changed = false;
        let address = resolve_host(&config.get_address()).await?;
        if self.destination_address != address {
            self.destination_address = address;
            info!("New destination address {}", self.destination_address);
            destination_changed = true;
        }
        if self.destination_port != config.get_port() {
            self.destination_port = config.get_port();
            info!("New destination port {}", self.destination_port);
            destination_changed = true;
        }
        Ok(destination_changed)
    }

    fn create_mdns_service_info(&self) -> Result<ServiceInfo, AnyError> {
        let properties = HashMap::from([("name".to_string(), self.name.clone())]);
        let service_info = ServiceInfo::new(
            MDNS_SERVICE_TYPE,
            &self.id,
            &format!("{}.local.", self.id),
            "",
            self.port,
            properties,
        )?
        .enable_addr_auto();
        Ok(service_info)
    }

    async fn handle_relay_connection(&mut self, tcp_stream: TcpStream, relay_address: SocketAddr) {
        match tokio_tungstenite::accept_async(tcp_stream).await {
            Ok(websocket_stream) => {
                info!("Relay connected: {}", relay_address);
                let (writer, reader) = websocket_stream.split();
                let Some(unique_index) = self.unique_indexes.pop() else {
                    return;
                };
                let Some(tun_ip_address) = self.tun_ip_network.nth(unique_index) else {
                    self.unique_indexes.insert(0, unique_index);
                    return;
                };
                let relay = Relay::new(
                    self.me.clone(),
                    relay_address,
                    writer,
                    tun_ip_address.to_string(),
                    unique_index,
                );
                relay.lock().await.start(reader);
                self.add_relay(relay);
            }
            Err(error) => {
                error!("Relay websocket handshake failed with: {}", error);
            }
        }
    }

    fn add_relay(&mut self, relay: Arc<Mutex<Relay>>) {
        self.relays.push(relay);
        self.log_number_of_relays();
    }

    async fn remove_relay(&mut self, relay: &Arc<Mutex<Relay>>) {
        let unique_index = relay.lock().await.unique_index;
        self.unique_indexes.insert(0, unique_index);
        self.relays.retain(|r| !Arc::ptr_eq(r, relay));
        self.log_number_of_relays();
    }

    fn log_number_of_relays(&self) {
        info!("Number of relays: {}", self.relays.len())
    }
}

pub struct Streamer {
    inner: Arc<Mutex<StreamerInner>>,
}

impl Streamer {
    pub fn new(
        id: String,
        name: String,
        address: String,
        port: u16,
        tun_ip_network: String,
        password: String,
        destination_address: String,
        destination_port: u16,
        belabox: bool,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Self {
            inner: StreamerInner::new(
                id,
                name,
                address,
                port,
                tun_ip_network,
                password,
                destination_address,
                destination_port,
                belabox,
            )?,
        })
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.inner.lock().await.start().await
    }
}

fn parse_tun_ip_network(network: &str) -> Result<Ipv4Network, AnyError> {
    let network: Ipv4Network = network.parse()?;
    if network.size() > 256 {
        return Err(format!("TUN IP network too big ({} > 256)", network.size()).into());
    }
    Ok(network)
}
