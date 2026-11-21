use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Weak};

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use tokio::fs::File;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::process::Command;
use tokio::sync::{Mutex, Notify, watch};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant, sleep, timeout};
use tokio_tungstenite::tungstenite::protocol::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use uuid::Uuid;

use crate::protocol::*;
use crate::utils::{AnyError, resolve_host};

#[derive(Default, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub battery_percentage: Option<i32>,
}

pub type GetStatusClosure =
    Box<dyn Fn() -> Pin<Box<dyn Future<Output = Status> + Send + Sync>> + Send + Sync>;

#[derive(Clone, Default, Serialize)]
pub struct ConnectionStatus {
    pub connected: bool,
    pub wrong_password: bool,
    pub streamer_ip: Option<String>,
}

struct RelayInner {
    me: Weak<Mutex<Self>>,
    /// Store a local IP address  for binding UDP sockets
    bind_address: String,
    relay_id: Uuid,
    streamer_url: String,
    password: String,
    name: String,
    on_status_updated: Option<Box<dyn Fn(String) + Send + Sync>>,
    get_status: Option<Arc<GetStatusClosure>>,
    ws_writer: Option<SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>>,
    ws_reader: Option<JoinHandle<()>>,
    started: bool,
    connected: bool,
    wrong_password: bool,
    connection_status: watch::Sender<ConnectionStatus>,
    streamer_ip: Option<String>,
    websocket_generation: u64,
    start_on_reconnect_soon: Arc<Mutex<bool>>,
    relay_to_destination: Option<JoinHandle<Result<(), AnyError>>>,
    relay_to_streamer: Option<JoinHandle<()>>,
}

impl RelayInner {
    fn new(connection_status: watch::Sender<ConnectionStatus>) -> Arc<Mutex<Self>> {
        Arc::new_cyclic(|me| {
            Mutex::new(Self {
                me: me.clone(),
                bind_address: Self::get_default_bind_address(),
                relay_id: Uuid::new_v4(),
                streamer_url: "".to_string(),
                password: "".to_string(),
                name: "".to_string(),
                on_status_updated: None,
                get_status: None,
                ws_writer: None,
                ws_reader: None,
                started: false,
                connected: false,
                wrong_password: false,
                connection_status,
                streamer_ip: None,
                websocket_generation: 0,
                start_on_reconnect_soon: Arc::new(Mutex::new(false)),
                relay_to_destination: None,
                relay_to_streamer: None,
            })
        })
    }

    fn set_bind_address(&mut self, address: String) {
        self.bind_address = address;
    }

    async fn setup<F>(
        &mut self,
        streamer_url: String,
        password: String,
        relay_id: Uuid,
        name: String,
        on_status_updated: F,
        get_status: Option<GetStatusClosure>,
    ) where
        F: Fn(String) + Send + Sync + 'static,
    {
        self.on_status_updated = Some(Box::new(on_status_updated));
        self.get_status = get_status.map(Arc::new);
        self.relay_id = relay_id;
        self.streamer_url = streamer_url;
        self.password = password;
        self.name = name;
    }

    fn is_started(&self) -> bool {
        self.started
    }

    async fn start(&mut self) {
        if !self.started {
            self.started = true;
            self.start_internal().await;
        }
    }

    async fn stop(&mut self) {
        if self.started {
            self.started = false;
            self.stop_internal().await;
        }
    }

    fn get_default_bind_address() -> String {
        // Get main network interface
        let interfaces = pnet::datalink::interfaces();
        let interface = interfaces.iter().find(|interface| {
            interface.is_up() && !interface.is_loopback() && !interface.ips.is_empty()
        });

        // Only ipv4 addresses are supported
        let ipv4_addresses: Vec<String> = interface
            .expect("No available network interfaces found")
            .ips
            .iter()
            .filter_map(|ip| {
                let ip = ip.ip();
                ip.is_ipv4().then(|| ip.to_string())
            })
            .collect();

        // Return the first address
        ipv4_addresses
            .first()
            .cloned()
            .unwrap_or("0.0.0.0:0".to_string())
    }

    async fn start_internal(&mut self) {
        if !self.started {
            self.stop_internal().await;
            return;
        }

        let request = match url::Url::parse(&self.streamer_url) {
            Ok(url) => url,
            Err(e) => {
                error!("Failed to parse URL: {}", e);
                return;
            }
        };

        match timeout(Duration::from_secs(10), connect_async(request.to_string())).await {
            Ok(Ok((ws_stream, _))) => {
                debug!("Connected to {}", self.streamer_url);
                self.streamer_ip = match ws_stream.get_ref() {
                    MaybeTlsStream::Plain(stream) => {
                        stream.peer_addr().ok().map(|p| p.ip().to_string())
                    }
                    _ => None,
                };
                self.update_status();
                let (writer, reader) = ws_stream.split();
                self.ws_writer = Some(writer);
                self.start_websocket_receiver(reader);
            }
            Ok(Err(error)) => {
                debug!(
                    "Failed to connect to {} with error: {}",
                    self.streamer_url, error
                );
                self.reconnect_soon().await;
            }
            Err(_elapsed) => {
                debug!(
                    "Failed to connect to {} within 10 seconds",
                    self.streamer_url
                );
                self.reconnect_soon().await;
            }
        }
    }

    fn start_websocket_receiver(
        &mut self,
        mut reader: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    ) {
        // Task to process messages received from the channel.
        let relay = self.me.clone();
        let generation = self.websocket_generation;

        self.ws_reader = Some(tokio::spawn(async move {
            let mut heartbeat = tokio::time::interval(Duration::from_secs(15));
            let mut last_received = Instant::now();
            loop {
                let deadline = last_received + Duration::from_secs(45);
                let result = tokio::select! {
                    message = tokio::time::timeout_at(deadline, reader.next()) => {
                        let Ok(Some(result)) = message else { break };
                        last_received = Instant::now();
                        result
                    }
                    _ = heartbeat.tick() => {
                        let sent = timeout(Duration::from_secs(5), async {
                            let Some(relay_arc) = relay.upgrade() else { return false };
                            let mut relay = relay_arc.lock().await;
                            if generation != relay.websocket_generation || !relay.started {
                                return false;
                            }
                            relay.send_message(Message::Ping(Vec::new().into())).await.is_ok()
                        }).await;
                        if !matches!(sent, Ok(true)) {
                            break;
                        }
                        continue;
                    }
                };
                // A received frame gets a fresh processing budget, independent
                // of the previous inactivity deadline, including mutex waits.
                let keep_reading = timeout(Duration::from_secs(5), async {
                    let Some(relay_arc) = relay.upgrade() else {
                        return false;
                    };
                    let mut relay = relay_arc.lock().await;
                    if generation != relay.websocket_generation || !relay.started {
                        return false;
                    }
                    match result {
                        Ok(message) => match message {
                            Message::Text(text) => {
                                match serde_json::from_str::<MessageToRelay>(&text) {
                                    Ok(message) => {
                                        let result = relay.handle_message(message).await;
                                        if let Err(error) = result {
                                            error!("Message handling failed with error: {}", error);
                                            return false;
                                        }
                                    }
                                    _ => {
                                        error!("Failed to deserialize message: {}", text);
                                    }
                                }
                            }
                            Message::Binary(data) => {
                                debug!("Received binary message of length: {}", data.len());
                            }
                            Message::Ping(data) => {
                                if relay.send_message(Message::Pong(data)).await.is_err() {
                                    return false;
                                }
                            }
                            Message::Pong(_) => {
                                debug!("Received pong message");
                            }
                            Message::Close(frame) => {
                                info!("Received close message: {:?}", frame);
                                return false;
                            }
                            Message::Frame(_) => {
                                unreachable!("This is never used")
                            }
                        },
                        Err(e) => {
                            debug!("Error processing message: {}", e);
                            return false;
                        }
                    }
                    true
                })
                .await;
                if !matches!(keep_reading, Ok(true)) {
                    break;
                }
            }
            let Some(relay_arc) = relay.upgrade() else {
                return;
            };
            let mut relay = relay_arc.lock().await;
            if generation == relay.websocket_generation && relay.started {
                // Reconnect stops the other workers. This reader is its caller.
                relay.ws_reader.take();
                drop(reader);
                relay.reconnect_soon().await;
            }
        }));
    }

    async fn stop_internal(&mut self) {
        self.websocket_generation = self.websocket_generation.wrapping_add(1);
        self.connected = false;
        self.wrong_password = false;
        self.streamer_ip = None;
        self.update_status();
        *self.start_on_reconnect_soon.lock().await = false;
        if let Some(reader) = self.ws_reader.take() {
            reader.abort();
            reader.await.ok();
        }
        self.stop_tunnel().await;
        if let Some(mut ws_writer) = self.ws_writer.take() {
            timeout(Duration::from_secs(2), ws_writer.close())
                .await
                .ok();
        }
        self.connected = false;
        self.wrong_password = false;
        self.update_status();
    }

    async fn stop_tunnel(&mut self) {
        let outbound = self.relay_to_destination.take();
        let inbound = self.relay_to_streamer.take();
        if let Some(task) = &outbound {
            task.abort();
        }
        if let Some(task) = &inbound {
            task.abort();
        }
        if let Some(task) = outbound {
            task.await.ok();
        }
        if let Some(task) = inbound {
            task.await.ok();
        }
    }

    fn update_status(&self) {
        self.connection_status.send_replace(ConnectionStatus {
            connected: self.connected,
            wrong_password: self.wrong_password,
            streamer_ip: self.streamer_ip.clone(),
        });
        let Some(on_status_updated) = &self.on_status_updated else {
            return;
        };
        let status = if self.connected {
            "Connected to streamer"
        } else if self.wrong_password {
            "Wrong password"
        } else if self.started {
            "Connecting to streamer"
        } else {
            "Disconnected from streamer"
        };
        on_status_updated(status.to_string());
    }

    async fn reconnect_soon(&mut self) {
        self.stop_internal().await;
        let start_on_reconnect_soon = Arc::new(Mutex::new(true));
        self.start_on_reconnect_soon = start_on_reconnect_soon.clone();
        self.start_soon(start_on_reconnect_soon);
    }

    fn start_soon(&mut self, start_on_reconnect_soon: Arc<Mutex<bool>>) {
        let relay = self.me.clone();

        tokio::spawn(async move {
            sleep(Duration::from_secs(5)).await;

            if let Some(relay) = relay.upgrade() {
                let mut relay = relay.lock().await;
                let should_start = *start_on_reconnect_soon.lock().await;
                if should_start {
                    debug!("Reconnecting...");
                    relay.start_internal().await;
                }
            }
        });
    }

    async fn handle_message(&mut self, message: MessageToRelay) -> Result<(), AnyError> {
        match message {
            MessageToRelay::Hello(hello) => self.handle_message_hello(hello).await,
            MessageToRelay::Identified(identified) => {
                self.handle_message_identified(identified).await
            }
            MessageToRelay::Request(request) => self.handle_message_request(request).await,
        }
    }

    async fn handle_message_hello(&mut self, hello: Hello) -> Result<(), AnyError> {
        let authentication = calculate_authentication(
            &self.password,
            &hello.authentication.salt,
            &hello.authentication.challenge,
        );
        let identify = Identify {
            id: self.relay_id,
            name: self.name.clone(),
            authentication,
        };
        self.send(MessageToStreamer::Identify(identify)).await
    }

    async fn handle_message_identified(&mut self, identified: Identified) -> Result<(), AnyError> {
        match identified.result {
            MoblinkResult::Ok(_) => {
                self.connected = true;
                self.wrong_password = false;
            }
            MoblinkResult::WrongPassword(_) => {
                self.connected = false;
                self.wrong_password = true;
            }
        }
        self.update_status();
        Ok(())
    }

    async fn handle_message_request(&mut self, request: MessageRequest) -> Result<(), AnyError> {
        match &request.data {
            MessageRequestData::StartTunnel(start_tunnel) => {
                self.handle_message_request_start_tunnel(&request, start_tunnel)
                    .await
            }
            MessageRequestData::Status(_) => self.handle_message_request_status(request).await,
        }
    }

    async fn handle_message_request_start_tunnel(
        &mut self,
        request: &MessageRequest,
        start_tunnel: &StartTunnelRequest,
    ) -> Result<(), AnyError> {
        self.stop_tunnel().await;

        // Pick bind addresses from the relay
        let local_bind_addr_for_streamer = parse_socket_addr("0.0.0.0")?;
        let local_bind_addr_for_destination = parse_socket_addr(&self.bind_address)?;

        debug!(
            "Binding streamer socket on: {}, destination socket on: {}",
            local_bind_addr_for_streamer, local_bind_addr_for_destination
        );
        // Create a UDP socket bound for receiving packets from the server.
        // Use dual-stack socket creation.
        let streamer_socket = create_dual_stack_udp_socket(local_bind_addr_for_streamer).await?;
        let streamer_port = streamer_socket.local_addr()?.port();
        let streamer_socket = Arc::new(streamer_socket);

        // Inform the server about the chosen port.
        let data = ResponseData::StartTunnel(StartTunnelResponseData {
            port: streamer_port,
        });
        let response = request.to_ok_response(data);
        self.send(MessageToStreamer::Response(response)).await?;

        // Create a new UDP socket for communication with the destination.
        // Use dual-stack socket creation.
        let destination_socket =
            create_dual_stack_udp_socket(local_bind_addr_for_destination).await?;

        let destination_socket = Arc::new(destination_socket);
        let destination_address = resolve_host(&start_tunnel.address).await?;
        let destination_address = match IpAddr::from_str(&destination_address)? {
            IpAddr::V4(v4) => IpAddr::V4(v4),
            IpAddr::V6(v6) => {
                // If it’s an IPv4-mapped IPv6 like ::ffff:x.x.x.x, convert to real IPv4
                if let Some(mapped_v4) = v6.to_ipv4() {
                    IpAddr::V4(mapped_v4)
                } else {
                    // Otherwise, keep it as IPv6
                    IpAddr::V6(v6)
                }
            }
        };

        let destination_address = SocketAddr::new(destination_address, start_tunnel.port);
        info!("Destination address: {}", destination_address);

        self.start_tunnel(streamer_socket, destination_socket, destination_address);
        Ok(())
    }

    fn start_tunnel(
        &mut self,
        streamer_socket: Arc<UdpSocket>,
        destination_socket: Arc<UdpSocket>,
        destination_addr: SocketAddr,
    ) {
        let streamer_address = Arc::new(Mutex::new(None));
        let first_packet = Arc::new(Notify::new());

        let relay = self.me.clone();
        let input = streamer_socket.clone();
        let output = destination_socket.clone();
        let address = streamer_address.clone();
        let ready = first_packet.clone();
        self.relay_to_streamer = Some(tokio::spawn(async move {
            // Start the return-path timeout only once the streamer is sending.
            ready.notified().await;
            loop {
                if let Err(error) =
                    relay_one_packet_from_destination_to_streamer(&input, &output, &address).await
                {
                    info!("(relay_to_streamer) Failed with error: {}", error);
                    break;
                }
            }

            drop((input, output));
            if let Some(relay) = relay.upgrade() {
                let mut relay = relay.lock().await;
                // This task owns the reconnect. Detach it before stopping
                // the tunnel so the relay does not try to join it here.
                relay.relay_to_streamer.take();
                relay.reconnect_soon().await;
            }
        }));

        self.relay_to_destination = Some(tokio::spawn(async move {
            let mut buf = [0; 2048];
            loop {
                let (size, remote_addr) = streamer_socket.recv_from(&mut buf).await?;
                destination_socket
                    .send_to(&buf[..size], &destination_addr)
                    .await?;
                if streamer_address.lock().await.replace(remote_addr).is_none() {
                    first_packet.notify_one();
                }
            }
        }));
    }

    async fn handle_message_request_status(
        &mut self,
        request: MessageRequest,
    ) -> Result<(), AnyError> {
        let mut battery_percentage = None;
        if let Some(get_status) = self.get_status.as_ref() {
            battery_percentage = get_status().await.battery_percentage;
        }
        let data = ResponseData::Status(StatusResponseData { battery_percentage });
        let response = request.to_ok_response(data);
        self.send(MessageToStreamer::Response(response)).await
    }

    async fn send(&mut self, message: MessageToStreamer) -> Result<(), AnyError> {
        let text = serde_json::to_string(&message)?;
        self.send_message(Message::Text(text.into())).await
    }

    async fn send_message(&mut self, message: Message) -> Result<(), AnyError> {
        let Some(writer) = self.ws_writer.as_mut() else {
            return Err("No websocket writer".into());
        };
        timeout(Duration::from_secs(5), writer.send(message)).await??;
        Ok(())
    }
}

pub struct Relay {
    inner: Arc<Mutex<RelayInner>>,
    connection_status: watch::Receiver<ConnectionStatus>,
}

impl Default for Relay {
    fn default() -> Self {
        Self::new()
    }
}

impl Relay {
    pub fn new() -> Self {
        let (sender, receiver) = watch::channel(ConnectionStatus::default());
        Self {
            inner: RelayInner::new(sender),
            connection_status: receiver,
        }
    }

    // A snapshot must not lock RelayInner while the supervisor holds its own lock:
    // relay status callbacks can acquire the supervisor lock in the opposite order.
    pub fn connection_status(&self) -> ConnectionStatus {
        self.connection_status.borrow().clone()
    }

    pub async fn set_bind_address(&self, address: String) {
        self.inner.lock().await.set_bind_address(address);
    }

    pub async fn setup<F>(
        &self,
        streamer_url: String,
        password: String,
        relay_id: Uuid,
        name: String,
        on_status_updated: F,
        get_status: Option<GetStatusClosure>,
    ) where
        F: Fn(String) + Send + Sync + 'static,
    {
        self.inner
            .lock()
            .await
            .setup(
                streamer_url,
                password,
                relay_id,
                name,
                on_status_updated,
                get_status,
            )
            .await;
    }

    pub async fn is_started(&self) -> bool {
        self.inner.lock().await.is_started()
    }

    pub async fn start(&self) {
        self.inner.lock().await.start().await;
    }

    pub async fn stop(&self) {
        self.inner.lock().await.stop().await;
    }
}

#[cfg(test)]
mod connection_tests {
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_async;

    use super::*;

    async fn pair() -> (Relay, WebSocketStream<TcpStream>, TcpListener) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay = Relay::new();
        relay
            .setup(
                format!("ws://localhost:{}", listener.local_addr().unwrap().port()),
                "test".into(),
                Uuid::new_v4(),
                "test".into(),
                |_| {},
                None,
            )
            .await;
        let (_, server) = tokio::join!(relay.start(), async {
            let (stream, _) = listener.accept().await.unwrap();
            accept_async(stream).await.unwrap()
        });
        (relay, server, listener)
    }

    async fn wait_state(relay: &Relay, connected: bool, wrong_password: bool) {
        timeout(Duration::from_secs(3), async {
            loop {
                let status = relay.connection_status();
                if status.connected == connected && status.wrong_password == wrong_password {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn identify(server: &mut WebSocketStream<TcpStream>, result: MoblinkResult) {
        let message =
            serde_json::to_string(&MessageToRelay::Identified(Identified { result })).unwrap();
        server.send(Message::Text(message.into())).await.unwrap();
    }

    #[tokio::test]
    async fn authentication_and_wrong_password_are_distinct_from_tcp() {
        let (relay, mut server, _listener) = pair().await;
        assert!(!relay.connection_status().connected);
        assert_eq!(
            relay.connection_status().streamer_ip.as_deref(),
            Some("127.0.0.1")
        );
        identify(&mut server, MoblinkResult::WrongPassword(Present {})).await;
        wait_state(&relay, false, true).await;
        identify(&mut server, MoblinkResult::Ok(Present {})).await;
        wait_state(&relay, true, false).await;
        relay.stop().await;
        wait_state(&relay, false, false).await;
    }

    #[tokio::test]
    async fn socket_loss_clears_authentication_and_reconnects() {
        let (relay, mut server, listener) = pair().await;
        identify(&mut server, MoblinkResult::Ok(Present {})).await;
        wait_state(&relay, true, false).await;
        drop(server);
        wait_state(&relay, false, false).await;
        let _new_server = timeout(Duration::from_secs(8), async {
            let (stream, _) = listener.accept().await.unwrap();
            accept_async(stream).await.unwrap()
        })
        .await
        .unwrap();
        assert!(!relay.connection_status().connected);
        relay.stop().await;
    }

    #[tokio::test]
    async fn graceful_close_clears_authentication() {
        let (relay, mut server, _listener) = pair().await;
        identify(&mut server, MoblinkResult::Ok(Present {})).await;
        wait_state(&relay, true, false).await;
        server.close(None).await.unwrap();
        wait_state(&relay, false, false).await;
        relay.stop().await;
    }

    #[tokio::test]
    async fn failed_connections_keep_retrying_without_a_timer_lock_deadlock() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let relay = Relay::new();
        relay
            .setup(
                format!("ws://{address}"),
                "test".into(),
                Uuid::new_v4(),
                "test".into(),
                |_| {},
                None,
            )
            .await;
        relay.start().await;
        sleep(Duration::from_secs(11)).await;
        let inner = timeout(Duration::from_secs(1), relay.inner.lock())
            .await
            .unwrap();
        assert!(inner.websocket_generation >= 3);
        drop(inner);
        relay.stop().await;
    }

    #[tokio::test]
    async fn cancelled_retry_waiting_for_mutex_cannot_replace_session() {
        let (relay, mut server, listener) = pair().await;
        let mut inner = relay.inner.lock().await;
        inner.reconnect_soon().await;
        // The timer expires while stop/restart owns the mutex.
        sleep(Duration::from_secs(6)).await;
        inner.stop_internal().await;
        let (_, replacement) = tokio::join!(inner.start_internal(), async {
            let (stream, _) = listener.accept().await.unwrap();
            accept_async(stream).await.unwrap()
        });
        server.close(None).await.ok();
        drop(inner);
        let mut replacement = replacement;
        identify(&mut replacement, MoblinkResult::Ok(Present {})).await;
        wait_state(&relay, true, false).await;
        assert!(
            timeout(Duration::from_secs(1), listener.accept())
                .await
                .is_err()
        );
        assert!(relay.connection_status().connected);
        relay.stop().await;
    }

    async fn stalled_status_pair() -> (Relay, WebSocketStream<TcpStream>, TcpListener) {
        let (relay, mut server, listener) = pair().await;
        identify(&mut server, MoblinkResult::Ok(Present {})).await;
        wait_state(&relay, true, false).await;
        let entered = Arc::new(tokio::sync::Notify::new());
        let notify = entered.clone();
        relay.inner.lock().await.get_status = Some(Arc::new(Box::new(move || {
            let notify = notify.clone();
            Box::pin(async move {
                notify.notify_one();
                std::future::pending().await
            })
        })));
        let request = MessageToRelay::Request(MessageRequest {
            id: 1,
            data: MessageRequestData::Status(Present {}),
        });
        server
            .send(Message::Text(
                serde_json::to_string(&request).unwrap().into(),
            ))
            .await
            .unwrap();
        timeout(Duration::from_secs(1), entered.notified())
            .await
            .unwrap();
        (relay, server, listener)
    }

    #[tokio::test]
    async fn stalled_status_handler_disconnects_and_retries() {
        let (relay, _server, listener) = stalled_status_pair().await;
        timeout(Duration::from_secs(8), async {
            while relay.connection_status().connected {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let _replacement = timeout(Duration::from_secs(8), async {
            let (stream, _) = listener.accept().await.unwrap();
            accept_async(stream).await.unwrap()
        })
        .await
        .unwrap();
        relay.stop().await;
    }

    #[tokio::test]
    async fn stop_is_bounded_while_status_handler_stalls() {
        let (relay, _server, _listener) = stalled_status_pair().await;
        timeout(Duration::from_secs(8), relay.stop()).await.unwrap();
        assert!(!relay.connection_status().connected);
        assert!(!relay.is_started().await);
    }

    #[tokio::test]
    async fn status_near_idle_deadline_gets_fresh_processing_budget() {
        let (relay, mut server, _listener) = pair().await;
        identify(&mut server, MoblinkResult::Ok(Present {})).await;
        wait_state(&relay, true, false).await;
        relay.inner.lock().await.get_status = Some(Arc::new(Box::new(|| {
            Box::pin(async {
                sleep(Duration::from_secs(2)).await;
                Status {
                    battery_percentage: Some(73),
                }
            })
        })));
        // Leave pings unread so they cannot refresh the receive deadline.
        sleep(Duration::from_secs(44)).await;
        let request = MessageToRelay::Request(MessageRequest {
            id: 42,
            data: MessageRequestData::Status(Present {}),
        });
        server
            .send(Message::Text(
                serde_json::to_string(&request).unwrap().into(),
            ))
            .await
            .unwrap();
        let response = timeout(Duration::from_secs(4), async {
            loop {
                if let Message::Text(text) = server.next().await.unwrap().unwrap() {
                    break text;
                }
            }
        })
        .await
        .unwrap();
        let response: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(response["response"]["id"], 42);
        assert_eq!(
            response["response"]["data"]["status"]["batteryPercentage"],
            73
        );
        assert!(relay.connection_status().connected);
        relay.stop().await;
    }

    #[tokio::test]
    async fn silent_peer_is_disconnected_by_heartbeat() {
        let (relay, mut server, _listener) = pair().await;
        identify(&mut server, MoblinkResult::Ok(Present {})).await;
        wait_state(&relay, true, false).await;
        // Keep the TCP connection open but never read/respond to WebSocket pings.
        sleep(Duration::from_secs(47)).await;
        wait_state(&relay, false, false).await;
        relay.stop().await;
    }
}

async fn relay_one_packet_from_destination_to_streamer(
    streamer_socket: &Arc<UdpSocket>,
    destination_socket: &Arc<UdpSocket>,
    streamer_address: &Arc<Mutex<Option<SocketAddr>>>,
) -> Result<(), AnyError> {
    let mut buf = [0; 2048];
    let size = timeout(Duration::from_secs(30), destination_socket.recv(&mut buf)).await??;
    let streamer_addr = streamer_address
        .lock()
        .await
        .ok_or("Failed to get address lock")?;
    streamer_socket
        .send_to(&buf[..size], &streamer_addr)
        .await?;
    Ok(())
}

async fn create_dual_stack_udp_socket(
    addr: SocketAddr,
) -> Result<tokio::net::UdpSocket, std::io::Error> {
    let socket = match addr.is_ipv4() {
        true => {
            // Create an IPv4 socket
            tokio::net::UdpSocket::bind(addr).await?
        }
        false => {
            // Create a dual-stack socket (supporting both IPv4 and IPv6)
            let socket = socket2::Socket::new(
                socket2::Domain::IPV6,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;

            // Set IPV6_V6ONLY to false to enable dual-stack support
            socket.set_only_v6(false)?;

            // Bind the socket
            socket.bind(&socket2::SockAddr::from(addr))?;

            // Convert to a tokio UdpSocket
            tokio::net::UdpSocket::from_std(socket.into())?
        }
    };

    Ok(socket)
}

// Helper function to parse a string into a SocketAddr, handling IP addresses
// without ports.
fn parse_socket_addr(addr_str: &str) -> Result<SocketAddr, std::io::Error> {
    // Attempt to parse the string as a full SocketAddr (IP:port)
    if let Ok(socket_addr) = SocketAddr::from_str(addr_str) {
        return Ok(socket_addr);
    }

    // If parsing as SocketAddr fails, try parsing as IP address and append default
    // port
    if let Ok(ip_addr) = IpAddr::from_str(addr_str) {
        // Use 0 as the default port, allowing the OS to assign an available port
        return Ok(SocketAddr::new(ip_addr, 0));
    }

    // Return an error if both attempts fail
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        "Invalid socket address syntax. Expected 'IP:port' or 'IP'.",
    ))
}

pub fn create_get_status_closure(
    status_executable: &Option<String>,
    status_file: &Option<String>,
) -> Option<GetStatusClosure> {
    let status_executable = status_executable.clone();
    let status_file = status_file.clone();
    Some(Box::new(move || {
        let status_executable = status_executable.clone();
        let status_file = status_file.clone();
        Box::pin(async move {
            let output = if let Some(status_executable) = &status_executable {
                let Ok(output) = Command::new(status_executable)
                    .kill_on_drop(true)
                    .output()
                    .await
                else {
                    return Default::default();
                };
                output.stdout
            } else if let Some(status_file) = &status_file {
                let Ok(mut file) = File::open(status_file).await else {
                    return Default::default();
                };
                let mut contents = vec![];
                if file.read_to_end(&mut contents).await.is_err() {
                    return Default::default();
                }
                contents
            } else {
                return Default::default();
            };
            let output = String::from_utf8(output).unwrap_or_default();
            match serde_json::from_str(&output) {
                Ok(status) => status,
                Err(e) => {
                    error!("Failed to decode status with error: {e}");
                    Default::default()
                }
            }
        })
    }))
}
