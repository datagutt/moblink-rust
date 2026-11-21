#![cfg(unix)]

use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::process::Command;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{WebSocketStream, accept_async};
use uuid::Uuid;

struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).ok();
    }
}

async fn request(peer: &mut WebSocketStream<TcpStream>, id: u32, data: Value) {
    let message = json!({ "request": { "id": id, "data": data } });
    peer.send(Message::Text(message.to_string().into()))
        .await
        .unwrap();
}

async fn response(peer: &mut WebSocketStream<TcpStream>, id: u32) -> Value {
    loop {
        match peer.next().await.unwrap().unwrap() {
            Message::Text(text) => {
                let message: Value = serde_json::from_str(&text).unwrap();
                let reply = &message["response"];
                assert_eq!(reply["id"], id);
                assert_eq!(reply["result"], json!({ "ok": {} }));
                return reply["data"].clone();
            }
            Message::Ping(payload) => peer.send(Message::Pong(payload)).await.unwrap(),
            frame => panic!("unexpected frame while awaiting response to {id}: {frame:?}"),
        }
    }
}

#[tokio::test]
async fn slow_status_executable_preserves_standalone_tunnel() {
    let scratch = Scratch(std::env::temp_dir().join(format!("moblink-status-{}", Uuid::new_v4())));
    std::fs::create_dir(&scratch.0).unwrap();
    let executable = scratch.0.join("status");
    std::fs::write(
        &executable,
        b"#!/bin/sh\nprintf started > started\nsleep 6\nprintf '{\"batteryPercentage\":73}\\n'\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();

    let local = Ipv4Addr::LOCALHOST;
    let listener = TcpListener::bind((local, 0)).await.unwrap();
    let destination = UdpSocket::bind((local, 0)).await.unwrap();
    let sender = UdpSocket::bind((local, 0)).await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let binary = std::env::var_os("MOBLINK_RELAY_BIN")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_moblink-relay").into());
    let mut relay = Command::new(std::fs::canonicalize(binary).unwrap())
        .args([
            "--streamer-url",
            &url,
            "--bind-address",
            "127.0.0.1",
            "--status-executable",
        ])
        .arg(executable)
        .current_dir(&scratch.0)
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut peer = timeout(Duration::from_secs(5), async {
        accept_async(listener.accept().await.unwrap().0)
            .await
            .unwrap()
    })
    .await
    .expect("standalone relay did not connect");

    let tunnel = timeout(Duration::from_secs(5), async {
        request(
            &mut peer,
            1,
            json!({ "startTunnel": {
                "address": local.to_string(),
                "port": destination.local_addr().unwrap().port()
            } }),
        )
        .await;
        let response = response(&mut peer, 1).await;
        let port = response["startTunnel"]["port"].as_u64().unwrap();
        (local, u16::try_from(port).unwrap())
    })
    .await
    .expect("tunnel setup stalled");

    let sender = &sender;
    let destination = &destination;
    let round_trip = |tag: u8| async move {
        sender.send_to(&[tag], tunnel).await.unwrap();
        let mut buf = [0; 8];
        let (len, relay_addr) = destination.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], &[tag]);
        destination.send_to(&[tag], relay_addr).await.unwrap();
        let (len, _) = sender.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], &[tag]);
    };
    timeout(Duration::from_secs(2), round_trip(0))
        .await
        .unwrap();
    let requested = tokio::time::Instant::now();
    request(&mut peer, 2, json!({ "status": {} })).await;
    tokio::join!(
        async {
            let reply = timeout(Duration::from_secs(7), response(&mut peer, 2))
                .await
                .expect("slow lookup did not return a status reply in time");
            assert_eq!(reply, json!({ "status": {} }));
            assert!(requested.elapsed() < Duration::from_secs(5));
        },
        async {
            // Keep probing past both the message deadline and the script's
            // six-second runtime, using the original tunnel throughout.
            for tag in 1..=14 {
                sleep(Duration::from_millis(500)).await;
                timeout(Duration::from_secs(1), round_trip(tag))
                    .await
                    .expect("status lookup interrupted the tunnel");
            }
        },
    );
    assert!(
        scratch.0.join("started").is_file(),
        "status executable never ran"
    );
    relay.kill().await.unwrap();
}
