//! A TCP forwarder that can be switched off, to simulate a dependency
//! (S3, Datadog, the control plane) going away and coming back.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::net::{TcpListener, TcpStream};

#[derive(Debug, Clone)]
pub struct ToggleProxy {
    pub addr: SocketAddr,
    up: Arc<AtomicBool>,
}

impl ToggleProxy {
    /// Forward 127.0.0.1:<random> to `target`.
    ///
    /// # Panics
    /// If it can't bind. Tests only.
    pub async fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let up = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&up);
        tokio::spawn(async move {
            while let Ok((mut inbound, _)) = listener.accept().await {
                if !flag.load(Ordering::SeqCst) {
                    // Down: refuse by closing immediately.
                    drop(inbound);
                    continue;
                }
                let flag = Arc::clone(&flag);
                tokio::spawn(async move {
                    let Ok(mut outbound) = TcpStream::connect(target).await else {
                        return;
                    };
                    let pump = tokio::io::copy_bidirectional(&mut inbound, &mut outbound);
                    tokio::pin!(pump);
                    loop {
                        tokio::select! {
                            _ = &mut pump => return,
                            () = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                                // Going down cuts open connections too.
                                if !flag.load(Ordering::SeqCst) {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });
        Self { addr, up }
    }

    pub fn set_up(&self, up: bool) {
        self.up.store(up, Ordering::SeqCst);
    }
}
