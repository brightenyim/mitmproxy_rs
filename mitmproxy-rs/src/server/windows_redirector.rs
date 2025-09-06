#[cfg(windows)]
use std::collections::HashMap;
#[cfg(windows)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
#[cfg(windows)]
use std::time::Duration;
#[cfg(windows)]
use std::thread;

#[cfg(windows)]
use anyhow::{anyhow, Result};
#[cfg(windows)]
use internet_packet::{ConnectionId, InternetPacket, TransportProtocol};
#[cfg(windows)]
use log::{debug, error, info, warn};
#[cfg(windows)]
use lru_time_cache::LruCache;
#[cfg(windows)]
use mitmproxy::intercept_conf::{InterceptConf, ProcessInfo};
#[cfg(windows)]
use mitmproxy::windows::network::network_table;
#[cfg(windows)]
use mitmproxy::processes::get_process_name;
#[cfg(windows)]
use mitmproxy::MAX_PACKET_SIZE;
#[cfg(windows)]
use tokio::sync::mpsc;
#[cfg(windows)]
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
#[cfg(windows)]
use windivert::address::WinDivertAddress;
#[cfg(windows)]
use windivert::prelude::*;
#[cfg(windows)]
use pyo3::prelude::*;

#[cfg(windows)]
#[derive(Debug)]
pub enum Event {
    NetworkPacket(WinDivertAddress<NetworkLayer>, Vec<u8>),
    SocketInfo(WinDivertAddress<SocketLayer>),
    InterceptConf(InterceptConf),
}

#[cfg(windows)]
#[derive(Debug)]
pub enum ConnectionState {
    Known(ConnectionAction),
    Unknown(Vec<(WinDivertAddress<NetworkLayer>, InternetPacket)>),
}

#[cfg(windows)]
#[derive(Debug, Clone)]
pub enum ConnectionAction {
    None,
    Intercept(ProcessInfo),
}

#[cfg(windows)]
pub struct ActiveListeners(HashMap<(SocketAddr, TransportProtocol), ProcessInfo>);

#[cfg(windows)]
impl ActiveListeners {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn insert(
        &mut self,
        mut socket: SocketAddr,
        protocol: TransportProtocol,
        process_info: ProcessInfo,
    ) -> Option<ProcessInfo> {
        if socket.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
            socket.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        }
        self.0.insert((socket, protocol), process_info)
    }

    pub fn remove(
        &mut self,
        mut socket: SocketAddr,
        protocol: TransportProtocol,
    ) -> Option<ProcessInfo> {
        if socket.ip() == IpAddr::V6(Ipv6Addr::UNSPECIFIED) {
            socket.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        }
        self.0.remove(&(socket, protocol))
    }

    pub fn get(&self, mut socket: SocketAddr, protocol: TransportProtocol) -> Option<&ProcessInfo> {
        if !self.0.contains_key(&(socket, protocol)) {
            socket.set_ip(Ipv4Addr::UNSPECIFIED.into());
        }
        self.0.get(&(socket, protocol))
    }

    pub fn clear(&mut self) {
        self.0.clear();
    }
}

#[cfg(windows)]
#[pyclass(module = "mitmproxy_rs.local")]
#[derive(Debug)]
pub struct WindowsRedirector {
    event_tx: UnboundedSender<Event>,
}

#[cfg(windows)]
#[pymethods]
impl WindowsRedirector {
    #[new]
    pub fn py_new() -> PyResult<Self> {
        Err(PyErr::new::<pyo3::exceptions::PyNotImplementedError, _>(
            "Use WindowsRedirector.create() instead"
        ))
    }

    pub fn send_intercept_conf(&self, conf: String) -> PyResult<()> {
        let intercept_conf = InterceptConf::try_from(conf.as_str())
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Invalid intercept conf: {}", e)))?;
        
        self.send_intercept_conf_internal(intercept_conf)
            .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(format!("Failed to send intercept conf: {}", e)))?;
        
        Ok(())
    }
}

#[cfg(windows)]
impl WindowsRedirector {
    pub async fn new(_pipe_name: Option<String>) -> Result<Self> {
        // 在同一个进程内，我们不需要命名管道，直接使用内存通道
        let (event_tx, event_rx) = mpsc::unbounded_channel::<Event>();

        // Initialize WinDivert handles
        let socket_handle = WinDivert::socket(
            "tcp || udp",
            1041,
            WinDivertFlags::new().set_recv_only().set_sniff(),
        )?;
        let wd_net_filter = "!loopback && ((ip && remoteAddr < 224.0.0.0) || (ipv6 && remoteAddr < ff00::)) && (tcp || udp)";
        let network_handle = WinDivert::network(wd_net_filter, 1040, WinDivertFlags::new())?;
        let inject_handle = WinDivert::network("false", 1039, WinDivertFlags::new().set_send_only())?;

        // Start event relay threads
        let tx_clone = event_tx.clone();
        thread::spawn(move || relay_socket_events(socket_handle, tx_clone));
        let tx_clone = event_tx.clone();
        thread::spawn(move || relay_network_events(network_handle, tx_clone));

        // Clone channels before moving them
        let event_tx_clone = event_tx.clone();

        // Start main event loop (no IPC needed in same process)
        tokio::spawn(async move {
            if let Err(e) = Self::run_event_loop(event_rx, inject_handle).await {
                error!("Error in event loop: {}", e);
                std::process::exit(1);
            }
        });

        Ok(Self { 
            event_tx: event_tx_clone,
        })
    }

    pub fn send_intercept_conf_internal(&self, conf: InterceptConf) -> Result<()> {
        // 在同一个进程内，我们直接发送配置更新事件
        self.event_tx
            .send(Event::InterceptConf(conf))
            .map_err(|_| anyhow!("Failed to send intercept conf"))?;
        Ok(())
    }

    async fn handle_network_packet(
        address: WinDivertAddress<NetworkLayer>,
        data: Vec<u8>,
        state: &InterceptConf,
        connections: &mut LruCache<ConnectionId, ConnectionState>,
        active_listeners: &ActiveListeners,
        inject_handle: &WinDivert<NetworkLayer>,
    ) -> Result<()> {
        let packet = match InternetPacket::try_from(data) {
            Ok(p) => p,
            Err(e) => {
                debug!("Error parsing packet: {:?}", e);
                return Ok(());
            }
        };

        debug!(
            "Received packet: {} {} {}",
            packet.connection_id(),
            packet.tcp_flag_str(),
            packet.payload().len()
        );

        let is_multicast = packet.src_ip().is_multicast() || packet.dst_ip().is_multicast();
        let is_loopback_only = packet.src_ip().is_loopback() && packet.dst_ip().is_loopback();
        if is_multicast || is_loopback_only {
            debug!("skipping multicast={} loopback={}", is_multicast, is_loopback_only);
            inject_handle.send(&WinDivertPacket::<NetworkLayer> {
                address,
                data: packet.inner().into(),
            })?;
            return Ok(());
        }

        match connections.get_mut(&packet.connection_id()) {
            Some(connection_state) => match connection_state {
                ConnectionState::Known(action) => {
                    Self::process_packet(address, packet, action, inject_handle).await?;
                }
                ConnectionState::Unknown(packets) => {
                    packets.push((address, packet));
                }
            },
            None => {
                if address.outbound() {
                    debug!("Adding unknown packet: {}", packet.connection_id());
                    connections.insert(
                        packet.connection_id(),
                        ConnectionState::Unknown(vec![(address, packet)]),
                    );
                } else {
                    let action = if let Some(proc_info) = active_listeners.get(packet.dst(), packet.protocol()) {
                        debug!("Inbound packet for known application: {:?} ({})", &proc_info.process_name, &proc_info.pid);
                        if state.should_intercept(proc_info) {
                            ConnectionAction::Intercept(proc_info.clone())
                        } else {
                            ConnectionAction::None
                        }
                    } else {
                        debug!("Unknown inbound packet. Passing through.");
                        ConnectionAction::None
                    };
                    Self::insert_into_connections(
                        packet.connection_id(),
                        &action,
                        &address.event(),
                        connections,
                        inject_handle,
                    ).await?;
                    Self::process_packet(address, packet, &action, inject_handle).await?;
                }
            }
        }
        Ok(())
    }

    async fn handle_socket_info(
        address: WinDivertAddress<SocketLayer>,
        state: &InterceptConf,
        connections: &mut LruCache<ConnectionId, ConnectionState>,
        active_listeners: &mut ActiveListeners,
        inject_handle: &WinDivert<NetworkLayer>,
    ) -> Result<()> {
        if address.process_id() == 4 {
            debug!("Skipping PID 4");
            return Ok(());
        }

        let Ok(proto) = TransportProtocol::try_from(address.protocol()) else {
            warn!("Unknown transport protocol: {}", address.protocol());
            return Ok(());
        };
        let connection_id = ConnectionId {
            proto,
            src: SocketAddr::from((address.local_address(), address.local_port())),
            dst: SocketAddr::from((address.remote_address(), address.remote_port())),
        };

        if connection_id.src.ip().is_multicast() || connection_id.dst.ip().is_multicast() {
            return Ok(());
        }

        match address.event() {
            WinDivertEvent::SocketConnect | WinDivertEvent::SocketAccept => {
                let make_entry = match connections.get(&connection_id) {
                    None => true,
                    Some(e) => matches!(e, ConnectionState::Unknown(_)),
                };

                debug!(
                    "{:<15?} make_entry={} pid={} {}",
                    address.event(),
                    make_entry,
                    address.process_id(),
                    connection_id
                );

                if !make_entry {
                    return Ok(());
                }

                let proc_info = ProcessInfo {
                    pid: address.process_id(),
                    process_name: get_process_name(address.process_id())
                        .map(|x| x.to_string_lossy().into_owned())
                        .ok(),
                };

                let action = if state.should_intercept(&proc_info) {
                    ConnectionAction::Intercept(proc_info)
                } else {
                    ConnectionAction::None
                };

                Self::insert_into_connections(
                    connection_id,
                    &action,
                    &address.event(),
                    connections,
                    inject_handle,
                ).await?;
            }
            WinDivertEvent::SocketListen => {
                let pid = address.process_id();
                let process_name = get_process_name(pid)
                    .map(|x| x.to_string_lossy().into_owned())
                    .ok();
                debug!("Registering {:?} on {}.", process_name, connection_id.src);
                active_listeners.insert(
                    connection_id.src,
                    proto,
                    ProcessInfo { pid, process_name },
                );
            }
            WinDivertEvent::SocketClose => {
                if let Some(ConnectionState::Unknown(packets)) = connections.get_mut(&connection_id) {
                    packets.clear();
                }
                active_listeners.remove(connection_id.src, proto);
            }
            _ => {}
        }
        Ok(())
    }


    async fn handle_intercept_conf_change(
        state: &InterceptConf,
        connections: &mut LruCache<ConnectionId, ConnectionState>,
        active_listeners: &mut ActiveListeners,
        inject_handle: &WinDivert<NetworkLayer>,
    ) -> Result<()> {
        connections.clear();
        active_listeners.clear();
        
        for e in network_table()? {
            let proc_info = ProcessInfo {
                pid: e.pid,
                process_name: get_process_name(e.pid)
                    .map(|x| x.to_string_lossy().into_owned())
                    .ok(),
            };
            let proto = TransportProtocol::try_from(e.protocol)?;
            if e.remote_addr.ip().is_unspecified() {
                active_listeners.insert(e.local_addr, proto, proc_info);
            } else {
                let connection_id = ConnectionId {
                    proto,
                    src: e.local_addr,
                    dst: e.remote_addr,
                };
                let action = if state.should_intercept(&proc_info) {
                    ConnectionAction::Intercept(proc_info)
                } else {
                    ConnectionAction::None
                };
                Self::insert_into_connections(
                    connection_id,
                    &action,
                    &WinDivertEvent::ReflectOpen,
                    connections,
                    inject_handle,
                ).await?;
            }
        }
        Ok(())
    }

    async fn insert_into_connections(
        connection_id: ConnectionId,
        action: &ConnectionAction,
        _event: &WinDivertEvent,
        connections: &mut LruCache<ConnectionId, ConnectionState>,
        inject_handle: &WinDivert<NetworkLayer>,
    ) -> Result<()> {
        debug!("Adding: {} with {:?}", &connection_id, action);

        let existing1 = connections.insert(
            connection_id.reverse(),
            ConnectionState::Known(ConnectionAction::None),
        );
        let existing2 = connections.insert(connection_id, ConnectionState::Known(action.clone()));

        if let Some(ConnectionState::Unknown(packets)) = existing1 {
            for (a, p) in packets {
                Self::process_packet(a, p, &ConnectionAction::None, inject_handle).await?;
            }
        }
        if let Some(ConnectionState::Unknown(packets)) = existing2 {
            for (a, p) in packets {
                Self::process_packet(a, p, action, inject_handle).await?;
            }
        }
        Ok(())
    }

    async fn process_packet(
        address: WinDivertAddress<NetworkLayer>,
        mut packet: InternetPacket,
        action: &ConnectionAction,
        inject_handle: &WinDivert<NetworkLayer>,
    ) -> Result<()> {
        match action {
            ConnectionAction::None => {
                debug!(
                    "Forwarding: {} {} outbound={} loopback={}",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    address.outbound(),
                    address.loopback()
                );
                inject_handle.send(&WinDivertPacket::<NetworkLayer> {
                    address,
                    data: packet.inner().into(),
                })?;
            }
            ConnectionAction::Intercept(ProcessInfo { pid, process_name }) => {
                info!(
                    "Intercepting: {} {} outbound={} loopback={} (PID: {}, Process: {:?})",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    address.outbound(),
                    address.loopback(),
                    pid,
                    process_name
                );

                if !address.ip_checksum() {
                    packet.recalculate_ip_checksum();
                }
                if !address.tcp_checksum() {
                    packet.recalculate_tcp_checksum();
                }
                if !address.udp_checksum() {
                    packet.recalculate_udp_checksum();
                }

                // 在同一个进程内，我们不需要通过 IPC 发送数据包
                // 数据包已经被拦截，可以根据需要在这里处理
                // 例如：记录日志、修改数据包内容等
            }
        }
        Ok(())
    }

    async fn run_event_loop(
        mut event_rx: UnboundedReceiver<Event>,
        inject_handle: WinDivert<NetworkLayer>,
    ) -> Result<()> {
        let mut state = InterceptConf::disabled();
        let mut connections = LruCache::<ConnectionId, ConnectionState>::with_expiry_duration(
            Duration::from_secs(60 * 10),
        );
        let mut active_listeners = ActiveListeners::new();

        while let Some(result) = event_rx.recv().await {
            match result {
                Event::NetworkPacket(address, data) => {
                    Self::handle_network_packet(
                        address, 
                        data, 
                        &state, 
                        &mut connections, 
                        &active_listeners, 
                        &inject_handle
                    ).await?;
                }
                Event::SocketInfo(address) => {
                    Self::handle_socket_info(
                        address, 
                        &state, 
                        &mut connections, 
                        &mut active_listeners, 
                        &inject_handle
                    ).await?;
                }
                Event::InterceptConf(conf) => {
                    state = conf;
                    info!("{}", state.description());
                    Self::handle_intercept_conf_change(
                        &state, 
                        &mut connections, 
                        &mut active_listeners, 
                        &inject_handle
                    ).await?;
                }
            }
        }
        Ok(())
    }
}



#[cfg(windows)]
fn relay_socket_events(handle: WinDivert<SocketLayer>, tx: UnboundedSender<Event>) {
    loop {
        let packets = handle.recv_ex(1);
        match packets {
            Ok(packets) => {
                for packet in packets {
                    if tx.send(Event::SocketInfo(packet.address)).is_err() {
                        return;
                    }
                }
            }
            Err(err) => {
                eprintln!("WinDivert Error: {err:?}");
                std::process::exit(74);
            }
        };
    }
}

#[cfg(windows)]
fn relay_network_events(handle: WinDivert<NetworkLayer>, tx: UnboundedSender<Event>) {
    const MAX_PACKETS: usize = 1;
    let mut buf = [0u8; MAX_PACKET_SIZE * MAX_PACKETS];
    loop {
        let packets = handle.recv_ex(Some(&mut buf), MAX_PACKETS);
        match packets {
            Ok(packets) => {
                for packet in packets {
                    if tx
                        .send(Event::NetworkPacket(packet.address, packet.data.into()))
                        .is_err()
                    {
                        return;
                    }
                }
            }
            Err(err) => {
                eprintln!("WinDivert Error: {err:?}");
                std::process::exit(74);
            }
        };
    }
}

#[cfg(not(windows))]
#[derive(Debug)]
pub struct WindowsRedirector;

#[cfg(not(windows))]
impl WindowsRedirector {
    pub async fn new(_pipe_name: Option<String>) -> anyhow::Result<Self> {
        Err(anyhow::anyhow!("Windows redirector only works on Windows"))
    }

    pub fn send_intercept_conf_internal(&self, _conf: mitmproxy::intercept_conf::InterceptConf) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("Windows redirector only works on Windows"))
    }
}
