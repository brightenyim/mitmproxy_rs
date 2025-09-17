// This module provides a direct integration of WinDivert functionality
// into mitmproxy-rs, eliminating the need for an external redirector process.

use anyhow::Result;
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender};
use crate::intercept_conf::InterceptConf;
use crate::messages::{TransportCommand, TransportEvent};
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};
use crate::shutdown;

// On Windows, we provide the actual implementation
#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::Duration;
    use std::{thread, sync::Arc};

    use anyhow::Context;
    use internet_packet::{ConnectionId, InternetPacket, TransportProtocol};
    use log::{debug, error, info, warn};
    use lru_time_cache::LruCache;
    use tokio::sync::mpsc;
    use tokio::sync::Mutex;
    use windivert::address::WinDivertAddress;
    use windivert::prelude::*;

    use crate::intercept_conf::ProcessInfo;
    use crate::windows::network::network_table;
    use crate::processes::get_process_name;
    use crate::MAX_PACKET_SIZE;
    use crate::messages::{NetworkCommand, NetworkEvent, SmolPacket, TunnelInfo};
    use crate::network::add_network_layer;

    #[derive(Debug)]
    enum Event {
        NetworkPacket(WinDivertAddress<NetworkLayer>, Vec<u8>),
        SocketInfo(WinDivertAddress<SocketLayer>),
        InterceptConf(InterceptConf),
    }

    #[derive(Debug)]
    enum ConnectionState {
        Known(ConnectionAction),
        Unknown(Vec<(WinDivertAddress<NetworkLayer>, InternetPacket)>),
    }

    #[derive(Debug, Clone)]
    enum ConnectionAction {
        None,
        Intercept(ProcessInfo),
    }

    struct ActiveListeners(HashMap<(SocketAddr, TransportProtocol), ProcessInfo>);

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

    pub struct WindowsDirectTask {
        event_rx: tokio::sync::mpsc::UnboundedReceiver<Event>,
        event_tx: tokio::sync::mpsc::UnboundedSender<Event>,
        conf_rx: UnboundedReceiver<InterceptConf>,
        net_tx: Sender<NetworkEvent>,
        net_rx: tokio::sync::mpsc::Receiver<NetworkCommand>,
        inject_handle: Arc<Mutex<WinDivert<NetworkLayer>>>,
        network_task_handle: tokio::task::JoinHandle<Result<()>>,
        _shutdown: shutdown::Receiver,
    }

    impl PacketSourceTask for WindowsDirectTask {
        async fn run(mut self) -> Result<()> {
            let mut connections = LruCache::<ConnectionId, ConnectionState>::with_expiry_duration(
                Duration::from_secs(60 * 10),
            );
            let mut active_listeners = ActiveListeners::new();
            let mut state = InterceptConf::disabled();

            self.event_tx.send(Event::InterceptConf(state.clone()))?;

            loop {
                tokio::select! {
                    exit = &mut self.network_task_handle => {
                        break exit.context("network task panic")?.context("network task error")?;
                    }
                    
                    Some(conf) = self.conf_rx.recv() => {
                        self.event_tx.send(Event::InterceptConf(conf))?;
                    }
                    
                    Some(cmd) = self.net_rx.recv() => {
                        match cmd {
                            NetworkCommand::SendPacket(packet) => {
                                self.handle_send_packet(packet.into_inner()).await?;
                            }
                        }
                    }
                    
                    Some(event) = self.event_rx.recv() => {
                        match event {
                            Event::NetworkPacket(address, data) => {
                                self.handle_network_packet(
                                    address, 
                                    data, 
                                    &state, 
                                    &mut connections, 
                                    &active_listeners
                                ).await?;
                            }
                            Event::SocketInfo(address) => {
                                self.handle_socket_info(
                                    address, 
                                    &state, 
                                    &mut connections, 
                                    &mut active_listeners
                                ).await?;
                            }
                            Event::InterceptConf(conf) => {
                                state = conf;
                                info!("{}", state.description());
                                
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
                                        self.insert_into_connections(
                                            connection_id,
                                            &action,
                                            &WinDivertEvent::ReflectOpen,
                                            &mut connections,
                                        ).await?;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            Ok(())
        }
    }

    impl WindowsDirectTask {
        async fn handle_network_packet(
            &self,
            address: WinDivertAddress<NetworkLayer>,
            data: Vec<u8>,
            state: &InterceptConf,
            connections: &mut LruCache<ConnectionId, ConnectionState>,
            active_listeners: &ActiveListeners,
        ) -> Result<()> {
            let packet = match InternetPacket::try_from(data) {
                Ok(p) => p,
                Err(e) => {
                    debug!("Error parsing packet: {:?}", e);
                    return Ok(());
                }
            };

            let is_multicast = packet.src_ip().is_multicast() || packet.dst_ip().is_multicast();
            let is_loopback_only = packet.src_ip().is_loopback() && packet.dst_ip().is_loopback();
            
            if is_multicast || is_loopback_only {
                self.inject_packet(address, packet).await?;
                return Ok(());
            }

            match connections.get_mut(&packet.connection_id()) {
                Some(state) => match state {
                    ConnectionState::Known(s) => {
                        self.process_packet(address, packet, s).await?;
                    }
                    ConnectionState::Unknown(packets) => {
                        packets.push((address, packet));
                    }
                },
                None => {
                    if address.outbound() {
                        connections.insert(
                            packet.connection_id(),
                            ConnectionState::Unknown(vec![(address, packet)]),
                        );
                    } else {
                        let action = {
                            if let Some(proc_info) = active_listeners.get(packet.dst(), packet.protocol()) {
                                if state.should_intercept(proc_info) {
                                    ConnectionAction::Intercept(proc_info.clone())
                                } else {
                                    ConnectionAction::None
                                }
                            } else {
                                ConnectionAction::None
                            }
                        };
                        self.insert_into_connections(
                            packet.connection_id(),
                            &action,
                            &address.event(),
                            connections,
                        ).await?;
                        self.process_packet(address, packet, &action).await?;
                    }
                }
            }

            Ok(())
        }

        async fn handle_socket_info(
            &self,
            address: WinDivertAddress<SocketLayer>,
            state: &InterceptConf,
            connections: &mut LruCache<ConnectionId, ConnectionState>,
            active_listeners: &mut ActiveListeners,
        ) -> Result<()> {
            if address.process_id() == 4 {
                return Ok(());
            }

            let Ok(proto) = TransportProtocol::try_from(address.protocol()) else {
                return Ok(());
            };
            
            let connection_id = ConnectionId {
                proto,
                src: SocketAddr::from((address.local_address(), address.local_port())),
                dst: SocketAddr::from((address.remote_address(), address.remote_port())),
            };

            match address.event() {
                WinDivertEvent::SocketConnect | WinDivertEvent::SocketAccept => {
                    let make_entry = match connections.get(&connection_id) {
                        None => true,
                        Some(e) => matches!(e, ConnectionState::Unknown(_)),
                    };

                    if make_entry {
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

                        self.insert_into_connections(
                            connection_id,
                            &action,
                            &address.event(),
                            connections,
                        ).await?;
                    }
                }
                WinDivertEvent::SocketListen => {
                    let proc_info = ProcessInfo {
                        pid: address.process_id(),
                        process_name: get_process_name(address.process_id())
                            .map(|x| x.to_string_lossy().into_owned())
                            .ok(),
                    };
                    active_listeners.insert(connection_id.src, proto, proc_info);
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

        async fn handle_send_packet(&self, data: Vec<u8>) -> Result<()> {
            let mut address = unsafe { WinDivertAddress::<NetworkLayer>::new() };
            address.set_outbound(true);
            address.set_ip_checksum(false);
            address.set_tcp_checksum(false);
            address.set_udp_checksum(false);

            let packet = match InternetPacket::try_from(data) {
                Ok(p) => p,
                Err(_) => return Ok(()),
            };

            self.inject_packet(address, packet).await
        }

        async fn insert_into_connections(
            &self,
            connection_id: ConnectionId,
            action: &ConnectionAction,
            _event: &WinDivertEvent,
            connections: &mut LruCache<ConnectionId, ConnectionState>,
        ) -> Result<()> {
            let existing1 = connections.insert(
                connection_id.reverse(),
                ConnectionState::Known(ConnectionAction::None),
            );
            let existing2 = connections.insert(connection_id, ConnectionState::Known(action.clone()));

            if let Some(ConnectionState::Unknown(packets)) = existing1 {
                for (a, p) in packets {
                    self.process_packet(a, p, &ConnectionAction::None).await?;
                }
            }
            if let Some(ConnectionState::Unknown(packets)) = existing2 {
                for (a, p) in packets {
                    self.process_packet(a, p, action).await?;
                }
            }
            Ok(())
        }

        async fn process_packet(
            &self,
            address: WinDivertAddress<NetworkLayer>,
            mut packet: InternetPacket,
            action: &ConnectionAction,
        ) -> Result<()> {
            match action {
                ConnectionAction::None => {
                    self.inject_packet(address, packet).await?;
                }
                ConnectionAction::Intercept(ProcessInfo { pid, process_name }) => {
                    if !address.ip_checksum() {
                        packet.recalculate_ip_checksum();
                    }
                    if !address.tcp_checksum() {
                        packet.recalculate_tcp_checksum();
                    }
                    if !address.udp_checksum() {
                        packet.recalculate_udp_checksum();
                    }

                    let mut smol_packet = match SmolPacket::try_from(packet.inner().to_vec()) {
                        Ok(p) => p,
                        Err(e) => {
                            error!("Failed to convert packet: {}", e);
                            return Ok(());
                        }
                    };

                    smol_packet.fill_ip_checksum();

                    let event = NetworkEvent::ReceivePacket {
                        packet: smol_packet,
                        tunnel_info: TunnelInfo::LocalRedirector {
                            pid: Some(*pid),
                            process_name: process_name.clone(),
                            remote_endpoint: None,
                        },
                    };
                    
                    if let Err(e) = self.net_tx.try_send(event) {
                        warn!("Failed to send packet to network layer: {}", e);
                    }
                }
            }
            Ok(())
        }

        async fn inject_packet(
            &self,
            address: WinDivertAddress<NetworkLayer>,
            packet: InternetPacket,
        ) -> Result<()> {
            let inject_handle = self.inject_handle.lock().await;
            inject_handle
                .send(&WinDivertPacket::<NetworkLayer> {
                    address,
                    data: packet.inner().into(),
                })
                .context("failed to re-inject packet")?;
            Ok(())
        }
    }

    pub fn build_windows_direct_task(
        transport_events_tx: Sender<TransportEvent>,
        transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: shutdown::Receiver,
    ) -> Result<(WindowsDirectTask, UnboundedSender<InterceptConf>)> {
        let (event_tx, event_rx) = mpsc::unbounded_channel::<Event>();
        let (conf_tx, conf_rx) = mpsc::unbounded_channel();

        let (network_task_handle, net_tx, net_rx) = 
            add_network_layer(transport_events_tx, transport_commands_rx, shutdown.clone());

        let socket_handle = WinDivert::socket(
            "tcp || udp",
            1041,
            WinDivertFlags::new().set_recv_only().set_sniff(),
        )?;
        
        let wd_net_filter = "!loopback && ((ip && remoteAddr < 224.0.0.0) || (ipv6 && remoteAddr < ff00::)) && (tcp || udp)";
        let network_handle = WinDivert::network(wd_net_filter, 1040, WinDivertFlags::new())?;
        let inject_handle = WinDivert::network("false", 1039, WinDivertFlags::new().set_send_only())?;

        let inject_handle_shared = Arc::new(Mutex::new(inject_handle));

        let tx_clone = event_tx.clone();
        thread::spawn(move || relay_socket_events(socket_handle, tx_clone));
        let tx_clone = event_tx.clone();
        thread::spawn(move || relay_network_events(network_handle, tx_clone));

        Ok((
            WindowsDirectTask {
                event_rx,
                event_tx,
                conf_rx,
                net_tx,
                net_rx,
                inject_handle: inject_handle_shared,
                network_task_handle,
                _shutdown: shutdown,
            },
            conf_tx,
        ))
    }

    fn relay_socket_events(handle: WinDivert<SocketLayer>, tx: tokio::sync::mpsc::UnboundedSender<Event>) {
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

    fn relay_network_events(handle: WinDivert<NetworkLayer>, tx: tokio::sync::mpsc::UnboundedSender<Event>) {
        const MAX_PACKETS: usize = 1;
        let mut buf = [0u8; MAX_PACKET_SIZE * MAX_PACKETS];
        loop {
            let packets = handle.recv_ex(Some(&mut buf), MAX_PACKETS);
            match packets {
                Ok(packets) => {
                    for packet in packets {
                        if tx.send(Event::NetworkPacket(packet.address, packet.data.into())).is_err() {
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
}

// Public interface that works on all platforms
pub struct WindowsDirectConf;

impl PacketSourceConf for WindowsDirectConf {
    #[cfg(windows)]
    type Task = windows_impl::WindowsDirectTask;
    #[cfg(not(windows))]
    type Task = DummyTask;
    
    type Data = UnboundedSender<InterceptConf>;

    fn name(&self) -> &'static str {
        "Windows Direct Proxy"
    }

    async fn build(
        self,
        transport_events_tx: Sender<TransportEvent>,
        transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: shutdown::Receiver,
    ) -> Result<(Self::Task, Self::Data)> {
        #[cfg(windows)]
        {
            windows_impl::build_windows_direct_task(transport_events_tx, transport_commands_rx, shutdown)
        }
        #[cfg(not(windows))]
        {
            let (conf_tx, _conf_rx) = tokio::sync::mpsc::unbounded_channel();
            Ok((DummyTask, conf_tx))
        }
    }
}

// Dummy implementation for non-Windows platforms
#[cfg(not(windows))]
pub struct DummyTask;

#[cfg(not(windows))]
impl PacketSourceTask for DummyTask {
    async fn run(self) -> Result<()> {
        Err(anyhow::anyhow!("WindowsDirectConf is only available on Windows"))
    }
}
