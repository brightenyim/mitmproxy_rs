#[cfg(windows)]
mod windows_redirector_impl {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::time::Duration;
    use std::{thread, sync::Arc, sync::atomic::{AtomicBool, Ordering}};

    use anyhow::{anyhow, Context, Result};
    use internet_packet::{ConnectionId, InternetPacket, TransportProtocol};
    use log::{debug, error, info, warn};
    use lru_time_cache::LruCache;
    use mitmproxy::intercept_conf::{InterceptConf, ProcessInfo};
    use mitmproxy::ipc;
    use mitmproxy::windows::network::network_table;
    use mitmproxy::processes::get_process_name;
    use mitmproxy::MAX_PACKET_SIZE;
    use tokio::sync::mpsc;
    use tokio::sync::mpsc::UnboundedSender;
    use windivert::address::WinDivertAddress;
    use windivert::prelude::*;

    #[derive(Debug)]
    enum Event {
        NetworkPacket(WinDivertAddress<NetworkLayer>, Vec<u8>),
        SocketInfo(WinDivertAddress<SocketLayer>),
        InterceptConf(InterceptConf),
        PacketToInject(Vec<u8>),
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

    pub type PacketCallback = Box<dyn Fn(Vec<u8>, Option<ProcessInfo>) + Send + Sync>;
    pub type InterceptConfCallback = Box<dyn Fn(InterceptConf) + Send + Sync>;

    pub struct WindowsRedirector {
        running: Arc<AtomicBool>,
        event_tx: Option<UnboundedSender<Event>>,
        packet_callback: Option<PacketCallback>,
        intercept_conf_callback: Option<InterceptConfCallback>,
    }

    impl WindowsRedirector {
        pub fn new() -> Self {
            Self {
                running: Arc::new(AtomicBool::new(false)),
                event_tx: None,
                packet_callback: None,
                intercept_conf_callback: None,
            }
        }

        pub fn set_packet_callback(&mut self, callback: PacketCallback) {
            self.packet_callback = Some(callback);
        }

        pub fn set_intercept_conf_callback(&mut self, callback: InterceptConfCallback) {
            self.intercept_conf_callback = Some(callback);
        }

        pub async fn start(&mut self) -> Result<()> {
            if self.running.load(Ordering::SeqCst) {
                return Err(anyhow!("Windows redirector is already running"));
            }

            let (event_tx, mut event_rx) = mpsc::unbounded_channel::<Event>();
            self.event_tx = Some(event_tx.clone());

            // We currently rely on handles being automatically closed when the program exits.
            let socket_handle = WinDivert::socket(
                "tcp || udp",
                1041,
                WinDivertFlags::new().set_recv_only().set_sniff(),
            )?;
            let wd_net_filter = "!loopback && ((ip && remoteAddr < 224.0.0.0) || (ipv6 && remoteAddr < ff00::)) && (tcp || udp)";
            let network_handle = WinDivert::network(wd_net_filter, 1040, WinDivertFlags::new())?;
            let inject_handle = WinDivert::network("false", 1039, WinDivertFlags::new().set_send_only())?;

            let tx_clone = event_tx.clone();
            thread::spawn(move || relay_socket_events(socket_handle, tx_clone));
            let tx_clone = event_tx.clone();
            thread::spawn(move || relay_network_events(network_handle, tx_clone));

            let mut state = InterceptConf::disabled();
            event_tx.send(Event::InterceptConf(state.clone()))?;

            let mut connections = LruCache::<ConnectionId, ConnectionState>::with_expiry_duration(
                Duration::from_secs(60 * 10),
            );
            let mut active_listeners = ActiveListeners::new();

            self.running.store(true, Ordering::SeqCst);

            // Main event loop
            let packet_callback = self.packet_callback.take();
            let intercept_conf_callback = self.intercept_conf_callback.take();
            
            tokio::spawn(async move {
                while let Some(result) = event_rx.recv().await {
                    match result {
                        Event::NetworkPacket(address, data) => {
                            if let Err(e) = handle_network_packet_with_callback(
                                address, 
                                data, 
                                &mut connections, 
                                &mut active_listeners, 
                                &state, 
                                &inject_handle, 
                                &packet_callback
                            ).await {
                                error!("Error handling network packet: {}", e);
                            }
                        }
                        Event::SocketInfo(address) => {
                            if let Err(e) = handle_socket_info_with_callback(
                                address, 
                                &mut connections, 
                                &mut active_listeners, 
                                &state, 
                                &inject_handle, 
                                &packet_callback
                            ).await {
                                error!("Error handling socket info: {}", e);
                            }
                        }
                        Event::PacketToInject(data) => {
                            if let Err(e) = handle_packet_injection(data, &inject_handle).await {
                                error!("Error injecting packet: {}", e);
                            }
                        }
                        Event::InterceptConf(conf) => {
                            state = conf;
                            info!("{}", state.description());
                            connections.clear();
                            active_listeners.clear();
                            
                            if let Some(ref callback) = intercept_conf_callback {
                                callback(state.clone());
                            }
                            
                            if let Ok(network_entries) = network_table() {
                                for e in network_entries {
                                    let proc_info = ProcessInfo {
                                        pid: e.pid,
                                        process_name: get_process_name(e.pid)
                                            .map(|x| x.to_string_lossy().into_owned())
                                            .ok(),
                                    };
                                    if let Ok(proto) = TransportProtocol::try_from(e.protocol) {
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
                                            if let Err(e) = insert_into_connections_with_callback(
                                                connection_id,
                                                &action,
                                                &WinDivertEvent::ReflectOpen,
                                                &mut connections,
                                                &inject_handle,
                                                &packet_callback,
                                            ).await {
                                                error!("Error inserting connection: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            });

            Ok(())
        }

        pub fn stop(&mut self) {
            self.running.store(false, Ordering::SeqCst);
            self.event_tx = None;
        }

        pub fn is_running(&self) -> bool {
            self.running.load(Ordering::SeqCst)
        }
    }

    async fn handle_network_packet_with_callback(
        address: WinDivertAddress<NetworkLayer>,
        data: Vec<u8>,
        connections: &mut LruCache<ConnectionId, ConnectionState>,
        active_listeners: &mut ActiveListeners,
        state: &InterceptConf,
        inject_handle: &WinDivert<NetworkLayer>,
        packet_callback: &Option<PacketCallback>,
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
            inject_handle.send(&WinDivertPacket {
                address,
                data: packet.inner().into(),
            })?;
            return Ok(());
        }

        match connections.get_mut(&packet.connection_id()) {
            Some(connection_state) => match connection_state {
                ConnectionState::Known(action) => {
                    process_packet_with_callback(address, packet, action, inject_handle, packet_callback).await?;
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
                    insert_into_connections_with_callback(
                        packet.connection_id(),
                        &action,
                        &address.event(),
                        connections,
                        inject_handle,
                        packet_callback,
                    ).await?;
                    process_packet_with_callback(address, packet, &action, inject_handle, packet_callback).await?;
                }
            }
        }
        Ok(())
    }

    async fn handle_network_packet(
        address: WinDivertAddress<NetworkLayer>,
        data: Vec<u8>,
        connections: &mut LruCache<ConnectionId, ConnectionState>,
        active_listeners: &mut ActiveListeners,
        state: &InterceptConf,
        inject_handle: &WinDivert<NetworkLayer>,
        ipc_tx: &mut UnboundedSender<ipc::PacketWithMeta>,
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
            inject_handle.send(&WinDivertPacket {
                address,
                data: packet.inner().into(),
            })?;
            return Ok(());
        }

        match connections.get_mut(&packet.connection_id()) {
            Some(connection_state) => match connection_state {
                ConnectionState::Known(action) => {
                    process_packet(address, packet, action, inject_handle, ipc_tx).await?;
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
                    insert_into_connections(
                        packet.connection_id(),
                        &action,
                        &address.event(),
                        connections,
                        inject_handle,
                        ipc_tx,
                    ).await?;
                    process_packet(address, packet, &action, inject_handle, ipc_tx).await?;
                }
            }
        }
        Ok(())
    }

    async fn handle_socket_info_with_callback(
        address: WinDivertAddress<SocketLayer>,
        connections: &mut LruCache<ConnectionId, ConnectionState>,
        active_listeners: &mut ActiveListeners,
        state: &InterceptConf,
        inject_handle: &WinDivert<NetworkLayer>,
        packet_callback: &Option<PacketCallback>,
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

                insert_into_connections_with_callback(
                    connection_id,
                    &action,
                    &address.event(),
                    connections,
                    inject_handle,
                    packet_callback,
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

    async fn handle_socket_info(
        address: WinDivertAddress<SocketLayer>,
        connections: &mut LruCache<ConnectionId, ConnectionState>,
        active_listeners: &mut ActiveListeners,
        state: &InterceptConf,
        inject_handle: &WinDivert<NetworkLayer>,
        ipc_tx: &mut UnboundedSender<ipc::PacketWithMeta>,
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

                insert_into_connections(
                    connection_id,
                    &action,
                    &address.event(),
                    connections,
                    inject_handle,
                    ipc_tx,
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

    async fn handle_packet_injection(
        buf: Vec<u8>,
        inject_handle: &WinDivert<NetworkLayer>,
    ) -> Result<()> {
        let mut address = unsafe { WinDivertAddress::<NetworkLayer>::new() };
        address.set_outbound(true);
        address.set_ip_checksum(false);
        address.set_tcp_checksum(false);
        address.set_udp_checksum(false);

        let packet = match InternetPacket::try_from(buf) {
            Ok(p) => p,
            Err(e) => {
                info!("Error parsing packet: {:?}", e);
                return Ok(());
            }
        };

        info!(
            "Injecting: {} {} with outbound={} loopback={}",
            packet.connection_id(),
            packet.tcp_flag_str(),
            address.outbound(),
            address.loopback()
        );

        let packet = WinDivertPacket::<NetworkLayer> {
            address,
            data: packet.inner().into(),
        };

        inject_handle.send(&packet)?;
        Ok(())
    }


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
                    return;
                }
            };
        }
    }

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
                    return;
                }
            };
        }
    }

    async fn insert_into_connections_with_callback(
        connection_id: ConnectionId,
        action: &ConnectionAction,
        event: &WinDivertEvent,
        connections: &mut LruCache<ConnectionId, ConnectionState>,
        inject_handle: &WinDivert<NetworkLayer>,
        packet_callback: &Option<PacketCallback>,
    ) -> Result<()> {
        debug!("Adding: {} with {:?} ({:?})", &connection_id, action, event);

        let existing1 = connections.insert(
            connection_id.reverse(),
            ConnectionState::Known(ConnectionAction::None),
        );
        let existing2 = connections.insert(connection_id, ConnectionState::Known(action.clone()));

        if let Some(ConnectionState::Unknown(packets)) = existing1 {
            for (a, p) in packets {
                process_packet_with_callback(a, p, &ConnectionAction::None, inject_handle, packet_callback).await?;
            }
        }
        if let Some(ConnectionState::Unknown(packets)) = existing2 {
            for (a, p) in packets {
                process_packet_with_callback(a, p, action, inject_handle, packet_callback).await?;
            }
        }
        Ok(())
    }

    async fn process_packet_with_callback(
        address: WinDivertAddress<NetworkLayer>,
        mut packet: InternetPacket,
        action: &ConnectionAction,
        inject_handle: &WinDivert<NetworkLayer>,
        packet_callback: &Option<PacketCallback>,
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
                inject_handle
                    .send(&WinDivertPacket::<NetworkLayer> {
                        address,
                        data: packet.inner().into(),
                    })
                    .context("failed to re-inject packet")?;
            }
            ConnectionAction::Intercept(ProcessInfo { pid, process_name }) => {
                info!(
                    "Intercepting: {} {} outbound={} loopback={}",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    address.outbound(),
                    address.loopback()
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

                if let Some(ref callback) = packet_callback {
                    callback(packet.inner().into(), Some(ProcessInfo {
                        pid: *pid,
                        process_name: process_name.clone(),
                    }));
                }
            }
        }
        Ok(())
    }

    async fn insert_into_connections(
        connection_id: ConnectionId,
        action: &ConnectionAction,
        event: &WinDivertEvent,
        connections: &mut LruCache<ConnectionId, ConnectionState>,
        inject_handle: &WinDivert<NetworkLayer>,
        ipc_tx: &mut UnboundedSender<ipc::PacketWithMeta>,
    ) -> Result<()> {
        debug!("Adding: {} with {:?} ({:?})", &connection_id, action, event);

        let existing1 = connections.insert(
            connection_id.reverse(),
            ConnectionState::Known(ConnectionAction::None),
        );
        let existing2 = connections.insert(connection_id, ConnectionState::Known(action.clone()));

        if let Some(ConnectionState::Unknown(packets)) = existing1 {
            for (a, p) in packets {
                process_packet(a, p, &ConnectionAction::None, inject_handle, ipc_tx).await?;
            }
        }
        if let Some(ConnectionState::Unknown(packets)) = existing2 {
            for (a, p) in packets {
                process_packet(a, p, action, inject_handle, ipc_tx).await?;
            }
        }
        Ok(())
    }

    async fn process_packet(
        address: WinDivertAddress<NetworkLayer>,
        mut packet: InternetPacket,
        action: &ConnectionAction,
        inject_handle: &WinDivert<NetworkLayer>,
        ipc_tx: &mut UnboundedSender<ipc::PacketWithMeta>,
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
                inject_handle
                    .send(&WinDivertPacket::<NetworkLayer> {
                        address,
                        data: packet.inner().into(),
                    })
                    .context("failed to re-inject packet")?;
            }
            ConnectionAction::Intercept(ProcessInfo { pid, process_name }) => {
                info!(
                    "Intercepting: {} {} outbound={} loopback={}",
                    packet.connection_id(),
                    packet.tcp_flag_str(),
                    address.outbound(),
                    address.loopback()
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

                ipc_tx.send(ipc::PacketWithMeta {
                    data: packet.inner().into(),
                    tunnel_info: Some(ipc::TunnelInfo {
                        pid: Some(*pid),
                        process_name: process_name.clone(),
                    }),
                })?;
            }
        }
        Ok(())
    }
}

use pyo3::prelude::*;
use pyo3::exceptions::PyRuntimeError;

#[cfg(windows)]
pub use windows_redirector_impl::WindowsRedirector;

#[cfg(not(windows))]
pub struct WindowsRedirector;

#[cfg(not(windows))]
impl WindowsRedirector {
    pub fn new() -> Self {
        Self
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        Err("Windows redirector only works on Windows".into())
    }

    pub fn stop(&mut self) {}

    pub fn is_running(&self) -> bool {
        false
    }
}

#[pyclass]
pub struct PyWindowsRedirector {
    inner: WindowsRedirector,
}

#[pymethods]
impl PyWindowsRedirector {
    #[new]
    fn new() -> Self {
        Self {
            inner: WindowsRedirector::new(),
        }
    }

    fn start(&mut self) -> PyResult<()> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            self.inner.start().await
        }).map_err(|e| PyRuntimeError::new_err(format!("Failed to start Windows redirector: {}", e)))?;
        Ok(())
    }

    fn inject_packet(&self, _packet_data: Vec<u8>) -> PyResult<()> {
        // This would need to be implemented to send packets to the redirector
        // For now, we'll leave this as a placeholder
        Ok(())
    }

    fn update_intercept_conf(&self, _conf: PyObject) -> PyResult<()> {
        // This would need to be implemented to convert Python object to InterceptConf
        // For now, we'll leave this as a placeholder
        Ok(())
    }

    fn stop(&mut self) {
        self.inner.stop();
    }

    fn is_running(&self) -> bool {
        self.inner.is_running()
    }
}

