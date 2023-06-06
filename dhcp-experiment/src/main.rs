#![no_std]
#![no_main]

use core::time::Duration;

use dhcp::{DhcpMessageType, DhcpOption, OpCode};
use domain::base::iana::{Class, Opcode, Rcode};
use domain::base::octets::Octets512;
use domain::base::{Record, Rtype};
use domain::rdata::A;
use embedded_io::blocking::*;
use embedded_svc::ipv4::Interface;
use embedded_svc::wifi::{AccessPointConfiguration, Configuration, Wifi};

use esp_backtrace as _;
use esp_println::{print, println};
use esp_wifi::initialize;
use esp_wifi::wifi::utils::create_network_interface;
use esp_wifi::wifi::WifiMode;
use esp_wifi::wifi_interface::{UdpSocket, WifiStack};
use esp_wifi::{current_millis, EspWifiInitFor};
use hal::clock::{ClockControl, CpuClock};
use hal::systimer::SystemTimer;
use hal::timer::TimerGroup;
use hal::Rng;
use hal::{peripherals::Peripherals, prelude::*, Rtc};

use smoltcp::iface::SocketStorage;
use smoltcp::wire::{IpAddress, Ipv4Address};

#[entry]
fn main() -> ! {
    esp_println::logger::init_logger_from_env();

    let peripherals = Peripherals::take();
    let mut system = peripherals.SYSTEM.split();
    let clocks = ClockControl::configure(system.clock_control, CpuClock::Clock160MHz).freeze();

    // Disable the RTC and TIMG watchdog timers
    let mut rtc = Rtc::new(peripherals.RTC_CNTL);
    let timer_group0 = TimerGroup::new(
        peripherals.TIMG0,
        &clocks,
        &mut system.peripheral_clock_control,
    );
    let mut wdt0 = timer_group0.wdt;
    let timer_group1 = TimerGroup::new(
        peripherals.TIMG1,
        &clocks,
        &mut system.peripheral_clock_control,
    );
    let mut wdt1 = timer_group1.wdt;
    rtc.swd.disable();
    rtc.rwdt.disable();
    wdt0.disable();
    wdt1.disable();

    let systimer = SystemTimer::new(peripherals.SYSTIMER);
    let init = initialize(
        EspWifiInitFor::Wifi,
        systimer.alarm0,
        Rng::new(peripherals.RNG),
        system.radio_clock_control,
        &clocks,
    )
    .unwrap();

    let (wifi, _) = peripherals.RADIO.split();
    let mut socket_set_entries: [SocketStorage; 3] = Default::default();
    let (iface, device, mut controller, sockets) =
        create_network_interface(&init, wifi, WifiMode::Ap, &mut socket_set_entries);
    let mut wifi_stack = WifiStack::new(iface, device, sockets, current_millis);

    let client_config = Configuration::AccessPoint(AccessPointConfiguration {
        ssid: "esp-wifi".into(),
        ..Default::default()
    });
    let res = controller.set_configuration(&client_config);
    println!("wifi_set_configuration returned {:?}", res);

    controller.start().unwrap();
    println!("is wifi started: {:?}", controller.is_started());

    println!("{:?}", controller.get_capabilities());

    wifi_stack
        .set_iface_configuration(&embedded_svc::ipv4::Configuration::Client(
            embedded_svc::ipv4::ClientConfiguration::Fixed(embedded_svc::ipv4::ClientSettings {
                ip: embedded_svc::ipv4::Ipv4Addr::from(parse_ip("192.168.2.1")),
                subnet: embedded_svc::ipv4::Subnet {
                    gateway: embedded_svc::ipv4::Ipv4Addr::from(parse_ip("192.168.2.1")),
                    mask: embedded_svc::ipv4::Mask(24),
                },
                dns: None,
                secondary_dns: None,
            }),
        ))
        .unwrap();

    println!("Start busy loop on main. Connect to the AP `esp-wifi`");

    let mut rx_meta1 = [smoltcp::socket::udp::PacketMetadata::EMPTY; 4];
    let mut rx_buffer1 = [0u8; 1536];
    let mut tx_meta1 = [smoltcp::socket::udp::PacketMetadata::EMPTY; 4];
    let mut tx_buffer1 = [0u8; 1536];
    let mut dhcp_socket = wifi_stack.get_udp_socket(
        &mut rx_meta1,
        &mut rx_buffer1,
        &mut tx_meta1,
        &mut tx_buffer1,
    );
    dhcp_socket.bind(67).unwrap();

    let mut dhcp_server = DhcpServer::new(&mut dhcp_socket, [192, 168, 2, 1], [192, 168, 2, 100]);

    let mut rx_meta1 = [smoltcp::socket::udp::PacketMetadata::EMPTY; 4];
    let mut rx_buffer1 = [0u8; 1536];
    let mut tx_meta1 = [smoltcp::socket::udp::PacketMetadata::EMPTY; 4];
    let mut tx_buffer1 = [0u8; 1536];
    let mut dns_socket = wifi_stack.get_udp_socket(
        &mut rx_meta1,
        &mut rx_buffer1,
        &mut tx_meta1,
        &mut tx_buffer1,
    );
    dns_socket.bind(53).unwrap();

    let mut dns_server = DnsServer::new(
        &mut dns_socket,
        [192, 168, 2, 1],
        Duration::from_secs(1 * 60 * 60),
    );

    let mut rx_buffer = [0u8; 1536];
    let mut tx_buffer = [0u8; 1536];
    let mut socket = wifi_stack.get_socket(&mut rx_buffer, &mut tx_buffer);

    let mut client_got_ip = false;
    loop {
        let res = dhcp_server.handle_dhcp();
        if res.unwrap() {
            println!("Client got it's IP hopefully! Open http://192.168.2.1/");
            client_got_ip = true;
        }

        dns_server.handle_dns();

        // handle http
        socket.work();

        if !socket.is_open() && client_got_ip {
            socket.listen_unblocking(80).unwrap();
        }

        if socket.is_connected() {
            println!("Connected");

            let mut time_out = false;
            let wait_end = current_millis() + 20 * 1000;
            let mut buffer = [0u8; 1024];
            let mut pos = 0;
            loop {
                // it's important to keep polling dhcp and dns
                dhcp_server.handle_dhcp().unwrap();
                dns_server.handle_dns();

                if let Ok(len) = socket.read(&mut buffer[pos..]) {
                    let to_print =
                        unsafe { core::str::from_utf8_unchecked(&buffer[..(pos + len)]) };

                    if to_print.contains("\r\n\r\n") {
                        print!("{}", to_print);
                        println!();
                        break;
                    }

                    pos += len;
                } else {
                    break;
                }

                if current_millis() > wait_end {
                    println!("Timeout");
                    time_out = true;
                    break;
                }
            }

            if !time_out {
                socket.write_all(b"HTTP/1.0 200 OK\r\n\r\n").unwrap();
                socket.write_all(CONTENT).unwrap();

                socket.flush().unwrap();
            }

            socket.close();

            println!("Done\n");
            println!();
        }

        let wait_end = current_millis() + 2 * 1000;
        while current_millis() < wait_end {
            socket.work();
        }
    }
}

fn parse_ip(ip: &str) -> [u8; 4] {
    let mut result = [0u8; 4];
    for (idx, octet) in ip.split(".").into_iter().enumerate() {
        result[idx] = u8::from_str_radix(octet, 10).unwrap();
    }
    result
}

pub struct DhcpServer<'a, 's, 'n>
where
    'n: 's,
{
    dhcp_socket: &'a mut UdpSocket<'s, 'n>,
    dhcp_buffer: [u8; 1536],
    gateway: [u8; 4],
    client_ip: [u8; 4],
}

impl<'a, 's, 'n> DhcpServer<'a, 's, 'n>
where
    'n: 's,
{
    fn new(dhcp_socket: &'a mut UdpSocket<'s, 'n>, gateway: [u8; 4], client_ip: [u8; 4]) -> Self {
        Self {
            dhcp_socket,
            dhcp_buffer: [0u8; 1536],
            gateway,
            client_ip,
        }
    }

    fn handle_dhcp(&mut self) -> Result<bool, ()> {
        self.dhcp_socket.work();

        match self.dhcp_socket.receive(&mut self.dhcp_buffer) {
            Ok((len, src_addr, src_port)) => {
                if len > 0 {
                    log::info!("DHCP FROM {:?} / {}", src_addr, src_port);
                    log::info!("DHCP {:02x?}", &self.dhcp_buffer[..len]);

                    let mut decoder = dhcp::PacketDecoder::new(&self.dhcp_buffer);
                    let mut encoder = dhcp::PacketEncoder::new();

                    let msg_type = decoder.next_option().unwrap();

                    match msg_type {
                        DhcpOption::DhcpMessageType(t) => {
                            println!("Got {:?}", t);
                            match t {
                                DhcpMessageType::Discover => {
                                    encoder.xid(decoder.xid().unwrap());
                                    encoder.op(OpCode::Reply);
                                    encoder.yiaddr(&self.client_ip);
                                    encoder.siaddr(&self.gateway);
                                    encoder.chaddr(decoder.chaddr().unwrap());
                                    encoder.encode_option(DhcpOption::DhcpMessageType(
                                        DhcpMessageType::Offer,
                                    ));
                                    encoder
                                        .encode_option(DhcpOption::SubnetMask([255, 255, 255, 0]));
                                    encoder.encode_option(DhcpOption::RenewalTime(43200));
                                    encoder.encode_option(DhcpOption::RebindingTime(75600));
                                    encoder.encode_option(DhcpOption::IpAddressLeaseTime(86400));
                                    encoder.encode_option(DhcpOption::DhcpServerIdentifier(
                                        self.gateway.clone(),
                                    ));
                                    encoder.encode_option(DhcpOption::Router(self.gateway.clone()));
                                    encoder.encode_option(DhcpOption::DomainNameServer(
                                        self.gateway.clone(),
                                    ));

                                    encoder.encode_option(DhcpOption::End);

                                    self.dhcp_socket
                                        .send(
                                            IpAddress::Ipv4(Ipv4Address::new(255, 255, 255, 255)),
                                            68,
                                            &encoder.as_slice(0),
                                        )
                                        .unwrap();
                                }
                                DhcpMessageType::Request => {
                                    encoder.xid(decoder.xid().unwrap());
                                    encoder.op(OpCode::Reply);
                                    encoder.yiaddr(&self.client_ip);
                                    encoder.siaddr(&self.gateway);
                                    encoder.chaddr(decoder.chaddr().unwrap());
                                    encoder.encode_option(DhcpOption::DhcpMessageType(
                                        DhcpMessageType::Ack,
                                    ));
                                    encoder
                                        .encode_option(DhcpOption::SubnetMask([255, 255, 255, 0]));
                                    encoder.encode_option(DhcpOption::RenewalTime(43200));
                                    encoder.encode_option(DhcpOption::RebindingTime(75600));
                                    encoder.encode_option(DhcpOption::IpAddressLeaseTime(86400));
                                    encoder.encode_option(DhcpOption::DhcpServerIdentifier(
                                        self.gateway.clone(),
                                    ));
                                    encoder.encode_option(DhcpOption::Router(self.gateway.clone()));
                                    encoder.encode_option(DhcpOption::DomainNameServer(
                                        self.gateway.clone(),
                                    ));

                                    encoder.encode_option(DhcpOption::End);

                                    self.dhcp_socket
                                        .send(
                                            IpAddress::Ipv4(Ipv4Address::new(255, 255, 255, 255)),
                                            68,
                                            &encoder.as_slice(0),
                                        )
                                        .unwrap();

                                    return Ok(true);
                                }
                                _ => (),
                            }
                        }
                        _ => {
                            log::info!("Expected DhcpMessageType Discover or Request");
                        }
                    }
                }
            }
            Err(_err) => (),
        }

        Ok(false)
    }
}

pub struct DnsServer<'a, 's, 'n>
where
    'n: 's,
{
    dns_socket: &'a mut UdpSocket<'s, 'n>,
    dns_buffer: [u8; 1536],
    ip: [u8; 4],
    ttl: Duration,
}

impl<'a, 's, 'n> DnsServer<'a, 's, 'n>
where
    'n: 's,
{
    fn new(dns_socket: &'a mut UdpSocket<'s, 'n>, ip: [u8; 4], ttl: Duration) -> Self {
        Self {
            dns_socket,
            dns_buffer: [0u8; 1536],
            ip,
            ttl,
        }
    }

    fn handle_dns(&mut self) {
        self.dns_socket.work();

        match self.dns_socket.receive(&mut self.dns_buffer) {
            Ok((len, src_addr, src_port)) => {
                if len > 0 {
                    log::info!("DNS FROM {:?} / {}", src_addr, src_port);
                    log::info!("DNS {:02x?}", &self.dns_buffer[..len]);

                    let request = &self.dns_buffer[..len];
                    let response = Octets512::new();

                    let message = domain::base::Message::from_octets(request).unwrap();
                    log::info!("Processing message with header: {:?}", message.header());

                    let mut responseb =
                        domain::base::MessageBuilder::from_target(response).unwrap();

                    let response = if matches!(message.header().opcode(), Opcode::Query) {
                        log::info!("Message is of type Query, processing all questions");

                        let mut answerb = responseb.start_answer(&message, Rcode::NoError).unwrap();

                        for question in message.question() {
                            let question = question.unwrap();

                            if matches!(question.qtype(), Rtype::A) {
                                log::info!(
                                    "Question {:?} is of type A, answering with IP {:?}, TTL {:?}",
                                    question,
                                    self.ip,
                                    self.ttl
                                );

                                let record = Record::new(
                                    question.qname(),
                                    Class::In,
                                    self.ttl.as_secs() as u32,
                                    A::from_octets(self.ip[0], self.ip[1], self.ip[2], self.ip[3]),
                                );
                                log::info!("Answering question {:?} with {:?}", question, record);
                                answerb.push(record).unwrap();
                            } else {
                                log::info!(
                                    "Question {:?} is not of type A, not answering",
                                    question
                                );
                            }
                        }

                        answerb.finish()
                    } else {
                        log::info!("Message is not of type Query, replying with NotImp");

                        let headerb = responseb.header_mut();

                        headerb.set_id(message.header().id());
                        headerb.set_opcode(message.header().opcode());
                        headerb.set_rd(message.header().rd());
                        headerb.set_rcode(domain::base::iana::Rcode::NotImp);

                        responseb.finish()
                    };

                    self.dns_socket.send(src_addr, src_port, &response).unwrap();
                }
            }
            _ => (),
        }
    }
}

const CONTENT: &[u8] = b"
<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">
    <title>Hello World</title>
    <style>
        body {
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            font-family: Arial, sans-serif;
            background-color: #f2f2f2;
        }
        
        h1 {
            font-size: 48px;
            color: #333;
            text-align: center;
            text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.5);
            animation: rainbow 5s linear infinite;
        }
        
        @keyframes rainbow {
            0% { color: red; }
            14% { color: orange; }
            28% { color: yellow; }
            42% { color: green; }
            57% { color: blue; }
            71% { color: indigo; }
            85% { color: violet; }
            100% { color: red; }
        }
    </style>
</head>
<body>
    <h1>Hello World! Hello esp-wifi! Hello captive-portal!</h1>
</body>
</html>
";
