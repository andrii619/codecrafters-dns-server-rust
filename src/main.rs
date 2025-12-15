// #[allow(unused_imports)]
use std::net::UdpSocket;
use tracing::{debug, error, info};
use tracing_subscriber::FmtSubscriber;

use clap::Parser;

// declare a rust modul
use codecrafters_dns_server::server_consts::{BUF_SIZE, SERVER_ADDR};

use codecrafters_dns_server::protocol::parser::{self, Answer, DNSPacket, Header};

// use std::net::Ipv4Addr;
// use std::str::FromStr;

use std::net::SocketAddr;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// IP of remote DNS server for forwarding requests in the form: ip:port
    #[arg(short, long)]
    resolver: String,
}

fn main() {
    // Initialize tracing subscriber
    // construct a subscriber that prints formatted traces to stdout
    let subscriber = FmtSubscriber::new();
    // use that subscriber to process traces emitted after this point
    let log_res = tracing::subscriber::set_global_default(subscriber);

    if log_res.is_err() {
        println!("Failed to setup logging. exiting");
        return;
    }

    // parse command line arguments
    let args = Args::parse();
    info!("resolver: {}", args.resolver);

    // check ip address
    let resolver_address = match args.resolver.parse::<SocketAddr>() {
        Ok(address) => address,
        Err(_) => {
            info!(
                "Was not able to parse resolver IP address {}",
                args.resolver
            );
            return;
        }
    };

    let conn_to_resolver = match UdpSocket::bind("0.0.0.0:0") {
        Ok(sock) => sock,
        Err(_) => {
            info!("Not able to bind local socket");
            return;
        }
    };

    info!("DNS server starting up...");
    info!(
        "Using {}:{} as the remote resolver",
        resolver_address.ip(),
        resolver_address.port()
    );

    info!("Binding to {}", SERVER_ADDR);
    let udp_socket = UdpSocket::bind(SERVER_ADDR).expect("Failed to bind to address");
    let mut buf = [0; BUF_SIZE];

    info!("DNS server ready to receive requests");

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                info!(size = size, source = %source, "Received DNS request");
                debug!("First few bytes: {:?}", &buf[..std::cmp::min(16, size)]);

                let request_packet_res = DNSPacket::from_bytes(&buf);

                let request_packet = match request_packet_res {
                    Ok(packet) => {
                        debug!(
                            id = packet.header.identifier,
                            opcode = packet.header.opcode,
                            recursion_desired = packet.header.recursion_desired,
                            question_count = packet.header.question_count,
                            "Request packet parsed successfully"
                        );
                        packet
                    }
                    Err(e) => {
                        error!(error = %e, "Error parsing DNS packet");
                        continue;
                    }
                };

                let mut answers: Vec<Answer> = vec![];
                if !request_packet.questions.is_empty() {
                    for question in &request_packet.questions {
                        // let question = &request_packet.questions[0];
                        info!(
                            domain = %question.domain_name,
                            type_code = question.record_type as u16,
                            "DNS query for domain"
                        );

                        answers.push(Answer {
                            domain_name: question.domain_name.clone(),
                            record_type: question.record_type,
                            class: question.class,
                            time_to_live: 60,
                            data_length: 4,
                            data: vec![0x8, 0x8, 0x8, 0x8],
                        });
                    }
                }

                // let tmp_name = request_packet.questions[0].domain_name.clone();

                // create a DNS packet for the response
                let response_packet = parser::DNSPacket {
                    header: Header {
                        identifier: request_packet.header.identifier,
                        is_response: true,
                        opcode: request_packet.header.opcode,
                        authoritative: false,
                        truncation: false,
                        recursion_desired: request_packet.header.recursion_desired,
                        recursion_available: false,
                        reserved: false,
                        authenticated_data: false,
                        checking_disabled: false,
                        response_code: if request_packet.header.opcode == 0 {
                            0
                        } else {
                            4
                        },
                        question_count: request_packet.header.question_count,
                        answer_count: request_packet.header.question_count,
                        authority_count: 0,
                        additional_count: 0,
                    },
                    questions: request_packet.questions,
                    answers,
                };

                // debug!("Creating response with IP 8.8.8.8 for domain {}");
                let response_data = response_packet.to_bytes();

                debug!(
                    first_bytes = format!(
                        "{:02X} {:02X} {:02X} {:02X}",
                        response_data[0], response_data[1], response_data[2], response_data[3]
                    ),
                    "Response header bytes"
                );

                match udp_socket.send_to(&response_data, source) {
                    Ok(sent) => info!(bytes = sent, "Response sent successfully"),
                    Err(e) => error!(error = %e, "Failed to send DNS response"),
                };
            }
            Err(e) => {
                error!(error = %e, "Error receiving data");
                break;
            }
        }
    }
}
