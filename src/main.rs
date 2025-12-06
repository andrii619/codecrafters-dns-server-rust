// #[allow(unused_imports)]
use std::net::UdpSocket;
use tracing::{info, debug, error};
use tracing_subscriber::{FmtSubscriber};

// declare a rust modul
use codecrafters_dns_server::server_consts::{BUF_SIZE, SERVER_ADDR};

use codecrafters_dns_server::protocol::parser::{self, Answer, DNSPacket, Header};

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

    info!("DNS server starting up...");

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
                    },
                    Err(e) => {
                        error!(error = %e, "Error parsing DNS packet");
                        continue;
                    }
                };

                if !request_packet.questions.is_empty() {
                    let question = &request_packet.questions[0];
                    info!(
                        domain = %question.domain_name,
                        type_code = question.record_type as u16,
                        "DNS query for domain"
                    );
                }

                let tmp_name = request_packet.questions[0].domain_name.clone();

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
                    answers: vec![Answer {
                        domain_name: tmp_name.clone(),
                        record_type: parser::RecordType::A,
                        class: parser::RecordClass::IN,
                        time_to_live: 60,
                        data_length: 4,
                        data: vec![0x08, 0x08, 0x08, 0x08],
                    }],
                };

                debug!("Creating response with IP 8.8.8.8 for domain {}", tmp_name);
                let response_data = response_packet.to_bytes();

                debug!(
                    first_bytes = format!("{:02X} {:02X} {:02X} {:02X}",
                    response_data[0], response_data[1], response_data[2], response_data[3]),
                    "Response header bytes"
                );

                match udp_socket.send_to(&response_data, source) {
                    Ok(sent) => info!(bytes = sent, "Response sent successfully"),
                    Err(e) => error!(error = %e, "Failed to send DNS response")
                };
            }
            Err(e) => {
                error!(error = %e, "Error receiving data");
                break;
            }
        }
    }
}
