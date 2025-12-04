// #[allow(unused_imports)]
use std::net::UdpSocket;

// declare a rust modul
use codecrafters_dns_server::server_consts::{BUF_SIZE, SERVER_ADDR};

use codecrafters_dns_server::protocol::parser::{self, Answer, DNSPacket, Header, Question};

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind(SERVER_ADDR).expect("Failed to bind to address");
    let mut buf = [0; BUF_SIZE];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                let request_packet_res = DNSPacket::from_bytes(&buf);

                let request_packet = match request_packet_res {
                    Ok(packet) => packet,
                    Err(e) => {
                        println!("Error parcing the packet {}", e);
                        continue;
                    }
                };

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
                        reserved: 0,
                        response_code: if request_packet.header.opcode == 0 {
                            0
                        } else {
                            4
                        },
                        question_count: request_packet.header.question_count,
                        answer_count: 1,
                        authority_count: 0,
                        additional_count: 0,
                    },
                    questions: request_packet.questions,
                    answers: vec![Answer {
                        domain_name: "codecrafters.io".to_string(),
                        record_type: parser::RecordType::A,
                        class: parser::RecordClass::IN,
                        time_to_live: 60,
                        data_length: 4,
                        data: vec![0x08, 0x08, 0x08, 0x08],
                    }],
                };

                let response_data = response_packet.to_bytes();

                println!(
                    "some bytes: {:X} {:X} {:X} {:X}",
                    response_data[0], response_data[1], response_data[2], response_data[3]
                );

                udp_socket
                    .send_to(&response_data, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
