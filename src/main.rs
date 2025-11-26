// #[allow(unused_imports)]
use std::net::UdpSocket;

// declare a rust modul
use codecrafters_dns_server::server_consts::{BUF_SIZE, SERVER_ADDR};

use codecrafters_dns_server::protocol::parser::{self, Header};

fn main()  {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind(SERVER_ADDR).expect("Failed to bind to address");
    let mut buf = [0; BUF_SIZE];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                // create a DNS packet for the response 
                let response_packet = parser::DNSPacket {
                    header: Header {
                        identifier: 1234,
                        is_response: true,
                        opcode: 0,
                        authoritative: false,
                        truncation: false,
                        recursion_desired: false,
                        recursion_available: false,
                        reserved: 0,
                        response_code: 0,
                        question_count: 0,
                        answer_record_count: 0,
                        authority_record_count: 0,
                        additional_record_count: 0,
                    }
                };


                let response_data = response_packet.to_bytes();
                
                

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
