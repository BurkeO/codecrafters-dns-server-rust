use crate::dns_server::udp_data::{DnsAnswer, DnsHeader, DnsQuestion};
use std::net::UdpSocket;

pub struct Server {
    source_ip: String,
    port: u16,
}

impl Server {
    pub fn new(source_ip: String, port: u16) -> Self {
        Self { source_ip, port }
    }

    pub fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let udp_socket = UdpSocket::bind(format!("{}:{}", self.source_ip, self.port))?;
        let mut response_buffer = [0; 1500];
        let mut receive_buffer = [0; 1500];
        loop {
            match udp_socket.recv_from(&mut receive_buffer) {
                Ok((size, source)) => {
                    println!("Received {} bytes from {}", size, source);
                    let response_header = DnsHeader {
                        packet_identifier: 1234,
                        query_response_indicator: 1, //todo don't hard code
                        question_count: 1,
                        answer_record_count: 1,
                        ..DnsHeader::default()
                    };
                    response_buffer[0..12].copy_from_slice(&response_header.to_bytes());
                    let dns_question =
                        DnsQuestion::decode_dns_question(&receive_buffer[12..]).unwrap();
                    let dns_question_bytes = dns_question.to_bytes();
                    response_buffer[12..dns_question_bytes.len() + 12]
                        .copy_from_slice(dns_question_bytes.as_slice());

                    let answer = DnsAnswer::new(
                        dns_question.domain_name,
                        dns_question.question_type,
                        dns_question.class,
                        60,
                        vec![8, 8, 8, 8],
                    );
                    response_buffer[12 + dns_question_bytes.len()..]
                        .copy_from_slice(&answer.to_bytes());

                    udp_socket.send_to(&response_buffer, source)?;
                }
                Err(e) => {
                    eprintln!("Error receiving data: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }
}
