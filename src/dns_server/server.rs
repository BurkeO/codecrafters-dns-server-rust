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

                    let query_header = DnsHeader::from_bytes(receive_buffer[0..12].try_into()?);

                    let mut response_header = query_header;
                    response_header.query_response_indicator = 1;
                    response_header.authoritative_answer = 0;
                    response_header.truncation = 0;
                    response_header.recursion_available = 0;
                    response_header.reserved = 0;
                    response_header.response_code = if response_header.opcode == 0 { 0 } else { 4 };
                    response_header.answer_record_count = 1;

                    response_buffer[0..12].copy_from_slice(&response_header.to_bytes());
                    let query_question =
                        DnsQuestion::decode_dns_question(&receive_buffer[12..]).unwrap();
                    let dns_question_bytes = query_question.to_bytes();

                    let mut response_question = query_question;
                    response_question.question_type = 1;
                    response_question.class = 1;

                    response_buffer[12..dns_question_bytes.len() + 12]
                        .copy_from_slice(dns_question_bytes.as_slice());

                    let answer = DnsAnswer::new(
                        response_question.domain_name,
                        1,
                        1,
                        60,
                        vec![8, 8, 8, 8],
                    );
                    let answer_end = 12 + dns_question_bytes.len() + answer.to_bytes().len();
                    response_buffer[12 + dns_question_bytes.len()..answer_end]
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
