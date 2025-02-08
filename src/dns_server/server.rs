use crate::dns_server::udp_data::{decode_questions, DnsHeader, ResourceRecord};
use std::net::UdpSocket;

pub struct Server {
    source_ip: String,
    port: u16,
}

const DNS_HEADER_SIZE: usize = 12;

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

                    let query_header =
                        DnsHeader::from_bytes(receive_buffer[0..DNS_HEADER_SIZE].try_into()?);

                    let mut response_header = query_header;
                    response_header.query_response_indicator = 1;
                    response_header.authoritative_answer = 0;
                    response_header.truncation = 0;
                    response_header.recursion_available = 0;
                    response_header.reserved = 0;
                    response_header.response_code = if response_header.opcode == 0 { 0 } else { 4 };
                    response_header.answer_record_count = response_header.question_count;
                    response_buffer[0..DNS_HEADER_SIZE]
                        .copy_from_slice(&response_header.to_bytes());

                    let mut question_index = DNS_HEADER_SIZE;
                    let query_questions = decode_questions(
                        &receive_buffer[DNS_HEADER_SIZE..],
                        response_header.question_count,
                    )
                    .unwrap();
                    let mut answers: Vec<ResourceRecord> = Vec::new();
                    for question in query_questions {
                        let mut response_question = question;
                        response_question.question_type = 1;
                        response_question.class = 1;
                        let response_question_bytes = response_question.to_bytes();
                        response_buffer
                            [question_index..question_index + response_question_bytes.len()]
                            .copy_from_slice(response_question_bytes.as_slice());
                        question_index += response_question_bytes.len();

                        let record = ResourceRecord::new(
                            response_question.domain_name,
                            1,
                            1,
                            60,
                            vec![8, 8, 8, 8],
                        );
                        answers.push(record);
                    }
                    let mut answer_index = question_index;
                    for answer in answers {
                        let answer_bytes = answer.to_bytes();
                        response_buffer[answer_index..answer_index + answer_bytes.len()]
                            .copy_from_slice(answer_bytes.as_slice());
                        answer_index += answer_bytes.len();
                    }
                    udp_socket.send_to(&response_buffer[..answer_index], source)?;
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
