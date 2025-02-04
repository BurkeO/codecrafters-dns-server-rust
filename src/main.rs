#[allow(unused_imports)]
use std::net::UdpSocket;

#[derive(Default)]
struct DnsHeader {
    packet_identifier: u16,
    query_response_indicator: u8,
    opcode: u8,
    authoritative_answer: u8,
    truncation: u8,
    recursion_desired: u8,
    recursion_available: u8,
    reserved: u8,
    response_code: u8,
    question_count: u16,
    answer_record_count: u16,
    authority_record_count: u16,
    additional_record_count: u16,
}

impl DnsHeader {
    fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0; 12];
        bytes[0] = (self.packet_identifier >> 8) as u8;
        bytes[1] = self.packet_identifier as u8;
        bytes[2] = (self.query_response_indicator << 7)
            | (self.opcode << 3)
            | (self.authoritative_answer << 2)
            | (self.truncation << 1)
            | self.recursion_desired;
        bytes[3] = (self.recursion_available << 7) | (self.reserved << 4) | self.response_code;
        bytes[4] = (self.question_count >> 8) as u8;
        bytes[5] = self.question_count as u8;
        bytes[6] = (self.answer_record_count >> 8) as u8;
        bytes[7] = self.answer_record_count as u8;
        bytes[8] = (self.authority_record_count >> 8) as u8;
        bytes[9] = self.authority_record_count as u8;
        bytes[10] = (self.additional_record_count >> 8) as u8;
        bytes[11] = self.additional_record_count as u8;
        bytes
    }
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let response_header = DnsHeader {
                    packet_identifier: 1234,
                    query_response_indicator: 1,
                    ..DnsHeader::default()
                };
                udp_socket
                    .send_to(&response_header.to_bytes(), source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
