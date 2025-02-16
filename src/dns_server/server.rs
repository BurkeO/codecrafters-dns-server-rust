use crate::dns_protocol::{
    dns_header::DnsHeader, dns_header::DNS_HEADER_SIZE, dns_question::decode_questions,
    dns_question::DnsQuestion, dns_resource_record::ResourceRecord,
};
use std::{
    net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    str::FromStr,
};

pub struct Server {
    source_ip: String,
    port: u16,
    forwarding_socket: UdpSocket,
    resolver_addr: String,
    client_response_buf: [u8; 10000],
    client_receive_buf: [u8; 10000],
}

impl Server {
    pub fn new(source_ip: String, port: u16, resolver_addr: String) -> Self {
        Self {
            source_ip,
            port,
            forwarding_socket: UdpSocket::bind("127.0.0.1:0")
                .expect("Failed to bind to forwarding socket"),
            resolver_addr,
            client_response_buf: [0; 10000],
            client_receive_buf: [0; 10000],
        }
    }

    pub fn start(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut udp_socket = UdpSocket::bind(format!("{}:{}", self.source_ip, self.port))?;
        loop {
            match udp_socket.recv_from(&mut self.client_receive_buf) {
                Ok((size, source)) => {
                    println!("Received {} bytes from {}", size, source);
                    self.handle_packet(&mut udp_socket, &source)?;
                }
                Err(e) => {
                    eprintln!("Error receiving data: {}", e);
                    break;
                }
            }
        }
        Ok(())
    }

    fn handle_packet(
        &mut self,
        udp_socket: &mut UdpSocket,
        source: &SocketAddr,
    ) -> Result<(), anyhow::Error> {
        let query_header =
            DnsHeader::from_network_bytes(self.client_receive_buf[..DNS_HEADER_SIZE].try_into()?);

        let query_questions = decode_questions(
            &self.client_receive_buf[DNS_HEADER_SIZE..],
            query_header.question_count,
        )
        .expect("Failed to decode questions in query");

        let mut response_header = query_header;
        response_header.query_response_indicator = 1;
        response_header.response_code = if response_header.opcode == 0 { 0 } else { 4 };
        response_header.answer_record_count = response_header.question_count;
        self.client_response_buf[0..DNS_HEADER_SIZE]
            .copy_from_slice(&response_header.to_network_bytes());

        let answers = self.forward_query(query_questions.as_slice())?;
        println!("Received {} answers", answers.len());
        let mut question_index = DNS_HEADER_SIZE;
        for question in query_questions {
            let mut response_question = question;
            response_question.question_type = 1;
            response_question.class = 1;
            let response_question_bytes = response_question.to_bytes();
            self.client_response_buf
                [question_index..question_index + response_question_bytes.len()]
                .copy_from_slice(response_question_bytes.as_slice());
            question_index += response_question_bytes.len();
        }

        let mut answer_index = question_index;
        for answer in answers {
            let answer_bytes = answer.to_bytes();
            println!("Answer index is {}", answer_index);
            println!("Answer bytes length is {}", answer_bytes.len());
            println!("Taking slice from {} to {}", answer_index, answer_index + answer_bytes.len());
            self.client_response_buf[answer_index..answer_index + answer_bytes.len()]
                .copy_from_slice(answer_bytes.as_slice());
            answer_index += answer_bytes.len();
        }
        udp_socket.send_to(&self.client_response_buf[..answer_index], source)?;
        Ok(())
    }

    fn forward_query(
        &mut self,
        query_questions: &[DnsQuestion],
    ) -> Result<Vec<ResourceRecord>, anyhow::Error> {
        println!("Forwarding query to resolver: {}", self.resolver_addr);
        let mut resource_records = Vec::<ResourceRecord>::new();
        //add udp socket to self (might be able to reuse current one)
        //same with buffers (could maybe reuse)
        let mut forwarding_buf = [0; 10000];
        let mut receive_buf: [u8; 10000] = [0; 10000];
        for (id, question) in query_questions.iter().enumerate() {
            let header = DnsHeader {
                packet_identifier: id as u16,
                question_count: 1,
                ..Default::default()
            };
            let header_bytes = header.to_network_bytes();
            let question_bytes = question.to_bytes();
            forwarding_buf[..DNS_HEADER_SIZE].copy_from_slice(&header_bytes);
            forwarding_buf[DNS_HEADER_SIZE..DNS_HEADER_SIZE + question_bytes.len()]
                .copy_from_slice(question_bytes.as_slice());
            self.forwarding_socket.send_to(
                &forwarding_buf[..DNS_HEADER_SIZE + question_bytes.len()],
                self.resolver_addr.to_string(),
            )?;

            let (_, _) = self.forwarding_socket.recv_from(&mut receive_buf)?;
            let response_header =
                DnsHeader::from_network_bytes(receive_buf[..DNS_HEADER_SIZE].try_into()?);
            let response_questions = decode_questions(
                &receive_buf[DNS_HEADER_SIZE..],
                response_header.question_count,
            )
            .expect("Failed to decode questions in response from forwarder");
            let response_answer = ResourceRecord::from_bytes(
                &receive_buf[DNS_HEADER_SIZE + response_questions[0].to_bytes().len()..], //assuming it's one question + one answer for forwarder
            )
            .expect("Failed to decode answer in response from forwarder");
            
            let answer = &response_answer;
            println!("Answer domain name {:?}", answer.domain_name);
            println!("Answer type {}", answer.answer_type);
            println!("Answer class {}", answer.class);
            println!("Answer ttl {}", answer.ttl);
            println!("Answer data length {}", answer.data_length);
            println!("Response Answer len {}", response_answer.to_bytes().len());
            
            resource_records.push(response_answer);
        }
        Ok(resource_records)
    }
}
