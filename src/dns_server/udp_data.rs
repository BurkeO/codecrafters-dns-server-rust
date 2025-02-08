#[derive(Default)]
pub struct DnsHeader {
    pub packet_identifier: u16,
    pub query_response_indicator: u8,
    pub opcode: u8,
    pub authoritative_answer: u8,
    pub truncation: u8,
    pub recursion_desired: u8,
    pub recursion_available: u8,
    pub reserved: u8,
    pub response_code: u8,
    pub question_count: u16,
    pub answer_record_count: u16,
    pub authority_record_count: u16,
    pub additional_record_count: u16,
}

impl DnsHeader {
    pub fn to_bytes(&self) -> [u8; 12] {
        //todo this is a bit ugly
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

    pub fn from_bytes(header : &[u8; 12]) -> Self
    {
        Self {
            packet_identifier: (header[0] as u16) << 8 | header[1] as u16,
            query_response_indicator: header[2] >> 7,
            opcode: (header[2] >> 3) & 0b00001111,
            authoritative_answer: (header[2] >> 2) & 0b00000001,
            truncation: (header[2] >> 1) & 0b00000001,
            recursion_desired: header[2] & 0b00000001,
            recursion_available: header[3] >> 7,
            reserved: (header[3] >> 4) & 0b00000111,
            response_code: header[3] & 0b00001111,
            question_count: (header[4] as u16) << 8 | header[5] as u16,
            answer_record_count: (header[6] as u16) << 8 | header[7] as u16,
            authority_record_count: (header[8] as u16) << 8 | header[9] as u16,
            additional_record_count: (header[10] as u16) << 8 | header[11] as u16,
        }
    }
}

pub struct Label {
    length: u8,
    content: String,
}

pub struct DnsQuestion {
    pub domain_name: Vec<Label>,
    pub question_type: u16,
    pub class: u16,
}

impl DnsQuestion {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        for label in &self.domain_name {
            bytes.push(label.length);
            bytes.extend(label.content.bytes());
        }
        bytes.push(0);
        bytes.push((self.question_type >> 8) as u8);
        bytes.push(self.question_type as u8);
        bytes.push((self.class >> 8) as u8);
        bytes.push(self.class as u8);
        bytes
    }

    pub fn decode_dns_question(buf: &[u8]) -> Option<Self> {
        //todo lots of copying going on here
        let mut labels = Vec::<Label>::new();
        let mut iter = buf.iter();
        while let Some(length) = iter.next() {
            if *length == 0x00 {
                iter.next();
                break;
            }
            let content: String = iter
                .clone()
                .take(*length as usize)
                .map(|&x| x as char)
                .collect();
            labels.push(Label {
                length: *length,
                content,
            });
            iter.nth(*length as usize - 1);
        }
        let question_type = (*iter.next()? as u16) | (*iter.next()? as u16) << 8; //todo handle the endianness correctly/platform agnostically, htons?
        let class = (*iter.next()? as u16) | (*iter.next()? as u16) << 8;
        Some(Self {
            domain_name: labels,
            question_type,
            class,
        })
    }
}


pub struct DnsAnswer {
    domain_name: Vec<Label>,
    answer_type: u16,
    class: u16,
    ttl: u32,
    data_length: u16,
    data: Vec<u8>,
}

impl DnsAnswer {
    pub fn new(domain_name: Vec<Label>, answer_type: u16, class: u16, ttl: u32, data: Vec<u8>) -> Self {
        Self {
            domain_name,
            answer_type,
            class,
            ttl,
            data_length: data.len() as u16,
            data,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::<u8>::new();
        for label in &self.domain_name {
            bytes.push(label.length);
            bytes.extend(label.content.bytes());
        }
        bytes.push(0);
        bytes.push((self.answer_type >> 8) as u8);
        bytes.push(self.answer_type as u8);
        bytes.push((self.class >> 8) as u8);
        bytes.push(self.class as u8);
        bytes.push((self.ttl >> 24) as u8);
        bytes.push((self.ttl >> 16) as u8);
        bytes.push((self.ttl >> 8) as u8);
        bytes.push(self.ttl as u8);
        bytes.push((self.data_length >> 8) as u8);
        bytes.push(self.data_length as u8);
        bytes.extend(self.data.iter());
        bytes
    }
}
