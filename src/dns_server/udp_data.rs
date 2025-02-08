// use super::dns_field_codes::{self, QueryResponseIndicator};

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

    pub fn from_bytes(header: &[u8; 12]) -> Self {
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
}

pub fn decode_questions(buf: &[u8], number_of_questions: u16) -> Option<Vec<DnsQuestion>> {
    //todo lots of copying going on here
    let mut questions = Vec::<DnsQuestion>::new();
    let mut iter = buf.iter();
    for _ in 0..number_of_questions {
        let mut labels = Vec::<Label>::new();
        while let Some(length) = iter.next() {
            if *length == 0x00 {
                // iter.next();
                break;
            }
            let (content_len, content) = if *length & 0b11000000 != 0 {
                //compressed label
                let offset = (((*length & 0b00111111) as u16) << 8 | *iter.next()? as u16) - 20;
                let mut label_iter = buf.iter().skip(offset as usize);
                let label_len = *label_iter.next()?;
                (
                    label_len,
                    label_iter
                        .take(label_len as usize)
                        .map(|&x| x as char)
                        .collect(),
                )
            } else {
                let content = iter
                    .clone()
                    .take(*length as usize)
                    .map(|&x| x as char)
                    .collect();
                iter.nth(*length as usize - 1);
                (*length, content)
            };
            println!("content_len: {}, content: {}", content_len, content);
            labels.push(Label {
                length: content_len,
                content,
            });
        }
        let question_type = (*iter.next()? as u16) << 8 | (*iter.next()? as u16); //todo handle the endianness correctly/platform agnostically, htons?
        let class = (*iter.next()? as u16) << 8 | (*iter.next()? as u16); //todo handle the endianness correctly/platform agnostically, htons?
        questions.push(DnsQuestion {
            domain_name: labels,
            question_type, //todo need to move this out but at end of all questions?????
            class,
        });
    }
    Some(questions)
}

pub struct ResourceRecord {
    domain_name: Vec<Label>,
    answer_type: u16,
    class: u16,
    ttl: u32,
    data_length: u16,
    data: Vec<u8>,
}

impl ResourceRecord {
    pub fn new(
        domain_name: Vec<Label>,
        answer_type: u16,
        class: u16,
        ttl: u32,
        data: Vec<u8>,
    ) -> Self {
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

//tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_question_parsing() {
        let question = vec![
            1,
            ('F' as u8),
            3,
            ('I' as u8),
            ('S' as u8),
            ('I' as u8),
            0,
            0,
            1,
            0,
            1, 
            3,
            ('F' as u8),
            ('O' as u8),
            ('O' as u8),
            0b11000000,
            0b00010100,
            0,
            0,
            1,
            0,
            1, 
        ];

        let questions = decode_questions(&question, 2).unwrap();

        assert_eq!(questions.len(), 2);
    }
}
