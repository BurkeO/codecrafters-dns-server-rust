use crate::dns_protocol::dns_question::Label;

#[derive(Debug)]
pub struct ResourceRecord {
    pub domain_name: Vec<Label>,
    pub answer_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data_length: u16,
    pub data: Vec<u8>,
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

    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        let mut iter = buf.iter();
        let mut labels = Vec::<Label>::new();
        loop {
            let length = *iter.next()?;
            if length == 0x00 {
                break;
            }
            let (content_len, content) =  {let content = iter
                    .clone()
                    .take(length as usize)
                    .map(|&x| x as char)
                    .collect();
                iter.nth(length as usize - 1);
                (length, content)
            };
            labels.push(Label {
                length: content_len,
                content,
            });
        }
        let answer_type = u16::from_be_bytes([*iter.next()?, *iter.next()?]);
        let class = u16::from_be_bytes([*iter.next()?, *iter.next()?]);
        let ttl = u32::from_be_bytes([
            *iter.next()?,
            *iter.next()?,
            *iter.next()?,
            *iter.next()?,
        ]);
        let data_length = u16::from_be_bytes([*iter.next()?, *iter.next()?]);
        let data = iter.take(data_length as usize).map(|&x| x).collect();
        Some(Self {
            domain_name: labels,
            answer_type,
            class,
            ttl,
            data_length,
            data,
        })
    }
}
