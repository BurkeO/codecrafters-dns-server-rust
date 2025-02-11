use bitfield::bitfield;
// use rkyv::{deserialize, rancor::Error, Archive, Deserialize, Serialize};

bitfield! {
    pub struct DnsHeaderFlags(u16);
    query_response_indicator, set_query_response_indicator: 0, 0;
    opcode, set_opcode: 4, 1;
    authoritative_answer, set_authoritative_answer: 5, 5;
    truncation, set_truncation: 6, 6;
    recursion_desired, set_recursion_desired: 7, 7;
    recursion_available, set_recursion_available: 8, 8;
    reserved, set_reserved: 11, 9;
    response_code, set_response_code: 15, 12;
}

pub const DNS_HEADER_SIZE: usize = 12;
// #[repr(packed(1))]
#[derive(Debug, PartialEq, Default)]
pub struct DnsHeader {
    pub packet_identifier: u16,
    // pub flags: DnsHeaderFlags,
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
// const _: () = assert!(size_of::<DnsHeader>() == 12, "DNS header is not 12 bytes");

// #[derive(PartialEq, Debug)]
// pub struct DnsHeader {
//     pub packet_identifier: u16,
//     pub query_response_indicator: u8,
//     pub opcode: u8,
//     pub authoritative_answer: u8,
//     pub truncation: u8,
//     pub recursion_desired: u8,
//     pub recursion_available: u8,
//     pub reserved: u8,
//     pub response_code: u8,
//     pub question_count: u16,
//     pub answer_record_count: u16,
//     pub authority_record_count: u16,
//     pub additional_record_count: u16,
// }

impl DnsHeader {
    pub fn to_network_bytes(&self) -> [u8; 12] {
        let mut bytes = [0; 12];
        bytes[0..=1].copy_from_slice(&self.packet_identifier.to_be_bytes());

        // bytes[2..=3].copy_from_slice(&self.flags.0.to_be_bytes());

        bytes[2] = (self.query_response_indicator << 7)
            | (self.opcode << 3)
            | (self.authoritative_answer << 2)
            | (self.truncation << 1)
            | self.recursion_desired;
        bytes[3] = (self.recursion_available << 7) | (self.reserved << 4) | self.response_code;
        bytes[4..=5].copy_from_slice(&self.question_count.to_be_bytes());
        bytes[6..=7].copy_from_slice(&self.answer_record_count.to_be_bytes());
        bytes[8..=9].copy_from_slice(&self.authority_record_count.to_be_bytes());
        bytes[10..=11].copy_from_slice(&self.additional_record_count.to_be_bytes());
        bytes
    }

    pub fn from_network_bytes(header: &[u8; 12]) -> Self {
        let flags: DnsHeaderFlags;
        // flags.0 =  u16::from_be_bytes([header[2], header[3]]);
        Self {
            packet_identifier: u16::from_be_bytes([header[0], header[1]]),
            // flags,
            query_response_indicator: header[2] >> 7,
            opcode: (header[2] >> 3) & 0b00001111,
            authoritative_answer: (header[2] >> 2) & 0b00000001,
            truncation: (header[2] >> 1) & 0b00000001,
            recursion_desired: header[2] & 0b00000001,
            recursion_available: header[3] >> 7,
            reserved: (header[3] >> 4) & 0b00000111,
            response_code: header[3] & 0b00001111,
            question_count: u16::from_be_bytes([header[4], header[5]]),
            answer_record_count: u16::from_be_bytes([header[6], header[7]]),
            authority_record_count: u16::from_be_bytes([header[8], header[9]]),
            additional_record_count: u16::from_be_bytes([header[10], header[11]]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_bytes() {
        let header = DnsHeader {
            packet_identifier: 0x1234,
            query_response_indicator: 1,
            opcode: 0,
            authoritative_answer: 0,
            truncation: 0,
            recursion_desired: 1,
            recursion_available: 1,
            reserved: 0,
            response_code: 0,
            question_count: 1,
            answer_record_count: 0,
            authority_record_count: 0,
            additional_record_count: 0,
        };
        let bytes = header.to_network_bytes();
        assert_eq!(
            bytes,
            [0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn test_from_bytes() {
        let bytes = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let header = DnsHeader::from_network_bytes(&bytes);
        assert_eq!(header.packet_identifier, 0x1234);
        assert_eq!(header.query_response_indicator, 1);
        assert_eq!(header.opcode, 0);
        assert_eq!(header.authoritative_answer, 0);
        assert_eq!(header.truncation, 0);
        assert_eq!(header.recursion_desired, 1);
        assert_eq!(header.recursion_available, 1);
        assert_eq!(header.reserved, 0);
        assert_eq!(header.response_code, 0);
        assert_eq!(header.question_count, 1);
        assert_eq!(header.answer_record_count, 0);
        assert_eq!(header.authority_record_count, 0);
        assert_eq!(header.additional_record_count, 0);
    }

    #[test]
    fn test_to_from_bytes() {
        let header = DnsHeader {
            packet_identifier: 0x5678,
            query_response_indicator: 0,
            opcode: 1,
            authoritative_answer: 1,
            truncation: 1,
            recursion_desired: 0,
            recursion_available: 0,
            reserved: 1,
            response_code: 2,
            question_count: 2,
            answer_record_count: 3,
            authority_record_count: 4,
            additional_record_count: 5,
        };
        let bytes = header.to_network_bytes();
        let new_header = DnsHeader::from_network_bytes(&bytes);
        assert_eq!(header, new_header);
    }
}
