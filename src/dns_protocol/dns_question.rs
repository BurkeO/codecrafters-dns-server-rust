#[derive(Debug)]
pub struct Label {
    pub length: u8,
    pub content: String,
}

#[derive(Debug)]
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
    println!("Parsing {} questions", number_of_questions);
    let mut questions = Vec::<DnsQuestion>::new();
    let mut label_iter = buf.iter();
    let mut end_of_label_iter = buf.iter();
    for index in 0..number_of_questions {
        let mut labels = Vec::<Label>::new();
        let mut is_compressed = false;
        while let Some(length) = label_iter.next() {
            if *length == 0x00 {
                // iter.next();
                if is_compressed {
                    end_of_label_iter.next();
                }
                let y = end_of_label_iter.next()?;
                break;
            }
            let (content_len, content) = if *length & 0b11000000 != 0 {
                is_compressed = true;
                let offset =
                    (((*length & 0b00111111) as u16) << 8 | *label_iter.next()? as u16) - 12;
                label_iter = buf.iter();
                label_iter.nth(offset as usize - 1);
                let label_len = *label_iter.next()?;
                let label = label_iter
                    .clone()
                    .take(label_len as usize)
                    .map(|&x| x as char)
                    .collect();
                label_iter.nth(label_len as usize - 1);
                (label_len, label)
            } else {
                let content = label_iter
                    .clone()
                    .take(*length as usize)
                    .map(|&x| x as char)
                    .collect();
                label_iter.nth(*length as usize - 1);
                (*length, content)
            };
            if !is_compressed {
                end_of_label_iter.nth(*length as usize).unwrap();
            }
            println!("content_len: {}, content: {}", content_len, content);
            labels.push(Label {
                length: content_len,
                content,
            });
        }
        let question_type =
            u16::from_be_bytes([*end_of_label_iter.next()?, *end_of_label_iter.next()?]);
        let class = u16::from_be_bytes([*end_of_label_iter.next()?, *end_of_label_iter.next()?]);
        questions.push(DnsQuestion {
            domain_name: labels,
            question_type, //todo need to move this out but at end of all questions?????
            class,
        });
        label_iter.nth(3);
    }
    Some(questions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_questions() {
        let buf = [
            0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63,
            0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        let questions = decode_questions(&buf, 1).unwrap();
        assert_eq!(questions.len(), 1);
        let question = &questions[0];
        assert_eq!(question.domain_name.len(), 3);
        assert_eq!(question.domain_name[0].length, 3);
        assert_eq!(question.domain_name[0].content, "www");
        assert_eq!(question.domain_name[1].length, 7);
        assert_eq!(question.domain_name[1].content, "example");
        assert_eq!(question.domain_name[2].length, 3);
        assert_eq!(question.domain_name[2].content, "com");
        assert_eq!(question.question_type, 1);
        assert_eq!(question.class, 1);
    }

    #[test]
    fn test_compressed_questions_middle() {
        let buf = [
            3, 97, 98, 99, 17, 108, 111, 110, 103, 97, 115, 115, 100, 111, 109, 97, 105, 110, 110,
            97, 109, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 3, 100, 101, 102, 192, 16, 0, 1, 0, 1,
        ];
        let questions = decode_questions(&buf, 2).unwrap();
        assert_eq!(questions.len(), 2);
        let mut question = &questions[0];
        assert_eq!(question.domain_name.len(), 3);
        assert_eq!(question.domain_name[0].length, 3);
        assert_eq!(question.domain_name[0].content, "abc");
        assert_eq!(question.domain_name[1].length, 17);
        assert_eq!(question.domain_name[1].content, "longassdomainname");
        assert_eq!(question.domain_name[2].length, 3);
        assert_eq!(question.domain_name[2].content, "com");
        assert_eq!(question.question_type, 1);
        assert_eq!(question.class, 1);

        question = &questions[1];
        assert_eq!(question.domain_name.len(), 3);
        assert_eq!(question.domain_name[0].length, 3);
        assert_eq!(question.domain_name[0].content, "def");
        assert_eq!(question.domain_name[1].length, 17);
        assert_eq!(question.domain_name[1].content, "longassdomainname");
        assert_eq!(question.domain_name[2].length, 3);
        assert_eq!(question.domain_name[2].content, "com");
        assert_eq!(question.question_type, 1);
        assert_eq!(question.class, 1);
    }
}
