pub struct Label {
    pub length: u8,
    pub content: String,
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
                let offset = (((*length & 0b00111111) as u16) << 8 | *iter.next()? as u16) - 12; //or 16? 16 passed the CI but i don't think it's right
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
