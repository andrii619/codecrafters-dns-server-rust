// use std::io::Read;

// use bytes::BufMut;

///
/// DNS Message:
/// !!! All data in big-endian format
/// |---------------------------|
/// | Header (12 bytes)         |
/// |---------------------------|
/// |
/// |
/// |
use crate::server_consts;
// use tracing::{debug, error, trace};

#[derive(Clone, Copy)]
pub enum RecordType {
    A = 1,
    NS,
    MD,
    MF,
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    PTR,
    HINFO,
    MINFO,
    MX,
    TXT,
}

#[derive(Clone, Copy)]
pub enum RecordClass {
    IN = 1,
}

/// Header is always 12bytes inside a raw packet
pub struct Header {
    pub identifier: u16, // [0:1] A random ID assigned to query packets. Response packets must reply with the same ID.
    pub is_response: bool, //[2] 1 for reply packet, 0 for a question packet
    pub opcode: u8,      //[2] 4 bits
    pub authoritative: bool, // [2]
    pub truncation: bool, // [2]
    pub recursion_desired: bool, // [2]
    pub recursion_available: bool, // [3]
    pub reserved: bool,    // [3] 1 bit
    pub authenticated_data: bool, // [3] 1 bit DNSSEC
    pub checking_disabled: bool, // [3] b bit DNSSEC
    pub response_code: u8, // 4bit response code
    pub question_count: u16, // [4:5]
    pub answer_count: u16, // [6:7]
    pub authority_count: u16, // [8:9]
    pub additional_count: u16, // [10:11]
}

impl Header {
    //pub fn from_bytes(data: &[u8]) -> Option<Self> {
    //    None
    //}

    pub fn to_bytes(&self, header_data: &mut Vec<u8>) {
        // identifier stored in big endian format
        header_data.extend_from_slice(&(self.identifier.to_be_bytes()));

        header_data.push(
            ((self.is_response as u8) << 7)
                | ((self.opcode & 0xF) << 3)
                | ((self.authoritative as u8) << 2)
                | ((self.truncation as u8) << 1)
                | ((self.recursion_desired as u8) << 0),
        );

        header_data.push(((self.recursion_available as u8) << 7) |
            ((self.authenticated_data as u8) << 5) |
            ((self.checking_disabled as u8) << 4) |
            (self.response_code & 0xF));

        header_data.extend_from_slice(&(self.question_count.to_be_bytes()));

        header_data.extend_from_slice(&(self.answer_count.to_be_bytes()));

        header_data.extend_from_slice(&(self.authority_count.to_be_bytes()));

        header_data.extend_from_slice(&(self.additional_count.to_be_bytes()));
    }
}

pub struct Question {
    pub domain_name: String,
    pub record_type: RecordType, //2 bytes
    pub class: RecordClass,      // 2 bytes
}

impl Question {
    pub fn to_bytes(&self, data: &mut Vec<u8>) {
        // check if output has enough capacity to store all data
        // worst case: domain bytes + labels + terminator + qtype + qclass
        data.reserve(self.domain_name.len() + self.domain_name.split('.').count() + 1 + 4);

        for label in self.domain_name.split('.') {
            data.push(label.len() as u8);
            data.extend_from_slice(label.as_bytes());
        }

        data.push(0); // terminator
        data.extend_from_slice(&(self.record_type as u16).to_be_bytes());
        data.extend_from_slice(&(self.class as u16).to_be_bytes());
    }
}

pub struct Answer {
    pub domain_name: String,
    pub record_type: RecordType, //2 bytes
    pub class: RecordClass,      // 2 bytes
    pub time_to_live: u32,
    pub data_length: u16,
    pub data: Vec<u8>,
}

impl Answer {
    pub fn to_bytes(&self, data: &mut Vec<u8>) {
        for label in self.domain_name.split('.') {
            data.push(label.len() as u8);
            data.extend_from_slice(label.as_bytes());
        }

        data.push(0); // terminator
        data.extend_from_slice(&(self.record_type as u16).to_be_bytes());
        data.extend_from_slice(&(self.class as u16).to_be_bytes());

        // time to live
        data.extend_from_slice(&(self.time_to_live.to_be_bytes()));

        // data length
        data.extend_from_slice(&(self.data_length.to_be_bytes()));

        // data section
        data.extend_from_slice(&(self.data.as_slice()));
    }
}

pub struct DNSPacket {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Answer>,
}

//pub struct Header {
//    pub identifier: u16, // [0:1] A random ID assigned to query packets. Response packets must reply with the same ID.
//    pub is_response: bool, //[2] 1 for reply packet, 0 for a question packet
//    pub opcode: u8,      //[2] 4 bits
//    pub authoritative: bool, // [2]
//    pub truncation: bool, // [2]
//    pub recursion_desired: bool, // [2]
//    pub recursion_available: bool, // [3]
//    pub reserved: u8,    // [3]   3 bits
//    pub response_code: u8, // [3] 4bit response code
//    pub question_count: u16,    // [4:5]
//    pub answer_count: u16,      // [6:7]
//    pub authority_count: u16,  // [8:9]
//    pub additional_count: u16, // [10:11]
//}
impl DNSPacket {
    ///For a proper implementation, you'd typically need a recursive helper function that:
    ///- Takes a starting offset and the full packet data
    ///- Reads labels until it hits a null terminator OR a pointer
    ///- If it hits a pointer, recursively calls itself at the pointer offset
    ///- Tracks visited offsets to prevent infinite loops

    /// parse a hostname from DNS packet data starting at an offset
    /// Returns parsed domain name as a string and how many bytes were parsed
    /// support parsing a packet slice that ONLY has the hostname string data in it terminated by the 0x00 byte
    fn domain_name_from_offset(data: &[u8], offset: usize) -> Result<(String, usize), String> {
        if offset >= data.len() || data.len() == 0 {
            return Err(String::from("Not enough data to parse domainname"));
        }

        let mut data_idx = offset;

        let mut domain_name = String::new();
        let mut first_label = true;
        while data_idx < data.len() && data[data_idx] != 0 {
            // this data belongs to current question
            let char_count = data[data_idx] as usize;
            data_idx += 1;
            if !first_label {
                domain_name.push('.');
            }
            first_label = false;

            // push character_count characters into the string buffer
            let start_idx = data_idx;
            while data_idx < data.len() && data_idx < (start_idx + char_count) {
                domain_name.push(data[data_idx] as char);
                data_idx += 1;
            }
        }

        // need to check if we managed to parse all hostname bytes before running out of data
        // either we ran out of data and last byte was 0x00 or we did not run out of data and last byte was 0x00
        let last_byte = if data_idx < data.len() {
            Some(data[data_idx])
        } else {
            None
        };

        // return pointing one past the 0x00 byte
        match last_byte {
            Some(0) => Ok((domain_name, (data_idx - offset + 1))),
            Some(_) => Err(String::from("Last byte not null")),
            None => Err(String::from("Not enough data")),
        }

        // Err(String::from("dwd"))
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 12 {
            return Err(String::from("Not enough data"));
        }

        let identifier = u16::from_be_bytes([data[0], data[1]]);
        let is_response = ((data[2] & 0x80) >> 7) == 1;
        let opcode: u8 = (data[2] & 0x78) >> 3;
        let authoritative = ((data[2] & 0x04) >> 2) == 1;
        let truncation = ((data[2] & 0x02) >> 1) == 1;
        let recursion_desired = (data[2] & 0x01) == 1;
        let recursion_available = ((data[3] & 0x80) >> 7) == 1;
        let reserved = ((data[3] & 0x40) >> 6)==1;
        let authenticated_data = ((data[3] & 0x20) >> 5)==1;
        let checking_disabled = ((data[3] & 0x10) >> 4)==1;
        let response_code = data[3] & 0x0F;
        let question_count = u16::from_be_bytes([data[4], data[5]]);
        let answer_count = u16::from_be_bytes([data[6], data[7]]);
        let authority_count = u16::from_be_bytes([data[8], data[9]]);
        let additional_count = u16::from_be_bytes([data[10], data[11]]);

        if reserved {
            return Err(String::from(
                "Not valid DNS packet. Reserved bits are not zero",
            ));
        }

        let mut questions = Vec::<Question>::new();
        let answers = Vec::<Answer>::new();

        // parse questions
        let mut data_idx: usize = 12; // one past the header
        let mut questions_parsed = 0;
        for _ in 0..question_count {
            if data_idx >= data.len() {
                break;
            }
            
            //let mut domain_name_opt: Option<String> = None;
            
            let domain_name_res = if data[data_idx] & 0xC0 == 0xC0 {
                // we have encountered a comprssed question. skip for now
                //data_idx += 6;
                //continue;
                let domain_name_pointer = u16::from_be_bytes([data[data_idx],data[data_idx+1]]) & 0x3F_FF;
                if domain_name_pointer as usize > server_consts::BUF_SIZE {
                    return Err(String::from("Compressed pointer is too large"));
                }
                //let domain_name_res = 
                DNSPacket::domain_name_from_offset(data, domain_name_pointer as usize)
            }
            else {
                // try to parse current uncompressed question
                //let domain_name_res = 
                DNSPacket::domain_name_from_offset(data, data_idx)
            };
            
            let (domain_name, bytes_read) = match domain_name_res {
                Ok(res) => res,
                Err(e) => return Err(e),
            };
            if bytes_read == 0 || bytes_read >= server_consts::BUF_SIZE {
                return Err(String::from("error reading domain name"));
            }
            
            data_idx += bytes_read;
            //domain_name_opt = Some(domain_name);
            // see if we can parse the record type and class number
            if data_idx + 4 > data.len() {
                return Err(String::from("not enough data"));
            }

            let record_type_num = u16::from_be_bytes([data[data_idx], data[data_idx + 1]]);
            data_idx += 2;
            let record_type = match record_type_num {
                1 => RecordType::A,
                _ => return Err(String::from("Record type error")),
            };

            let class_num = u16::from_be_bytes([data[data_idx], data[data_idx + 1]]);
            data_idx += 2;

            let class = match class_num {
                1 => RecordClass::IN,
                _ => return Err(String::from("bad record class")),
            };

            questions.push(Question {
                domain_name,
                record_type,
                class,
            });
            questions_parsed += 1;
        }

        if questions_parsed != question_count {
            return Err(String::from("Not enough data to parse all questions"));
        }

        Ok(DNSPacket {
            header: Header {
                identifier,
                is_response,
                opcode,
                authoritative,
                truncation,
                recursion_desired,
                recursion_available,
                reserved,
                authenticated_data,
                checking_disabled,
                response_code,
                question_count,
                answer_count,
                authority_count,
                additional_count,
            },
            questions,
            answers,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::<u8>::with_capacity(server_consts::BUF_SIZE);

        // push header data
        self.header.to_bytes(&mut data);

        // push question data
        for question in &self.questions {
            question.to_bytes(&mut data);
        }

        // push answer data
        for answer in &self.answers {
            answer.to_bytes(&mut data);
        }

        data
    }
}
