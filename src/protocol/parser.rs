use std::io::Read;

use bytes::BufMut;

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
    pub reserved: u8,    // [3] 3 bits
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

        header_data.push(((self.recursion_available as u8) << 7) | (self.response_code & 0xF));

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
        let reserved = (data[3] & 0x70) >> 4;
        let response_code = data[3] & 0x0F;
        let question_count = u16::from_be_bytes([data[4], data[5]]);
        let answer_count = u16::from_be_bytes([data[6], data[7]]);
        let authority_count = u16::from_be_bytes([data[8], data[9]]);
        let additional_count = u16::from_be_bytes([data[10], data[11]]);

        if reserved != 0 {
            return Err(String::from(
                "Not valid DNS packet. Reserved bits are not zero",
            ));
        }
        
        
        let mut questions = Vec::<Question>::new();
        let mut answers = Vec::<Answer>::new();
        
        // parse questions 
        let mut data_idx: usize = 12; // one past the header
        let mut questions_parsed =0;
        for question_num in 0..question_count {
            if data_idx >= data.len() {
                break;
            }
            
            // try to parse current question
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
                while data_idx < data.len() && data_idx < (start_idx+char_count) {
                    domain_name.push(data[data_idx] as char);
                    data_idx += 1;
                }
            }
            
            
            // here we should have \x00 byte
            if data_idx+5 > data.len() || data[data_idx] != 0 
            {
                return Err(String::from("data label not ending in 0 or not enough data"));
            }
            data_idx += 1;
            
            let record_type_num = u16::from_be_bytes([data[data_idx], data[data_idx+1]]);
            data_idx += 2;
            let record_type = match record_type_num {
                1 => RecordType::A,
                _ => {return Err(String::from("Record type error"))}
            };
            
            
            let class_num = u16::from_be_bytes([data[data_idx], data[data_idx+1]]);
            data_idx += 2;
            
            let class = match class_num {
                1 => RecordClass::IN,
                _ => {return Err(String::from("bad record class"))}
            };
            
            
            questions.push(Question { domain_name, record_type, class });
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
