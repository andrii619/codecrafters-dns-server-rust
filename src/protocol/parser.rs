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
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,  // [ ]
    pub additional_count: u16, // [10:11]
}

impl Header {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        None
    }

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

impl DNSPacket {
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        None
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
