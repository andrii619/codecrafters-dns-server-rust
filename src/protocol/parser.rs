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

#[derive(Clone, Copy, PartialEq)]
pub enum RecordType {
    /// Adress Record: domain name -> IPv4 address (ex example.com -> 192.0.2.1)
    A = 1,
    /// domain name -> IPv6
    AAAA,
    /// Name Server Record: Lists authoritative name servers for a domain name (Ex example.com -> ns1.examplehostingprovider.com, ns2.examplehostingprovider.com)
    NS,
    MD,
    MF,
    /// Canonical Name Record: alias for domain names. domain name -> domain name. (Ex: www.example.com -> example.com, ftp.example.com -> example.com). Used for running multiple subdomains for different purposes
    CNAME,
    SOA,
    MB,
    MG,
    MR,
    NULL,
    WKS,
    // Pointer Record. IP address -> domain name. Used in reverse DNS to map IP to a domain name
    PTR,
    HINFO,
    MINFO,
    /// Mail Exchange Record: directs email for domain to the correct mail server
    MX,
    /// Stores arbitrary text. Often used for email verification
    TXT,
}

#[derive(Clone, Copy)]
pub enum RecordClass {
    IN = 1,
}

/// DNS Response codes
#[derive(Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum ResponseCode {
    NOERROR = 0,
    FORMERR,
    SERVFAIL,
    NXDOMAIN,
    NOTIMP,
    REFUSED,
    YXDOMAIN,
    YXRRSET,
    NXRSET,
    NOTAUTH,
    NOTZONE,
    BADVERS = 16,
    BADSIG,
    BADKEY,
    BADTIME,
    BADMODE,
    BADNAME,
    BADALG,
    // TIMEOUT,
}

#[repr(u8)]
#[derive(Copy, Clone, PartialEq)]
/// 4 bit DNS Operation code
pub enum Opcode {
    QUERY = 0,
    /// finding a name from IP
    IQUERY,
    /// request the server status information
    STATUS,
    NOTIFY = 4,
    /// for DDNS to add, delete, or modify a record
    UPDATE,
    DSO,
    NOTIMPLEMENTED,
}

pub trait DNSRecord {
    // the timestamp of when this record is considered to be expired
    //
    fn get_domain_name(&self) -> &str;
    /// Get the expiration time
    fn get_expiration_time(&self) -> chrono::DateTime<chrono::Utc>;
    // Check if the record is expired
    fn is_expired(&self) -> bool {
        self.get_expiration_time() < chrono::Utc::now()
    }
}

pub struct DNSRecordBase {
    pub domain_name: String,
    // time_to_live: u32,
    pub expiration_time: chrono::DateTime<chrono::Utc>,
}

pub struct ARecord {
    pub base: DNSRecordBase,
    // pub domain_name: String,
    /// 4 tuple to represent IPv4 Address
    pub ip_v4: [u8; 4],
}

impl DNSRecord for ARecord {
    fn get_domain_name(&self) -> &str {
        return &self.base.domain_name;
    }
    fn get_expiration_time(&self) -> chrono::DateTime<chrono::Utc> {
        return self.base.expiration_time;
    }
}

pub struct CNameRecord {
    pub base: DNSRecordBase,
    pub domain_name_alias: String,
    // pub domain_name: String,
}

/// Header is always 12bytes inside a raw packet
#[derive(Clone, Copy)]
pub struct Header {
    pub identifier: u16, // [0:1] A random ID assigned to query packets. Response packets must reply with the same ID.
    pub is_response: bool, //[2] 1 for reply packet, 0 for a question packet
    pub opcode: Opcode,  //[2] 4 bits
    pub authoritative: bool, // [2]
    pub truncation: bool, // [2]
    pub recursion_desired: bool, // [2]
    pub recursion_available: bool, // [3]
    pub reserved: bool,  // [3] 1 bit
    pub authenticated_data: bool, // [3] 1 bit DNSSEC
    pub checking_disabled: bool, // [3] b bit DNSSEC
    pub response_code: ResponseCode, // 4bit response code
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
                | ((self.opcode as u8 & 0xF) << 3)
                | ((self.authoritative as u8) << 2)
                | ((self.truncation as u8) << 1)
                | ((self.recursion_desired as u8) << 0),
        );

        header_data.push(
            ((self.recursion_available as u8) << 7)
                | ((self.authenticated_data as u8) << 5)
                | ((self.checking_disabled as u8) << 4)
                | (self.response_code as u8 & 0xF),
        );

        header_data.extend_from_slice(&(self.question_count.to_be_bytes()));

        header_data.extend_from_slice(&(self.answer_count.to_be_bytes()));

        header_data.extend_from_slice(&(self.authority_count.to_be_bytes()));

        header_data.extend_from_slice(&(self.additional_count.to_be_bytes()));
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
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
    ///
    fn label_from_offset(
        data: &[u8],
        offset: usize,
        first_label: bool,
        result: &mut String,
    ) -> Result<usize, String> {
        if offset >= data.len() || data.len() == 0 {
            return Err(String::from("Not enough data to parse domainname"));
        }

        if data[offset] == 0 {
            // sequence of labels terminates with null byte
            return Ok(1);
        }
        let first_two_bits = data[offset] & 0xC0;
        if first_two_bits == 0x40 || first_two_bits == 0x80 {
            return Err(String::from("Reserved label bit pattern (01 or 10)"));
        }

        if data[offset] & 0xC0 == 0xC0 {
            // this is a compressed label
            if offset + 1 >= data.len() {
                return Err(String::from("Incomplete compression pointer"));
            }
            let domain_name_pointer =
                u16::from_be_bytes([data[offset], data[offset + 1]]) & 0x3F_FF;
            if domain_name_pointer as usize >= data.len() {
                return Err(String::from("Compressed pointer is too large"));
            }
            //let domain_name_res =
            tracing::info!("Reading compressed label at {} offset", domain_name_pointer);
            //if let Ok(bytes_read) =
            match DNSPacket::label_from_offset(
                data,
                domain_name_pointer as usize,
                first_label,
                result,
            ) {
                Ok(bytes_read) => return Ok(2),
                Err(e) => return Err(e),
            };
        }

        // this is not a compressed label

        let mut data_idx = offset;
        let mut current_label = String::new();

        let char_count = data[data_idx] as usize;
        // check if char count is more than we have data or if it exeeds the max allowed label length
        if (char_count + data_idx) >= data.len() || char_count > 63 {
            return Err(String::from("Not enough data"));
        }

        data_idx += 1;

        if !first_label {
            current_label.push('.');
            result.push('.');
        }

        // push character_count characters into the string buffer
        let start_idx = data_idx;
        while data_idx < data.len() && data_idx < (start_idx + char_count) {
            result.push(data[data_idx] as char);
            current_label.push(data[data_idx] as char); // for debugging
            data_idx += 1;
        }

        // go to the next label
        tracing::info!("Parsed Current uncompressed label: {}", current_label);

        let recursive_res = DNSPacket::label_from_offset(data, data_idx, false, result);
        match recursive_res {
            Ok(rec_len) => Ok(rec_len + (data_idx - offset)), // recursivelly add the number of bytes read
            Err(e) => Err(e),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < 12 {
            return Err(String::from("Not enough data"));
        }

        let identifier = u16::from_be_bytes([data[0], data[1]]);
        let is_response = ((data[2] & 0x80) >> 7) == 1;
        let opcode: Opcode = match (data[2] & 0x78) >> 3 {
            0 => Opcode::QUERY,
            1 => Opcode::IQUERY,
            2 => Opcode::STATUS,
            4 => Opcode::NOTIFY,
            5 => Opcode::UPDATE,
            6 => Opcode::DSO,
            a => {
                tracing::info!("Invalid opcode {}", a);
                Opcode::NOTIMPLEMENTED
            }
        };
        let authoritative = ((data[2] & 0x04) >> 2) == 1;
        let truncation = ((data[2] & 0x02) >> 1) == 1;
        let recursion_desired = (data[2] & 0x01) == 1;
        let recursion_available = ((data[3] & 0x80) >> 7) == 1;
        let reserved = ((data[3] & 0x40) >> 6) == 1;
        let authenticated_data = ((data[3] & 0x20) >> 5) == 1;
        let checking_disabled = ((data[3] & 0x10) >> 4) == 1;
        let response_code: ResponseCode = match data[3] & 0x0F {
            0 => ResponseCode::NOERROR,
            _ => return Err(String::from("Invalid response code")),
        };
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
        let mut answers = Vec::<Answer>::new();

        // parse questions
        let mut data_idx: usize = 12; // one past the header
        let mut questions_parsed = 0;
        for _ in 0..question_count {
            if data_idx >= data.len() {
                break;
            }

            // recurively parse the domain name
            let mut domain_name = String::new();
            let bytes_read =
                match DNSPacket::label_from_offset(data, data_idx, true, &mut domain_name) {
                    Ok(bytes_read) => bytes_read,
                    Err(e) => return Err(e),
                };

            if bytes_read == 0 || bytes_read >= server_consts::BUF_SIZE {
                return Err(String::from("error reading domain name"));
            }

            data_idx += bytes_read;

            tracing::info!("Read domain name: {}", domain_name);

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

        // parse answer section
        let mut answers_parsed = 0;
        for _ in 0..answer_count {
            if data_idx >= data.len() {
                break;
            }

            // recurively parse the domain name
            let mut domain_name = String::new();
            let bytes_read =
                match DNSPacket::label_from_offset(data, data_idx, true, &mut domain_name) {
                    Ok(bytes_read) => bytes_read,
                    Err(e) => return Err(e),
                };

            if bytes_read == 0 || bytes_read >= server_consts::BUF_SIZE {
                return Err(String::from("error reading domain name"));
            }

            data_idx += bytes_read;

            tracing::info!("Read domain name: {}", domain_name);

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

            // parse TTL which is 4 bytes
            if data_idx + 6 > data.len() {
                // 4 for TTL + 2 for data_length
                return Err(String::from("Not enough data for TTL and data length"));
            }
            let time_to_live = u32::from_be_bytes([
                data[data_idx],
                data[data_idx + 1],
                data[data_idx + 2],
                data[data_idx + 3],
            ]);

            data_idx += 4;

            // parse RD length which is 2 bytes
            let data_length = u16::from_be_bytes([data[data_idx], data[data_idx + 1]]);
            data_idx += 2;

            // parse the actual answer data
            let rdata_length = data_length as usize;
            if data_idx + rdata_length > data.len() {
                return Err(String::from("Not enough data for answer RDATA"));
            }
            let answer_data = Vec::<u8>::from(&data[data_idx..data_idx + rdata_length]);

            data_idx += rdata_length;

            answers.push(Answer {
                domain_name,
                record_type,
                class,
                time_to_live,
                data_length,
                data: answer_data,
            });
            answers_parsed += 1;
        }

        if answers_parsed != answer_count {
            return Err(String::from("Not enough data to parse all answers"));
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
