



pub struct Header {
    pub identifier: u16,//A random ID assigned to query packets. Response packets must reply with the same ID.
    pub query_or_response: bool,// 1 for reply packet, 0 for a question packet
    pub opcode: u8, // 4 bits
    pub authoritative: bool,
    pub truncation: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub response_code: u8, // 4bit response code + 3bit reserved
    pub question_count: u16,
    pub answer_record_count: u16,
    pub authority_record_count: u16,
    pub additional_record_count: u16,
}

pub struct DNSPacket {
    h: Header,
}