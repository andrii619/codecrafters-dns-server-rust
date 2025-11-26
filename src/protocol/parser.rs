
///
/// DNS Message:
/// !!! All data in big-endian format
/// |---------------------------|
/// | Header (12 bytes)         |
/// |---------------------------|
/// |
/// |
/// |



/// Header is always 12bytes inside a raw packet
pub struct Header {
    pub identifier: u16,// [0:1] A random ID assigned to query packets. Response packets must reply with the same ID.
    pub is_response: bool,//[2] 1 for reply packet, 0 for a question packet
    pub opcode: u8, //[2] 4 bits
    pub authoritative: bool, // [2]
    pub truncation: bool, // [2]
    pub recursion_desired: bool, // [2]
    pub recursion_available: bool, // [3]
    pub reserved: u8, // [3] 3 bits 
    pub response_code: u8, // 4bit response code
    pub question_count: u16,
    pub answer_record_count: u16,
    pub authority_record_count: u16, // [ ]
    pub additional_record_count: u16, // [10:11]
}

impl Header {
    
    pub fn from_bytes(data: &[u8])->Option<Self> {
        None
    }
    
    pub fn to_bytes(&self) -> Box<[u8]> {
        
        // 1. try allocating 12 bytes on the heap
        //
        let mut header_data = Box::new([0; 12]);
        
        // identifier stored in big endian format
        header_data[0] = (self.identifier & 0xFF00) as u8;
        header_data[1] = ( self.identifier & 0x00FF) as u8;
        
        header_data[2] = ((self.is_response as u8) << 7) | ((self.opcode & 0xF) << 3) | ((self.authoritative as u8) << 2) 
            | ((self.truncation as u8) << 1) | ((self.recursion_desired as u8) << 0);
        
        header_data[3] = ((self.recursion_available as u8) << 7) | (self.response_code & 0xF);

        header_data[4] = (self.question_count & 0xFF00) as u8;
        header_data[5] = (self.question_count & 0x00FF) as u8;


        header_data[6] = (self.answer_record_count & 0xFF00) as u8;
        header_data[7] = (self.answer_record_count & 0x00FF) as u8;

        header_data[8] = (self.authority_record_count & 0xFF00) as u8;
        header_data[9] = (self.authority_record_count & 0x00FF) as u8;


        header_data[10] = (self.additional_record_count & 0xFF00) as u8;
        header_data[11] = (self.additional_record_count & 0x00FF) as u8;

        header_data
    }

}

pub struct DNSPacket {
    pub header: Header,
}




impl DNSPacket {
    
    pub fn from_bytes(data: &[u8])->Option<Self> {
        None
    }
    
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.header.to_bytes()
    }
    

}


