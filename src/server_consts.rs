/// Compile time constants for our DNS server
/// 
pub fn meow() {
    println!("meow");
}

// let const SERVER_PORT: int = 2044;
pub const SERVER_ADDR: &str = "127.0.0.1:2053";
pub const BUF_SIZE: usize = 512;

pub fn log_startup() {
    println!("Starting DNS server on {SERVER_ADDR}");
}
