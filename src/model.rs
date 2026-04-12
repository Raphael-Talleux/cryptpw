#[derive(Debug)]
pub struct Secret {
    pub source: String,
    pub password: String,
    pub nonce: String,
    pub salt: String,
    pub is_encrypted: bool
}
