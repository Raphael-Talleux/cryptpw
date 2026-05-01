use crate::encrypt;

#[derive(Debug)]
pub struct Secret {
    pub source: String,
    pub _password: String,
    pub nonce: String,
    pub salt: String,
}

impl Secret {
    pub fn as_source_plaintext(&self, key: &str) -> String {
        encrypt::decrypt_data(key, &self.source, &self.nonce, &self.salt).unwrap()
    }
}
