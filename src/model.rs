use crate::encryption;

#[derive(Debug, Clone)]
pub struct Secret {
    pub source: Encryptable,
    pub _password: Encryptable,
    pub nonce: String,
    pub salt: String,
}

impl Secret {
    pub fn as_source_plaintext(&self, key: &str) -> String {
        match &self.source {
            Encryptable::Encrypted(ciphertext) => {
                encryption::decrypt_data(key, &ciphertext, &self.nonce, &self.salt).unwrap()
            }
            Encryptable::Plain(plaintext) => plaintext.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Encryptable {
    Plain(String),
    Encrypted(String),
}

#[allow(unused)]
impl Encryptable {
    pub fn is_plain(&self) -> bool {
        matches!(self, Self::Plain(_))
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, Self::Encrypted(_))
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Encryptable::Plain(s) | Encryptable::Encrypted(s) => s.is_empty(),
        }
    }
}
