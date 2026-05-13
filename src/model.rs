use crate::encryption;

#[derive(Debug, Clone, PartialEq)]
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

    pub fn decrypt_source(&mut self, key: &str) {
        if let Encryptable::Encrypted(cipher) = &self.source {
            self.source = Encryptable::Plain(
                encryption::decrypt_data(key, cipher, &self.nonce, &self.salt).unwrap(),
            );
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


#[cfg(test)]
mod tests {
    use super::*;

    // Create SECRET test with cipher
    fn create_encrypted_secret(key: &str) -> Secret {
        let (cipher, nonce, salt) =
            encryption::encrypt_data(key, "Test encrypted date", None, None).unwrap();

        Secret {
            source: Encryptable::Encrypted(cipher.clone()),
            _password: Encryptable::Encrypted(cipher),
            nonce,
            salt,
        }
    }

    #[test]
    fn test_decrypt_source() {
        let key = "test_key";
        let mut secret = create_encrypted_secret(key);

        assert!(secret.source.is_encrypted());
        secret.decrypt_source(key);
        assert!(secret.source.is_plain());

        secret.decrypt_source(key);
        assert!(secret.source.is_plain());
    }
}
