use clap::error::*;
use std::collections::BTreeMap;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq)]
enum AlpnTarget {
    // Advertise ALPN protocol but use default destination
    Default,
    // Advertise ALPN protocol and use custom destination
    Value(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Fallback {
    alpn: BTreeMap<Vec<u8>, AlpnTarget>,
    default: Option<String>,
}

impl Fallback {
    pub fn alpn_protocols(&self) -> Vec<Vec<u8>> {
        self.alpn.keys().cloned().collect()
    }

    pub fn resolve(&self, alpn: Option<&[u8]>) -> Option<&str> {
        if let Some(alpn) = alpn
            && let Some(value) = self.alpn.get(alpn)
        {
            match value {
                AlpnTarget::Value(dest) => Some(dest),
                AlpnTarget::Default => self.default.as_deref(),
            }
        } else {
            self.default.as_deref()
        }
    }
}

impl FromStr for Fallback {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut fallback = Self {
            alpn: BTreeMap::new(),
            default: None,
        };
        for chunk in s.split(',') {
            if let Some((alpn, dest)) = chunk.split_once('=') {
                fallback.alpn.insert(
                    alpn.as_bytes().to_vec(),
                    if dest.is_empty() {
                        AlpnTarget::Default
                    } else {
                        AlpnTarget::Value(dest.to_string())
                    },
                );
            } else {
                fallback.default = Some(chunk.to_string());
            }
        }
        Ok(fallback)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fallback_from_str() {
        let fallback = Fallback::from_str("example.com:80").unwrap();
        assert_eq!(
            fallback,
            Fallback {
                alpn: BTreeMap::new(),
                default: Some("example.com:80".to_string()),
            }
        );
        assert_eq!(fallback.alpn_protocols(), Vec::<Vec<u8>>::new());
        assert_eq!(fallback.resolve(None), Some("example.com:80"));
        // This technically can't happen because if http/1.1 was negotiated, we also have a rule for it
        assert_eq!(fallback.resolve(Some(b"http/1.1")), Some("example.com:80"));
    }

    // This case is barely valid, test to make sure this doesn't panic,
    // but behavior is undefined and may change
    #[test]
    fn test_fallback_empty() {
        let fallback = Fallback::from_str("").unwrap();
        assert_eq!(
            fallback,
            Fallback {
                alpn: BTreeMap::new(),
                default: Some("".to_string()),
            }
        );
        assert_eq!(fallback.alpn_protocols(), Vec::<Vec<u8>>::new());
        assert_eq!(fallback.resolve(None), Some(""));
    }

    #[test]
    fn test_fallback_default_and_alpn_http1() {
        let fallback = Fallback::from_str("http/1.1=,example.com:80").unwrap();
        assert_eq!(
            fallback,
            Fallback {
                alpn: BTreeMap::from_iter([(b"http/1.1".to_vec(), AlpnTarget::Default)]),
                default: Some("example.com:80".to_string()),
            }
        );
        assert_eq!(fallback.alpn_protocols(), vec![b"http/1.1".to_vec()]);
        assert_eq!(fallback.resolve(None), Some("example.com:80"));
        assert_eq!(fallback.resolve(Some(b"http/1.1")), Some("example.com:80"));
    }

    #[test]
    fn test_fallback_default_and_different_alpn_http1() {
        let fallback = Fallback::from_str("http/1.1=127.0.0.1:8080,example.com:80").unwrap();
        assert_eq!(
            fallback,
            Fallback {
                alpn: BTreeMap::from_iter([(
                    b"http/1.1".to_vec(),
                    AlpnTarget::Value("127.0.0.1:8080".to_string())
                )]),
                default: Some("example.com:80".to_string()),
            }
        );
        assert_eq!(fallback.alpn_protocols(), vec![b"http/1.1".to_vec()]);
        assert_eq!(fallback.resolve(None), Some("example.com:80"));
        assert_eq!(fallback.resolve(Some(b"http/1.1")), Some("127.0.0.1:8080"));
    }

    #[test]
    fn test_fallback_alpn_http1_only() {
        let fallback = Fallback::from_str("http/1.1=127.0.0.1:8080").unwrap();
        assert_eq!(
            fallback,
            Fallback {
                alpn: BTreeMap::from_iter([(
                    b"http/1.1".to_vec(),
                    AlpnTarget::Value("127.0.0.1:8080".to_string())
                )]),
                default: None,
            }
        );
        assert_eq!(fallback.alpn_protocols(), vec![b"http/1.1".to_vec()]);
        assert_eq!(fallback.resolve(None), None);
        assert_eq!(fallback.resolve(Some(b"http/1.1")), Some("127.0.0.1:8080"));
    }

    #[test]
    fn test_fallback_alpn_http1_and_h2_only() {
        let fallback = Fallback::from_str("http/1.1=127.0.0.1:8080,h2=127.0.0.1:8081").unwrap();
        assert_eq!(
            fallback,
            Fallback {
                alpn: BTreeMap::from_iter([
                    (
                        b"http/1.1".to_vec(),
                        AlpnTarget::Value("127.0.0.1:8080".to_string())
                    ),
                    (
                        b"h2".to_vec(),
                        AlpnTarget::Value("127.0.0.1:8081".to_string())
                    )
                ]),
                default: None,
            }
        );
        assert_eq!(
            fallback.alpn_protocols(),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        );
        assert_eq!(fallback.resolve(None), None);
        assert_eq!(fallback.resolve(Some(b"http/1.1")), Some("127.0.0.1:8080"));
        assert_eq!(fallback.resolve(Some(b"h2")), Some("127.0.0.1:8081"));
        assert_eq!(fallback.resolve(Some(b"xyz")), None);
    }
}
