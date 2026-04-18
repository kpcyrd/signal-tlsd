use std::collections::BTreeSet;

// List taken from https://github.com/signalapp/Signal-TLS-Proxy/blob/main/data/nginx-relay/nginx.conf
pub const SIGNAL_HOSTS: &[&str] = &[
    "chat.signal.org",
    "storage.signal.org",
    "cdn.signal.org",
    "cdn2.signal.org",
    "cdn3.signal.org",
    "cdsi.signal.org",
    "contentproxy.signal.org",
    "grpc.chat.signal.org",
    "sfu.voip.signal.org",
    "svr2.signal.org",
    "svrb.signal.org",
    "updates.signal.org",
    "updates2.signal.org",
];

#[derive(Debug, PartialEq)]
pub struct Rules {
    restricted_to: Option<BTreeSet<String>>,
    fallback: Option<String>,
}

impl Rules {
    pub fn allowed(&self, server_name: &str) -> bool {
        if let Some(set) = &self.restricted_to {
            set.contains(server_name)
        } else {
            true
        }
    }

    pub fn set_fallback(&mut self, fallback: Option<String>) {
        self.fallback = fallback;
    }

    pub fn fallback(&self) -> Option<&str> {
        self.fallback.as_deref()
    }
}

impl<I: Into<String>> FromIterator<I> for Rules {
    fn from_iter<T: IntoIterator<Item = I>>(iter: T) -> Self {
        let mut rules = Self {
            restricted_to: Some(Default::default()),
            fallback: None,
        };
        for dest in iter {
            let dest = dest.into();
            match dest.as_str() {
                // Lift any restrictions
                "*" => {
                    rules.restricted_to = None;
                }
                // Counts as custom filter to prevent default allowlist,
                // but doesn't actually allow anything
                "-" => (),
                _ => {
                    if let Some(set) = &mut rules.restricted_to {
                        set.insert(dest);
                    }
                }
            }
        }
        rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_from_iter() {
        let rules = Rules::from_iter(["example.com", "example.org"]);
        assert_eq!(
            rules,
            Rules {
                restricted_to: Some(
                    ["example.com".to_string(), "example.org".to_string()]
                        .into_iter()
                        .collect()
                ),
                fallback: None,
            }
        );
        assert!(rules.allowed("example.com"));
        assert!(!rules.allowed("example.xyz"));
    }

    #[test]
    fn rules_from_iter_empty() {
        let rules = Rules::from_iter(Vec::<String>::new());
        assert_eq!(
            rules,
            Rules {
                restricted_to: Some(Default::default()),
                fallback: None,
            }
        );
        assert!(!rules.allowed("example.com"));
    }

    #[test]
    fn rules_allow_all() {
        let rules = Rules::from_iter(["a", "*", "b"]);
        assert_eq!(
            rules,
            Rules {
                restricted_to: None,
                fallback: None,
            }
        );
        assert!(rules.allowed("example.com"));
        assert!(rules.allowed("example.xyz"));
    }

    #[test]
    fn rules_disallow_all() {
        // Prevent the default set from being used, but don't actually
        // allow anything.  This routes everything to the fallback, effectively
        // becoming a TLS offloader.
        let rules = Rules::from_iter(["-"]);
        assert_eq!(
            rules,
            Rules {
                restricted_to: Some(Default::default()),
                fallback: None,
            }
        );
        assert!(!rules.allowed("example.com"));
        assert!(!rules.allowed("example.xyz"));
    }

    #[test]
    fn rules_edgecase_disallow_all_mixed_with_allow() {
        // This doesn't make much sense, but define this anyway
        let rules = Rules::from_iter(["example.com", "-", "example.org"]);
        assert_eq!(
            rules,
            Rules {
                restricted_to: Some(
                    ["example.com".to_string(), "example.org".to_string()]
                        .into_iter()
                        .collect()
                ),
                fallback: None,
            }
        );
        assert!(rules.allowed("example.com"));
        assert!(!rules.allowed("example.xyz"));
    }
}
