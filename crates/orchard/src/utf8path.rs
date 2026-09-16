//! A UTF-8 path buffer: a `String` newtype used where the ceremony requires a path to be UTF-8
                                                                                                 
//! and the resolved tool context's three path fields.

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// A path constrained to UTF-8 text.
#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(transparent)]
pub struct Utf8PathBuf(String);

           
impl PartialEq for Utf8PathBuf {
    fn eq(&self, other: &Self) -> bool {
        self.as_path() == other.as_path()
    }
}

impl Eq for Utf8PathBuf {}

impl Utf8PathBuf {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    pub fn to_path_buf(&self) -> PathBuf {
        PathBuf::from(&self.0)
    }

    pub fn join(&self, rel: &Utf8PathBuf) -> Utf8PathBuf {
        match self
            .as_path()
            .join(rel.as_path())
            .into_os_string()
            .into_string()
        {
            Ok(s) => Utf8PathBuf(s),
                                                                                               
            Err(_) => unreachable!(),
        }
    }
}

impl Deref for Utf8PathBuf {
    type Target = Path;

    fn deref(&self) -> &Path {
        self.as_path()
    }
}

impl FromStr for Utf8PathBuf {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Utf8PathBuf(s.to_owned()))
    }
}

impl std::fmt::Display for Utf8PathBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<Path> for Utf8PathBuf {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl From<&str> for Utf8PathBuf {
    fn from(s: &str) -> Self {
        Utf8PathBuf(s.to_owned())
    }
}

impl From<String> for Utf8PathBuf {
    fn from(s: String) -> Self {
        Utf8PathBuf(s)
    }
}

impl From<Utf8PathBuf> for PathBuf {
    fn from(p: Utf8PathBuf) -> Self {
        PathBuf::from(p.0)
    }
}
