                                                                              
//!
//! ALL parsing in this crate goes through [`Reader`] — there is no direct slice indexing anywhere
//! (lint-enforced via `clippy::indexing_slicing`). Every read is bounds-checked with `checked_*`
//! arithmetic; reading past the end is a fail-closed [`Error::Malformed`], never a panic. A failed
//! read does not advance the cursor.

use crate::Error;

/// A bounds-checked cursor over an input buffer. Reads yield subslices of the original buffer
/// (zero-copy); the cursor only advances on success.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Read exactly `n` bytes. Past-the-end or arithmetic overflow = `Malformed("truncated")`;
    /// the cursor is untouched on failure.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::Malformed("truncated"))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(Error::Malformed("truncated"))?;
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8, Error> {
        match self.take(1)? {
            [b] => Ok(*b),
            _ => Err(Error::Malformed("truncated")),
        }
    }

    pub fn u16_be(&mut self) -> Result<u16, Error> {
        match self.take(2)? {
            [a, b] => Ok(u16::from_be_bytes([*a, *b])),
            _ => Err(Error::Malformed("truncated")),
        }
    }

    pub fn u32_be(&mut self) -> Result<u32, Error> {
        match self.take(4)? {
            [a, b, c, d] => Ok(u32::from_be_bytes([*a, *b, *c, *d])),
            _ => Err(Error::Malformed("truncated")),
        }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;
    use crate::Error;

    #[test]
    fn take_reads_in_order_and_advances() {
        let mut r = Reader::new(&[0xAA, 0xBB, 0xCC, 0xDD]);
        assert_eq!(r.take(2), Ok(&[0xAA, 0xBB][..]));
        assert_eq!(r.remaining(), 2);
        assert_eq!(r.take(2), Ok(&[0xCC, 0xDD][..]));
        assert!(r.is_empty());
    }

    #[test]
    fn take_past_end_is_malformed_and_does_not_consume() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.take(4), Err(Error::Malformed("truncated")));
                                                              
        assert_eq!(r.remaining(), 3);
        assert_eq!(r.take(3), Ok(&[1, 2, 3][..]));
        assert_eq!(r.take(1), Err(Error::Malformed("truncated")));
    }

    #[test]
    fn take_zero_is_ok_even_at_end() {
        let mut r = Reader::new(&[]);
        assert_eq!(r.take(0), Ok(&[][..]));
        assert!(r.is_empty());
        let mut r = Reader::new(&[7]);
        assert_eq!(r.take(1), Ok(&[7][..]));
        assert_eq!(r.take(0), Ok(&[][..]));
    }

    #[test]
    fn integers_are_big_endian_exact() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert_eq!(r.u8(), Ok(0x01));
        assert_eq!(r.u16_be(), Ok(0x0203));
        assert_eq!(r.u32_be(), Ok(0x0405_0607));
        assert!(r.is_empty());
                                                              
        let mut r = Reader::new(&[0xFF]);
        assert_eq!(r.u16_be(), Err(Error::Malformed("truncated")));
        let mut r = Reader::new(&[0xFF, 0xFF, 0xFF]);
        assert_eq!(r.u32_be(), Err(Error::Malformed("truncated")));
        let mut r = Reader::new(&[]);
        assert_eq!(r.u8(), Err(Error::Malformed("truncated")));
    }

    #[test]
    fn huge_take_never_overflows() {
                                                                                                  
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.take(usize::MAX), Err(Error::Malformed("truncated")));
        assert_eq!(r.remaining(), 3);
                                                                       
        assert_eq!(r.take(2), Ok(&[1, 2][..]));
        assert_eq!(r.take(usize::MAX), Err(Error::Malformed("truncated")));
        assert_eq!(r.remaining(), 1);
    }

    #[test]
    fn remaining_and_is_empty_track_position() {
        let mut r = Reader::new(&[9, 9]);
        assert_eq!(r.remaining(), 2);
        assert!(!r.is_empty());
        assert_eq!(r.u8(), Ok(9));
        assert_eq!(r.remaining(), 1);
        assert_eq!(r.u8(), Ok(9));
        assert_eq!(r.remaining(), 0);
        assert!(r.is_empty());
    }
}
