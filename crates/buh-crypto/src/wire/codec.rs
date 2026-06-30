//! Low-level wire primitives: unsigned LEB128 varints and a bounds-checked reader.
//!
//! These are the only place raw byte arithmetic happens; everything above
//! ([`super::v1`]) is framed in terms of varints and length-prefixed slices. Every read is
//! bounds-checked and every length is validated against the remaining input *before*
//! allocating, so a hostile or truncated buffer can never panic or over-allocate — the
//! property the `parseInvite`/`decryptMessage` fuzz targets assert.

use super::WireError;

/// Maximum number of bytes a varint may occupy. A `u64` needs at most ten 7-bit groups.
pub const MAX_VARINT_LEN: usize = 10;

/// Append `value` to `out` as an unsigned LEB128 varint.
pub fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// A forward-only cursor over a byte slice. Every accessor is bounds-checked.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Wrap a slice for reading from the start.
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Whether the cursor has consumed all input.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Read a single byte, advancing the cursor.
    pub fn read_u8(&mut self) -> Result<u8, WireError> {
        let b = *self.buf.get(self.pos).ok_or(WireError::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }

    /// Read an unsigned LEB128 varint. Rejects non-canonical overlong encodings and any
    /// value that does not fit in a `u64`.
    pub fn read_varint(&mut self) -> Result<u64, WireError> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        for _ in 0..MAX_VARINT_LEN {
            let byte = self.read_u8()?;
            let payload = u64::from(byte & 0x7f);
            // The tenth group only has room for a single bit of a u64.
            if shift == 63 && payload > 1 {
                return Err(WireError::VarintOverflow);
            }
            result |= payload << shift;
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
        }
        Err(WireError::VarintOverflow)
    }

    /// Borrow `len` bytes, advancing the cursor. Fails if fewer remain.
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(len).ok_or(WireError::UnexpectedEof)?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(WireError::UnexpectedEof)?;
        self.pos = end;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        write_varint(&mut out, v);
        let mut r = Reader::new(&out);
        assert_eq!(r.read_varint().unwrap(), v);
        assert!(r.is_empty());
        out
    }

    #[test]
    fn varint_golden_bytes() {
        assert_eq!(roundtrip(0), vec![0x00]);
        assert_eq!(roundtrip(1), vec![0x01]);
        assert_eq!(roundtrip(127), vec![0x7f]);
        assert_eq!(roundtrip(128), vec![0x80, 0x01]);
        assert_eq!(roundtrip(300), vec![0xac, 0x02]);
        assert_eq!(
            roundtrip(u64::MAX),
            vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );
    }

    #[test]
    fn varint_rejects_overlong() {
        // Eleven continuation bytes: never terminates within MAX_VARINT_LEN.
        let bytes = [0x80u8; 11];
        assert_eq!(
            Reader::new(&bytes).read_varint(),
            Err(WireError::VarintOverflow)
        );
    }

    #[test]
    fn varint_rejects_overflow_in_last_group() {
        // Tenth group payload of 2 would set a 65th bit.
        let bytes = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
        assert_eq!(
            Reader::new(&bytes).read_varint(),
            Err(WireError::VarintOverflow)
        );
    }

    #[test]
    fn read_bytes_bounds_checked() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert!(r.read_bytes(4).is_err());
        assert_eq!(r.read_bytes(2).unwrap(), &[1, 2]);
        assert_eq!(r.remaining(), 1);
    }
}
