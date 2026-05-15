//! Parent↔child handshake protocol used during sandbox setup.
//!
//! After the parent has joined the child to its network namespace and
//! spawned pasta, it sends a small framed message over a pipe to unblock
//! the child:
//!
//! ```text
//! ┌─────────────────┬─────────────────┬───────────────────────┐
//! │ proxy_port (u16)│  dns_len (u16)  │  dns_addr (dns_len B) │
//! └─────────────────┴─────────────────┴───────────────────────┘
//!     big-endian        big-endian            UTF-8 bytes
//! ```
//!
//! Both `proxy_port` and `dns_len` are big-endian. `dns_addr` is the
//! UTF-8 bytes of an address like `"10.0.0.1:53"` or `"[fd00::1]:53"`.
//!
//! The decoder is forgiving: if `dns_len` is zero or `>= 256`, or the
//! payload fails UTF-8 decoding, it falls back to a caller-provided
//! default rather than failing the whole sandbox launch. Short reads on
//! the fixed-size headers are still propagated as I/O errors — those
//! mean the pipe was closed mid-handshake, which is fatal.

use std::io::{self, Read, Write};

const DNS_LEN_CAP: usize = 256;

/// Parent→child sandbox handshake payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkHandshake {
    pub proxy_port: u16,
    pub dns_addr: String,
}

/// Encode and write the handshake to `w`. All three components are
/// emitted in one logical message; partial writes are surfaced.
pub fn write_handshake<W: Write>(w: &mut W, msg: &NetworkHandshake) -> io::Result<()> {
    let dns_bytes = msg.dns_addr.as_bytes();
    if dns_bytes.len() >= DNS_LEN_CAP {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "dns_addr length {} exceeds protocol limit of {} bytes",
                dns_bytes.len(),
                DNS_LEN_CAP - 1
            ),
        ));
    }
    w.write_all(&msg.proxy_port.to_be_bytes())?;
    w.write_all(&(dns_bytes.len() as u16).to_be_bytes())?;
    w.write_all(dns_bytes)?;
    Ok(())
}

/// Read a handshake from `r`. On a malformed DNS payload (length 0,
/// length >= [`DNS_LEN_CAP`], or invalid UTF-8) the returned
/// `dns_addr` is set to `default_dns`. Short reads on the fixed
/// headers propagate as errors.
pub fn read_handshake<R: Read>(r: &mut R, default_dns: &str) -> io::Result<NetworkHandshake> {
    let mut port_buf = [0u8; 2];
    r.read_exact(&mut port_buf)?;
    let proxy_port = u16::from_be_bytes(port_buf);

    let mut len_buf = [0u8; 2];
    r.read_exact(&mut len_buf)?;
    let dns_len = u16::from_be_bytes(len_buf) as usize;

    let dns_addr = if dns_len > 0 && dns_len < DNS_LEN_CAP {
        let mut dns_buf = vec![0u8; dns_len];
        r.read_exact(&mut dns_buf)?;
        String::from_utf8(dns_buf).unwrap_or_else(|_| default_dns.to_string())
    } else {
        default_dns.to_string()
    };

    Ok(NetworkHandshake {
        proxy_port,
        dns_addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const DEFAULT: &str = "10.0.0.1:53";

    fn roundtrip(msg: &NetworkHandshake) -> NetworkHandshake {
        let mut buf = Vec::new();
        write_handshake(&mut buf, msg).expect("encode");
        let mut cursor = Cursor::new(buf);
        read_handshake(&mut cursor, DEFAULT).expect("decode")
    }

    #[test]
    fn round_trip_ipv4_dns_addr() {
        let msg = NetworkHandshake {
            proxy_port: 18080,
            dns_addr: "10.0.0.1:53".to_string(),
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn round_trip_ipv6_bracketed_dns_addr() {
        let msg = NetworkHandshake {
            proxy_port: 9000,
            dns_addr: "[fd00::1]:53".to_string(),
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn round_trip_port_zero_means_no_proxy() {
        let msg = NetworkHandshake {
            proxy_port: 0,
            dns_addr: "1.2.3.4:53".to_string(),
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn round_trip_port_max() {
        let msg = NetworkHandshake {
            proxy_port: u16::MAX,
            dns_addr: "8.8.8.8:53".to_string(),
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn round_trip_max_length_dns_addr() {
        // Boundary: DNS_LEN_CAP - 1 is the largest legal length.
        let dns_addr = "a".repeat(DNS_LEN_CAP - 1);
        let msg = NetworkHandshake {
            proxy_port: 1234,
            dns_addr,
        };
        assert_eq!(roundtrip(&msg), msg);
    }

    #[test]
    fn encode_rejects_dns_addr_at_or_past_cap() {
        let msg = NetworkHandshake {
            proxy_port: 1,
            dns_addr: "a".repeat(DNS_LEN_CAP),
        };
        let mut buf = Vec::new();
        let err = write_handshake(&mut buf, &msg).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        // Nothing should have been emitted on validation failure.
        assert!(buf.is_empty(), "no bytes should be written on rejection");
    }

    #[test]
    fn decode_falls_back_when_dns_len_is_zero() {
        // Manually craft: port=4242, dns_len=0, no payload.
        let mut buf = Vec::new();
        buf.extend_from_slice(&4242u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        let mut cursor = Cursor::new(buf);
        let got = read_handshake(&mut cursor, DEFAULT).expect("decode");
        assert_eq!(got.proxy_port, 4242);
        assert_eq!(got.dns_addr, DEFAULT);
    }

    #[test]
    fn decode_falls_back_when_dns_len_at_cap() {
        // dns_len exactly 256 must trigger fallback (cap is exclusive).
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&(DNS_LEN_CAP as u16).to_be_bytes());
        // No payload bytes — fallback path must NOT try to read more.
        let mut cursor = Cursor::new(buf);
        let got = read_handshake(&mut cursor, DEFAULT).expect("decode");
        assert_eq!(got.proxy_port, 1);
        assert_eq!(got.dns_addr, DEFAULT);
    }

    #[test]
    fn decode_falls_back_on_invalid_utf8() {
        // Valid length but invalid UTF-8 in the payload.
        let mut buf = Vec::new();
        buf.extend_from_slice(&7u16.to_be_bytes());
        buf.extend_from_slice(&4u16.to_be_bytes());
        buf.extend_from_slice(&[0xff, 0xfe, 0xfd, 0xfc]);
        let mut cursor = Cursor::new(buf);
        let got = read_handshake(&mut cursor, DEFAULT).expect("decode");
        assert_eq!(got.proxy_port, 7);
        assert_eq!(got.dns_addr, DEFAULT);
    }

    #[test]
    fn decode_propagates_eof_on_short_port() {
        let mut cursor = Cursor::new(vec![0u8]); // only 1 of 2 port bytes
        let err = read_handshake(&mut cursor, DEFAULT).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn decode_propagates_eof_on_short_dns_len() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.push(0); // only 1 of 2 dns_len bytes
        let mut cursor = Cursor::new(buf);
        let err = read_handshake(&mut cursor, DEFAULT).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn decode_propagates_eof_on_truncated_dns_payload() {
        // Declares 8 bytes of payload but only delivers 3 — read_exact
        // must surface this as a short read; we don't silently fall back.
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&8u16.to_be_bytes());
        buf.extend_from_slice(b"abc");
        let mut cursor = Cursor::new(buf);
        let err = read_handshake(&mut cursor, DEFAULT).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn wire_format_is_stable_big_endian() {
        // Pin the on-wire layout: proxy_port=0x0102, dns="abc"
        // → 01 02 | 00 03 | 61 62 63
        let msg = NetworkHandshake {
            proxy_port: 0x0102,
            dns_addr: "abc".to_string(),
        };
        let mut buf = Vec::new();
        write_handshake(&mut buf, &msg).unwrap();
        assert_eq!(buf, vec![0x01, 0x02, 0x00, 0x03, 0x61, 0x62, 0x63]);
    }
}
