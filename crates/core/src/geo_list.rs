//! Merge for GeoSiteList/GeoIpList protobufs. Provider geo assets are
//! minimal overlays that carry only their own categories, so they must be
//! layered over the managed stock file instead of replacing it.

use std::collections::HashSet;
use std::io;

fn invalid_data() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "geo list is malformed")
}

fn read_varint(bytes: &[u8], pos: &mut usize) -> io::Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(*pos).ok_or_else(invalid_data)?;
        *pos += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            return Err(invalid_data());
        }
    }
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn skip_field(bytes: &[u8], pos: &mut usize, wire: u64) -> io::Result<()> {
    let len = match wire {
        0 => {
            read_varint(bytes, pos)?;
            return Ok(());
        }
        1 => 8,
        2 => read_varint(bytes, pos)? as usize,
        5 => 4,
        _ => return Err(invalid_data()),
    };
    *pos = pos
        .checked_add(len)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(invalid_data)?;
    Ok(())
}

/// Extract the country_code (the first field-1 string) from a record payload.
fn record_code(payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut pos = 0usize;
    while pos < payload.len() {
        let tag = read_varint(payload, &mut pos)?;
        if tag >> 3 == 1 && tag & 7 == 2 {
            let len = read_varint(payload, &mut pos)? as usize;
            let end = pos
                .checked_add(len)
                .filter(|e| *e <= payload.len())
                .ok_or_else(invalid_data)?;
            return Ok(payload[pos..end].to_vec());
        }
        skip_field(payload, &mut pos, tag & 7)?;
    }
    Err(invalid_data())
}

/// Split a Geo*List into `(country_code, record payload)` pairs. Every
/// top-level field must be `entry` (field 1, length-delimited).
fn geo_records(bytes: &[u8]) -> io::Result<Vec<(Vec<u8>, &[u8])>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let tag = read_varint(bytes, &mut pos)?;
        if tag != 0x0a {
            return Err(invalid_data());
        }
        let len = read_varint(bytes, &mut pos)? as usize;
        let end = pos
            .checked_add(len)
            .filter(|e| *e <= bytes.len())
            .ok_or_else(invalid_data)?;
        let payload = &bytes[pos..end];
        out.push((record_code(payload)?, payload));
        pos = end;
    }
    Ok(out)
}

/// Merge `overlay` over `stock`: records whose country_code appears in the
/// overlay are dropped from stock and all overlay records are appended, so
/// the overlay wins on conflicts and extends the list with custom codes.
/// Both inputs must be well-formed GeoSiteList/GeoIpList streams.
pub fn merge_geo_list(stock: &[u8], overlay: &[u8]) -> io::Result<Vec<u8>> {
    let stock_records = geo_records(stock)?;
    let overlay_records = geo_records(overlay)?;
    let overlay_codes: HashSet<&[u8]> = overlay_records
        .iter()
        .map(|(code, _)| code.as_slice())
        .collect();
    let mut out = Vec::with_capacity(stock.len() + overlay.len());
    for (code, payload) in &stock_records {
        if !overlay_codes.contains(code.as_slice()) {
            out.push(0x0a);
            write_varint(&mut out, payload.len() as u64);
            out.extend_from_slice(payload);
        }
    }
    // A duplicated code inside the overlay keeps its last definition.
    let last_occurrence: std::collections::HashMap<&[u8], usize> = overlay_records
        .iter()
        .enumerate()
        .map(|(index, (code, _))| (code.as_slice(), index))
        .collect();
    for (index, (code, payload)) in overlay_records.iter().enumerate() {
        if last_occurrence[code.as_slice()] == index {
            out.push(0x0a);
            write_varint(&mut out, payload.len() as u64);
            out.extend_from_slice(payload);
        }
    }
    Ok(out)
}

/// List all country codes present in a Geo*List, for diagnostics.
pub fn geo_codes(bytes: &[u8]) -> io::Result<Vec<String>> {
    Ok(geo_records(bytes)?
        .into_iter()
        .map(|(code, _)| String::from_utf8_lossy(&code).into_owned())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Geo*List entry: field-1 record containing only a country_code.
    fn entry(code: &str, extra: &[u8]) -> Vec<u8> {
        let mut payload = vec![0x0a, code.len() as u8];
        payload.extend_from_slice(code.as_bytes());
        payload.extend_from_slice(extra);
        let mut record = vec![0x0a, payload.len() as u8];
        record.extend_from_slice(&payload);
        record
    }

    fn codes(list: &[u8]) -> Vec<String> {
        geo_codes(list).unwrap()
    }

    #[test]
    fn merge_extends_stock_with_overlay_codes() {
        let mut stock = entry("GOOGLE", b"");
        stock.extend(entry("YANDEX", b""));
        let mut overlay = entry("TORRENT", b"");
        overlay.extend(entry("DIRECT", b""));
        let merged = merge_geo_list(&stock, &overlay).unwrap();
        assert_eq!(codes(&merged), ["GOOGLE", "YANDEX", "TORRENT", "DIRECT"]);
    }

    #[test]
    fn merge_overlay_replaces_shared_code() {
        let stock = entry("PRIVATE", b"\x12\x04rest");
        let overlay = entry("PRIVATE", b"\x12\x04new!");
        let merged = merge_geo_list(&stock, &overlay).unwrap();
        assert_eq!(codes(&merged), ["PRIVATE"]);
        assert!(merged.windows(4).any(|w| w == b"new!"));
        assert!(!merged.windows(4).any(|w| w == b"rest"));
    }

    #[test]
    fn merge_empty_overlay_passes_stock_through() {
        let stock = entry("TORRENT", b"");
        let merged = merge_geo_list(&stock, &[]).unwrap();
        assert_eq!(codes(&merged), ["TORRENT"]);
    }

    #[test]
    fn merge_rejects_malformed_input() {
        assert!(merge_geo_list(b"\xff\xff\xff", &[]).is_err());
        assert!(merge_geo_list(&entry("A", b""), b"\x0a\x05ab").is_err());
        // A top-level field that is not `entry` is rejected.
        assert!(merge_geo_list(b"\x10\x01", &[]).is_err());
        // A record without a country_code is rejected.
        let mut bad = vec![0x0a, 2];
        bad.extend_from_slice(b"\x12\x00");
        assert!(merge_geo_list(&bad, &[]).is_err());
    }

    #[test]
    fn merge_overlay_duplicate_code_keeps_last() {
        let mut overlay = entry("TORRENT", b"\x12\x01a");
        overlay.extend(entry("TORRENT", b"\x12\x01b"));
        let merged = merge_geo_list(&[], &overlay).unwrap();
        assert_eq!(codes(&merged), ["TORRENT"]);
        assert!(merged.windows(3).any(|w| w == b"\x12\x01b"));
        assert!(!merged.windows(3).any(|w| w == b"\x12\x01a"));
    }

    #[test]
    #[ignore = "Requires NETORCH_TEST_GEOSITE_STOCK and NETORCH_TEST_GEOSITE_OVERLAY"]
    fn real_dats_parse_and_merge() {
        let stock = std::fs::read(
            std::env::var_os("NETORCH_TEST_GEOSITE_STOCK").expect("set the stock geosite path"),
        )
        .expect("read stock geosite data");
        let overlay = std::fs::read(
            std::env::var_os("NETORCH_TEST_GEOSITE_OVERLAY").expect("set the overlay geosite path"),
        )
        .expect("read overlay geosite data");
        let merged = merge_geo_list(&stock, &overlay).unwrap();
        let merged_codes: std::collections::HashSet<String> = codes(&merged).into_iter().collect();
        for code in geo_codes(&stock)
            .unwrap()
            .iter()
            .chain(geo_codes(&overlay).unwrap().iter())
        {
            assert!(merged_codes.contains(code), "missing {code}");
        }
    }
}
