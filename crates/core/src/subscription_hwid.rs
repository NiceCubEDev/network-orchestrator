use std::io;

/// Derive a subscription HWID without returning the Windows machine identifier.
pub fn generate_windows_hwid() -> io::Result<String> {
    derive_with(read_machine_guid)
}

fn unavailable() -> io::Error {
    io::Error::other("could not generate subscription device ID")
}

fn read_machine_guid() -> io::Result<String> {
    use windows::core::w;
    use windows::Win32::System::Registry::{
        RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
    };

    let mut buffer = [0u16; 128];
    let mut length = std::mem::size_of_val(&buffer) as u32;
    let result = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            w!("SOFTWARE\\Microsoft\\Cryptography"),
            w!("MachineGuid"),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut length),
        )
    };
    if result.0 != 0 || length < 2 || length as usize > std::mem::size_of_val(&buffer) {
        return Err(unavailable());
    }
    let end = buffer
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(unavailable)?;
    String::from_utf16(&buffer[..end]).map_err(|_| unavailable())
}

fn derive_with(read_guid: impl FnOnce() -> io::Result<String>) -> io::Result<String> {
    let raw = read_guid().map_err(|_| unavailable())?;
    let trimmed = raw.trim();
    let guid = trimmed
        .strip_prefix('{')
        .and_then(|value| value.strip_suffix('}'))
        .unwrap_or(trimmed);
    if guid.len() != 36
        || !guid.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(unavailable());
    }
    Ok(crate::subscription::derive_hwid(&guid.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_device_id_is_stable_and_never_returns_the_machine_guid() {
        let seed = "11111111-abcd-4111-8111-111111111111";
        let first = derive_with(|| Ok(seed.to_string())).unwrap();
        assert_eq!(first, crate::subscription::derive_hwid(seed));
        assert_eq!(first, derive_with(|| Ok(seed.to_string())).unwrap());
        assert_ne!(first, seed);
        assert_ne!(
            first,
            derive_with(|| Ok("22222222-abcd-4222-8222-222222222222".into())).unwrap()
        );
    }

    #[test]
    fn machine_guid_formatting_does_not_create_another_device_id() {
        let canonical = "11111111-abcd-4111-8111-111111111111";
        let formatted = "  {11111111-ABCD-4111-8111-111111111111} \r\n";
        assert_eq!(
            derive_with(|| Ok(formatted.into())).unwrap(),
            crate::subscription::derive_hwid(canonical)
        );
    }

    #[test]
    fn invalid_or_unreadable_machine_ids_return_only_a_generic_error() {
        let secret = "synthetic-private-registry-value";
        for value in ["", " ", secret, "11111111-abcd-4111-8111-11111111111g"] {
            let error = derive_with(|| Ok(value.into())).unwrap_err();
            assert!(!error.to_string().contains(secret));
            assert_eq!(
                error.to_string(),
                "could not generate subscription device ID"
            );
        }
        let error = derive_with(|| Err(io::Error::other(secret))).unwrap_err();
        assert!(!error.to_string().contains(secret));
        assert_eq!(
            error.to_string(),
            "could not generate subscription device ID"
        );
    }
}
