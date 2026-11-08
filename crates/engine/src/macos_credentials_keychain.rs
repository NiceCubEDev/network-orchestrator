//! Direct SecItem adapter: stable Swift identity and accessibility, no shell.
use super::{CredentialStoreError, NativeKeychain, SecretStore, MAX_SECRET_BYTES};
use core_foundation::base::{CFGetTypeID, CFRelease, CFType, CFTypeRef, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::{CFData, CFDataRef};
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::{CFString, CFStringRef};
use security_framework_sys::access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword, kSecReturnData,
    kSecValueData,
};
use security_framework_sys::keychain_item::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete, SecItemUpdate,
};

// security-framework-sys 2.17 does not expose this dictionary key.
unsafe extern "C" {
    static kSecAttrAccessible: CFStringRef;
}

const NOT_FOUND: i32 = -25300;
const DUPLICATE: i32 = -25299;

fn status_error(status: i32) -> CredentialStoreError {
    match status {
        -25308 => CredentialStoreError::Locked,
        -25293 | -128 => CredentialStoreError::AccessDenied,
        -25291 => CredentialStoreError::Unavailable,
        -50 | -26275 => CredentialStoreError::InvalidData,
        _ => CredentialStoreError::OperationFailed,
    }
}

fn query(service: &str, account: &str) -> Vec<(CFString, CFType)> {
    // Static Security constants are retained under the get rule; the resulting
    // dictionary and all owned values are released by their Rust wrappers.
    unsafe {
        vec![
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrService),
                CFString::new(service).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccount),
                CFString::new(account).into_CFType(),
            ),
        ]
    }
}

impl SecretStore for NativeKeychain {
    fn load(&self, service: &str, account: &str) -> Result<Option<Vec<u8>>, CredentialStoreError> {
        crate::macos_transaction::user_uid().map_err(|_| CredentialStoreError::AccessDenied)?;
        let mut pairs = query(service, account);
        pairs.push((
            unsafe { CFString::wrap_under_get_rule(kSecReturnData) },
            CFBoolean::true_value().into_CFType(),
        ));
        // SecItemCopyMatching defaults to kSecMatchLimitOne, matching Swift.
        let dictionary = CFDictionary::from_CFType_pairs(&pairs);
        let mut result: CFTypeRef = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(dictionary.as_concrete_TypeRef(), &mut result) };
        if status == NOT_FOUND {
            return Ok(None);
        }
        if status != 0 {
            return Err(status_error(status));
        }
        if result.is_null() {
            return Err(CredentialStoreError::InvalidData);
        }
        if unsafe { CFGetTypeID(result) } != CFData::type_id() {
            unsafe {
                CFRelease(result);
            }
            return Err(CredentialStoreError::InvalidData);
        }
        let data = unsafe { CFData::wrap_under_create_rule(result as CFDataRef) };
        if data.len() > MAX_SECRET_BYTES as isize {
            return Err(CredentialStoreError::InvalidData);
        }
        Ok(Some(data.bytes().to_vec()))
    }

    fn save(
        &self,
        service: &str,
        account: &str,
        secret: &[u8],
    ) -> Result<(), CredentialStoreError> {
        crate::macos_transaction::user_uid().map_err(|_| CredentialStoreError::AccessDenied)?;
        if secret.len() > MAX_SECRET_BYTES {
            return Err(CredentialStoreError::InvalidData);
        }
        let mut pairs = query(service, account);
        let attributes = unsafe {
            vec![
                (
                    CFString::wrap_under_get_rule(kSecValueData),
                    CFData::from_buffer(secret).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrAccessible),
                    CFString::wrap_under_get_rule(kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
                        .into_CFType(),
                ),
            ]
        };
        let query = CFDictionary::from_CFType_pairs(&pairs);
        pairs.extend(attributes.iter().cloned());
        let addition = CFDictionary::from_CFType_pairs(&pairs);
        let status = unsafe { SecItemAdd(addition.as_concrete_TypeRef(), std::ptr::null_mut()) };
        let status = if status == DUPLICATE {
            // Updating rather than deleting first retains the old saved item if
            // Keychain denies replacement; never claim the new value was saved.
            let update = CFDictionary::from_CFType_pairs(&attributes);
            unsafe { SecItemUpdate(query.as_concrete_TypeRef(), update.as_concrete_TypeRef()) }
        } else {
            status
        };
        if status == 0 {
            Ok(())
        } else {
            Err(status_error(status))
        }
    }

    fn delete(&self, service: &str, account: &str) -> Result<(), CredentialStoreError> {
        crate::macos_transaction::user_uid().map_err(|_| CredentialStoreError::AccessDenied)?;
        let dictionary = CFDictionary::from_CFType_pairs(&query(service, account));
        let status = unsafe { SecItemDelete(dictionary.as_concrete_TypeRef()) };
        if status == 0 || status == NOT_FOUND {
            Ok(())
        } else {
            Err(status_error(status))
        }
    }
}
