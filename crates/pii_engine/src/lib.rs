use pii::recognizers::validator::{iban_check, ValidatorRecognizer};
use pii::{
    default_recognizers, nlp::SimpleNlpEngine, Analyzer, EntityType, Language, PolicyConfig,
};
use serde_json::{json, Value};
use std::sync::Arc;
use std::{
    alloc::{alloc_zeroed, dealloc, Layout},
    ffi::{c_char, CString},
    slice,
};

// Keep contextual identifiers out of the broad PHONE preset and exclude domains/URLs:
// those are not automatically PII. The TypeScript layer provides stricter phone validation.
fn scan(text: &str) -> Result<Value, pii::PiiError> {
    let mut policy = PolicyConfig::default();
    policy.enabled_entities = [
        EntityType::Email,
        EntityType::CreditCard,
        EntityType::Iban,
        EntityType::Ssn,
        EntityType::Itin,
        EntityType::RoutingNumber,
        EntityType::CryptoAddress,
        EntityType::IpAddress,
        EntityType::Ipv6,
    ]
    .into_iter()
    .collect();
    let mut recognizers = default_recognizers();
    recognizers.push(Box::new(
        ValidatorRecognizer::new(
            "spaced_iban",
            EntityType::Iban,
            r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b",
            0.9,
            "iban",
            Arc::new(iban_check),
        )
        .map_err(|_| pii::PiiError::Recognizer("Invalid IBAN pattern".into()))?,
    ));
    let analyzer = Analyzer::new(
        Box::new(SimpleNlpEngine::new(false)),
        recognizers,
        vec![],
        policy,
    );
    let result = analyzer.analyze(text, &Language::new("en"))?;
    let entities: Vec<Value> = result
        .entities
        .iter()
        .map(|d| {
            let kind = match d.entity_type {
                EntityType::Email => "EMAIL",
                EntityType::CreditCard => "CREDIT_CARD",
                EntityType::Ssn | EntityType::Itin => "SSN",
                EntityType::IpAddress | EntityType::Ipv6 => "IP_ADDRESS",
                _ => "FINANCIAL",
            };
            json!({"type": kind, "start": text[..d.start].encode_utf16().count(),
            "end": text[..d.end].encode_utf16().count(), "confidence": d.score})
        })
        .collect();
    Ok(json!(entities))
}

#[no_mangle]
pub extern "C" fn pii_alloc(len: usize) -> *mut u8 {
    if len == 0 || len > 65536 {
        return std::ptr::null_mut();
    }
    unsafe { alloc_zeroed(Layout::array::<u8>(len).unwrap()) }
}

#[no_mangle]
pub unsafe extern "C" fn pii_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        // Volatile writes ensure the compiler cannot elide secret erasure.
        for i in 0..len {
            ptr.add(i).write_volatile(0);
        }
        dealloc(ptr, Layout::array::<u8>(len).unwrap());
    }
}

#[no_mangle]
pub unsafe extern "C" fn pii_scan(ptr: *const u8, len: usize) -> *mut c_char {
    let result = if ptr.is_null() || len == 0 || len > 65536 {
        json!({"error": "Invalid PII input"})
    } else {
        match std::str::from_utf8(slice::from_raw_parts(ptr, len)) {
            Ok(text) => scan(text).unwrap_or_else(|_| json!({"error": "PII analysis failed"})),
            Err(_) => json!({"error": "Invalid UTF-8"}),
        }
    };
    CString::new(result.to_string()).unwrap().into_raw()
}

#[no_mangle]
pub unsafe extern "C" fn pii_free_result(ptr: *mut c_char) {
    if !ptr.is_null() {
        let value = CString::from_raw(ptr);
        let len = value.as_bytes().len();
        for i in 0..len {
            ptr.add(i).write_volatile(0);
        }
        drop(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_iban_and_utf16_offsets() {
        let text = "🔐 漢字 contact user@example.com IBAN GB82 WEST 1234 5698 7654 32";
        let entities = scan(text).unwrap();
        assert!(entities
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["type"] == "FINANCIAL"));
        let email = entities
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["type"] == "EMAIL")
            .unwrap();
        assert_eq!(
            email["start"],
            text[..text.find("user@").unwrap()].encode_utf16().count()
        );
    }
}
