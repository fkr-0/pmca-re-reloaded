//! Optional real-image test. The WBI fixture is supplied from outside the repository.
use pmca_core::wbi;
use sha2::{Digest, Sha256};
use std::{env, fs};

#[test]
#[ignore = "requires HX50V_WBI_HOST_FIXTURE pointing to a locally held saved readback"]
fn byte_flip_preserves_all_other_real_sections() {
    let path = env::var_os("HX50V_WBI_HOST_FIXTURE")
        .expect("set HX50V_WBI_HOST_FIXTURE to a local WBI1 readback");
    let original = fs::read(path).expect("read external WBI host fixture");
    let before = wbi::parse(&original).expect("parse original WBI1 readback");
    assert!(before.sections.len() > 4);

    // Small section limits growth while still using a real section from the
    // archived image. The patch operation only constructs a host Vec<u8>.
    let section_index = 4;
    let target_before = before.sections[section_index];
    let mut expected_target = wbi::decode_section(&original, &target_before).unwrap();
    expected_target[0] ^= 1;

    let candidate = wbi::flip_section_byte(&original, section_index, 0, 1).unwrap();
    let after = wbi::parse(&candidate).expect("parse rebuilt WBI candidate");

    assert_eq!(after.header.sections, before.header.sections);
    assert_eq!(after.header.resume_vector, before.header.resume_vector);
    assert_eq!(after.header.version, before.header.version);
    assert_eq!(after.header.expanded_size, before.header.expanded_size);
    assert_eq!(after.sections.len(), before.sections.len());

    for (index, (old, new)) in before.sections.iter().zip(&after.sections).enumerate() {
        assert_eq!(old.physical_address, new.physical_address, "section {index}");
        assert_eq!(old.virtual_address, new.virtual_address, "section {index}");
        assert_eq!(old.expanded_size, new.expanded_size, "section {index}");
        if index == section_index {
            assert_eq!(wbi::decode_section(&candidate, new).unwrap(), expected_target);
        } else {
            assert_eq!(
                wbi::digest_section(&original, old).unwrap(),
                wbi::digest_section(&candidate, new).unwrap(),
                "untouched section {index} changed"
            );
        }
    }

    let digest = Sha256::digest(&candidate);
    let digest_hex = digest.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    println!("host-only candidate: {} bytes, sha256={digest_hex}", candidate.len());
}
