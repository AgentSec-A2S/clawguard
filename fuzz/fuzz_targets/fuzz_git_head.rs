#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(content) = std::str::from_utf8(data) {
        // Split input into HEAD content and optional ref/packed-refs
        let parts: Vec<&str> = content.splitn(3, '\0').collect();
        let head = parts[0];
        let ref_content = parts.get(1).copied();
        let packed_refs = parts.get(2).copied();
        let _ = clawguard::scan::skills::parse_git_head_sha_from_str(head, ref_content, packed_refs);
    }
});
