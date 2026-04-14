#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(content) = std::str::from_utf8(data) {
        let _ = clawguard::scan::skills::parse_git_config_remote_url_from_str(content);
    }
});
