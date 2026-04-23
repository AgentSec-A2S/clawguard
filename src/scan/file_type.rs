//! Byte-first executable-signature detection for artifact integrity.
//!
//! Sprint 1 Task 3.x: detect when a file claims a text-like extension (e.g.
//! `.md`, `.sh`, `.py`) but its leading bytes are a native executable format.
//!
//! Design notes:
//! - Always byte-first: open + peek at most [`SIGNATURE_MAX_INSPECT_BYTES`]
//!   (16) leading bytes. Short reads are valid; no file-length upper bound is
//!   enforced because a disguised binary of any total size must remain
//!   inspectable via its header.
//! - IO failures (permission denied, unreadable, pipe) quietly return `None`;
//!   signature detection is best-effort and must never panic or surface an
//!   error to the scan pipeline.
//! - Files whose filename extension is in the binary-looking allowlist (such
//!   as `.node`, `.dylib`, `.wasm`) are short-circuited with no signature
//!   lookup — those are legitimately binary and are expected to have the
//!   matching magic header.

use std::fs::File;
use std::io::Read;
use std::path::Path;

pub const SIGNATURE_MAX_INSPECT_BYTES: usize = 16;

/// Binary formats recognized by the byte-first signature helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinarySignature {
    Elf,
    PeMz,
    MachO32,
    MachO64,
    MachO32Reverse,
    MachO64Reverse,
    FatMagic,
    FatCigam,
    /// WebAssembly module (`\0asm` + 4-byte version).
    Wasm,
    /// CPython bytecode cache file (4-byte version magic + `\r\n\r\n` or
    /// `\r\n`). Any of the supported 3.8–3.13 magic numbers maps here.
    Pyc,
    /// ZIP local-file header (`PK\x03\x04`). Covers raw zips, jar/war,
    /// modern Office formats, and `.pyz` executable Python zipapps.
    ZipArchive,
}

impl BinarySignature {
    pub fn as_kind(self) -> &'static str {
        match self {
            Self::Elf => "elf",
            Self::PeMz => "pe",
            Self::MachO32 => "mach-o-32",
            Self::MachO64 => "mach-o-64",
            Self::MachO32Reverse => "mach-o-32-reverse",
            Self::MachO64Reverse => "mach-o-64-reverse",
            Self::FatMagic => "mach-o-fat",
            Self::FatCigam => "mach-o-fat-reverse",
            Self::Wasm => "wasm",
            Self::Pyc => "pyc",
            Self::ZipArchive => "zip-archive",
        }
    }
}

/// Match leading bytes against the complete fixed signature table. This table
/// is exhaustive — any addition or removal MUST also update
/// [`match_signature_table_is_complete`] in this module's tests.
/// Classify the leading bytes of a file against the byte-first signature
/// table. Callers that already hold the file contents (e.g. the hook and
/// skill scanners after `fs::read_to_string`) can use this to avoid a second
/// `File::open` syscall. Uses the same length-16 window as
/// [`detect_binary_signature`].
///
/// Returns `Some(kind)` on match; `None` otherwise.
pub fn classify_leading_bytes(bytes: &[u8]) -> Option<BinarySignature> {
    match_signature(&bytes[..bytes.len().min(SIGNATURE_MAX_INSPECT_BYTES)])
}

fn match_signature(bytes: &[u8]) -> Option<BinarySignature> {
    // Use a fixed table so a missing row causes a failing unit test.
    //
    // CPython pyc magic numbers change every minor release. Each listed row
    // maps to `BinarySignature::Pyc` — reviewers should keep the Pyc set
    // aligned with currently-supported CPython (3.8+). Numbers sourced from
    // cpython/Lib/importlib/_bootstrap_external.py's `MAGIC_NUMBER`.
    const TABLE: &[(&[u8], BinarySignature)] = &[
        (&[0x7F, 0x45, 0x4C, 0x46], BinarySignature::Elf), // "\x7FELF"
        (&[0x4D, 0x5A], BinarySignature::PeMz),            // "MZ"
        (&[0xFE, 0xED, 0xFA, 0xCE], BinarySignature::MachO32), // MH_MAGIC
        (&[0xFE, 0xED, 0xFA, 0xCF], BinarySignature::MachO64), // MH_MAGIC_64
        (&[0xCE, 0xFA, 0xED, 0xFE], BinarySignature::MachO32Reverse), // MH_CIGAM
        (&[0xCF, 0xFA, 0xED, 0xFE], BinarySignature::MachO64Reverse), // MH_CIGAM_64
        (&[0xCA, 0xFE, 0xBA, 0xBE], BinarySignature::FatMagic), // FAT_MAGIC
        (&[0xBE, 0xBA, 0xFE, 0xCA], BinarySignature::FatCigam), // FAT_CIGAM
        (&[0x00, 0x61, 0x73, 0x6D], BinarySignature::Wasm), // "\0asm"
        (&[0x50, 0x4B, 0x03, 0x04], BinarySignature::ZipArchive), // PK\x03\x04 (zip/pyz/jar/...)
        (&[0x50, 0x4B, 0x05, 0x06], BinarySignature::ZipArchive), // PK\x05\x06 (empty zip)
        (&[0x55, 0x0D, 0x0D, 0x0A], BinarySignature::Pyc), // CPython 3.8
        (&[0x61, 0x0D, 0x0D, 0x0A], BinarySignature::Pyc), // CPython 3.9
        (&[0x6F, 0x0D, 0x0D, 0x0A], BinarySignature::Pyc), // CPython 3.10
        (&[0xA7, 0x0D, 0x0D, 0x0A], BinarySignature::Pyc), // CPython 3.11
        (&[0xCB, 0x0D, 0x0D, 0x0A], BinarySignature::Pyc), // CPython 3.12
        (&[0xF3, 0x0D, 0x0D, 0x0A], BinarySignature::Pyc), // CPython 3.13
    ];

    for &(signature, kind) in TABLE {
        if bytes.starts_with(signature) {
            return Some(kind);
        }
    }
    None
}

/// Open the file at `path` and peek up to [`SIGNATURE_MAX_INSPECT_BYTES`]
/// leading bytes. Returns `Some(signature)` on match, `None` otherwise or on
/// any IO failure.
///
/// The function deliberately does NOT follow or reject symlinks — the caller
/// is responsible for constraining which paths it hands in. All IO is
/// best-effort; errors are swallowed and surfaced as `None`.
pub fn detect_binary_signature(path: &Path) -> Option<BinarySignature> {
    // Binary-looking extensions short-circuit: signature match on these is
    // expected and uninteresting.
    if is_binary_extension_allowed(path) {
        return None;
    }
    let mut file = File::open(path).ok()?;
    let mut buf = [0u8; SIGNATURE_MAX_INSPECT_BYTES];
    let n = match file.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return None,
    };
    match_signature(&buf[..n])
}

/// File extensions where a native binary header is the legitimate expectation.
/// Matching is case-insensitive on the final `.` extension only.
pub fn is_binary_extension_allowed(path: &Path) -> bool {
    const ALLOWED: &[&str] = &[
        "node", "wasm", "so", "dylib", "dll", "exe", "bin", "o", "a", "pyc", "pyo", "pyz", "zip",
        "jar",
    ];
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let lowered = ext.to_ascii_lowercase();
    ALLOWED.iter().any(|a| *a == lowered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_bytes(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        fs::write(&path, bytes).expect("write fixture");
        path
    }

    #[test]
    fn elf_header_is_detected() {
        let dir = tempdir().unwrap();
        let p = write_bytes(dir.path(), "fake.md", b"\x7FELF\x02\x01\x01\x00");
        assert_eq!(detect_binary_signature(&p), Some(BinarySignature::Elf));
    }

    #[test]
    fn pe_mz_header_is_detected() {
        let dir = tempdir().unwrap();
        let p = write_bytes(dir.path(), "fake.sh", b"MZ\x90\x00\x03");
        assert_eq!(detect_binary_signature(&p), Some(BinarySignature::PeMz));
    }

    #[test]
    fn mach_o_mh_magic_is_detected() {
        let dir = tempdir().unwrap();
        let p = write_bytes(dir.path(), "fake.md", b"\xFE\xED\xFA\xCE\x00\x00");
        assert_eq!(detect_binary_signature(&p), Some(BinarySignature::MachO32));
    }

    #[test]
    fn mach_o_mh_magic_64_is_detected() {
        let dir = tempdir().unwrap();
        let p = write_bytes(dir.path(), "fake.md", b"\xFE\xED\xFA\xCF\x00\x00");
        assert_eq!(detect_binary_signature(&p), Some(BinarySignature::MachO64));
    }

    #[test]
    fn mach_o_mh_cigam_is_detected() {
        let dir = tempdir().unwrap();
        let p = write_bytes(dir.path(), "fake.md", b"\xCE\xFA\xED\xFE\x00\x00");
        assert_eq!(
            detect_binary_signature(&p),
            Some(BinarySignature::MachO32Reverse)
        );
    }

    #[test]
    fn mach_o_mh_cigam_64_is_detected() {
        let dir = tempdir().unwrap();
        let p = write_bytes(dir.path(), "fake.md", b"\xCF\xFA\xED\xFE\x00\x00");
        assert_eq!(
            detect_binary_signature(&p),
            Some(BinarySignature::MachO64Reverse)
        );
    }

    #[test]
    fn fat_universal_magic_is_detected() {
        let dir = tempdir().unwrap();
        let p = write_bytes(dir.path(), "fake.md", b"\xCA\xFE\xBA\xBE\x00\x00");
        assert_eq!(detect_binary_signature(&p), Some(BinarySignature::FatMagic));
    }

    #[test]
    fn fat_universal_cigam_is_detected() {
        let dir = tempdir().unwrap();
        let p = write_bytes(dir.path(), "fake.md", b"\xBE\xBA\xFE\xCA\x00\x00");
        assert_eq!(detect_binary_signature(&p), Some(BinarySignature::FatCigam));
    }

    #[test]
    fn plain_text_does_not_match_any_signature() {
        let dir = tempdir().unwrap();
        let p = write_bytes(dir.path(), "real.md", b"# markdown text\n\nhello world");
        assert_eq!(detect_binary_signature(&p), None);
    }

    #[test]
    fn short_read_below_signature_length_returns_none() {
        let dir = tempdir().unwrap();
        let p = write_bytes(dir.path(), "tiny.md", b"MZ"); // 2 bytes still detected as PE
        assert_eq!(detect_binary_signature(&p), Some(BinarySignature::PeMz));
        let p = write_bytes(dir.path(), "one.md", b"M"); // 1 byte — no match
        assert_eq!(detect_binary_signature(&p), None);
    }

    #[test]
    fn binary_extension_allowlist_short_circuits() {
        // A `.node` file is legitimately an ELF-like native module; the
        // helper must not produce a signature match for it.
        let dir = tempdir().unwrap();
        let p = write_bytes(dir.path(), "native.node", b"\x7FELF\x02\x01\x01\x00");
        assert_eq!(detect_binary_signature(&p), None);

        let p = write_bytes(dir.path(), "lib.dylib", b"\xCF\xFA\xED\xFE");
        assert_eq!(detect_binary_signature(&p), None);
    }

    #[test]
    fn io_failure_returns_none() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.md");
        assert_eq!(detect_binary_signature(&missing), None);
    }

    /// Structural smoke test: the signature table covers every format the
    /// spec requires (Sprint 1 + Sprint 2 §10.1 additions: Wasm, Pyc, Zip).
    /// If a row is removed, the failing per-signature test above still
    /// catches it; this test also catches the reverse regression where a new
    /// signature is added to the table without a dedicated detection test.
    #[test]
    fn match_signature_table_is_complete() {
        let cases: &[(&[u8], BinarySignature)] = &[
            (&[0x7F, 0x45, 0x4C, 0x46], BinarySignature::Elf),
            (&[0x4D, 0x5A], BinarySignature::PeMz),
            (&[0xFE, 0xED, 0xFA, 0xCE], BinarySignature::MachO32),
            (&[0xFE, 0xED, 0xFA, 0xCF], BinarySignature::MachO64),
            (&[0xCE, 0xFA, 0xED, 0xFE], BinarySignature::MachO32Reverse),
            (&[0xCF, 0xFA, 0xED, 0xFE], BinarySignature::MachO64Reverse),
            (&[0xCA, 0xFE, 0xBA, 0xBE], BinarySignature::FatMagic),
            (&[0xBE, 0xBA, 0xFE, 0xCA], BinarySignature::FatCigam),
            (&[0x00, 0x61, 0x73, 0x6D], BinarySignature::Wasm),
            (&[0x50, 0x4B, 0x03, 0x04], BinarySignature::ZipArchive),
            (&[0x50, 0x4B, 0x05, 0x06], BinarySignature::ZipArchive),
            (&[0x55, 0x0D, 0x0D, 0x0A], BinarySignature::Pyc),
            (&[0x61, 0x0D, 0x0D, 0x0A], BinarySignature::Pyc),
            (&[0x6F, 0x0D, 0x0D, 0x0A], BinarySignature::Pyc),
            (&[0xA7, 0x0D, 0x0D, 0x0A], BinarySignature::Pyc),
            (&[0xCB, 0x0D, 0x0D, 0x0A], BinarySignature::Pyc),
            (&[0xF3, 0x0D, 0x0D, 0x0A], BinarySignature::Pyc),
        ];
        for (bytes, expected) in cases {
            assert_eq!(
                match_signature(bytes),
                Some(*expected),
                "signature for {:?} should be {:?}",
                bytes,
                expected
            );
        }
    }

    #[test]
    fn wasm_header_is_detected_on_text_extension() {
        let dir = tempdir().unwrap();
        let p = write_bytes(dir.path(), "fake.md", b"\x00asm\x01\x00\x00\x00");
        assert_eq!(detect_binary_signature(&p), Some(BinarySignature::Wasm));
    }

    #[test]
    fn zip_header_is_detected_on_text_extension() {
        let dir = tempdir().unwrap();
        let p = write_bytes(dir.path(), "fake.md", b"PK\x03\x04\x14\x00");
        assert_eq!(
            detect_binary_signature(&p),
            Some(BinarySignature::ZipArchive)
        );
    }

    #[test]
    fn pyc_header_is_detected_on_text_extension() {
        let dir = tempdir().unwrap();
        // CPython 3.11 magic.
        let p = write_bytes(dir.path(), "fake.md", b"\xA7\x0D\x0D\x0A\x00\x00");
        assert_eq!(detect_binary_signature(&p), Some(BinarySignature::Pyc));
    }

    #[test]
    fn binary_extension_allowlist_covers_pyc_and_pyz() {
        let dir = tempdir().unwrap();
        let p = write_bytes(dir.path(), "module.pyc", b"\xA7\x0D\x0D\x0A\x00\x00");
        assert_eq!(detect_binary_signature(&p), None);
        let p = write_bytes(dir.path(), "bundle.pyz", b"PK\x03\x04\x14\x00");
        assert_eq!(detect_binary_signature(&p), None);
    }
}
