//! Fail-closed error type. Every fallible step returns [`Error`] instead of panicking — the B1
//! spike's `unwrap`/`expect`/`assert`/`panic!` are all replaced so a malformed image or an
//! out-of-scope ext4 shape aborts the bake cleanly (no partial write, no crash). The
//! `deny(clippy::unwrap_used)` lint (lib.rs) keeps new code honest.

use std::fmt;

/// Anything that can go wrong reading the boot-fs or patching the syslinux core. All variants are
/// terminal: the caller (`bake_boot_fs`) maps any of them to a build abort.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The boot-fs image is not ext2/3/4 — the superblock magic at offset 0x438 is not `0xEF53`.
    NotExt4 { found: u16 },
    /// A read or write would fall outside the image bytes — a truncated/too-small image, a corrupt
    /// offset, or a placement the bake did not expect. `what` names the access for diagnosis.
    OutOfBounds {
        what: &'static str,
        offset: u64,
        len: usize,
        image_len: usize,
    },
    /// An inode number was 0 (the unused sentinel) or beyond the filesystem's inode count.
    BadInode { inode: u32 },
    /// The inode's extent header magic (`0xF30A`) is wrong — not an extents-mapped inode (the boot-fs
    /// is always `-O extent`, so a mismatch means corruption or an unexpected inode).
    BadExtentHeader { inode: u32, found: u16 },
    /// The inode uses an indirect (depth > 0) extent tree. The reader is deliberately scoped to
    /// depth-0 — the small boot-fs guarantees contiguous, single-node extents (findings §5) — so a
    /// deeper tree is REJECTED rather than silently mis-read.
    UnsupportedExtentDepth { inode: u32, depth: u16 },
    /// The inode is a hash-indexed (htree, `EXT4_INDEX_FL`) directory. `find_dirent` scans linear
    /// dirent blocks, which would miss the real names in an htree dir's dx_root, so — like depth > 0
    /// extents — the reader REJECTS it by construction rather than mis-read. The boot-fs's tiny
    /// `mke2fs -d` dirs never index, so this never fires in practice.
    HtreeDirUnsupported { inode: u32 },
    /// A path component (e.g. `slot-a` or `ldlinux.sys`) was not found while walking directories
    /// from the root inode to resolve the install path.
    DirEntryNotFound { name: String },
    /// A path component resolved but is not usable as expected (e.g. an intermediate path element
    /// has no directory entries to walk). `path` is the absolute path being resolved.
    NotADirectory { path: String },
    /// `LDLINUX_MAGIC` (`0x3eb202fe`) was not found in the staged `ldlinux.sys` — the bytes are not a
    /// syslinux 6.04 core, or the template/staging is wrong.
    LdlinuxMagicNotFound,
    /// The RLE-compressed sector-extent table overflows the patch area's fixed extent slots — the
    /// `ldlinux.sys` is too fragmented. A freshly-`mke2fs -d`'d small boot-fs is contiguous, so this
    /// never fires in practice; rejected fail-closed if it does.
    TooManyExtents { runs: usize, slots: usize },
    /// The post-patch bootloader checksum self-check failed (the sum of `dwords` words did not equal
    /// `LDLINUX_MAGIC`) — the patch did not produce a core the VBR will accept at boot.
    ChecksumSelfCheckFailed,
    /// The VBR template (`ldlinux.bss`) is not exactly one 512-byte sector.
    VbrLength { found: usize },
    /// The on-disk `ldlinux.sys` is smaller than the 2-sector ADV it must end with (i.e. its size is
    /// less than `boot_image_len + 2*512`), so the patch-area / ADV math would underflow.
    OnDiskTooSmallForAdv { size: u64 },
    /// The patch area's recorded offsets point outside `ldlinux.sys` — a malformed template.
    PatchAreaOutOfRange { what: &'static str },
    /// The install subdir + its NUL terminator does not fit the core's reserved dir field. The C
    /// `extlinux` `exit(1)`s here; we fail closed too (a silent skip would bake a stale/empty subdir →
    /// a wrong-path boot). Never fires for the fixed `/slot-a` install dir.
    SubdirTooLong { len: usize, max: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotExt4 { found } => {
                write!(f, "not an ext2/3/4 image (superblock magic {found:#06x}, want 0xef53)")
            }
            Error::OutOfBounds { what, offset, len, image_len } => write!(
                f,
                "{what}: read/write of {len} bytes at offset {offset} exceeds image length {image_len}"
            ),
            Error::BadInode { inode } => write!(f, "bad inode number {inode}"),
            Error::BadExtentHeader { inode, found } => write!(
                f,
                "inode {inode}: bad extent header magic {found:#06x} (want 0xf30a)"
            ),
            Error::UnsupportedExtentDepth { inode, depth } => write!(
                f,
                "inode {inode}: extent tree depth {depth} unsupported (B1 reader is depth-0 only)"
            ),
            Error::HtreeDirUnsupported { inode } => write!(
                f,
                "inode {inode}: htree (EXT4_INDEX_FL) directory unsupported (B1 reader is linear-dir only)"
            ),
            Error::DirEntryNotFound { name } => write!(f, "directory entry {name:?} not found"),
            Error::NotADirectory { path } => write!(f, "{path:?}: path component is not a directory"),
            Error::LdlinuxMagicNotFound => {
                write!(f, "LDLINUX_MAGIC (0x3eb202fe) not found in ldlinux.sys")
            }
            Error::TooManyExtents { runs, slots } => write!(
                f,
                "ldlinux.sys too fragmented: {runs} extent runs > {slots} patch-area slots"
            ),
            Error::ChecksumSelfCheckFailed => {
                write!(f, "post-patch ldlinux.sys checksum self-check failed")
            }
            Error::VbrLength { found } => {
                write!(f, "VBR template (ldlinux.bss) is {found} bytes, want exactly 512")
            }
            Error::OnDiskTooSmallForAdv { size } => write!(
                f,
                "on-disk ldlinux.sys is {size} bytes — too small for the 2-sector ADV tail"
            ),
            Error::PatchAreaOutOfRange { what } => {
                write!(f, "patch-area field {what} points outside ldlinux.sys")
            }
            Error::SubdirTooLong { len, max } => write!(
                f,
                "install subdir is {len} bytes + NUL > the core's {max}-byte dir field (would mis-boot)"
            ),
        }
    }
}

impl std::error::Error for Error {}
