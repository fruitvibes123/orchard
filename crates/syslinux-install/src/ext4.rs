//! A minimal, read-only ext4 reader scoped to the boot-fs shape — the crux of the no-privilege
//! install. Real `extlinux --install` loop-mounts the filesystem and `FIBMAP`s `ldlinux.sys` to learn
//! its physical sector map (needs `CAP_SYS_ADMIN`). Instead we parse the ext4 extent tree directly
//! out of the baked image bytes: superblock → block group descriptor → inode → extent list. This
//! reproduces `debugfs dump_extents` EXACTLY (the spike's oracle gate), with no mount and no syscall.
//!
//! SCOPE (asserted, fail-closed): depth-0 extent trees + linear (non-htree) directories. The boot-fs
//! is small + freshly `mke2fs -d`'d, so files are contiguous and directories tiny — both hold by
//! construction. A deeper tree or an htree dir is REJECTED ([`Error::UnsupportedExtentDepth`] /
//! a missed dirent) rather than mis-read. Every read is bounds-checked.

use crate::error::Error;

/// Read a little-endian u16 at `o` in `b`, fail-closed on a short slice.
fn rd_u16(b: &[u8], o: usize, what: &'static str) -> Result<u16, Error> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or(Error::OutOfBounds {
            what,
            offset: o as u64,
            len: 2,
            image_len: b.len(),
        })
}

/// Read a little-endian u32 at `o` in `b`, fail-closed on a short slice.
fn rd_u32(b: &[u8], o: usize, what: &'static str) -> Result<u32, Error> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(Error::OutOfBounds {
            what,
            offset: o as u64,
            len: 4,
            image_len: b.len(),
        })
}

/// A physical extent run: `(first_block, block_count)`, both in filesystem blocks.
pub(crate) type Extent = (u64, u16);

/// Read-only view over an ext4 image already held in memory (the `mke2fs -d` output).
pub(crate) struct Ext4<'a> {
    data: &'a [u8],
    block_size: u64,
    inodes_per_group: u32,
    inode_size: u64,
    desc_size: u64,
    inode_count: u32,
}

impl<'a> Ext4<'a> {
    /// Borrow `[off, off+len)` of the image, fail-closed if it runs past the end.
    fn slice(&self, off: u64, len: usize, what: &'static str) -> Result<&'a [u8], Error> {
        let start = off as usize;
        self.data
            .get(start..start.saturating_add(len))
            .ok_or(Error::OutOfBounds {
                what,
                offset: off,
                len,
                image_len: self.data.len(),
            })
    }

    /// Parse the superblock (at byte offset 1024) and capture the geometry the reader needs.
    pub(crate) fn open(data: &'a [u8]) -> Result<Ext4<'a>, Error> {
                                                                                          
        let sb = data.get(1024..2048).ok_or(Error::OutOfBounds {
            what: "superblock",
            offset: 1024,
            len: 1024,
            image_len: data.len(),
        })?;
        let magic = rd_u16(sb, 0x38, "sb.magic")?;
        if magic != 0xEF53 {
            return Err(Error::NotExt4 { found: magic });
        }
        let log_block_size = rd_u32(sb, 0x18, "sb.log_block_size")?;
                                                                         
        let is_64bit = rd_u32(sb, 0x60, "sb.feature_incompat")? & 0x80 != 0;
        let desc_size = if is_64bit {
            let d = rd_u16(sb, 0xFE, "sb.desc_size")?;
            if d == 0 {
                64
            } else {
                d as u64
            }
        } else {
            32
        };
        Ok(Ext4 {
            data,
            block_size: 1024u64 << log_block_size,
            inodes_per_group: rd_u32(sb, 0x28, "sb.inodes_per_group")?,
            inode_size: rd_u16(sb, 0x58, "sb.inode_size")? as u64,
            desc_size,
            inode_count: rd_u32(sb, 0x00, "sb.inode_count")?,
        })
    }

    /// Resolve inode `ino` to `(file_size, physical_extents)`. Rejects depth > 0 extent trees.
    pub(crate) fn read_inode(&self, ino: u32) -> Result<(u64, Vec<Extent>), Error> {
        if ino == 0 || ino > self.inode_count {
            return Err(Error::BadInode { inode: ino });
        }
        if self.inodes_per_group == 0 {
            return Err(Error::BadInode { inode: ino });
        }
        let group = (ino - 1) / self.inodes_per_group;
        let index = (ino - 1) % self.inodes_per_group;
                                                                                             
                                                                                                
                                  
        let gdt_block = if self.block_size == 1024 { 2 } else { 1 };
        let gd = self.slice(
            gdt_block * self.block_size + group as u64 * self.desc_size,
            self.desc_size as usize,
            "group_desc",
        )?;
        let it_lo = rd_u32(gd, 0x08, "gd.inode_table_lo")? as u64;
        let it_hi = if self.desc_size >= 64 {
            rd_u32(gd, 0x28, "gd.inode_table_hi")? as u64
        } else {
            0
        };
        let inode_table_block = (it_hi << 32) | it_lo;
        let raw = self.slice(
            inode_table_block * self.block_size + index as u64 * self.inode_size,
            self.inode_size as usize,
            "inode",
        )?;
        let i_size = rd_u32(raw, 0x04, "inode.size_lo")? as u64;
                                                                                                        
                                                                                                      
                                                                                                       
                                                                                                        
        const EXT4_INDEX_FL: u32 = 0x0000_1000;
        if rd_u32(raw, 0x20, "inode.flags")? & EXT4_INDEX_FL != 0 {
            return Err(Error::HtreeDirUnsupported { inode: ino });
        }
                                                                                              
        let ib = raw.get(0x28..0x28 + 60).ok_or(Error::OutOfBounds {
            what: "inode.i_block",
            offset: 0x28,
            len: 60,
            image_len: raw.len(),
        })?;
        let eh_magic = rd_u16(ib, 0, "extent.magic")?;
        if eh_magic != 0xF30A {
            return Err(Error::BadExtentHeader {
                inode: ino,
                found: eh_magic,
            });
        }
        let depth = rd_u16(ib, 6, "extent.depth")?;
        if depth != 0 {
            return Err(Error::UnsupportedExtentDepth { inode: ino, depth });
        }
        let entries = rd_u16(ib, 2, "extent.entries")? as usize;
        let mut extents = Vec::with_capacity(entries);
        for i in 0..entries {
                                                                                                               
            let e = ib
                .get(12 + i * 12..12 + i * 12 + 12)
                .ok_or(Error::OutOfBounds {
                    what: "extent.entry",
                    offset: (12 + i * 12) as u64,
                    len: 12,
                    image_len: ib.len(),
                })?;
            let rl = rd_u16(e, 4, "extent.len")?;
                                                                                           
            let len = if rl > 32768 { rl - 32768 } else { rl };
            let phys = ((rd_u16(e, 6, "extent.start_hi")? as u64) << 32)
                | rd_u32(e, 8, "extent.start_lo")? as u64;
            extents.push((phys, len));
        }
        Ok((i_size, extents))
    }

    /// Read `size` bytes of file content from the physical `extents` (truncating the block-padded tail).
    pub(crate) fn read_extent_data(&self, extents: &[Extent], size: u64) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(size as usize);
        for &(phys, len) in extents {
            let bytes = self.slice(
                phys * self.block_size,
                len as usize * self.block_size as usize,
                "extent_data",
            )?;
            out.extend_from_slice(bytes);
        }
        out.truncate(size as usize);
        Ok(out)
    }

    /// Walk directories from the root inode (2) to resolve an absolute path to its inode number.
    pub(crate) fn resolve(&self, path: &str) -> Result<u32, Error> {
        let mut ino = 2u32;                   
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            let (size, extents) = self.read_inode(ino)?;
            if extents.is_empty() {
                return Err(Error::NotADirectory {
                    path: path.to_string(),
                });
            }
            let data = self.read_extent_data(&extents, size)?;
            ino = find_dirent(&data, comp).ok_or_else(|| Error::DirEntryNotFound {
                name: comp.to_string(),
            })?;
        }
        Ok(ino)
    }

    /// Filesystem block size in bytes (for the caller's sector-map math).
    pub(crate) fn block_size(&self) -> u64 {
        self.block_size
    }
}

/// Linear scan of `ext4_dir_entry_2` records for `name`. Tail/`metadata_csum` entries carry inode 0
/// and are skipped. Returns the entry's inode number, or `None` if absent. Only ever scans LINEAR
/// directory blocks: `read_inode` rejects hash-indexed (htree, `EXT4_INDEX_FL`) dirs up front, whose
/// `dx_root` would NOT lay the real names out as scannable dirents (INFO-4) — so no silent miss.
fn find_dirent(data: &[u8], name: &str) -> Option<u32> {
    let mut o = 0usize;
    while o + 8 <= data.len() {
        let inode = u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
        let rec_len = u16::from_le_bytes([data[o + 4], data[o + 5]]) as usize;
        if rec_len < 8 {
            break;                                                     
        }
        let name_len = data[o + 6] as usize;
        if inode != 0
            && name_len == name.len()
            && o + 8 + name_len <= data.len()
            && &data[o + 8..o + 8 + name_len] == name.as_bytes()
        {
            return Some(inode);
        }
        o += rec_len;
    }
    None
}
