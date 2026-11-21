//! Read-only parser for Sony `WBI1` warm-boot RAM images.
//!
//! Sony stores compressed memory sections under physical and virtual addresses,
//! not as a filesystem. The format is documented in ma1co/fwtool.py's
//! `fwtool/sony/wbi.py` and `fwtool/lz77/__init__.py`. No image is written back
//! to a camera by this module. Header `resume_vector` is *not* a timestamp.
//!
//! Unlike an `mtime`, the format has no known creation-time field. A host
//! acquisition timestamp must be recorded separately from the image itself.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use crate::util::parse32le;
use crate::{Error, Result};

const HEADER_BYTES: usize = 44;
const SECTION_BYTES: usize = 32;
const VERSION: u32 = 0x2006_0224;
const MAX_SECTIONS: usize = 512;
const MAX_EXPANDED: usize = 512 * 1024 * 1024;
const MAX_SECTION: usize = 64 * 1024 * 1024;

/// The fixed `WBI1` header; unknown fields are retained verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Number of entries in the section table.
    pub sections: u32,
    /// Image flags; bit zero means LZ77-compressed.
    pub flags: u32,
    /// ARM resume vector, not an image creation date.
    pub resume_vector: u32,
    /// Sony's WBI format version.
    pub version: u32,
    /// Alignment of the data region and header.
    pub sector_size: u32,
    /// Compressed data region length.
    pub compressed_size: u32,
    /// Kernel start address.
    pub kernel_start: u32,
    /// Kernel image length.
    pub kernel_size: u32,
    /// Original kernel checksum field (not yet independently characterized).
    pub kernel_checksum: u32,
    /// Total size of decompressed memory segments.
    pub expanded_size: u32,
}

/// One memory region in the `WBI1` section table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    /// Index in the WBI table, beginning at zero.
    pub index: usize,
    /// Physical destination address for a restore.
    pub physical_address: u32,
    /// Virtual address used by the captured kernel.
    pub virtual_address: u32,
    /// Offset of this section's compressed stream in the file.
    pub compressed_offset: usize,
    /// Number of bytes of compressed data.
    pub compressed_size: usize,
    /// Number of bytes after decompression.
    pub expanded_size: usize,
    /// Original section checksum (algorithm not independently verified).
    pub checksum: u32,
    /// Original section flags.
    pub flags: u32,
    /// Original table padding field.
    pub padding: u32,
    /// Original table metadata checksum.
    pub metadata_checksum: u32,
}

/// A parsed image with validated section boundaries, without decompressed data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// Fixed header fields.
    pub header: Header,
    /// First byte of the compressed data region.
    pub data_offset: usize,
    /// All memory sections in table order.
    pub sections: Vec<Section>,
}

fn word(data: &[u8], offset: usize) -> Result<u32> {
    parse32le(data.get(offset..offset + 4).ok_or(Error::OutOfBounds { context: "WBI field" })?)
}

/// Parse Sony WBI1 metadata, rejecting excessive sizes and truncated sections.
///
/// Section checksums are preserved but not checked: their algorithm has not
/// been established, and treating them as CRC32 would be misleading.
pub fn parse(data: &[u8]) -> Result<Image> {
    if !data.starts_with(b"WBI1") {
        return Err(Error::BadMagic { expected: "WBI1" });
    }
    if data.len() < HEADER_BYTES {
        return Err(Error::OutOfBounds { context: "WBI header" });
    }
    let h = Header {
        sections: word(data, 4)?,
        flags: word(data, 8)?,
        resume_vector: word(data, 12)?,
        version: word(data, 16)?,
        sector_size: word(data, 20)?,
        compressed_size: word(data, 24)?,
        kernel_start: word(data, 28)?,
        kernel_size: word(data, 32)?,
        kernel_checksum: word(data, 36)?,
        expanded_size: word(data, 40)?,
    };
    if h.version != VERSION || h.flags & 1 == 0 {
        return Err(Error::Invalid("WBI version or compression mode"));
    }
    let count = usize::try_from(h.sections).map_err(|_| Error::Invalid("WBI section count"))?;
    let sector = h.sector_size as usize;
    if !(1..=MAX_SECTIONS).contains(&count)
        || !matches!(sector, 128 | 256 | 512 | 1024 | 2048 | 4096)
        || h.expanded_size as usize > MAX_EXPANDED
        || h.compressed_size == 0
    {
        return Err(Error::Invalid("WBI sizes outside supported bounds"));
    }
    // fwtool.py skips whole zero-filled or 0xff-filled sectors before the
    // compressed section data. The first header sector is always skipped.
    let mut offset = sector;
    loop {
        let end = offset.checked_add(sector).ok_or(Error::Invalid("WBI sector overflow"))?;
        let block =
            data.get(offset..end).ok_or(Error::OutOfBounds { context: "WBI leading sectors" })?;
        if !block.iter().all(|&b| b == 0 || b == 0xff)
            || (block.contains(&0) && block.contains(&0xff))
        {
            break;
        }
        offset = end;
    }
    let packed_end = offset
        .checked_add(h.compressed_size as usize)
        .ok_or(Error::Invalid("WBI compressed offset overflow"))?;
    let toc_end = packed_end
        .checked_add(count * SECTION_BYTES)
        .ok_or(Error::Invalid("WBI table offset overflow"))?;
    if toc_end > data.len() {
        return Err(Error::OutOfBounds { context: "WBI table" });
    }
    let mut sections = Vec::with_capacity(count);
    let mut packed_pos = offset;
    let mut expanded_total = 0usize;
    for index in 0..count {
        let entry = packed_end + index * SECTION_BYTES;
        let size = word(data, entry + 4)? as usize;
        let expanded_size = word(data, entry + 16)? as usize;
        let end =
            packed_pos.checked_add(size).ok_or(Error::Invalid("WBI section size overflow"))?;
        expanded_total = expanded_total
            .checked_add(expanded_size)
            .ok_or(Error::Invalid("WBI decoded size overflow"))?;
        if size == 0
            || expanded_size == 0
            || expanded_size > MAX_SECTION
            || end > packed_end
            || expanded_total > MAX_EXPANDED
        {
            return Err(Error::Invalid("WBI section outside declared data region"));
        }
        sections.push(Section {
            index,
            physical_address: word(data, entry)?,
            virtual_address: word(data, entry + 20)?,
            compressed_offset: packed_pos,
            compressed_size: size,
            expanded_size,
            checksum: word(data, entry + 8)?,
            flags: word(data, entry + 12)?,
            padding: word(data, entry + 24)?,
            metadata_checksum: word(data, entry + 28)?,
        });
        packed_pos = end;
    }
    if expanded_total != h.expanded_size as usize || packed_pos != packed_end {
        return Err(Error::Invalid("WBI declared total sizes disagree"));
    }
    Ok(Image { header: h, data_offset: offset, sections })
}

/// Decompress one section with Sony's LZ77 variant (`0x0f` raw / `0xf0` backrefs).
///
/// Each section is an independent stream of blocks. Bounds are checked before
/// every access, including against a corrupt back-reference distance.
pub fn decode_section(data: &[u8], section: &Section) -> Result<Vec<u8>> {
    let packed = data
        .get(section.compressed_offset..section.compressed_offset + section.compressed_size)
        .ok_or(Error::OutOfBounds { context: "WBI section source" })?;
    let mut out = Vec::with_capacity(section.expanded_size);
    let mut pos = 0usize;
    while pos < packed.len() && out.len() < section.expanded_size {
        let kind = packed[pos];
        pos += 1;
        match kind {
            0x0f => {
                let head = packed
                    .get(pos..pos + 3)
                    .ok_or(Error::OutOfBounds { context: "WBI raw block header" })?;
                let size = usize::from(u16::from_le_bytes([head[1], head[2]]));
                pos += 3;
                let raw = packed
                    .get(pos..pos + size)
                    .ok_or(Error::OutOfBounds { context: "WBI raw block" })?;
                if size == 0 || size > section.expanded_size - out.len() {
                    return Err(Error::Invalid("WBI raw block size"));
                }
                out.extend_from_slice(raw);
                pos += size;
            }
            0xf0 => {
                // Every LZ packet has its own back-reference window. It must
                // not refer to the output of a previous packet in the section.
                let lengths: [usize; 16] =
                    [3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 32, 64];
                let mut packet = Vec::new();
                let limit = (section.expanded_size - out.len()).min(65536);
                let mut ended = false;
                while !ended {
                    let flags =
                        *packed.get(pos).ok_or(Error::OutOfBounds { context: "WBI LZ77 flags" })?;
                    pos += 1;
                    for bit in 0..8 {
                        if (flags >> bit) & 1 == 0 {
                            let b = *packed
                                .get(pos)
                                .ok_or(Error::OutOfBounds { context: "WBI LZ77 literal" })?;
                            pos += 1;
                            if packet.len() >= limit {
                                return Err(Error::Invalid("WBI LZ77 output overflow"));
                            }
                            packet.push(b);
                        } else {
                            let pair = packed
                                .get(pos..pos + 2)
                                .ok_or(Error::OutOfBounds { context: "WBI LZ77 backref" })?;
                            pos += 2;
                            let size = lengths[usize::from(pair[0] >> 4)];
                            let distance = (usize::from(pair[0] & 15) << 8) | usize::from(pair[1]);
                            if distance == 0 {
                                ended = true;
                                break;
                            }
                            if distance > packet.len() || size > limit - packet.len() {
                                return Err(Error::Invalid("WBI LZ77 invalid back-reference"));
                            }
                            for _ in 0..size {
                                let idx = packet.len() - distance;
                                packet.push(packet[idx]);
                            }
                        }
                    }
                }
                if packet.is_empty() {
                    return Err(Error::Invalid("empty WBI LZ77 packet"));
                }
                out.extend_from_slice(&packet);
            }
            _ => return Err(Error::Invalid("unknown Sony WBI LZ77 block type")),
        }
    }
    if out.len() != section.expanded_size {
        return Err(Error::Invalid("WBI section decoded size mismatch"));
    }
    // The table's compressed extent is an allocation, not an exact count of
    // LZ packets. Real Sony images retain nonzero bytes after the final
    // packet; the original fwtool.py decoder stops at expanded_size too.
    Ok(out)
}

/// Encode bytes as literal records in the WBI LZ77 token grammar.
///
/// This uses the documented `0x0f` literal token, a zero reserved byte,
/// a little-endian u16 length, and raw bytes. It is a portable host encoding,
/// not a reproduction of Sony's CMPR hardware output.
pub fn encode_literal_section(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.is_empty() {
        return Err(Error::Invalid("empty WBI section"));
    }
    let blocks = bytes.len().div_ceil(usize::from(u16::MAX));
    let capacity = bytes
        .len()
        .checked_add(blocks.checked_mul(4).ok_or(Error::Invalid("WBI literal size overflow"))?)
        .ok_or(Error::Invalid("WBI literal size overflow"))?;
    let mut out = Vec::with_capacity(capacity);
    for chunk in bytes.chunks(usize::from(u16::MAX)) {
        out.push(0x0f);
        out.push(0); // reserved byte consumed by Sony/fwtool readers
        out.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
        out.extend_from_slice(chunk);
    }
    Ok(out)
}

fn sector_round(size: usize, sector: usize) -> Result<usize> {
    if sector == 0 || !sector.is_power_of_two() {
        return Err(Error::Invalid("invalid WBI sector size"));
    }
    size.checked_add(sector - 1)
        .map(|n| n & !(sector - 1))
        .ok_or(Error::Invalid("WBI sector extent overflow"))
}

fn wbi_xor_checksum(bytes: &[u8]) -> u32 {
    bytes.chunks_exact(4).fold(0x0f0f_0f0f, |sum, word| {
        sum ^ u32::from_le_bytes([word[0], word[1], word[2], word[3]])
    })
}

/// Replace one existing WBI section with same-length decoded bytes.
///
/// The target section is re-encoded using literal `0x0f` tokens, then its
/// stored extent, source checksum (when enabled), and metadata XOR are
/// recalculated. Other section streams and descriptors are copied verbatim.
/// The resulting buffer is a host-only WBI candidate accepted by this
/// crate's parser; it is **not** guaranteed to match Sony's CMPR hardware
/// bytes or to be accepted by the immutable EXBL/WBI boot consumer.
///
/// This function never opens a device, writes NAND, or activates an image.
pub fn replace_section_contents(
    original: &[u8],
    section_index: usize,
    replacement: &[u8],
) -> Result<Vec<u8>> {
    let image = parse(original)?;
    if image.header.flags & 0x09 != 0x09 {
        return Err(Error::Invalid("WBI image is not in the supported compressed LZ77 mode"));
    }
    let target = image.sections.get(section_index).ok_or(Error::Invalid("WBI section index"))?;
    if replacement.len() != target.expanded_size {
        return Err(Error::Invalid("replacement section size must remain unchanged"));
    }

    let literal = encode_literal_section(replacement)?;
    let sector =
        usize::try_from(image.header.sector_size).map_err(|_| Error::Invalid("WBI sector size"))?;
    let new_target_extent = sector_round(literal.len(), sector)?;
    let old_table_start = image
        .data_offset
        .checked_add(image.header.compressed_size as usize)
        .ok_or(Error::Invalid("WBI table offset overflow"))?;
    let table_len = image
        .sections
        .len()
        .checked_mul(SECTION_BYTES)
        .ok_or(Error::Invalid("WBI table size overflow"))?;
    let old_table_end = old_table_start
        .checked_add(table_len)
        .ok_or(Error::Invalid("WBI table extent overflow"))?;
    let old_table = original
        .get(old_table_start..old_table_end)
        .ok_or(Error::OutOfBounds { context: "WBI section table for replacement" })?;

    let mut data_region = Vec::new();
    let mut table = Vec::with_capacity(table_len);
    let mut stored_total = 0usize;

    for section in &image.sections {
        let is_target = section.index == section_index;
        let stored = if is_target {
            literal.as_slice()
        } else {
            original
                .get(section.compressed_offset..section.compressed_offset + section.compressed_size)
                .ok_or(Error::OutOfBounds { context: "WBI unchanged section stream" })?
        };
        let stored_extent = if is_target { new_target_extent } else { section.compressed_size };
        data_region.extend_from_slice(stored);
        data_region.resize(
            data_region
                .len()
                .checked_add(stored_extent - stored.len())
                .ok_or(Error::Invalid("WBI section padding overflow"))?,
            0,
        );
        stored_total = stored_total
            .checked_add(stored_extent)
            .ok_or(Error::Invalid("WBI stored extent overflow"))?;

        if is_target {
            let checksum = if image.header.flags & 0x04 != 0 {
                wbi_xor_checksum(replacement)
            } else {
                // Sony's writer skips source-data checksum recalculation when
                // WBI_CKSUM is clear; preserve the original descriptor value.
                section.checksum
            };
            let words = [
                section.physical_address,
                u32::try_from(new_target_extent)
                    .map_err(|_| Error::Invalid("WBI section extent exceeds ARM32"))?,
                checksum,
                0,
                u32::try_from(section.expanded_size)
                    .map_err(|_| Error::Invalid("WBI expanded size exceeds ARM32"))?,
                section.virtual_address,
                section.padding,
            ];
            let metadata = words.iter().fold(0x0f0f_0f0f, |sum, word| sum ^ word);
            for word in words.into_iter().chain([metadata]) {
                table.extend_from_slice(&word.to_le_bytes());
            }
        } else {
            let descriptor_offset = section.index * SECTION_BYTES;
            table.extend_from_slice(
                old_table
                    .get(descriptor_offset..descriptor_offset + SECTION_BYTES)
                    .ok_or(Error::OutOfBounds { context: "WBI unchanged descriptor" })?,
            );
        }
    }

    let output_data_offset = image.data_offset;
    let table_start = output_data_offset
        .checked_add(stored_total)
        .ok_or(Error::Invalid("WBI output table offset overflow"))?;
    let unrounded_end =
        table_start.checked_add(table.len()).ok_or(Error::Invalid("WBI output extent overflow"))?;
    let output_len = sector_round(unrounded_end, sector)?;

    // Keep the complete original prefix (header sector and any observed
    // leading erased sectors) byte-for-byte, but discard part5 storage slack.
    let mut output = Vec::with_capacity(output_len);
    output.extend_from_slice(
        original
            .get(..output_data_offset)
            .ok_or(Error::OutOfBounds { context: "WBI header/data prefix" })?,
    );
    output.extend_from_slice(&data_region);
    output.extend_from_slice(&table);
    output.resize(output_len, 0);
    let stored_total_u32 =
        u32::try_from(stored_total).map_err(|_| Error::Invalid("WBI stored size exceeds ARM32"))?;
    output[24..28].copy_from_slice(&stored_total_u32.to_le_bytes());

    // Prove the rebuilt candidate parses and that the patched section decodes
    // to exactly the supplied bytes. This remains a host parser check only.
    let rebuilt = parse(&output)?;
    let rebuilt_target = rebuilt
        .sections
        .get(section_index)
        .ok_or(Error::Invalid("rebuilt WBI target section missing"))?;
    if decode_section(&output, rebuilt_target)? != replacement {
        return Err(Error::Invalid("rebuilt WBI literal stream did not round-trip"));
    }
    Ok(output)
}

/// Flip a byte in one decoded section and rebuild a detached WBI candidate.
///
/// `mask` must be non-zero. This convenience function is useful for offline
/// fault injection and byte-level experiments; it performs no device write.
pub fn flip_section_byte(
    original: &[u8],
    section_index: usize,
    offset: usize,
    mask: u8,
) -> Result<Vec<u8>> {
    if mask == 0 {
        return Err(Error::Invalid("WBI byte-flip mask is zero"));
    }
    let image = parse(original)?;
    let section = image.sections.get(section_index).ok_or(Error::Invalid("WBI section index"))?;
    let mut decoded = decode_section(original, section)?;
    let byte = decoded.get_mut(offset).ok_or(Error::Invalid("WBI byte-flip offset"))?;
    *byte ^= mask;
    replace_section_contents(original, section_index, &decoded)
}

/// Hash the uncompressed data of one memory section for comparisons.
pub fn digest_section(data: &[u8], section: &Section) -> Result<[u8; 32]> {
    let decoded = decode_section(data, section)?;
    Ok(Sha256::digest(decoded).into())
}

/// Report the physical sections added, removed or changed between two images.
///
/// Each image is keyed by (physical address, expanded size) so changes in
/// virtual mappings still count as changes; duplicate physical ranges fail.
pub fn diff(before: &[u8], after: &[u8]) -> Result<Vec<Change>> {
    let left = parse(before)?;
    let right = parse(after)?;
    let mut a = BTreeMap::new();
    let mut b = BTreeMap::new();
    for s in &left.sections {
        if a.insert(s.physical_address, s).is_some() {
            return Err(Error::Invalid("duplicate physical WBI section address"));
        }
    }
    for s in &right.sections {
        if b.insert(s.physical_address, s).is_some() {
            return Err(Error::Invalid("duplicate physical WBI section address"));
        }
    }
    let mut changes = Vec::new();
    let addresses: BTreeSet<_> = a.keys().chain(b.keys()).copied().collect();
    for address in addresses {
        let old = a.get(&address).copied();
        let new = b.get(&address).copied();
        let kind = match (old, new) {
            (Some(x), Some(y))
                if x.expanded_size == y.expanded_size
                    && x.virtual_address == y.virtual_address
                    && digest_section(before, x)? == digest_section(after, y)? =>
            {
                continue;
            }
            (Some(_), Some(_)) => ChangeKind::Modified,
            (Some(_), None) => ChangeKind::Removed,
            (None, Some(_)) => ChangeKind::Added,
            (None, None) => unreachable!(),
        };
        changes.push(Change {
            physical_address: address,
            kind,
            before: old.copied(),
            after: new.copied(),
        });
    }
    changes.sort_by_key(|c| c.physical_address);
    Ok(changes)
}

/// Classification for a section-level WBI diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    /// Section appeared in the newer image.
    Added,
    /// Section disappeared from the newer image.
    Removed,
    /// Same address but the bytes, size or virtual mapping changed.
    Modified,
}

/// One address that differs between two WBI captures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change {
    /// Start physical address.
    pub physical_address: u32,
    /// Difference classification.
    pub kind: ChangeKind,
    /// Original section, when present.
    pub before: Option<Section>,
    /// New section, when present.
    pub after: Option<Section>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(raw: &[u8], address: u32) -> Vec<u8> {
        assert!(!raw.is_empty());
        let encoded = encode_literal_section(raw).unwrap();
        let stored_size = sector_round(encoded.len(), 512).unwrap();
        let table_start = 512 + stored_size;
        let mut out = vec![0; 512];
        out[0..4].copy_from_slice(b"WBI1");
        for (off, value) in [
            (4, 1),
            (8, 9),
            (12, 0x8004_96e0),
            (16, VERSION),
            (20, 512),
            (24, stored_size as u32),
            (40, raw.len() as u32),
        ] {
            out[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&encoded);
        out.resize(table_start, 0);
        let mut table = [0u8; 32];
        for (off, value) in [
            (0, address),
            (4, stored_size as u32),
            (16, raw.len() as u32),
            (20, address + 0x4000_0000),
        ] {
            table[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
        out.extend_from_slice(&table);
        out.resize(sector_round(out.len(), 512).unwrap(), 0);
        out
    }

    #[test]
    fn parses_and_decodes_raw_blocks() {
        let bytes = fixture(b"hello", 0x8100_0000);
        let image = parse(&bytes).unwrap();
        assert_eq!(image.header.sections, 1);
        assert_eq!(image.sections[0].physical_address, 0x8100_0000);
        assert_eq!(decode_section(&bytes, &image.sections[0]).unwrap(), b"hello");
    }

    #[test]
    fn literal_encoder_round_trips_multiple_u16_blocks() {
        let raw = vec![0x5a; usize::from(u16::MAX) + 17];
        let encoded = encode_literal_section(&raw).unwrap();
        assert_eq!(encoded[0], 0x0f);
        assert_eq!(u16::from_le_bytes([encoded[2], encoded[3]]), u16::MAX);
        assert_eq!(encoded[usize::from(u16::MAX) + 4], 0x0f);

        // Use a synthetic WBI fixture with the multi-block section size.
        let original = fixture(&raw, 0x8100_0000);
        let candidate = replace_section_contents(&original, 0, &raw).unwrap();
        let image = parse(&candidate).unwrap();
        assert_eq!(decode_section(&candidate, &image.sections[0]).unwrap(), raw);
        assert_eq!(image.sections[0].expanded_size, usize::from(u16::MAX) + 17);
    }

    #[test]
    fn flip_section_byte_rebuilds_a_parser_accepted_host_candidate() {
        let original = fixture(b"hello", 0x8100_0000);
        let before = parse(&original).unwrap();
        let patched = flip_section_byte(&original, 0, 1, 0x20).unwrap();
        let after = parse(&patched).unwrap();

        assert_eq!(after.header.sections, before.header.sections);
        assert_eq!(after.header.resume_vector, before.header.resume_vector);
        assert_eq!(after.header.version, before.header.version);
        assert_eq!(after.header.expanded_size, before.header.expanded_size);
        assert_eq!(after.sections[0].physical_address, before.sections[0].physical_address);
        assert_eq!(after.sections[0].virtual_address, before.sections[0].virtual_address);
        assert_eq!(after.sections[0].expanded_size, before.sections[0].expanded_size);
        assert_eq!(decode_section(&patched, &after.sections[0]).unwrap(), b"hEllo");
        assert_eq!(patched.len() % after.header.sector_size as usize, 0);
        assert_eq!(after.sections[0].compressed_size, 512);
    }

    #[test]
    fn replace_section_rejects_length_mask_and_index_errors() {
        let original = fixture(b"hello", 0x8100_0000);
        assert!(replace_section_contents(&original, 0, b"short!").is_err());
        assert!(flip_section_byte(&original, 0, 0, 0).is_err());
        assert!(flip_section_byte(&original, 0, 99, 1).is_err());
        assert!(flip_section_byte(&original, 1, 0, 1).is_err());
    }

    #[test]
    fn replace_section_recomputes_payload_checksum_only_when_enabled() {
        let mut original = fixture(b"abcdefgh", 0x8100_0000);
        original[8..12].copy_from_slice(&13u32.to_le_bytes()); // COMPRESS | CKSUM | LZ77
        let patched = flip_section_byte(&original, 0, 0, 1).unwrap();
        let image = parse(&patched).unwrap();
        let section = image.sections[0];
        let table = image.data_offset + image.header.compressed_size as usize;
        let checksum = u32::from_le_bytes(patched[table + 8..table + 12].try_into().unwrap());
        assert_eq!(checksum, wbi_xor_checksum(b"\x60bcdefgh"));
        let metadata = u32::from_le_bytes(patched[table + 28..table + 32].try_into().unwrap());
        let words = [
            section.physical_address,
            section.compressed_size as u32,
            checksum,
            0,
            section.expanded_size as u32,
            section.virtual_address,
            section.padding,
        ];
        assert_eq!(metadata, words.iter().fold(0x0f0f_0f0f, |sum, word| sum ^ word));
    }

    #[test]
    fn rejects_truncated_and_corrupt_images() {
        let mut bytes = fixture(b"hello", 0x8100_0000);
        assert!(parse(&bytes[..12]).is_err());
        assert!(parse(&[0u8; 512]).is_err());
        bytes[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse(&bytes).is_err());
    }

    #[test]
    fn diff_tracks_changed_and_equal_sections() {
        let a = fixture(b"hello", 0x8100_0000);
        let b = fixture(b"world", 0x8100_0000);
        assert!(diff(&a, &a).unwrap().is_empty());
        assert_eq!(diff(&a, &b).unwrap()[0].kind, ChangeKind::Modified);
        let c = fixture(b"world", 0x8200_0000);
        assert_eq!(diff(&a, &c).unwrap().len(), 2);
    }

    #[test]
    fn decodes_backrefs_and_terminates_on_zero_distance() {
        let mut bytes = fixture(b"AAAA", 0x8100_0000);
        // A raw test fixture has 8 bytes of compressed data. Replace them
        // with a 7-byte LZ packet and a harmless trailing padding byte.
        bytes[512..520].copy_from_slice(&[0xf0, 0x06, b'A', 0, 1, 0, 0, 0]);
        assert_eq!(decode_section(&bytes, &parse(&bytes).unwrap().sections[0]).unwrap(), b"AAAA");
    }

    #[test]
    fn rejects_invalid_backref() {
        let mut bytes = fixture(b"x", 0x8100_0000);
        bytes[512] = 0xf0;
        bytes[513] = 1;
        bytes[514] = 0x10;
        bytes[515] = 0x02;
        assert!(decode_section(&bytes, &parse(&bytes).unwrap().sections[0]).is_err());
    }
}
