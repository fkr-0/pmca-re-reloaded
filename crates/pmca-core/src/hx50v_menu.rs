//! Read-only, evidence-bounded view of the Sony HX50V native menu ABI.
//!
//! This module deliberately does not bind Sony function addresses or dereference
//! camera pointers. It parses captured item bytes and defines a narrow runtime
//! adapter contract for the static call signatures that have been verified.
//! Unknown UXC fields, tree ownership, and insertion remain unsupported.

use thiserror::Error;

/// Verified layout constants for Sony FW1.00 `libObj.so`.
pub mod abi {
    /// Minimum byte length needed to read the verified item fields.
    pub const ITEM_PREFIX_LEN: usize = 0x1e;
    /// Sony's child item array advances by this many bytes per item.
    pub const ITEM_STRIDE: usize = 0x28;
    /// Item's child-array pointer (little-endian 32-bit address).
    pub const CHILD_ARRAY_PTR_OFFSET: usize = 0x00;
    /// Number of child entries (unsigned byte).
    pub const CHILD_COUNT_OFFSET: usize = 0x04;
    /// Item ID (little-endian 32-bit value).
    pub const ITEM_ID_OFFSET: usize = 0x08;
    /// Execution type (unsigned byte).
    pub const EXEC_TYPE_OFFSET: usize = 0x1d;

    /// Thumb symbol addresses from the SHA-pinned original `libObj.so`.
    pub mod thumb {
        /// CmnViewMenuData::getRootItem.
        pub const GET_ROOT_ITEM: u32 = 0x0055_6255;
        /// CmnViewMenuData::getId.
        pub const GET_ID: u32 = 0x0063_6bad;
        /// CmnViewMenuData::getExecType.
        pub const GET_EXEC_TYPE: u32 = 0x004b_2c39;
        /// CmnViewMenuData::getSubItem.
        pub const GET_SUB_ITEM: u32 = 0x004d_03e5;
        /// CmnViewMenuData::getCountAll.
        pub const GET_COUNT_ALL: u32 = 0x004b_5e55;
        /// CmnViewMenuData::getCountEnable.
        pub const GET_COUNT_ENABLE: u32 = 0x0055_6779;
        /// CmnViewMenuData::isItemDisplayed.
        pub const IS_ITEM_DISPLAYED: u32 = 0x004b_217b;
        /// CmnViewMenuData::isItemGreyout.
        pub const IS_ITEM_GREYOUT: u32 = 0x004d_1941;
        /// CmnViewMenuData::setGreyOut.
        pub const SET_GREY_OUT: u32 = 0x004b_2c45;
        /// CmnViewMenuData::setItemInh.
        pub const SET_ITEM_INH: u32 = 0x004b_5e6d;
        /// CmnViewMenuData::showItem.
        pub const SHOW_ITEM: u32 = 0x004b_7de9;
        /// Three-argument initMenuData overload.
        pub const INIT_MENU_DATA: u32 = 0x0055_63ff;
    }
}

/// Errors from parsing a captured Sony menu item array.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MenuError {
    /// The captured bytes do not include all fields that this API reads.
    #[error("menu item prefix is truncated: need {needed} bytes, got {actual}")]
    TruncatedItem {
        /// Required prefix length.
        needed: usize,
        /// Available captured byte length.
        actual: usize,
    },
    /// The captured child array is shorter than the verified count and stride.
    #[error("menu child array is truncated: need {needed} bytes, got {actual}")]
    TruncatedArray {
        /// Required byte length from count multiplied by the Sony stride.
        needed: usize,
        /// Available captured byte length.
        actual: usize,
    },
    /// The requested child index is outside the verified item count.
    #[error("menu child index {index} is outside count {count}")]
    IndexOutOfRange {
        /// Requested child index.
        index: usize,
        /// Verified child count.
        count: usize,
    },
    /// A complete child-array snapshot does not exactly match its count.
    #[error("menu child array length mismatch: expected {expected} bytes, got {actual}")]
    ArrayLengthMismatch {
        /// Exact expected length (`count * 0x28`).
        expected: usize,
        /// Actual byte length.
        actual: usize,
    },
    /// Appending would overflow the one-byte child count.
    #[error("menu child count would exceed 255")]
    CountOverflow,
}

/// Read-only view of a captured 0x28-byte Sony menu item record.
///
/// Only four fields are currently exposed: child-array pointer, child count,
/// item ID, and execution type. The remaining bytes are intentionally opaque.
#[derive(Clone, Copy, Debug)]
pub struct MenuItemView<'a> {
    bytes: &'a [u8],
}

impl<'a> MenuItemView<'a> {
    /// Construct a view after checking that all currently verified fields fit.
    pub fn new(bytes: &'a [u8]) -> Result<Self, MenuError> {
        if bytes.len() < abi::ITEM_PREFIX_LEN {
            return Err(MenuError::TruncatedItem {
                needed: abi::ITEM_PREFIX_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self { bytes })
    }

    /// Read the 32-bit pointer value stored at item offset 0.
    ///
    /// This is an address from a captured target address space, not a host
    /// pointer. The API never dereferences it.
    pub fn child_array_address(self) -> u32 {
        read_u32(self.bytes, abi::CHILD_ARRAY_PTR_OFFSET)
    }

    /// Read the verified unsigned child count at item offset 4.
    pub fn child_count(self) -> u8 {
        self.bytes[abi::CHILD_COUNT_OFFSET]
    }

    /// Read the signed 32-bit item ID at offset 8.
    pub fn id(self) -> i32 {
        read_u32(self.bytes, abi::ITEM_ID_OFFSET) as i32
    }

    /// Read the execution type byte at offset 0x1d.
    ///
    /// This is an enum-like selector only; it does not itself identify or
    /// execute a callback.
    pub fn exec_type(self) -> u8 {
        self.bytes[abi::EXEC_TYPE_OFFSET]
    }

    /// Return the exact verified prefix bytes; all other fields stay opaque.
    pub fn verified_prefix(self) -> &'a [u8] {
        &self.bytes[..abi::ITEM_PREFIX_LEN]
    }
}

/// Read-only view over the contiguous child records of one captured menu node.
#[derive(Clone, Copy, Debug)]
pub struct MenuItemArrayView<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> MenuItemArrayView<'a> {
    /// Validate the byte extent using Sony's observed 0x28-byte item stride.
    pub fn new(bytes: &'a [u8], count: usize) -> Result<Self, MenuError> {
        let needed = count
            .checked_mul(abi::ITEM_STRIDE)
            .ok_or(MenuError::TruncatedArray { needed: usize::MAX, actual: bytes.len() })?;
        if bytes.len() < needed {
            return Err(MenuError::TruncatedArray { needed, actual: bytes.len() });
        }
        Ok(Self { bytes, count })
    }

    /// Number of records represented by this bounded snapshot.
    pub fn len(self) -> usize {
        self.count
    }

    /// Whether the bounded snapshot contains no records.
    pub fn is_empty(self) -> bool {
        self.count == 0
    }

    /// Return a checked item view for the requested child index.
    pub fn get(self, index: usize) -> Result<MenuItemView<'a>, MenuError> {
        if index >= self.count {
            return Err(MenuError::IndexOutOfRange { index, count: self.count });
        }
        let start = index * abi::ITEM_STRIDE;
        MenuItemView::new(&self.bytes[start..start + abi::ITEM_STRIDE])
    }

    /// Iterate through the verified records without interpreting opaque fields.
    pub fn iter(self) -> impl Iterator<Item = MenuItemView<'a>> + 'a {
        self.bytes
            .chunks_exact(abi::ITEM_STRIDE)
            .take(self.count)
            .map(|record| MenuItemView { bytes: &record[..abi::ITEM_PREFIX_LEN] })
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

/// Lossless 40-byte representation of one observed Sony menu item record.
///
/// The mapped fields are at +0x00, +0x04, +0x08, +0x0c and +0x1d. The
/// remaining bytes are opaque and preserved byte-for-byte. This host model
/// does not prove that a newly constructed record is accepted by Sony.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MenuItemRecord {
    /// Target-process address of the contiguous child array; never dereferenced here.
    pub child_array_address: u32,
    /// Child count at +0x04.
    pub child_count: u8,
    /// Original padding bytes at +0x05..+0x08.
    pub padding: [u8; 3],
    /// Numeric item ID at +0x08.
    pub id: i32,
    /// InconstPart pointer written by the three-argument initMenuData overload.
    pub inconst_part_address: u32,
    /// Opaque original bytes at +0x10..+0x1d.
    pub unknown_10: [u8; 0x0d],
    /// Execution-type selector at +0x1d.
    pub exec_type: u8,
    /// Opaque original bytes at +0x1e..+0x28.
    pub unknown_1e: [u8; 0x0a],
}

impl MenuItemRecord {
    /// Parse one exact 0x28-byte Sony menu item, retaining every opaque byte.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MenuError> {
        if bytes.len() != abi::ITEM_STRIDE {
            return Err(MenuError::ArrayLengthMismatch {
                expected: abi::ITEM_STRIDE,
                actual: bytes.len(),
            });
        }
        Ok(Self {
            child_array_address: read_u32(bytes, 0x00),
            child_count: bytes[0x04],
            padding: bytes[0x05..0x08].try_into().expect("fixed 3-byte range"),
            id: read_u32(bytes, 0x08) as i32,
            inconst_part_address: read_u32(bytes, 0x0c),
            unknown_10: bytes[0x10..0x1d].try_into().expect("fixed 13-byte range"),
            exec_type: bytes[0x1d],
            unknown_1e: bytes[0x1e..0x28].try_into().expect("fixed 10-byte range"),
        })
    }

    /// Serialize to the exact 0x28-byte original layout without losing opaque bytes.
    pub fn to_bytes(self) -> [u8; abi::ITEM_STRIDE] {
        let mut out = [0u8; abi::ITEM_STRIDE];
        out[0x00..0x04].copy_from_slice(&self.child_array_address.to_le_bytes());
        out[0x04] = self.child_count;
        out[0x05..0x08].copy_from_slice(&self.padding);
        out[0x08..0x0c].copy_from_slice(&self.id.to_le_bytes());
        out[0x0c..0x10].copy_from_slice(&self.inconst_part_address.to_le_bytes());
        out[0x10..0x1d].copy_from_slice(&self.unknown_10);
        out[0x1d] = self.exec_type;
        out[0x1e..0x28].copy_from_slice(&self.unknown_1e);
        out
    }

    /// Create a synthetic childless record with opaque/padding bytes zeroed.
    ///
    /// Zeroing is only a host-fixture convenience. It is not evidence that
    /// these unknown bytes may safely be zero in a live Sony menu object.
    pub fn synthetic_leaf(id: i32, exec_type: u8) -> Self {
        Self {
            child_array_address: 0,
            child_count: 0,
            padding: [0; 3],
            id,
            inconst_part_address: 0,
            unknown_10: [0; 0x0d],
            exec_type,
            unknown_1e: [0; 0x0a],
        }
    }
}

/// Exact, detached child-array bytes and the count they would require.
///
/// This is a host-side edit plan only. It does not allocate target memory,
/// update a parent's pointer/count atomically, register a callback, or install
/// a new menu item in the camera.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildArrayPlan {
    /// New contiguous child bytes, preserving all existing records exactly.
    pub bytes: Vec<u8>,
    /// New one-byte child count.
    pub count: u8,
}

/// Parse exactly `count` contiguous 0x28-byte child records.
pub fn parse_children_exact(bytes: &[u8], count: u8) -> Result<Vec<MenuItemRecord>, MenuError> {
    let expected = usize::from(count) * abi::ITEM_STRIDE;
    if bytes.len() != expected {
        return Err(MenuError::ArrayLengthMismatch { expected, actual: bytes.len() });
    }
    bytes.chunks_exact(abi::ITEM_STRIDE).map(MenuItemRecord::from_bytes).collect()
}

/// Serialize complete records with an exact, lossless 0x28-byte stride.
pub fn serialize_children(items: &[MenuItemRecord]) -> Vec<u8> {
    let mut out = Vec::with_capacity(items.len() * abi::ITEM_STRIDE);
    for item in items {
        out.extend_from_slice(&item.to_bytes());
    }
    out
}

/// Build a detached append plan for an existing child array.
///
/// No target pointer is changed and no Sony runtime callback is invoked. A
/// caller cannot treat this plan as a proven dynamic insertion operation.
pub fn extend_children(
    existing: &[u8],
    existing_count: u8,
    new_item: MenuItemRecord,
) -> Result<ChildArrayPlan, MenuError> {
    let expected = usize::from(existing_count) * abi::ITEM_STRIDE;
    if existing.len() != expected {
        return Err(MenuError::ArrayLengthMismatch { expected, actual: existing.len() });
    }
    let count = existing_count.checked_add(1).ok_or(MenuError::CountOverflow)?;
    let capacity = expected
        .checked_add(abi::ITEM_STRIDE)
        .ok_or(MenuError::ArrayLengthMismatch { expected: usize::MAX, actual: existing.len() })?;
    let mut bytes = Vec::with_capacity(capacity);
    bytes.extend_from_slice(existing);
    bytes.extend_from_slice(&new_item.to_bytes());
    Ok(ChildArrayPlan { bytes, count })
}

/// Runtime handle supplied by a future, separately qualified Sony adapter.
///
/// It is deliberately opaque: target addresses must never be confused with
/// Rust references or host pointers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MenuItemHandle(pub u32);

/// Narrow adapter contract for verified Sony menu operations.
///
/// This trait is an interface only. No implementation currently calls into
/// Sony firmware. A concrete runtime adapter must independently prove object
/// lifetime, address-space validity, calling convention, and lifecycle rules.
pub trait MenuDataBackend {
    /// Return the root item handle using the CmnViewMenuData root getter.
    fn root_item(&self) -> Result<MenuItemHandle, MenuBackendError>;

    /// Return the indexed child handle using the verified 0x28-byte stride.
    fn sub_item(
        &self,
        parent: MenuItemHandle,
        index: usize,
    ) -> Result<Option<MenuItemHandle>, MenuBackendError>;

    /// Return the total child count for a menu item.
    fn count_all(&self, item: MenuItemHandle) -> Result<usize, MenuBackendError>;

    /// Return the enabled child count using Sony's state helper.
    fn count_enabled(&self, item: MenuItemHandle) -> Result<usize, MenuBackendError>;

    /// Evaluate Sony's distinct item-validity predicate for an option index.
    fn is_item_valid(
        &self,
        item: MenuItemHandle,
        option_index: i32,
    ) -> Result<bool, MenuBackendError>;

    /// Return the stable item ID.
    fn item_id(&self, item: MenuItemHandle) -> Result<i32, MenuBackendError>;

    /// Return the raw Sony execution-type byte; caller must interpret it.
    fn exec_type(&self, item: MenuItemHandle) -> Result<u8, MenuBackendError>;

    /// Query Sony's displayed predicate (not equivalent to grey-out).
    fn is_displayed(&self, item: MenuItemHandle) -> Result<bool, MenuBackendError>;

    /// Query Sony's grey-out predicate.
    fn is_greyed_out(&self, item: MenuItemHandle) -> Result<bool, MenuBackendError>;

    /// Set the grey-out state through Sony's existing API.
    fn set_grey_out(
        &mut self,
        item: MenuItemHandle,
        greyed_out: bool,
    ) -> Result<(), MenuBackendError>;

    /// Set inherited state for a child index through Sony's existing API.
    fn set_item_inherited(
        &mut self,
        item: MenuItemHandle,
        child_index: usize,
        inherited: bool,
    ) -> Result<(), MenuBackendError>;

    /// Toggle visibility by numeric item ID through Sony's existing API.
    fn show_item(&mut self, item_id: i32, visible: bool) -> Result<(), MenuBackendError>;
}

/// Failure from a not-yet-qualified runtime adapter.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MenuBackendError {
    /// The backend has no live Sony binding; this is the default state.
    #[error("Sony menu runtime binding is not qualified")]
    NotQualified,
    /// The requested operation is not supported by the proven Sony ABI.
    #[error("operation is not supported by the proven Sony menu ABI: {0}")]
    Unsupported(&'static str),
    /// The Sony-side operation failed or returned an invalid result.
    #[error("Sony menu operation failed: {0}")]
    Operation(&'static str),
}

/// Capabilities justified by the current original-binary evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MenuCapabilities {
    /// Existing root and child records can be read through verified getters.
    pub read_existing_items: bool,
    /// Existing items can be greyed out.
    pub set_grey_out: bool,
    /// Existing items can have inherited state changed.
    pub set_inherited_state: bool,
    /// Existing items can be shown/hidden by numeric ID.
    pub show_existing_item: bool,
    /// Adding a new node to a live menu tree has not been proven.
    pub insert_new_item: bool,
}

impl MenuCapabilities {
    /// Return the capability snapshot established by the pinned static evidence.
    pub fn evidenced() -> Self {
        Self::EVIDENCED
    }

    /// Capabilities established by the currently pinned static evidence.
    pub const EVIDENCED: Self = Self {
        read_existing_items: true,
        set_grey_out: true,
        set_inherited_state: true,
        show_existing_item: true,
        insert_new_item: false,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: u32, count: u8, exec_type: u8, ptr: u32) -> [u8; abi::ITEM_STRIDE] {
        let mut bytes = [0u8; abi::ITEM_STRIDE];
        bytes[0..4].copy_from_slice(&ptr.to_le_bytes());
        bytes[4] = count;
        bytes[8..12].copy_from_slice(&id.to_le_bytes());
        bytes[abi::EXEC_TYPE_OFFSET] = exec_type;
        bytes
    }

    #[test]
    fn reads_only_verified_fields() {
        let bytes = record(0x1234_5678, 3, 0x2a, 0x8765_4321);
        let item = MenuItemView::new(&bytes).unwrap();
        assert_eq!(item.child_array_address(), 0x8765_4321);
        assert_eq!(item.child_count(), 3);
        assert_eq!(item.id(), 0x1234_5678);
        assert_eq!(item.exec_type(), 0x2a);
    }

    #[test]
    fn rejects_short_item_prefix() {
        assert_eq!(
            MenuItemView::new(&[0u8; 0x1d]).unwrap_err(),
            MenuError::TruncatedItem { needed: 0x1e, actual: 0x1d }
        );
    }

    #[test]
    fn array_uses_verified_0x28_stride() {
        let a = record(1, 0, 4, 0);
        let b = record(2, 1, 7, 0);
        let bytes = [a.as_slice(), b.as_slice()].concat();
        let view = MenuItemArrayView::new(&bytes, 2).unwrap();
        assert_eq!(view.get(0).unwrap().id(), 1);
        assert_eq!(view.get(1).unwrap().id(), 2);
        assert_eq!(view.iter().map(MenuItemView::id).collect::<Vec<_>>(), vec![1, 2]);
    }

    #[test]
    fn array_rejects_truncation_and_bad_index() {
        assert_eq!(
            MenuItemArrayView::new(&[0u8; 0x27], 1).unwrap_err(),
            MenuError::TruncatedArray { needed: 0x28, actual: 0x27 }
        );
        let view = MenuItemArrayView::new(&[0u8; 0x28], 1).unwrap();
        assert_eq!(view.get(1).unwrap_err(), MenuError::IndexOutOfRange { index: 1, count: 1 });
    }

    #[test]
    fn full_record_round_trip_preserves_every_opaque_byte() {
        let mut bytes = [0u8; abi::ITEM_STRIDE];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (index as u8).wrapping_mul(17).wrapping_add(3);
        }
        let item = MenuItemRecord::from_bytes(&bytes).unwrap();
        assert_eq!(item.to_bytes(), bytes);
        assert_eq!(MenuItemView::new(&bytes).unwrap().id(), item.id);
    }

    #[test]
    fn child_array_plan_preserves_existing_items_and_appends_exactly() {
        let first = MenuItemRecord::synthetic_leaf(10, 1);
        let second = MenuItemRecord::synthetic_leaf(20, 2);
        let third = MenuItemRecord::synthetic_leaf(30, 3);
        let original = serialize_children(&[first, second]);
        let plan = extend_children(&original, 2, third).unwrap();
        assert_eq!(plan.count, 3);
        assert_eq!(&plan.bytes[..original.len()], original.as_slice());
        assert_eq!(
            parse_children_exact(&plan.bytes, plan.count).unwrap(),
            vec![first, second, third]
        );
    }

    #[test]
    fn child_array_plan_rejects_mismatch_and_count_overflow() {
        let item = MenuItemRecord::synthetic_leaf(1, 0);
        assert_eq!(
            extend_children(&[], 1, item),
            Err(MenuError::ArrayLengthMismatch { expected: abi::ITEM_STRIDE, actual: 0 })
        );
        let full = vec![0; usize::from(u8::MAX) * abi::ITEM_STRIDE];
        assert_eq!(extend_children(&full, u8::MAX, item), Err(MenuError::CountOverflow));
    }

    #[test]
    fn capabilities_do_not_claim_insertion() {
        let capabilities = MenuCapabilities::evidenced();
        assert!(capabilities.read_existing_items);
        assert!(capabilities.show_existing_item);
        assert!(!capabilities.insert_new_item);
    }
}
