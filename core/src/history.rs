//! In-memory LRU clipboard history with BLAKE3 deduplication.
//!
//! Bounded by **both** entry count and total bytes, evicting on whichever limit
//! binds first. No SQLite dependency — this is designed to be lightweight per
//! INV-01 (target ~15MB idle RAM, hard ceiling 20MB).
//!
//! ## Why bytes and not just entries
//!
//! The cap used to be 100 *entries* of unbounded size, all resident, each
//! holding a full `Vec<u8>`. A hundred copied screenshots is hundreds of
//! megabytes against a 20 MB ceiling. The module doc cited INV-01 as the reason
//! it avoids SQLite, which was the wrong lever: the payloads are the cost, not
//! the index.
//!
//! ## Why the index is keyed, not positional
//!
//! The hash index used to map hash → *position in the deque*, so every
//! structural change invalidated it and `rebuild_index()` cleared the map and
//! re-inserted every entry — cloning each hash string — on every push, every
//! dedup hit, and every removal. The documented O(1) lookup sat behind an O(n)
//! write with n string allocations.
//!
//! Entries now live in a slab under stable `EntryKey`s and the deque holds keys,
//! so reordering never touches the index.

use crate::protocol::{ClipboardItem, ContentType};
use std::collections::{HashMap, VecDeque};

/// Default ceiling on the total bytes held in history (8 MiB).
///
/// Sized against INV-01's 20 MB hard ceiling with room for the rest of the
/// daemon. A single item larger than this can never be stored.
pub const DEFAULT_MAX_BYTES: usize = 8 * 1024 * 1024;

/// A stable handle to a stored entry. Never reused within a store's lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct EntryKey(u64);

/// In-memory LRU clipboard history store.
///
/// Maintains a bounded ordering of [`ClipboardItem`] entries, using BLAKE3
/// content hashes for genuinely O(1) deduplication lookups.
pub struct ClipboardHistory {
    /// Stored entries by stable key.
    entries: HashMap<EntryKey, ClipboardItem>,
    /// Ordering, most recent at the front. Holds keys, not items.
    order: VecDeque<EntryKey>,
    /// content_hash -> key. Unaffected by reordering.
    hash_index: HashMap<String, EntryKey>,
    /// Maximum number of items to keep.
    capacity: usize,
    /// Maximum total payload bytes to keep.
    max_bytes: usize,
    /// Payload bytes currently held.
    current_bytes: usize,
    /// Source of the next stable key.
    next_key: u64,
}

impl ClipboardHistory {
    /// Create a new ClipboardHistory with the given entry capacity and the
    /// default byte budget.
    pub fn new(capacity: usize) -> Self {
        Self::with_limits(capacity, DEFAULT_MAX_BYTES)
    }

    /// Create a ClipboardHistory with explicit entry and byte limits.
    pub fn with_limits(capacity: usize, max_bytes: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            hash_index: HashMap::with_capacity(capacity),
            capacity,
            max_bytes,
            current_bytes: 0,
            next_key: 0,
        }
    }

    /// Create a ClipboardHistory with the default capacity
    /// ([`crate::MAX_HISTORY_ENTRIES`]) and byte budget.
    pub fn with_default_capacity() -> Self {
        Self::new(crate::MAX_HISTORY_ENTRIES)
    }

    /// Push a new clipboard item. Returns `true` if the item was added,
    /// `false` if it was a duplicate or too large to store.
    ///
    /// If the item already exists, it is moved to the front and its timestamp
    /// and source peer are refreshed from the incoming copy. If the history is
    /// over either limit, the oldest items are evicted until it is not.
    pub fn push(&mut self, item: ClipboardItem) -> bool {
        if let Some(&key) = self.hash_index.get(&item.content_hash) {
            self.touch(key, item);
            return false;
        }

        // An item bigger than the whole budget can never be stored; evicting
        // everything else would not make room for it.
        let size = item.data.len();
        if size > self.max_bytes {
            log::warn!(
                "Refusing a {} byte clipboard item — the history budget is {} bytes",
                size,
                self.max_bytes
            );
            return false;
        }

        let key = self.allocate_key();
        self.hash_index.insert(item.content_hash.clone(), key);
        self.current_bytes += size;
        self.entries.insert(key, item);
        self.order.push_front(key);

        self.evict_until_within_limits();
        true
    }

    /// Move an existing entry to the front and refresh its metadata.
    ///
    /// The dedup branch used to return before touching `timestamp` or
    /// `source_peer`, so something copied one second ago displayed as "3h ago":
    /// the UI orders by position but renders the stored time.
    fn touch(&mut self, key: EntryKey, incoming: ClipboardItem) {
        if let Some(existing) = self.entries.get_mut(&key) {
            existing.timestamp = incoming.timestamp;
            existing.source_peer = incoming.source_peer;
        }
        self.move_to_front(key);
    }

    fn move_to_front(&mut self, key: EntryKey) {
        if self.order.front() == Some(&key) {
            return;
        }
        if let Some(pos) = self.order.iter().position(|&k| k == key) {
            self.order.remove(pos);
        }
        self.order.push_front(key);
    }

    /// Drop the oldest entries until both limits are satisfied.
    fn evict_until_within_limits(&mut self) {
        while self.order.len() > self.capacity
            || (self.current_bytes > self.max_bytes && self.order.len() > 1)
        {
            let Some(oldest) = self.order.pop_back() else {
                break;
            };
            self.forget(oldest);
        }
    }

    /// Remove an entry from every structure, keeping the byte total honest.
    fn forget(&mut self, key: EntryKey) -> Option<ClipboardItem> {
        let item = self.entries.remove(&key)?;
        self.hash_index.remove(&item.content_hash);
        self.current_bytes = self.current_bytes.saturating_sub(item.data.len());
        Some(item)
    }

    fn allocate_key(&mut self) -> EntryKey {
        let key = EntryKey(self.next_key);
        self.next_key += 1;
        key
    }

    /// Get the most recent clipboard item, if any.
    pub fn latest(&self) -> Option<&ClipboardItem> {
        self.order.front().and_then(|key| self.entries.get(key))
    }

    /// Get all items in order (most recent first).
    pub fn items(&self) -> impl Iterator<Item = &ClipboardItem> {
        self.order
            .iter()
            .filter_map(move |key| self.entries.get(key))
    }

    /// Get an item by its BLAKE3 content hash. O(1), genuinely.
    pub fn get_by_hash(&self, hash: &str) -> Option<&ClipboardItem> {
        self.hash_index
            .get(hash)
            .and_then(|key| self.entries.get(key))
    }

    /// Remove an item by its BLAKE3 content hash. Returns the removed item if found.
    pub fn remove_by_hash(&mut self, hash: &str) -> Option<ClipboardItem> {
        let key = self.hash_index.get(hash).copied()?;
        if let Some(pos) = self.order.iter().position(|&k| k == key) {
            self.order.remove(pos);
        }
        self.forget(key)
    }

    /// Return the number of items currently in history.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Return whether the history is empty.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Return the maximum entry capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Return the byte budget.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Return the payload bytes currently held.
    pub fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    /// Clear all items from history.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.hash_index.clear();
        self.current_bytes = 0;
    }

    /// Search items by text content (case-insensitive substring match).
    /// Only searches PlainText and RichText items.
    pub fn search(&self, query: &str) -> Vec<&ClipboardItem> {
        let query_lower = query.to_lowercase();
        self.items()
            .filter(|item| {
                matches!(
                    item.content_type,
                    ContentType::PlainText | ContentType::RichText
                ) && String::from_utf8_lossy(&item.data)
                    .to_lowercase()
                    .contains(&query_lower)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::PeerId;

    fn make_text_item(text: &str) -> ClipboardItem {
        ClipboardItem::from_text(text, PeerId::new("test-peer"))
    }

    fn make_sized_item(tag: &str, bytes: usize) -> ClipboardItem {
        let mut data = tag.as_bytes().to_vec();
        data.resize(bytes.max(tag.len()), b'.');
        ClipboardItem::new(ContentType::Image, data, PeerId::new("test-peer"))
    }

    #[test]
    fn test_push_and_latest() {
        let mut history = ClipboardHistory::new(10);
        assert!(history.is_empty());

        let item = make_text_item("hello");
        assert!(history.push(item));
        assert_eq!(history.len(), 1);

        let latest = history.latest().unwrap();
        assert_eq!(latest.data, b"hello");
    }

    #[test]
    fn test_deduplication() {
        let mut history = ClipboardHistory::new(10);

        let item1 = make_text_item("duplicate");
        let item2 = make_text_item("duplicate");

        assert!(history.push(item1));
        assert!(!history.push(item2)); // duplicate
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_lru_ordering() {
        let mut history = ClipboardHistory::new(10);

        history.push(make_text_item("first"));
        history.push(make_text_item("second"));
        history.push(make_text_item("third"));

        let items: Vec<_> = history.items().collect();
        assert_eq!(items[0].data, b"third");
        assert_eq!(items[1].data, b"second");
        assert_eq!(items[2].data, b"first");
    }

    #[test]
    fn test_capacity_eviction() {
        let mut history = ClipboardHistory::new(3);

        history.push(make_text_item("a"));
        history.push(make_text_item("b"));
        history.push(make_text_item("c"));
        assert_eq!(history.len(), 3);

        // This should evict "a" (oldest)
        history.push(make_text_item("d"));
        assert_eq!(history.len(), 3);

        let items: Vec<_> = history.items().collect();
        assert_eq!(items[0].data, b"d");
        assert_eq!(items[1].data, b"c");
        assert_eq!(items[2].data, b"b");
    }

    #[test]
    fn test_duplicate_moves_to_front() {
        let mut history = ClipboardHistory::new(10);

        history.push(make_text_item("first"));
        history.push(make_text_item("second"));
        history.push(make_text_item("third"));

        // Re-push "first" — should move it to front
        history.push(make_text_item("first"));
        assert_eq!(history.len(), 3);

        let latest = history.latest().unwrap();
        assert_eq!(latest.data, b"first");
    }

    /// The F-09 regression: re-copying existing content used to keep the
    /// original timestamp, so something copied a second ago read "3h ago".
    #[test]
    fn test_recopy_refreshes_timestamp_and_source() {
        let mut history = ClipboardHistory::new(10);

        let mut old = ClipboardItem::from_text("shared", PeerId::new("laptop"));
        old.timestamp = 1_000;
        history.push(old);

        let mut fresh = ClipboardItem::from_text("shared", PeerId::new("phone"));
        fresh.timestamp = 9_999;
        assert!(!history.push(fresh), "still reports a duplicate");

        let stored = history.latest().unwrap();
        assert_eq!(stored.timestamp, 9_999);
        assert_eq!(stored.source_peer, PeerId::new("phone"));
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_get_by_hash() {
        let mut history = ClipboardHistory::new(10);

        let item = make_text_item("findme");
        let hash = item.content_hash.clone();
        history.push(item);

        let found = history.get_by_hash(&hash).unwrap();
        assert_eq!(found.data, b"findme");

        assert!(history.get_by_hash("nonexistent").is_none());
    }

    /// The index must survive reordering. When it was positional, moving an
    /// entry to the front silently pointed every other hash at the wrong item.
    #[test]
    fn test_index_survives_reordering() {
        let mut history = ClipboardHistory::new(10);
        let hashes: Vec<String> = ["a", "b", "c", "d"]
            .iter()
            .map(|t| {
                let item = make_text_item(t);
                let hash = item.content_hash.clone();
                history.push(item);
                hash
            })
            .collect();

        // Reorder repeatedly.
        history.push(make_text_item("a"));
        history.push(make_text_item("c"));
        history.push(make_text_item("a"));

        for (text, hash) in ["a", "b", "c", "d"].iter().zip(&hashes) {
            let found = history
                .get_by_hash(hash)
                .unwrap_or_else(|| panic!("{} lost from the index", text));
            assert_eq!(found.data, text.as_bytes());
        }
    }

    #[test]
    fn test_remove_by_hash() {
        let mut history = ClipboardHistory::new(10);

        let item = make_text_item("removeme");
        let hash = item.content_hash.clone();
        history.push(item);
        history.push(make_text_item("keeper"));

        let removed = history.remove_by_hash(&hash).unwrap();
        assert_eq!(removed.data, b"removeme");
        assert_eq!(history.len(), 1);
        assert!(history.get_by_hash(&hash).is_none());
        assert!(history.remove_by_hash(&hash).is_none());
    }

    #[test]
    fn test_clear() {
        let mut history = ClipboardHistory::new(10);
        history.push(make_text_item("a"));
        history.push(make_text_item("b"));
        assert_eq!(history.len(), 2);

        history.clear();
        assert!(history.is_empty());
        assert_eq!(history.len(), 0);
        assert_eq!(history.current_bytes(), 0);
    }

    #[test]
    fn test_search() {
        let mut history = ClipboardHistory::new(10);

        history.push(make_text_item("Hello World"));
        history.push(make_text_item("foo bar baz"));
        history.push(make_text_item("HELLO there"));

        let results = history.search("hello");
        assert_eq!(results.len(), 2); // case-insensitive

        let results = history.search("bar");
        assert_eq!(results.len(), 1);

        let results = history.search("nonexistent");
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_search_skips_non_text() {
        let mut history = ClipboardHistory::new(10);

        history.push(ClipboardItem::new(
            ContentType::Image,
            b"fake image data containing hello".to_vec(),
            PeerId::new("p1"),
        ));
        history.push(make_text_item("hello world"));

        let results = history.search("hello");
        assert_eq!(results.len(), 1); // Only the text item
    }

    #[test]
    fn test_with_default_capacity() {
        let history = ClipboardHistory::with_default_capacity();
        assert_eq!(history.capacity(), crate::MAX_HISTORY_ENTRIES);
        assert_eq!(history.max_bytes(), DEFAULT_MAX_BYTES);
    }

    #[test]
    fn test_many_items_stress() {
        let mut history = ClipboardHistory::new(50);
        for i in 0..200 {
            history.push(make_text_item(&format!("item-{}", i)));
        }
        assert_eq!(history.len(), 50);
        // Most recent should be item-199
        assert_eq!(history.latest().unwrap().data, b"item-199");
    }

    // ── Byte budgeting (F-21) ────────────────────────────────────────────────

    #[test]
    fn test_byte_budget_evicts_before_the_entry_cap() {
        // 100 entries allowed, but only 1000 bytes. Ten 300-byte screenshots
        // must not become 3000 resident bytes.
        let mut history = ClipboardHistory::with_limits(100, 1000);
        for i in 0..10 {
            history.push(make_sized_item(&format!("img-{}", i), 300));
        }

        assert!(
            history.len() < 10,
            "entry cap alone would have kept all ten"
        );
        assert!(
            history.current_bytes() <= 1000,
            "held {} bytes against a 1000 byte budget",
            history.current_bytes()
        );
        // Newest survives.
        assert!(history.latest().unwrap().data.starts_with(b"img-9"));
    }

    #[test]
    fn test_byte_total_tracks_pushes_and_removals() {
        let mut history = ClipboardHistory::with_limits(10, 100_000);
        assert_eq!(history.current_bytes(), 0);

        let a = make_sized_item("a", 500);
        let hash_a = a.content_hash.clone();
        history.push(a);
        assert_eq!(history.current_bytes(), 500);

        history.push(make_sized_item("b", 300));
        assert_eq!(history.current_bytes(), 800);

        history.remove_by_hash(&hash_a);
        assert_eq!(history.current_bytes(), 300);

        history.clear();
        assert_eq!(history.current_bytes(), 0);
    }

    #[test]
    fn test_duplicate_does_not_double_count_bytes() {
        let mut history = ClipboardHistory::with_limits(10, 100_000);
        history.push(make_sized_item("same", 400));
        let before = history.current_bytes();

        history.push(make_sized_item("same", 400));
        assert_eq!(history.current_bytes(), before);
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_item_larger_than_the_whole_budget_is_refused() {
        let mut history = ClipboardHistory::with_limits(10, 1000);
        history.push(make_text_item("keep me"));

        assert!(!history.push(make_sized_item("huge", 5000)));
        // And it did not evict the existing entry on the way out.
        assert_eq!(history.len(), 1);
        assert_eq!(history.latest().unwrap().data, b"keep me");
    }

    #[test]
    fn test_a_single_oversized_entry_is_never_evicted_to_nothing() {
        // An item that fits the budget exactly must be storable on its own.
        let mut history = ClipboardHistory::with_limits(10, 1000);
        assert!(history.push(make_sized_item("exact", 1000)));
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_eviction_keeps_every_structure_consistent() {
        let mut history = ClipboardHistory::with_limits(3, 100_000);
        let mut hashes = Vec::new();
        for i in 0..6 {
            let item = make_text_item(&format!("e{}", i));
            hashes.push(item.content_hash.clone());
            history.push(item);
        }

        assert_eq!(history.len(), 3);
        assert_eq!(history.items().count(), 3);

        // The evicted hashes are gone from the index, the survivors are present.
        for hash in &hashes[..3] {
            assert!(history.get_by_hash(hash).is_none());
        }
        for hash in &hashes[3..] {
            assert!(history.get_by_hash(hash).is_some());
        }
    }
}
