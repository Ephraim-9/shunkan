//! In-memory LRU clipboard history with BLAKE3 deduplication.
//!
//! Provides a fixed-capacity ring buffer of clipboard items that automatically
//! deduplicates entries by their BLAKE3 content hash. No SQLite dependency —
//! this is designed to be lightweight per INV-01 (target ~15MB idle RAM).

use crate::protocol::{ClipboardItem, ContentType, PeerId};
use std::collections::{HashMap, VecDeque};

/// In-memory LRU clipboard history store.
///
/// Maintains a bounded deque of [`ClipboardItem`] entries, using BLAKE3
/// content hashes for O(1) deduplication lookups.
pub struct ClipboardHistory {
    /// Ordered list of clipboard items (most recent at front).
    items: VecDeque<ClipboardItem>,
    /// Map from content_hash -> index in `items` for O(1) dedup checks.
    hash_index: HashMap<String, usize>,
    /// Maximum number of items to keep.
    capacity: usize,
}

impl ClipboardHistory {
    /// Create a new ClipboardHistory with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            items: VecDeque::with_capacity(capacity),
            hash_index: HashMap::with_capacity(capacity),
            capacity,
        }
    }

    /// Create a ClipboardHistory with the default capacity ([`crate::MAX_HISTORY_ENTRIES`]).
    pub fn with_default_capacity() -> Self {
        Self::new(crate::MAX_HISTORY_ENTRIES)
    }

    /// Push a new clipboard item. Returns `true` if the item was added,
    /// `false` if it was a duplicate (already exists in history).
    ///
    /// If the item already exists, it is moved to the front (most recent).
    /// If the history is at capacity, the oldest item is evicted.
    pub fn push(&mut self, item: ClipboardItem) -> bool {
        // Check for duplicate by content hash
        if let Some(&existing_idx) = self.hash_index.get(&item.content_hash) {
            // Move existing item to front (most recently used)
            if existing_idx < self.items.len() {
                if let Some(existing) = self.items.remove(existing_idx) {
                    self.items.push_front(existing);
                    self.rebuild_index();
                }
            }
            return false;
        }

        // Evict oldest if at capacity
        if self.items.len() >= self.capacity {
            if let Some(evicted) = self.items.pop_back() {
                self.hash_index.remove(&evicted.content_hash);
            }
        }

        // Add new item at front
        let hash = item.content_hash.clone();
        self.items.push_front(item);
        self.rebuild_index();
        // Verify the item is in the index (it should be at position 0)
        debug_assert!(self.hash_index.contains_key(&hash));

        true
    }

    /// Get the most recent clipboard item, if any.
    pub fn latest(&self) -> Option<&ClipboardItem> {
        self.items.front()
    }

    /// Get all items in order (most recent first).
    pub fn items(&self) -> impl Iterator<Item = &ClipboardItem> {
        self.items.iter()
    }

    /// Get an item by its BLAKE3 content hash.
    pub fn get_by_hash(&self, hash: &str) -> Option<&ClipboardItem> {
        self.hash_index
            .get(hash)
            .and_then(|&idx| self.items.get(idx))
    }

    /// Remove an item by its BLAKE3 content hash. Returns the removed item if found.
    pub fn remove_by_hash(&mut self, hash: &str) -> Option<ClipboardItem> {
        if let Some(&idx) = self.hash_index.get(hash) {
            let item = self.items.remove(idx);
            self.rebuild_index();
            item
        } else {
            None
        }
    }

    /// Return the number of items currently in history.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Return whether the history is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Return the maximum capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Clear all items from history.
    pub fn clear(&mut self) {
        self.items.clear();
        self.hash_index.clear();
    }

    /// Search items by text content (case-insensitive substring match).
    /// Only searches PlainText and RichText items.
    pub fn search(&self, query: &str) -> Vec<&ClipboardItem> {
        let query_lower = query.to_lowercase();
        self.items
            .iter()
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

    /// Rebuild the hash-to-index mapping after structural changes.
    fn rebuild_index(&mut self) {
        self.hash_index.clear();
        for (idx, item) in self.items.iter().enumerate() {
            self.hash_index.insert(item.content_hash.clone(), idx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_text_item(text: &str) -> ClipboardItem {
        ClipboardItem::from_text(text, PeerId::new("test-peer"))
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
}
