/**
 * Shunkan — Command Palette Frontend Logic
 *
 * Handles the glassmorphic clipboard history overlay:
 * - Keyboard navigation (↑/↓/Enter/Esc)
 * - Search/filter clipboard history
 * - Peer discovery display
 * - Tauri IPC bridge (when available)
 *
 * @module app
 */

// ─── State ───────────────────────────────────────────────────────────────────

const state = {
    history: [],
    filteredHistory: [],
    peers: [],
    selectedIndex: 0,
    searchQuery: '',
    lastError: null,
};

/** How long to wait after the last keystroke before re-filtering. */
const SEARCH_DEBOUNCE_MS = 80;

// ─── Tauri IPC Bridge ────────────────────────────────────────────────────────
//
// Tauri v2 exposes `window.__TAURI__.core.invoke`, and only when
// `withGlobalTauri` is enabled — which `tauri.conf.json` sets, because this
// frontend is deliberately buildless and has no bundler to import
// `@tauri-apps/api/core` through. The old bridge called
// `window.__TAURI__.invoke`, the v1 shape, so the global was always undefined
// and the UI silently ran on mock data forever. That is why it looked like it
// worked.
//
// The mock is now behind an explicit opt-in. A missing backend fails loudly
// instead of quietly rendering plausible fake history.

/** True when a real Tauri v2 backend is present. */
function hasTauriBackend() {
    return typeof window.__TAURI__?.core?.invoke === 'function';
}

/**
 * True when the mock backend has been explicitly requested.
 * Opt in with `?mock=1` or by setting `window.SHUNKAN_DEV_MOCK = true`.
 */
function mockRequested() {
    if (window.SHUNKAN_DEV_MOCK === true) return true;
    try {
        return new URLSearchParams(window.location.search).get('mock') === '1';
    } catch {
        return false;
    }
}

/**
 * Invoke a Tauri IPC command.
 * @param {string} command - Command name
 * @param {object} args - Command arguments (camelCase; Tauri maps to snake_case)
 * @returns {Promise<any>}
 */
async function invoke(command, args = {}) {
    if (hasTauriBackend()) {
        return window.__TAURI__.core.invoke(command, args);
    }
    if (mockRequested()) {
        return mockInvoke(command, args);
    }
    throw new Error(
        `No Tauri backend available for "${command}". ` +
        'Run the app with `cargo tauri dev`, or append ?mock=1 for UI-only development.',
    );
}

/**
 * Subscribe to a backend event. Resolves to an unlisten function.
 * @param {string} event
 * @param {() => void} handler
 * @returns {Promise<() => void>}
 */
async function listen(event, handler) {
    if (typeof window.__TAURI__?.event?.listen === 'function') {
        return window.__TAURI__.event.listen(event, handler);
    }
    return () => {};
}

/** Hide the palette window, if there is one to hide. */
async function hidePalette() {
    const getCurrentWindow = window.__TAURI__?.window?.getCurrentWindow;
    if (typeof getCurrentWindow === 'function') {
        try {
            await getCurrentWindow().hide();
            return;
        } catch (err) {
            console.error('Failed to hide the palette window:', err);
        }
    }
    console.warn('No window to hide (running without a Tauri backend)');
}

/**
 * Mock IPC handler for development without Tauri backend.
 */
function mockInvoke(command, args) {
    switch (command) {
        case 'get_peers':
            return Promise.resolve([
                { id: 'peer-001', device_name: 'Pixel 8 Pro', platform: 'android', connected: true },
                { id: 'peer-002', device_name: 'ThinkPad X1', platform: 'linux', connected: true },
            ]);
        case 'get_history':
            return Promise.resolve([
                { hash: 'abc123', content_type: 'text', preview: 'git push origin main --force', full_text: 'git push origin main --force', timestamp: Date.now() / 1000 - 30, source: 'ThinkPad X1' },
                { hash: 'def456', content_type: 'text', preview: 'https://github.com/example/repo', full_text: 'https://github.com/example/repo', timestamp: Date.now() / 1000 - 120, source: 'Pixel 8 Pro' },
                { hash: 'ghi789', content_type: 'text', preview: 'const result = await fetch("/api/sync");', full_text: 'const result = await fetch("/api/sync");', timestamp: Date.now() / 1000 - 300, source: 'ThinkPad X1' },
                { hash: 'jkl012', content_type: 'text', preview: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI...', full_text: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGe8mK...', timestamp: Date.now() / 1000 - 600, source: 'ThinkPad X1' },
            ]);
        case 'get_status':
            return Promise.resolve({
                peer_count: 2,
                session_type: 'wayland-wlroots',
                listening_port: 4433,
                version: '0.1.0',
            });
        case 'paste_entry':
            console.log('[mock] paste_entry:', args.hash);
            return Promise.resolve(true);
        case 'send_to_peer':
            console.log('[mock] send_to_peer:', args.peer_id, args.text?.length, 'bytes');
            return Promise.resolve(true);
        default:
            console.warn('[mock] Unknown command:', command);
            return Promise.resolve(null);
    }
}

// ─── Rendering ───────────────────────────────────────────────────────────────

/**
 * Get the icon for a content type.
 */
function getContentTypeIcon(type) {
    switch (type) {
        case 'text':      return '📝';
        case 'rich_text':  return '📄';
        case 'image':     return '🖼️';
        case 'file':      return '📁';
        default:          return '📋';
    }
}

/**
 * Format a UNIX timestamp into a relative time string.
 */
function formatRelativeTime(timestamp) {
    const now = Date.now() / 1000;
    const delta = Math.floor(now - timestamp);

    if (delta < 5)    return 'just now';
    if (delta < 60)   return `${delta}s ago`;
    if (delta < 3600) return `${Math.floor(delta / 60)}m ago`;
    if (delta < 86400) return `${Math.floor(delta / 3600)}h ago`;
    return `${Math.floor(delta / 86400)}d ago`;
}

// ─── DOM construction ────────────────────────────────────────────────────────
//
// Rows are built with createElement/textContent/setAttribute rather than
// interpolated into markup. Escaping text nodes but not attributes left
// `data-hash="${item.hash}"`, `data-peer-id="${peer.id}"` and
// `title="${peer.platform}"` open: peer names and platform strings arrive over
// the network, so a peer advertising `linux" onmouseover="…` executed script in
// the palette. Building nodes closes the whole class rather than one instance
// of it — there is no parser to confuse.

/**
 * Create an element with optional class, text content, and attributes.
 * @param {string} tag
 * @param {{className?: string, text?: string, attrs?: Record<string, string>}} [options]
 * @returns {HTMLElement}
 */
function el(tag, options = {}) {
    const node = document.createElement(tag);
    if (options.className) node.className = options.className;
    // textContent never parses markup, whatever the string contains.
    if (options.text !== undefined) node.textContent = String(options.text);
    if (options.attrs) {
        for (const [name, value] of Object.entries(options.attrs)) {
            node.setAttribute(name, String(value));
        }
    }
    return node;
}

/**
 * Replace an element's children with the given nodes.
 * @param {HTMLElement} container
 * @param {Node[]} children
 */
function replaceChildren(container, children) {
    container.replaceChildren(...children);
}

/**
 * Build the empty-state block shown when a list has nothing in it.
 * @param {string} icon
 * @param {string} title
 * @param {string} hint
 * @returns {HTMLElement}
 */
function buildEmptyState(icon, title, hint) {
    const wrapper = el('div', { className: 'empty-state' });
    wrapper.append(
        el('div', { className: 'empty-icon', text: icon }),
        el('p', { text: title }),
        el('p', { className: 'empty-hint', text: hint }),
    );
    return wrapper;
}

/**
 * Build one clipboard history row.
 * @param {object} item
 * @param {number} index
 * @returns {HTMLElement}
 */
function buildHistoryRow(item, index) {
    const row = el('div', {
        className: `history-item${index === state.selectedIndex ? ' selected' : ''}`,
        attrs: { 'data-index': index, 'data-hash': item.hash ?? '' },
    });

    const content = el('div', { className: 'history-content' });
    content.append(el('div', { className: 'history-preview', text: item.preview ?? '' }));

    const meta = el('div', { className: 'history-meta' });
    meta.append(
        el('span', { text: formatRelativeTime(item.timestamp) }),
        el('span', { text: '·' }),
        el('span', { className: 'history-source', text: item.source ?? '' }),
    );
    content.append(meta);

    row.append(
        el('div', { className: 'history-icon', text: getContentTypeIcon(item.content_type) }),
        content,
    );
    return row;
}

/**
 * Render the clipboard history list.
 */
function renderHistory() {
    const container = document.getElementById('history-list');
    const items = state.filteredHistory;

    if (items.length === 0) {
        replaceChildren(container, [
            buildEmptyState(
                '📋',
                state.searchQuery ? 'No matching entries' : 'No clipboard history yet',
                state.searchQuery ? 'Try a different search' : 'Copy something to get started',
            ),
        ]);
        return;
    }

    replaceChildren(container, items.map(buildHistoryRow));

    // Scroll selected item into view.
    const selected = container.querySelector('.selected');
    if (selected) {
        selected.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
}

/**
 * Build one peer chip.
 * @param {object} peer
 * @returns {HTMLElement}
 */
function buildPeerChip(peer) {
    const chip = el('div', {
        className: 'peer-chip',
        attrs: { 'data-peer-id': peer.id ?? '', title: peer.platform ?? '' },
    });
    chip.append(
        el('span', { className: 'peer-dot' }),
        el('span', { className: 'peer-name', text: peer.device_name ?? '' }),
    );
    return chip;
}

/**
 * Render the peers panel.
 */
function renderPeers() {
    const container = document.getElementById('peers-list');

    if (state.peers.length === 0) {
        replaceChildren(container, [
            el('div', { className: 'empty-peers', text: 'No peers discovered' }),
        ]);
        return;
    }

    replaceChildren(container, state.peers.map(buildPeerChip));
}

/**
 * Update the status bar.
 */
function renderStatus(status) {
    document.getElementById('peer-count').textContent = `${status.peer_count} peer${status.peer_count !== 1 ? 's' : ''}`;
    document.getElementById('session-type').textContent = status.session_type;
    document.getElementById('version').textContent = status.version;
    document.getElementById('port').textContent = status.listening_port;
}

// ─── Search / Filter ─────────────────────────────────────────────────────────

/**
 * Recompute `filteredHistory` from `history` and the current query.
 *
 * Selection is preserved **by hash**, not by index: a background refresh can
 * insert an entry at the front, and an index-based selection would silently
 * point at a different row.
 */
function applyFilter() {
    const previousHash = state.filteredHistory[state.selectedIndex]?.hash ?? null;
    const query = state.searchQuery.toLowerCase().trim();

    state.filteredHistory = !query
        ? [...state.history]
        : state.history.filter(item =>
            (item.preview ?? '').toLowerCase().includes(query) ||
            (item.source ?? '').toLowerCase().includes(query)
        );

    const restored = previousHash === null
        ? -1
        : state.filteredHistory.findIndex(item => item.hash === previousHash);
    state.selectedIndex = restored >= 0 ? restored : 0;
}

/**
 * Re-filter and re-render after the query changed. Selection resets to the top,
 * because a new query means a new list.
 */
function filterHistory() {
    state.selectedIndex = 0;
    state.filteredHistory = [];
    applyFilter();
    renderHistory();
}

/**
 * Debounce a function so a burst of calls results in one invocation.
 * @param {Function} fn
 * @param {number} waitMs
 */
function debounce(fn, waitMs) {
    let timer = null;
    return (...args) => {
        if (timer !== null) clearTimeout(timer);
        timer = setTimeout(() => {
            timer = null;
            fn(...args);
        }, waitMs);
    };
}

// ─── Keyboard Navigation ────────────────────────────────────────────────────

/**
 * Whether an event originated inside a text field.
 *
 * The keydown handler is bound to `document`, so without this check ordinary
 * typing in the search box competed with palette navigation — pressing Enter to
 * commit a search pasted the highlighted entry into the system clipboard.
 * @param {Event} e
 */
function isTypingTarget(e) {
    const el = e.target;
    if (!el) return false;
    if (el.isContentEditable) return true;
    const tag = el.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT';
}

/**
 * Handle keyboard events for navigation.
 */
function handleKeyDown(e) {
    // Escape always closes, wherever focus is — that is what a palette does.
    if (e.key === 'Escape') {
        e.preventDefault();
        closePalette();
        return;
    }

    const typing = isTypingTarget(e);
    const maxIndex = state.filteredHistory.length - 1;

    switch (e.key) {
        // Arrows drive the list even while typing: moving through results
        // without leaving the search box is the point of a palette.
        case 'ArrowDown':
            e.preventDefault();
            state.selectedIndex = Math.min(state.selectedIndex + 1, Math.max(maxIndex, 0));
            renderHistory();
            break;

        case 'ArrowUp':
            e.preventDefault();
            state.selectedIndex = Math.max(state.selectedIndex - 1, 0);
            renderHistory();
            break;

        case 'Enter':
            // Enter in the search box commits the search; it must not paste.
            // Enter with the palette focused pastes the selection.
            if (typing) return;
            e.preventDefault();
            pasteSelected();
            break;

        default:
            break;
    }
}

/**
 * Handle keys inside the search input, which owns its own editing keys.
 */
function handleSearchKeyDown(e) {
    if (e.key === 'Enter') {
        // Commit the search: apply it now rather than waiting out the debounce.
        e.preventDefault();
        state.searchQuery = e.target.value;
        filterHistory();
    }
}

/**
 * Paste the currently selected history entry, then close the palette.
 */
async function pasteSelected() {
    const item = state.filteredHistory[state.selectedIndex];
    if (!item) return;

    try {
        const success = await invoke('paste_entry', { hash: item.hash });
        if (success) {
            await closePalette();
        } else {
            console.error('Backend refused to paste entry', item.hash);
        }
    } catch (err) {
        console.error('Failed to paste entry:', err);
    }
}

/** Hide the palette window. */
async function closePalette() {
    await hidePalette();
}

// ─── Click Handlers ──────────────────────────────────────────────────────────

/**
 * Handle clicks on history items.
 *
 * A single click **selects**; Enter or a double click pastes. Clicking used to
 * overwrite the system clipboard immediately, so brushing a row while scanning
 * silently replaced whatever you had copied — and the footer advertised a
 * keyboard model the mouse did not follow.
 */
function handleHistoryClick(e) {
    const row = e.target.closest('.history-item');
    if (!row) return;

    const index = Number.parseInt(row.dataset.index, 10);
    if (Number.isNaN(index)) return;

    state.selectedIndex = index;
    renderHistory();

    if (e.detail >= 2) {
        pasteSelected();
    }
}

/**
 * Handle clicks on peer chips.
 */
function handlePeerClick(e) {
    const chip = e.target.closest('.peer-chip');
    if (!chip) return;

    const peerId = chip.dataset.peerId;
    console.log('Clicked peer:', peerId);
    // TODO: Show peer context menu or send clipboard to this peer.
}

// ─── Data Loading ────────────────────────────────────────────────────────────

/**
 * Load data from the backend and re-render.
 *
 * `loadData` used to assign `filteredHistory = [...history]` without
 * re-applying the search query, and ran on a 2-second timer: type a query, wait
 * two seconds, and the full list returned underneath you with the selection
 * reset, while the search box still showed your text. It re-applies the filter
 * now, and it is driven by backend events rather than a timer.
 */
async function loadData() {
    try {
        const [history, peers, status] = await Promise.all([
            invoke('get_history', { limit: 50 }),
            invoke('get_peers'),
            invoke('get_status'),
        ]);

        state.history = history || [];
        state.peers = peers || [];
        applyFilter();

        renderHistory();
        renderPeers();
        if (status) renderStatus(status);
        state.lastError = null;
    } catch (err) {
        state.lastError = err;
        console.error('Failed to load data:', err);
        renderLoadError(err);
    }
}

/** Refresh only the history list. */
async function refreshHistory() {
    try {
        state.history = (await invoke('get_history', { limit: 50 })) || [];
        applyFilter();
        renderHistory();
    } catch (err) {
        console.error('Failed to refresh history:', err);
    }
}

/** Refresh only the peers list and status bar. */
async function refreshPeers() {
    try {
        const [peers, status] = await Promise.all([
            invoke('get_peers'),
            invoke('get_status'),
        ]);
        state.peers = peers || [];
        renderPeers();
        if (status) renderStatus(status);
    } catch (err) {
        console.error('Failed to refresh peers:', err);
    }
}

/**
 * Show a visible failure rather than an empty palette that looks idle.
 */
function renderLoadError(err) {
    const container = document.getElementById('history-list');
    replaceChildren(container, [
        buildEmptyState('⚠️', 'Cannot reach the Shunkan backend', String(err?.message ?? err)),
    ]);
}

/**
 * Subscribe to backend change events instead of polling.
 */
async function startEventSubscriptions() {
    await listen('shunkan://history-changed', refreshHistory);
    await listen('shunkan://peers-changed', refreshPeers);
}

// ─── Initialization ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    // Set up search input. Debounced: it used to re-render the whole list on
    // every keystroke.
    const searchInput = document.getElementById('search-input');
    const onSearchInput = debounce((value) => {
        state.searchQuery = value;
        filterHistory();
    }, SEARCH_DEBOUNCE_MS);

    searchInput.addEventListener('input', (e) => onSearchInput(e.target.value));
    searchInput.addEventListener('keydown', handleSearchKeyDown);

    // Set up keyboard navigation.
    document.addEventListener('keydown', handleKeyDown);

    // Set up click handlers.
    document.getElementById('history-list').addEventListener('click', handleHistoryClick);
    document.getElementById('peers-list').addEventListener('click', handlePeerClick);

    // Load initial data, then let the backend push updates.
    loadData();
    startEventSubscriptions();
});
