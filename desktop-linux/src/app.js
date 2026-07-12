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
};

// ─── Tauri IPC Bridge ────────────────────────────────────────────────────────

/**
 * Invoke a Tauri IPC command. Falls back to mock data in browser dev mode.
 * @param {string} command - Command name
 * @param {object} args - Command arguments
 * @returns {Promise<any>}
 */
async function invoke(command, args = {}) {
    if (window.__TAURI__) {
        return window.__TAURI__.invoke(command, args);
    }
    // Dev mode fallback — return mock data for UI development.
    return mockInvoke(command, args);
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

/**
 * Render the clipboard history list.
 */
function renderHistory() {
    const container = document.getElementById('history-list');
    const items = state.filteredHistory;

    if (items.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📋</div>
                <p>${state.searchQuery ? 'No matching entries' : 'No clipboard history yet'}</p>
                <p class="empty-hint">${state.searchQuery ? 'Try a different search' : 'Copy something to get started'}</p>
            </div>
        `;
        return;
    }

    container.innerHTML = items.map((item, index) => `
        <div class="history-item ${index === state.selectedIndex ? 'selected' : ''}"
             data-index="${index}"
             data-hash="${item.hash}">
            <div class="history-icon">${getContentTypeIcon(item.content_type)}</div>
            <div class="history-content">
                <div class="history-preview">${escapeHtml(item.preview)}</div>
                <div class="history-meta">
                    <span>${formatRelativeTime(item.timestamp)}</span>
                    <span>·</span>
                    <span class="history-source">${escapeHtml(item.source)}</span>
                </div>
            </div>
        </div>
    `).join('');

    // Scroll selected item into view.
    const selected = container.querySelector('.selected');
    if (selected) {
        selected.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
}

/**
 * Render the peers panel.
 */
function renderPeers() {
    const container = document.getElementById('peers-list');

    if (state.peers.length === 0) {
        container.innerHTML = '<div class="empty-peers">No peers discovered</div>';
        return;
    }

    container.innerHTML = state.peers.map(peer => `
        <div class="peer-chip" data-peer-id="${peer.id}" title="${peer.platform}">
            <span class="peer-dot"></span>
            ${escapeHtml(peer.device_name)}
        </div>
    `).join('');
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

/**
 * Escape HTML special characters to prevent XSS.
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ─── Search / Filter ─────────────────────────────────────────────────────────

/**
 * Filter history entries based on the search query.
 */
function filterHistory() {
    const query = state.searchQuery.toLowerCase().trim();

    if (!query) {
        state.filteredHistory = [...state.history];
    } else {
        state.filteredHistory = state.history.filter(item =>
            item.preview.toLowerCase().includes(query) ||
            item.source.toLowerCase().includes(query)
        );
    }

    // Reset selection to top.
    state.selectedIndex = 0;
    renderHistory();
}

// ─── Keyboard Navigation ────────────────────────────────────────────────────

/**
 * Handle keyboard events for navigation.
 */
function handleKeyDown(e) {
    const maxIndex = state.filteredHistory.length - 1;

    switch (e.key) {
        case 'ArrowDown':
            e.preventDefault();
            state.selectedIndex = Math.min(state.selectedIndex + 1, maxIndex);
            renderHistory();
            break;

        case 'ArrowUp':
            e.preventDefault();
            state.selectedIndex = Math.max(state.selectedIndex - 1, 0);
            renderHistory();
            break;

        case 'Enter':
            e.preventDefault();
            pasteSelected();
            break;

        case 'Escape':
            e.preventDefault();
            // In Tauri, this would close the window.
            console.log('Escape pressed — would close overlay');
            break;
    }
}

/**
 * Paste the currently selected history entry.
 */
async function pasteSelected() {
    const item = state.filteredHistory[state.selectedIndex];
    if (!item) return;

    console.log('Pasting entry:', item.hash);
    const success = await invoke('paste_entry', { hash: item.hash });

    if (success) {
        console.log('Paste successful');
        // In Tauri, this would close the overlay window.
    }
}

// ─── Click Handlers ──────────────────────────────────────────────────────────

/**
 * Handle clicks on history items.
 */
function handleHistoryClick(e) {
    const item = e.target.closest('.history-item');
    if (!item) return;

    const index = parseInt(item.dataset.index, 10);
    state.selectedIndex = index;
    renderHistory();
    pasteSelected();
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
 * Load initial data from the backend.
 */
async function loadData() {
    try {
        const [history, peers, status] = await Promise.all([
            invoke('get_history', { limit: 50 }),
            invoke('get_peers'),
            invoke('get_status'),
        ]);

        state.history = history || [];
        state.filteredHistory = [...state.history];
        state.peers = peers || [];

        renderHistory();
        renderPeers();
        if (status) renderStatus(status);
    } catch (err) {
        console.error('Failed to load data:', err);
    }
}

/**
 * Refresh data periodically.
 */
function startPolling() {
    // Refresh every 2 seconds while the palette is open.
    setInterval(loadData, 2000);
}

// ─── Initialization ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    // Set up search input.
    const searchInput = document.getElementById('search-input');
    searchInput.addEventListener('input', (e) => {
        state.searchQuery = e.target.value;
        filterHistory();
    });

    // Set up keyboard navigation.
    document.addEventListener('keydown', handleKeyDown);

    // Set up click handlers.
    document.getElementById('history-list').addEventListener('click', handleHistoryClick);
    document.getElementById('peers-list').addEventListener('click', handlePeerClick);

    // Load initial data.
    loadData();
    startPolling();
});
