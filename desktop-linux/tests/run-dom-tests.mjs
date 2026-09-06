#!/usr/bin/env node
/**
 * Run the palette DOM safety harness in a real headless browser.
 *
 * No npm dependencies: it drives Chromium with `--dump-dom` and reads the
 * verdict the page writes into `#result`. A real browser is the point — the
 * behaviour under test is how the HTML parser treats attribute values, which a
 * DOM stub cannot tell you anything about.
 *
 * Usage:  node desktop-linux/tests/run-dom-tests.mjs
 * Chromium is located via $CHROMIUM, then $PLAYWRIGHT_BROWSERS_PATH, then PATH.
 * Exits 0 on pass, 1 on failure, and 0 with a notice if no browser is present.
 */

import { execFileSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const page = resolve(here, 'palette-dom.html');

/** @returns {string|null} path to a Chromium binary, or null if none is found */
function findChromium() {
    if (process.env.CHROMIUM && existsSync(process.env.CHROMIUM)) {
        return process.env.CHROMIUM;
    }

    const browsersPath = process.env.PLAYWRIGHT_BROWSERS_PATH;
    if (browsersPath && existsSync(browsersPath)) {
        const direct = join(browsersPath, 'chromium');
        if (existsSync(direct)) return direct;

        // Playwright installs into versioned directories.
        for (const entry of readdirSync(browsersPath)) {
            for (const suffix of ['chrome-linux/chrome', 'chrome-linux/headless_shell']) {
                const candidate = join(browsersPath, entry, suffix);
                if (existsSync(candidate)) return candidate;
            }
        }
    }

    for (const name of ['chromium', 'chromium-browser', 'google-chrome', 'chrome']) {
        try {
            const found = execFileSync('which', [name], { encoding: 'utf8' }).trim();
            if (found) return found;
        } catch {
            // not on PATH, keep looking
        }
    }
    return null;
}

const chromium = findChromium();
if (!chromium) {
    console.log('SKIP: no Chromium binary found (set $CHROMIUM to run these tests)');
    process.exit(0);
}

console.log(`Running palette DOM tests in ${chromium}`);

let dom;
try {
    dom = execFileSync(
        chromium,
        [
            '--headless',
            '--disable-gpu',
            '--no-sandbox',
            '--allow-file-access-from-files',
            '--virtual-time-budget=5000',
            '--dump-dom',
            pathToFileURL(page).href,
        ],
        { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 60_000 },
    );
} catch (err) {
    console.error('FAIL: browser run failed');
    console.error(err.stderr || err.message);
    process.exit(1);
}

const match = dom.match(/RESULT:(PASS|FAIL[^<]*)/);
if (!match) {
    console.error('FAIL: the page produced no verdict — did it fail to load app.js?');
    console.error(dom.slice(0, 2000));
    process.exit(1);
}

if (match[1] === 'PASS') {
    console.log(
        'PASS: hostile strings stay inert, search survives refresh, ' +
        'Enter/click/Escape behave',
    );
    process.exit(0);
}

console.error(`FAIL: ${match[1]}`);
process.exit(1);
