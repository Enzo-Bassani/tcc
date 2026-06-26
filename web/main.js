// Browser verifier app. All cryptography is done by the WASM engine (ssi-core);
// this file does only I/O and presentation: build the OID4VP request, talk to the
// relay, fetch issuer documents, and render the 3-step flow (Request → Scan →
// Verify) plus the Trust Anchors panel.
//
// Rendering uses Preact + htm (vendored, no build step — see index.html's import
// map). A central store holds the app state; mutating it re-renders the <App/>
// tree, and Preact's VDOM diff patches only what actually changed.
//
// The credential catalogue and attribute picker are **metadata-driven**: the app
// fetches SD-JWT VC Type Metadata documents (served by the relay under
// /type-metadata) and builds the UI from them. This demonstrates that the verifier
// is universal — it works against any credential type it is served metadata for,
// not just the diploma. (Only the University Diploma is actually held by a wallet
// in this system; the Mobile Driver's License is present purely to prove the point,
// and its request is built just the same.)
import { h, render, Fragment } from "preact";
import { useState, useEffect } from "preact/hooks";
import htm from "htm";
import init, {
  build_request,
  decrypt_response,
  inspect,
  validate,
  request_qr_svg,
  default_anchors,
  anchor_info,
} from "./pkg/verifier_wasm.js";

const html = htm.bind(h);
const RELAY = location.origin;
const app = document.getElementById("app");

// The verifier's catalogue is whatever Type Metadata the relay serves: the manifest
// lists the artifacts (the relay enumerates its metadata directory) and the app
// builds a credential type from each. No client-side list to keep in sync.
const METADATA_MANIFEST = "type-metadata.json";
const METADATA_DIR = "type-metadata/";

// ---------------------------------------------------------------------------
// Store — a tiny external store. `set()` shallow-merges a patch and notifies
// subscribers; components subscribe with the `useStore()` hook so any change
// re-renders <App/> and Preact diffs the result. Async flow functions read the
// live state with `get()` (they fire from clicks and timers, so it's always
// current) and write with `set()`.
// ---------------------------------------------------------------------------
const store = {
  state: {
    step: "compose", // 'compose' | 'awaiting' | 'verified'
    catalog: [], // [{ id, vct, name, accent, logo, fields:[{key,path,label,default}] }]
    selectedType: null, // catalog id
    selectedFields: {}, // { [id]: string[] }  (remembered per type)
    qrMode: "compact", // 'compact' | 'embedded'
    showDcql: false,
    showAnchors: false,
    toast: "",
    session: null, // { request, encPrivateJwk, responseUri, clientId, qrSvg, typeId, fieldKeys }
    report: null, // last verification report
    verifyInputs: null, // { vpToken, fetched } — kept to re-validate live on anchor change
  },
  listeners: new Set(),
};
const get = () => store.state;
function set(patch) {
  store.state = { ...store.state, ...patch };
  store.listeners.forEach((l) => l());
}
function useStore() {
  const [, force] = useState(0);
  useEffect(() => {
    const l = () => force((n) => n + 1);
    store.listeners.add(l);
    return () => store.listeners.delete(l);
  }, []);
  return store.state;
}

let pollTimer = null;
let toastTimer = null;

// ---------------------------------------------------------------------------
// Trust anchors — a user-managed set of trusted CA roots, persisted in this
// browser. Seeded on first run with the bundled default (mock ICP-Brasil root).
// ---------------------------------------------------------------------------
const TRUST_KEY = "ssi.trustAnchors";

function loadAnchors() {
  let raw = localStorage.getItem(TRUST_KEY);
  if (raw === null) {
    raw = default_anchors();
    localStorage.setItem(TRUST_KEY, raw);
  }
  try {
    return JSON.parse(raw);
  } catch {
    return [];
  }
}

function saveAnchors(pems) {
  localStorage.setItem(TRUST_KEY, JSON.stringify(pems));
}

function anchorInfo(pem) {
  try {
    return JSON.parse(anchor_info(pem));
  } catch {
    return { label: "(unparseable certificate)", fingerprint: "" };
  }
}

function anchorEntries() {
  return loadAnchors().map((pem) => ({ pem, ...anchorInfo(pem) }));
}

// Add a user-supplied trust anchor (a pasted PEM CA certificate). The engine
// (`anchor_info`) validates it — it throws on anything that isn't a CA cert — and
// we de-duplicate by fingerprint. Returns "" on success, or an error message to
// show inline.
function addAnchor(pem) {
  const trimmed = (pem || "").trim();
  if (!trimmed) return "Paste a PEM certificate first.";
  let info;
  try {
    info = JSON.parse(anchor_info(trimmed));
  } catch (e) {
    return (e && e.message ? e.message : String(e)) || "Not a valid CA certificate.";
  }
  const pems = loadAnchors();
  if (pems.some((p) => anchorInfo(p).fingerprint === info.fingerprint)) {
    return `Already trusted: ${info.label}.`;
  }
  pems.push(trimmed);
  saveAnchors(pems);
  reverifyIfNeeded();
  showToast(`Trust anchor added: ${info.label}`); // re-verifies live with the new trust store
  return "";
}

// Whether the bundled default (mock ICP-Brasil root) is currently trusted.
function defaultPresent() {
  const have = new Set(loadAnchors().map((p) => anchorInfo(p).fingerprint));
  return JSON.parse(default_anchors()).every((pem) => have.has(anchorInfo(pem).fingerprint));
}

// Restore the bundled default anchor (mock ICP-Brasil root) if it was removed.
function restoreDefaultAnchor() {
  const pems = loadAnchors();
  const have = new Set(pems.map((p) => anchorInfo(p).fingerprint));
  let added = 0;
  for (const pem of JSON.parse(default_anchors())) {
    if (!have.has(anchorInfo(pem).fingerprint)) {
      pems.push(pem);
      added++;
    }
  }
  if (!added) return showToast("Default anchor already present");
  saveAnchors(pems);
  reverifyIfNeeded();
  showToast("Default ICP-Brasil anchor restored");
}

function removeAnchor(pem) {
  saveAnchors(loadAnchors().filter((p) => p !== pem));
  reverifyIfNeeded();
  showToast("Trust anchor removed"); // re-verifies live with the new trust store
}

// ---------------------------------------------------------------------------
// Type-metadata → catalogue
// ---------------------------------------------------------------------------
function pickLocale(arr) {
  if (!Array.isArray(arr)) return {};
  return arr.find((d) => String(d.locale || "").toLowerCase().startsWith("en")) || arr[0] || {};
}

function idFromVct(vct) {
  const parts = String(vct).split(":");
  return (parts.length >= 2 ? parts[parts.length - 2] : parts[parts.length - 1]) || String(vct);
}

function initials(name) {
  const words = String(name)
    .replace(/['’]/g, "")
    .replace(/[^A-Za-z0-9 ]/g, " ")
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  const s = words.map((w) => w[0]).join("").toUpperCase();
  return s.slice(0, 2) || "ID";
}

function lighten(hex, amt) {
  const m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex || "");
  if (!m) return hex;
  const mix = (c) => Math.round(parseInt(c, 16) + (255 - parseInt(c, 16)) * amt);
  const to = (n) => n.toString(16).padStart(2, "0");
  return `#${to(mix(m[1]))}${to(mix(m[2]))}${to(mix(m[3]))}`;
}

// The selectable attributes for a type: selectively-disclosable (`sd: always`)
// leaf claims, derived straight from the metadata. Container nodes and array
// wildcards (paths with `null`) are skipped. Defaults = the `mandatory` ones.
function leafFields(claims) {
  const out = [];
  for (const c of claims) {
    const path = c.path || [];
    if (path.some((seg) => seg === null)) continue;
    if (c.sd !== "always") continue;
    const isContainer = claims.some((o) => {
      const op = o.path || [];
      return op.length > path.length && path.every((seg, i) => op[i] === seg);
    });
    if (isContainer) continue;
    out.push({
      key: path.join("."),
      path,
      label: pickLocale(c.display).label || path.join("."),
      default: c.mandatory === true,
    });
  }
  return out;
}

// A display-label map (dotted path → label) and the top-level claim order, both
// straight from the metadata. The Step-3 viewer uses these to label *every*
// disclosed claim — not just the selectable `sd: always` leaves — and to present
// them in the credential's natural order.
function metaIndex(claims) {
  const labels = {};
  const topOrder = [];
  for (const c of claims) {
    const p = c.path || [];
    if (p.some((s) => s === null)) continue;
    labels[p.join(".")] = pickLocale(c.display).label || p.join(".");
    if (p.length && !topOrder.includes(p[0])) topOrder.push(p[0]);
  }
  return { labels, topOrder };
}

function buildType(meta) {
  const disp = pickLocale(meta.display);
  const name = disp.name || meta.name || meta.vct;
  const bg = (disp.rendering && disp.rendering.simple && disp.rendering.simple.background_color) || "#4F46E5";
  const claims = meta.claims || [];
  const { labels, topOrder } = metaIndex(claims);
  return {
    id: idFromVct(meta.vct),
    vct: meta.vct,
    name,
    accent: `linear-gradient(135deg, ${bg}, ${lighten(bg, 0.24)})`,
    logo: initials(name),
    fields: leafFields(claims),
    labels,
    topOrder,
  };
}

async function fetchType(name) {
  try {
    const r = await fetch(METADATA_DIR + name);
    if (!r.ok) throw new Error(`${r.status}`);
    return buildType(await r.json());
  } catch (e) {
    console.warn(`Could not load type metadata ${name}:`, e);
    return null;
  }
}

async function loadCatalog() {
  let names = [];
  try {
    names = await (await fetch(METADATA_MANIFEST)).json();
  } catch (e) {
    console.warn("Could not load the Type Metadata manifest:", e);
  }
  const types = (await Promise.all(names.map(fetchType))).filter(Boolean);
  const selectedFields = { ...get().selectedFields };
  for (const t of types) {
    if (!(t.id in selectedFields)) selectedFields[t.id] = defaultsFor(t);
  }
  set({
    catalog: types,
    selectedFields,
    selectedType: get().selectedType || (types.length ? types[0].id : null),
  });
}

// ---------------------------------------------------------------------------
// Derived helpers
// ---------------------------------------------------------------------------
const selType = () => get().catalog.find((t) => t.id === get().selectedType) || get().catalog[0];
const defaultsFor = (t) => t.fields.filter((f) => f.default).map((f) => f.key);
function selKeys() {
  const t = selType();
  if (!t) return [];
  const sel = get().selectedFields[t.id] || [];
  return t.fields.filter((f) => sel.includes(f.key)).map((f) => f.key);
}
const trusted = () => loadAnchors().length > 0;

function toggleField(typeId, key) {
  const cur = get().selectedFields[typeId] || [];
  const next = cur.includes(key) ? cur.filter((k) => k !== key) : [...cur, key];
  set({ selectedFields: { ...get().selectedFields, [typeId]: next } });
}

function showToast(msg) {
  set({ toast: msg });
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => set({ toast: "" }), 2400);
}

function copy(text, msg) {
  try {
    navigator.clipboard && navigator.clipboard.writeText(text);
  } catch {
    /* clipboard unavailable */
  }
  showToast(msg);
}

// ---------------------------------------------------------------------------
// OID4VP flow (real engine + relay)
// ---------------------------------------------------------------------------
async function generateRequest() {
  const t = selType();
  const keys = selKeys();
  if (!t || keys.length === 0) return;
  try {
    const dcql = {
      credentials: [
        {
          id: t.id,
          format: "dc+sd-jwt",
          meta: { vct_values: [t.vct] },
          claims: keys.map((k) => ({ path: t.fields.find((f) => f.key === k).path })),
        },
      ],
    };

    // Open a transport session on the relay.
    const s = await (await fetch(`${RELAY}/sessions`, { method: "POST" })).json();
    // Build a SIGNED Authorization Request (did:jwk JAR) with an ephemeral
    // response-encryption key.
    const built = JSON.parse(build_request(JSON.stringify(dcql), s.response_uri));

    // The QR always carries client_id; the signed request is delivered either by
    // value (embedded in the QR — relay never sees it) or by reference (uploaded
    // to the relay; the QR carries a request_uri).
    let qrText = `openid4vp://?client_id=${encodeURIComponent(built.client_id)}`;
    if (get().qrMode === "embedded") {
      qrText += `&request=${encodeURIComponent(built.request_jwt)}`;
    } else {
      await fetch(s.request_uri, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ request: built.request_jwt }),
      });
      qrText += `&request_uri=${encodeURIComponent(s.request_uri)}`;
    }

    set({
      session: {
        request: built.request,
        encPrivateJwk: built.enc_private_jwk,
        responseUri: s.response_uri,
        clientId: built.client_id,
        qrSvg: request_qr_svg(qrText),
        typeId: t.id,
        fieldKeys: keys,
      },
      report: null,
      verifyInputs: null,
      showDcql: false,
      step: "awaiting",
    });
    startPolling();
  } catch (e) {
    showToast("Could not build request: " + (e && e.message ? e.message : e));
  }
}

function startPolling() {
  stopPolling();
  pollTimer = setInterval(poll, 1500);
}
function stopPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
}

async function poll() {
  const session = get().session;
  if (!session) return;
  let res;
  try {
    res = await fetch(session.responseUri);
  } catch {
    return; // relay briefly unreachable — keep polling
  }
  if (res.status !== 200) return; // 204 = still waiting
  stopPolling();
  try {
    const response = await res.json();
    // The relay only ever saw ciphertext; decrypt with our session key.
    const vpToken = JSON.parse(
      decrypt_response(JSON.stringify(response), JSON.stringify(session.encPrivateJwk)),
    );
    await runVerify(vpToken);
  } catch (e) {
    showToast("Verification failed: " + (e && e.message ? e.message : e));
  }
}

async function runVerify(vpToken) {
  // The engine reports which external documents it needs (status lists); fetch
  // them over HTTP exactly as a production verifier would.
  const urls = JSON.parse(inspect(JSON.stringify(vpToken)));
  const fetched = {};
  await Promise.all(
    urls.map(async (url) => {
      try {
        const r = await fetch(url);
        if (r.ok) fetched[url] = await r.text();
      } catch {
        /* unreachable status URL — the engine reports the missing-document failure */
      }
    }),
  );
  set({
    verifyInputs: { vpToken, fetched },
    report: computeReport(vpToken, fetched),
    step: "verified",
  });
}

function computeReport(vpToken, fetched) {
  return JSON.parse(
    validate(
      JSON.stringify(get().session.request),
      JSON.stringify(vpToken),
      JSON.stringify(fetched),
      JSON.stringify(loadAnchors()),
    ),
  );
}

// Removing/adding an anchor while a result is on screen recomputes it live —
// the same VP Token, re-validated against the new trust store.
function reverifyIfNeeded() {
  const s = get();
  if (s.step === "verified" && s.verifyInputs && s.session) {
    set({ report: computeReport(s.verifyInputs.vpToken, s.verifyInputs.fetched) });
  }
}

function editRequest() {
  stopPolling();
  set({ step: "compose" });
}

function verifyAnother() {
  stopPolling();
  set({ step: "compose", session: null, report: null, verifyInputs: null });
}

// ---------------------------------------------------------------------------
// Icons (inline SVG, Lucide-style geometry) — rendered as real Preact <svg>
// vnodes; the path geometry is injected as trusted static markup.
// ---------------------------------------------------------------------------
const svg = (body, { s = 20, stroke = "currentColor", w = 2 } = {}) =>
  html`<svg
    width=${s}
    height=${s}
    viewBox="0 0 24 24"
    fill="none"
    stroke=${stroke}
    stroke-width=${w}
    stroke-linecap="round"
    stroke-linejoin="round"
    dangerouslySetInnerHTML=${{ __html: body }}
  ></svg>`;
const I = {
  shield: (o) => svg('<path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/>', o),
  check: (o) => svg('<path d="M5 13l4 4L19 7"/>', o),
  x: (o) => svg('<path d="M6 6l12 12M18 6L6 18"/>', o),
  copy: (o) => svg('<rect x="8" y="8" width="12" height="12" rx="2.5"/><path d="M16 8V6a2 2 0 00-2-2H6a2 2 0 00-2 2v8a2 2 0 002 2h2"/>', o),
  chevR: (o) => svg('<path d="M9 6l6 6-6 6"/>', o),
  chevL: (o) => svg('<path d="M15 6l-6 6 6 6"/>', o),
  lock: (o) => svg('<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>', o),
  qr: (o) => svg('<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><path d="M14 14h3v3M21 14v7h-7"/>', o),
  alert: (o) => svg('<path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/>', o),
  refresh: (o) => svg('<path d="M3 12a9 9 0 1 0 3-6.7M3 4v4h4"/>', o),
  plus: (o) => svg('<path d="M12 5v14M5 12h14"/>', o),
};

// The two QR-encoding modes, shared by the Step-1 chooser (title/tag/desc) and the
// Step-2 status line (tag/stroke/color) so their copy can't drift apart.
const MODES = [
  {
    id: "compact", title: "Compact", tag: "Standard · easy scan", stroke: "#9AA1B9", color: "#6B7390",
    desc: "The wallet fetches the signed request from the relay. Smaller QR, easier to scan.",
  },
  {
    id: "embedded", title: "Embedded", tag: "Max privacy · dense", stroke: "#4F46E5", color: "#4F46E5",
    desc: "The full signed request is embedded in the QR — the relay never sees the query. Larger and denser.",
  },
];
const modeOf = (id) => MODES.find((m) => m.id === id) || MODES[0];

// A filled checkbox/radio marker: a `cls` box (`.radio`/`.check`) showing an inset
// white check when `on`.
const Mark = (on, cls) => html`<div class=${`${cls} ${on ? "on" : ""}`}>${on ? I.check({ s: 13, stroke: "#fff", w: 3.2 }) : null}</div>`;

// "3 attributes" / "1 attribute" — one place for the pluralization.
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

// ---------------------------------------------------------------------------
// JSON syntax highlighting (for the dark code blocks)
// ---------------------------------------------------------------------------
const esc = (s) => s.replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
function highlight(jsonStr) {
  const KEY = "#93C5FD", STR = "#86EFAC", NUM = "#FBBF24", KW = "#F0ABFC", PUN = "#7E879B";
  const re = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+\.?\d*(?:[eE][+-]?\d+)?)/g;
  const span = (c, t) => `<span style="color:${c}">${esc(t)}</span>`;
  let out = "", last = 0, m;
  while ((m = re.exec(jsonStr)) !== null) {
    if (m.index > last) out += span(PUN, jsonStr.slice(last, m.index));
    if (m[1]) {
      if (m[2] !== undefined) out += span(KEY, m[1]) + span(PUN, m[2]);
      else out += span(STR, m[1]);
    } else if (m[3]) out += span(KW, m[3]);
    else if (m[4]) out += span(NUM, m[4]);
    last = re.lastIndex;
  }
  if (last < jsonStr.length) out += span(PUN, jsonStr.slice(last));
  return out;
}
const JsonBlock = (obj) =>
  html`<div class="json-block"><pre dangerouslySetInnerHTML=${{ __html: highlight(JSON.stringify(obj, null, 2)) }}></pre></div>`;

// ---------------------------------------------------------------------------
// Top-bar + stepper
// ---------------------------------------------------------------------------
function Header() {
  return html`
    <div class="header">
      <div class="logo-tile">${I.shield({ s: 27, stroke: "#fff", w: 2.1 })}</div>
      <div class="header-grow">
        <h1>SSI Verifier</h1>
        <div class="sub">OID4VP · DCQL · SD-JWT VC · verifies locally</div>
      </div>
      <button class="anchors-btn" onClick=${() => set({ showAnchors: true })}>
        ${I.shield({ s: 17, stroke: "#4F46E5" })} Trust anchors
        <span class="dot" style=${`background:${trusted() ? "#15A06B" : "#E5484D"}`}></span>
      </button>
    </div>`;
}

function Stepper({ step }) {
  const order = ["compose", "awaiting", "verified"];
  const ci = order.indexOf(step);
  const labels = ["Request", "Scan", "Verify"];
  return html`<div class="stepper">
    ${labels.map((label, i) => {
      const done = i < ci, active = i === ci;
      const cls = done ? "done" : active ? "active" : "future";
      const inner = done ? I.check({ s: 16, stroke: "#fff", w: 3 }) : html`<span>${i + 1}</span>`;
      return html`<${Fragment} key=${label}>
        ${i > 0 ? html`<div class="connector" style=${`background:${i <= ci ? "#4F46E5" : "#E2E4EE"}`}></div>` : null}
        <div class="step">
          <div class=${`circle ${cls}`}>${inner}</div>
          <span class=${`label ${cls}`}>${label}</span>
        </div>
      </${Fragment}>`;
    })}
  </div>`;
}

// ---------------------------------------------------------------------------
// Step 1 — compose the request
// ---------------------------------------------------------------------------
function Compose({ state }) {
  const t = selType();
  if (!t) {
    return html`<div class="card">
      <div class="eyebrow">Step 1 · Create request</div>
      <h2>No credential types</h2>
      <p class="intro">No Type Metadata could be loaded. Is the relay serving <code>/type-metadata</code>?</p>
    </div>`;
  }
  const count = selKeys().length;
  const sel = state.selectedFields[t.id] || [];

  return html`<div class="card">
    <div class="eyebrow">Step 1 · Create request</div>
    <h2>Request a credential</h2>
    <p class="intro">Pick a credential type, choose which attributes to ask for, then generate the request.</p>

    <div class="section-eyebrow">Credential type</div>
    <div class="pick-grid">
      ${state.catalog.map((c) => {
        const on = c.id === t.id;
        return html`<div
          key=${c.id}
          class=${`pick type-card ${on ? "selected" : ""}`}
          onClick=${() => set({ selectedType: c.id })}
        >
          <div class="type-logo" style=${`background:${c.accent}`}>${c.logo}</div>
          <div class="grow0">
            <div class="type-name">${c.name}</div>
            <div class="type-vct">${c.vct}</div>
          </div>
          ${Mark(on, "radio")}
        </div>`;
      })}
    </div>

    <div class="attr-head">
      <div class="section-eyebrow" style="margin:0">${t.name} · Attributes</div>
      <div class="attr-actions">
        <button class="linkbtn" style="color:#6B7390" onClick=${() => set({ selectedFields: { ...state.selectedFields, [t.id]: defaultsFor(t) } })}>Defaults</button>
        <button class="linkbtn" style="color:#4F46E5" onClick=${() => set({ selectedFields: { ...state.selectedFields, [t.id]: t.fields.map((f) => f.key) } })}>Select all</button>
      </div>
    </div>
    <div class="attr-list">
      ${t.fields.map((f) => {
        const on = sel.includes(f.key);
        return html`<div key=${f.key} class="attr-row" onClick=${() => toggleField(t.id, f.key)}>
          ${Mark(on, "check")}
          <span class="attr-label">${f.label}</span>
          <span class="attr-path">${f.key}</span>
        </div>`;
      })}
    </div>

    <div class="section-eyebrow">QR encoding</div>
    <div class="pick-grid">
      ${MODES.map((m) => {
        const on = state.qrMode === m.id;
        return html`<div key=${m.id} class=${`pick mode-card ${on ? "selected" : ""}`} onClick=${() => set({ qrMode: m.id })}>
          <div class="mode-top">
            <span class="mode-title">${m.title}</span>
            ${Mark(on, "radio")}
          </div>
          <span class="mode-tag" style=${`color:${on ? "#4F46E5" : "#A8AEC4"}`}>${m.tag}</span>
          <p class="mode-desc">${m.desc}</p>
        </div>`;
      })}
    </div>

    ${count > 0
      ? html`<button class="btn-primary mt24" onClick=${generateRequest}>${I.qr({ s: 19, w: 2.2 })} Generate request · ${plural(count, "attribute")}</button>`
      : html`<div class="btn-disabled mt24">Select at least one attribute to request</div>`}
  </div>`;
}

// ---------------------------------------------------------------------------
// Step 2 — scan
// ---------------------------------------------------------------------------
function Scan({ state }) {
  const t = state.catalog.find((c) => c.id === state.session.typeId) || selType();
  const count = state.session.fieldKeys.length;
  const mode = modeOf(state.qrMode);

  return html`<div class="card">
    <div class="scan-head">
      <div>
        <div class="eyebrow">Step 2 · Scan with wallet</div>
        <h2>Present a credential</h2>
      </div>
      <button class="btn-ghost" onClick=${editRequest}>${I.chevL({ s: 15, w: 2.2 })} Edit request</button>
    </div>

    <div class="summary-chip">
      <div class="summary-logo" style=${`background:${t.accent}`}>${t.logo}</div>
      <div class="grow0">
        <div class="type-name" style="font-size:14px">${t.name}</div>
        <div style="font-size:11.5px;color:#6B7390;font-weight:600">${plural(count, "attribute")} requested</div>
      </div>
    </div>

    <div class="qr-wrap">
      <div class="qr-frame" dangerouslySetInnerHTML=${{ __html: state.session.qrSvg }}></div>
      <div class="mode-line" style=${`color:${mode.color}`}>
        ${I.lock({ s: 15, stroke: mode.stroke, w: 2.2 })}<span>${mode.tag}</span>
      </div>
      <div class="waiting"><span class="pdot"></span><span>Waiting for the wallet to present…</span></div>
    </div>

    <div class="mono-head">
      <span class="mono-label">CLIENT_ID</span>
      <button class="copybtn" onClick=${() => copy(state.session.clientId, "client_id copied")}>${I.copy({ s: 13 })} Copy</button>
    </div>
    <div class="mono-box">${state.session.clientId}</div>

    <div class="collapse-toggle" onClick=${() => set({ showDcql: !state.showDcql })}>
      <span class=${`chev ${state.showDcql ? "open" : ""}`}>${I.chevR({ s: 16, w: 2.4 })}</span>Request Object (DCQL)
    </div>
    ${state.showDcql ? JsonBlock(state.session.request) : null}
  </div>`;
}

// ---------------------------------------------------------------------------
// Presented-credential viewer (Step 3) — render the disclosed SD-JWT payload as
// a labelled, human-readable view instead of raw JSON. Registered JWT/SD-JWT VC
// claims are surfaced separately as "credential details"; everything else is the
// credential's own data, labelled from the Type Metadata and tagged when it was a
// claim the verifier explicitly requested.
// ---------------------------------------------------------------------------
const humanize = (k) => String(k).replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());

function fmtDate(ts) {
  if (typeof ts !== "number") return String(ts);
  const d = new Date(ts * 1000);
  return Number.isNaN(d.getTime()) ? String(ts) : d.toISOString().slice(0, 10);
}

function fmtValue(v) {
  if (v === null) return "—";
  if (typeof v === "boolean") return v ? "Yes" : "No";
  if (Array.isArray(v)) return v.map(fmtValue).join(", ");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

// Flatten an object to leaf rows, keeping the full dotted path for labelling.
function leafRows(obj, base, labels, requested) {
  const rows = [];
  for (const [k, v] of Object.entries(obj)) {
    const path = [...base, k];
    if (v && typeof v === "object" && !Array.isArray(v)) {
      rows.push(...leafRows(v, path, labels, requested));
    } else {
      const dot = path.join(".");
      rows.push({
        label: labels[dot] || humanize(k),
        path: dot,
        value: fmtValue(v),
        requested: requested.has(dot),
      });
    }
  }
  return rows;
}

const ClaimRow = (r) => html`<div key=${r.path} class=${`claim-row ${r.requested ? "requested" : ""}`}>
  <div class="claim-main">
    <div class="claim-label">${r.label}${r.requested ? html`<span class="req-pill">requested</span>` : null}</div>
    <div class="claim-path">${r.path}</div>
  </div>
  <div class="claim-value">${r.value}</div>
</div>`;

// The credential body — the metadata-declared claims (registered JWT/SD-JWT VC
// claims like iss/iat/cnf/status are handled by <Details/>), grouped by their
// top-level objects in the metadata's own order.
function ClaimsView({ claims, labels, topOrder, requested }) {
  const keys = topOrder.filter((k) => k in claims);
  if (!keys.length) return html`<div class="claims-box"><div class="empty-claims">No attributes were disclosed.</div></div>`;
  return html`<div class="claims-box">
    ${keys.map((k) => {
      const v = claims[k];
      if (v && typeof v === "object" && !Array.isArray(v)) {
        const rows = leafRows(v, [k], labels, requested);
        if (!rows.length) return null;
        return html`<${Fragment} key=${k}>
          <div class="claim-group-head">${labels[k] || humanize(k)}</div>
          ${rows.map(ClaimRow)}
        </${Fragment}>`;
      }
      return ClaimRow({ label: labels[k] || humanize(k), path: k, value: fmtValue(v), requested: requested.has(k) });
    })}
  </div>`;
}

// The always-present credential metadata: validity window, holder binding, status.
function Details({ claims }) {
  const rows = [];
  if (typeof claims.iat === "number") rows.push({ label: "Issued", value: fmtDate(claims.iat) });
  if (typeof claims.nbf === "number") rows.push({ label: "Valid from", value: fmtDate(claims.nbf) });
  if (typeof claims.exp === "number") rows.push({ label: "Expires", value: fmtDate(claims.exp) });
  if (claims.cnf) {
    const crv = claims.cnf.jwk && claims.cnf.jwk.crv;
    rows.push({ label: "Holder binding", value: crv ? `Bound to holder key (${crv})` : "Bound to holder key" });
  }
  if (claims.status && claims.status.status_list) {
    const sl = claims.status.status_list;
    rows.push({ label: "Revocation", value: `Status List entry #${sl.idx}`, sub: sl.uri });
  }
  if (!rows.length) return null;
  return html`<${Fragment}>
    <div class="section-eyebrow">Credential details</div>
    <div class="detail-card">
      ${rows.map((r) => html`<div key=${r.label} class="detail-row">
        <span class="detail-label">${r.label}</span>
        <div class="detail-rt">
          <div class="detail-value">${r.value}</div>
          ${r.sub ? html`<span class="detail-sub">${r.sub}</span>` : null}
        </div>
      </div>`)}
    </div>
  </${Fragment}>`;
}

const CHECK_DEFS = [
  ["issuer_signature", "Issuer signature"],
  ["holder_binding", "Holder binding"],
  ["dcql_satisfied", "DCQL satisfied"],
  ["revocation", "Revocation"],
  ["trusted_issuer", "Trusted issuer"],
];

// ---------------------------------------------------------------------------
// Step 3 — verification result
// ---------------------------------------------------------------------------
function Verify({ state }) {
  const rep = state.report;
  const cred = (rep.credentials && rep.credentials[0]) || {};
  const valid = !!rep.valid;
  const catEntry = state.catalog.find((c) => c.vct === cred.vct);
  const credName = catEntry ? catEntry.name : cred.query_id || "Credential";

  const checks = CHECK_DEFS.map(([key, label]) => {
    const c = cred[key] || { status: "skip" };
    return { key, label, status: c.status, detail: c.detail };
  });
  const failing = checks.filter((c) => c.status === "fail");
  const reason =
    failing.length === 1 && failing[0].key === "trusted_issuer"
      ? "Issuer is not anchored to a trusted root CA"
      : (failing[0] && failing[0].detail) || "One or more cryptographic checks failed";

  const banner = valid
    ? html`<div class="banner valid">
        <div class="banner-icon">${I.check({ s: 23, stroke: "#fff", w: 2.8 })}</div>
        <div><div class="banner-title">Valid presentation</div><div class="banner-sub">All cryptographic checks passed</div></div>
      </div>`
    : html`<div class="banner invalid">
        <div class="banner-icon">${I.x({ s: 23, stroke: "#fff", w: 2.8 })}</div>
        <div><div class="banner-title">Invalid presentation</div><div class="banner-sub">${reason}</div></div>
      </div>`;

  const claims = cred.disclosed_claims || {};
  const labels = (catEntry && catEntry.labels) || {};
  const topOrder = (catEntry && catEntry.topOrder) || [];
  const requested = new Set((state.session && state.session.fieldKeys) || []);
  const reqCount = requested.size;

  return html`<div class="card">
    <div class="eyebrow">Step 3 · Verification result</div>
    ${banner}

    <div class="cred-line">
      <span class="cred-name">${credName}</span>
      <span class="cred-vct">${cred.vct || ""}</span>
      ${cred.issuer ? html`<span class="cred-from">from</span><span class="cred-iss">${cred.issuer}</span>` : null}
    </div>

    <div>
      ${checks.map((c) => html`<div key=${c.key} class="check-row">
        <span class=${`badge ${c.status}`}>${c.status.toUpperCase()}</span>
        <span class="check-label">${c.label}</span>
        ${c.detail ? html`<span class="check-detail">— ${c.detail}</span>` : null}
      </div>`)}
    </div>

    <div class="mono-head">
      <span class="mono-label">PRESENTED CREDENTIAL</span>
      <button class="copybtn" onClick=${() => copy(JSON.stringify((rep.credentials[0] || {}).disclosed_claims || {}, null, 2), "Disclosed claims copied")}>${I.copy({ s: 13 })} Copy JSON</button>
    </div>
    <p class="intro" style="margin:0 0 4px">${plural(reqCount, "requested attribute")} (highlighted) plus the data the credential always carries.</p>
    <${ClaimsView} claims=${claims} labels=${labels} topOrder=${topOrder} requested=${requested} />

    <${Details} claims=${claims} />

    <button
      class="btn-primary mt24"
      style="font-size:15px;padding:15px;box-shadow:0 12px 26px rgba(79,70,229,.3)"
      onClick=${verifyAnother}
    >
      ${I.refresh({ s: 18, w: 2.2 })} Verify another credential
    </button>
  </div>`;
}

// ---------------------------------------------------------------------------
// Trust-anchors panel + toast
// ---------------------------------------------------------------------------
const PEM_PLACEHOLDER =
  "-----BEGIN CERTIFICATE-----\n…paste a root CA certificate (PEM)…\n-----END CERTIFICATE-----";

function AnchorsPanel() {
  const entries = anchorEntries();
  // Editor state is panel-local: the add form and its draft/error live only while
  // the panel is open (a fresh open resets them).
  const [adding, setAdding] = useState(false);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState("");

  const submit = () => {
    const err = addAnchor(draft);
    if (err) setError(err);
    else {
      setDraft("");
      setError("");
      setAdding(false);
    }
  };
  const cancel = () => {
    setAdding(false);
    setDraft("");
    setError("");
  };

  const footer = adding
    ? html`<div class="anchor-add">
        <textarea
          class="anchor-textarea"
          spellcheck="false"
          autocapitalize="off"
          placeholder=${PEM_PLACEHOLDER}
          value=${draft}
          onInput=${(e) => {
            setDraft(e.target.value);
            if (error) setError("");
          }}
        ></textarea>
        ${error ? html`<div class="anchor-error">${I.alert({ s: 16, w: 2.2 })}<span>${error}</span></div>` : null}
        <div class="anchor-add-row">
          <button class="btn-add" onClick=${submit}>${I.plus({ s: 16, w: 2.4 })} Add anchor</button>
          <button class="btn-cancel" onClick=${cancel}>Cancel</button>
        </div>
      </div>`
    : html`<${Fragment}>
        <button class="add-anchor" onClick=${() => setAdding(true)}>${I.plus({ s: 17, w: 2.2 })} Add trust anchor</button>
        ${!defaultPresent()
          ? html`<button class="btn-restore" onClick=${restoreDefaultAnchor}>${I.refresh({ s: 16, w: 2.2 })} Restore ICP-Brasil default</button>`
          : null}
      </${Fragment}>`;

  return html`<div class="overlay">
    <div class="scrim" onClick=${() => set({ showAnchors: false })}></div>
    <div class="panel">
      <div class="panel-head">
        <div style="display:flex;align-items:center;gap:12px">
          <div class="panel-chip">${I.shield({ s: 20 })}</div>
          <div><div class="panel-title">Trust anchors</div><div class="panel-sub">CA ROOTS · CONFIGURATION</div></div>
        </div>
        <button class="panel-x" onClick=${() => set({ showAnchors: false })}>${I.x({ s: 17, w: 2.2 })}</button>
      </div>
      <div class="panel-body">
        <p class="panel-explain">An issuer's <code>x5c</code> chain must validate up to one of these roots for the <strong>Trusted issuer</strong> check to pass. Stored in this browser only — changes apply to the next verification.</p>
        ${entries.length
          ? html`<div class="anchor-list">
              ${entries.map((a) => html`<div key=${a.fingerprint || a.pem} class="anchor-card">
                <div class="panel-chip">${I.shield({ s: 19 })}</div>
                <div class="grow0">
                  <div class="anchor-name">${a.label}</div>
                  <div class="anchor-hash">${a.fingerprint}</div>
                </div>
                <button class="remove-btn" onClick=${() => removeAnchor(a.pem)}>Remove</button>
              </div>`)}
            </div>`
          : html`<div class="empty-anchors">${I.alert({ s: 20, w: 2.2 })}<span>No trust anchors. Every issuer is untrusted until you add one.</span></div>`}
        ${footer}
      </div>
    </div>
  </div>`;
}

function Toast({ toast }) {
  if (!toast) return null;
  return html`<div class="toast">${I.check({ s: 18, stroke: "#34D399", w: 2.4 })}<span>${toast}</span></div>`;
}

// ---------------------------------------------------------------------------
// App — subscribes to the store and renders the current step. Preact diffs the
// returned tree against the live DOM, so only the parts that changed are patched.
// ---------------------------------------------------------------------------
function App() {
  const state = useStore();
  let view = null;
  if (state.step === "compose") view = html`<${Compose} state=${state} />`;
  else if (state.step === "awaiting" && state.session) view = html`<${Scan} state=${state} />`;
  else if (state.step === "verified" && state.report) view = html`<${Verify} state=${state} />`;

  return html`<${Fragment}>
    <${Header} />
    <${Stepper} step=${state.step} />
    ${view}
    ${state.showAnchors ? html`<${AnchorsPanel} />` : null}
    <${Toast} toast=${state.toast} />
  </${Fragment}>`;
}

// ---------------------------------------------------------------------------
// Boot — initialise the WASM engine and load the catalogue (the "Loading engine…"
// placeholder in index.html stays visible until the first Preact render), then
// mount the app.
// ---------------------------------------------------------------------------
await init();
await loadCatalog();
app.replaceChildren(); // drop the "Loading engine…" placeholder before the first mount
render(html`<${App} />`, app);
