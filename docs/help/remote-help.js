// TivEPG Remote Help: the helper's side.
//
// Talks to the person's device through the relay worker. Everything after the key exchange
// is AES-GCM encrypted between this page and the device; the relay only forwards ciphertext.
// Crypto must match My TV - VLC/RemoteHelpCrypto.swift exactly:
//   P-256 ECDH, raw (65-byte) public keys, HKDF-SHA256(salt "tivepg-remote-help:<code>",
//   info "TivEPG Remote Help v1") -> AES-256-GCM, 12-byte nonce, tag appended.
(() => {
  "use strict";

  const RELAY = "wss://remote-help.ewan-laww.workers.dev/ws";
  const CHUNK = 256 * 1024;

  const $ = (id) => document.getElementById(id);
  const te = new TextEncoder();
  const td = new TextDecoder();

  // ---------- state ----------
  let ws = null;
  let code = "";
  let helperName = "";
  let keyPair = null;
  let aesKey = null;
  let snapshot = null;
  let reqSeq = 0;
  let pingTimer = null;
  let reconnectTries = 0;
  let ended = false;
  let everConnected = false;
  const pending = new Map();
  const chunks = new Map();
  // Category edits are sent as the whole "shown" list; held back briefly so a run of
  // clicks becomes one message.
  const catTimers = {};
  const localCats = { live: null, vod: null, series: null };
  const catSearch = { live: "", vod: "", series: "" };

  const hid = (() => {
    let id = localStorage.getItem("rh-hid");
    if (!id) {
      id = [...crypto.getRandomValues(new Uint8Array(16))].map((b) => b.toString(16).padStart(2, "0")).join("");
      localStorage.setItem("rh-hid", id);
    }
    return id;
  })();

  // ---------- helpers ----------
  const b64e = (buf) => {
    const bytes = new Uint8Array(buf);
    let s = "";
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    return btoa(s);
  };
  const b64d = (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0));

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else if (v === true) node.setAttribute(k, "");
      else node.setAttribute(k, v);
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  function show(screen) {
    for (const s of ["join", "connecting", "help", "ended"]) $("screen-" + s).hidden = s !== screen;
  }

  let toastTimer = null;
  function toast(message, bad = false) {
    const t = $("toast");
    t.textContent = message;
    t.className = "toast" + (bad ? " bad" : "");
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => (t.hidden = true), bad ? 6000 : 3500);
  }

  // ---------- crypto ----------
  async function newKeys() {
    keyPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    aesKey = null;
  }

  async function publicKeyB64() {
    return b64e(await crypto.subtle.exportKey("raw", keyPair.publicKey));
  }

  async function deriveKey(peerB64) {
    const peer = await crypto.subtle.importKey("raw", b64d(peerB64), { name: "ECDH", namedCurve: "P-256" }, false, []);
    const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, keyPair.privateKey, 256);
    const hkdf = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
    aesKey = await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: te.encode("tivepg-remote-help:" + code), info: te.encode("TivEPG Remote Help v1") },
      hkdf, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
    );
  }

  async function sendEncrypted(obj) {
    if (!aesKey || !ws || ws.readyState !== WebSocket.OPEN) return false;
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, te.encode(JSON.stringify(obj)));
    const c = b64e(ct);
    const id = crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random();
    const n = Math.max(1, Math.ceil(c.length / CHUNK));
    for (let i = 0; i < n; i++) {
      ws.send(JSON.stringify({ t: "enc", id, i, n, iv: b64e(iv), c: c.slice(i * CHUNK, (i + 1) * CHUNK) }));
    }
    return true;
  }

  async function openEncrypted(ivB64, cB64) {
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(ivB64) }, aesKey, b64d(cB64));
    return JSON.parse(td.decode(plain));
  }

  // Sends a command and resolves with the device's {ok, message} reply.
  function command(type, fields = {}) {
    const req = String(++reqSeq);
    return new Promise((resolve) => {
      pending.set(req, resolve);
      sendEncrypted({ type, req, ...fields }).then((sent) => {
        if (!sent) { pending.delete(req); resolve({ ok: false, message: "Not connected right now. Trying again…" }); }
      });
      setTimeout(() => {
        if (pending.has(req)) {
          pending.delete(req);
          resolve({ ok: false, message: "Their device didn't answer. Is TivEPG still open on it?" });
        }
      }, 90000);
    });
  }

  async function run(type, fields, button) {
    if (button) button.disabled = true;
    const result = await command(type, fields);
    if (button) button.disabled = false;
    toast(result.message || (result.ok ? "Done." : "That didn't work."), !result.ok);
    return result;
  }

  // ---------- connection ----------
  async function connect() {
    clearInterval(pingTimer);
    await newKeys();
    const url = `${RELAY}?code=${code}&role=helper&hid=${hid}`;
    const socket = new WebSocket(url);
    ws = socket;

    socket.onopen = () => {
      pingTimer = setInterval(() => socket.readyState === WebSocket.OPEN && socket.send("ping"), 40000);
    };

    socket.onmessage = async (event) => {
      if (event.data === "pong") return;
      let msg;
      try { msg = JSON.parse(event.data); } catch { return; }

      if (msg.t === "peer") {
        if (msg.state === "joined") {
          socket.send(JSON.stringify({ t: "hello", pub: await publicKeyB64() }));
        } else {
          setLink(false, "Their device went offline. Waiting for it to come back…");
        }
      } else if (msg.t === "hello") {
        try {
          await deriveKey(msg.pub);
          reconnectTries = 0;
          everConnected = true;
          setLink(true);
          await sendEncrypted({ type: "hi", name: helperName });
        } catch (e) {
          fail("Couldn't set up a secure connection. Try entering the number again.");
        }
      } else if (msg.t === "enc" && aesKey) {
        const parts = chunks.get(msg.id) || [];
        parts[msg.i] = msg.c;
        if (parts.filter((p) => p !== undefined).length < msg.n) { chunks.set(msg.id, parts); return; }
        chunks.delete(msg.id);
        try {
          handle(await openEncrypted(msg.iv, parts.join("")));
        } catch (e) {
          console.warn("Remote Help: message failed to decrypt", e);
        }
      }
    };

    socket.onclose = (event) => {
      clearInterval(pingTimer);
      if (ws !== socket || ended) return;
      const reasons = {
        4003: "Someone else is already helping with this number. Ask them to stop Remote Help and start it again for a new number.",
        4004: everConnected
          ? "Remote Help was stopped on their device."
          : "That number didn't work. Check it with them: it has 6 digits and only works while Remote Help is open on their screen.",
        4008: "TivEPG Remote timed out. They can start it again for a new number.",
        4010: "They stopped Remote Help.",
        4029: "Too many tries. Wait a minute, then try again.",
      };
      if (reasons[event.code]) return fail(reasons[event.code], everConnected);
      // Network blip: try again with the same number.
      if (reconnectTries < 6) {
        reconnectTries++;
        setLink(false, "Connection lost. Reconnecting…");
        setTimeout(connect, Math.min(15000, 1000 * 2 ** reconnectTries));
      } else {
        fail("Lost the connection. Check your internet and try again.", everConnected);
      }
    };
  }

  function fail(message, wasConnected = false) {
    ended = true;
    clearInterval(pingTimer);
    try { ws && ws.close(); } catch {}
    ws = null;
    if (!wasConnected && !everConnected) {
      show("join");
      $("join-error").textContent = message;
      $("join-error").hidden = false;
      $("join").disabled = false;
      return;
    }
    $("ended-title").textContent = "Remote Help has ended";
    $("ended-text").textContent = message;
    show("ended");
  }

  function setLink(up, message) {
    const pill = $("link-pill");
    pill.textContent = up ? "Connected" : "Reconnecting";
    pill.className = "pill " + (up ? "ok" : "warn");
    if (!up && message) toast(message, true);
  }

  function handle(msg) {
    if (msg.type === "result") {
      const resolve = pending.get(String(msg.req));
      if (resolve) { pending.delete(String(msg.req)); resolve(msg); }
    } else if (msg.type === "snapshot") {
      snapshot = msg.snapshot;
      if ($("screen-help").hidden) {
        show("help"); history.replaceState({ section: null }, ""); showTab(null, false);
        // Opened from the app's "Connect to …": straight to the Remote.
        if (ownDevice) showTab("remote");
      }
      render();
    }
  }

  // ---------- join screen ----------
  function startJoin() {
    const digits = $("code").value.replace(/\D/g, "");
    if (digits.length !== 6) {
      $("join-error").textContent = "The number has 6 digits.";
      $("join-error").hidden = false;
      return;
    }
    code = digits;
    helperName = $("name").value.trim().slice(0, 30);
    if (helperName && !ownDevice) localStorage.setItem("rh-name", helperName);
    $("join-error").hidden = true;
    $("join").disabled = true;
    ended = false;
    everConnected = false;
    reconnectTries = 0;
    $("connecting-text").textContent = "Connecting to their device…";
    show("connecting");
    // Don't leave the number in the address bar (or in history) once it's been used.
    history.replaceState(null, "", location.pathname);
    connect();
  }

  $("code").addEventListener("input", (e) => {
    const d = e.target.value.replace(/\D/g, "").slice(0, 6);
    e.target.value = d.length > 3 ? d.slice(0, 3) + " " + d.slice(3) : d;
  });
  $("code").addEventListener("keydown", (e) => e.key === "Enter" && $("name").focus());
  $("name").addEventListener("keydown", (e) => e.key === "Enter" && startJoin());
  $("join").addEventListener("click", startJoin);
  $("again").addEventListener("click", () => {
    snapshot = null;
    $("code").value = "";
    $("join").disabled = false;
    show("join");
    $("code").focus();
  });

  // ---------- tabs ----------
  // App-style navigation: a home screen of cards, each opening its own page. The browser's
  // Back button returns to the cards.
  let currentTab = null;
  const SECTIONS = [
    { id: "health", title: "Check-up", icon: "#i-pulse", tint: "red" },
    { id: "playlists", title: "Playlists", icon: "#i-list", tint: "blue" },
    { id: "live", title: "TV Channels", icon: "#i-tv", tint: "blue" },
    { id: "vod", title: "Movies", icon: "#i-film", tint: "purple" },
    { id: "series", title: "Series", icon: "#i-stack", tint: "purple" },
    { id: "custom", title: "Custom Categories", icon: "#i-folder", tint: "teal" },
    { id: "sports", title: "Sports Hub", icon: "#i-trophy", tint: "green" },
    { id: "favourites", title: "Favourites & Home", icon: "#i-star", tint: "gold" },
    { id: "settings", title: "Settings", icon: "#i-gear", tint: "grey" },
    { id: "remote", title: "TivEPG Remote", icon: "#i-remote", tint: "blue" },
    { id: "selection", title: "Category & Sport Selection", icon: "#i-stack", tint: "purple" },
    { id: "copy", title: "Copy Setup", icon: "#i-copy", tint: "grey" },
  ];

  function showTab(name, push = true) {
    currentTab = name;
    document.querySelectorAll(".epg-cat-scrim").forEach((n) => n.remove());
    try { remote.guide.catMenu = false; } catch (_) {}
    const section = SECTIONS.find((x) => x.id === name);
    $("home-grid").hidden = !!name;
    document.querySelector(".device-head").hidden = !!name;
    $("section-bar").hidden = !name;
    $("section-title").textContent = section ? section.title : "";
    // The Remote is an app screen: one slim bar (back, its own tabs), sections pinned under it.
    document.body.classList.toggle("remote-app", name === "remote");
    $("remote-bar").hidden = name !== "remote";
    for (const panel of document.querySelectorAll(".tab-panel")) panel.hidden = panel.id !== "tab-" + name;
    if (push) history.pushState({ section: name, depth: 0 }, "");
    if (name === "remote") {
      navRestoring++;
      try { remoteMode(remote.mode === "goto" ? "goto" : remote.mode); } finally { navRestoring--; }
      if (push) history.replaceState({ section: "remote", depth: 0, r: navState() }, "");
      startPlayerPoll();
    }
    else if (typeof remoteRefreshEvery === "function") { remoteRefreshEvery(0); startPlayerPoll(false); }
    if (name !== "remote") { document.body.classList.remove("wide-guide", "live-on"); if (typeof liveStop === "function") liveStop(); }
    if (name !== "remote" && $("np-dock")) { $("np-dock").hidden = true; document.body.classList.remove("has-dock"); }
    window.scrollTo({ top: 0 });
    if (!name) renderHome();
    if (name === "selection") renderSelection();
  }
  $("back").addEventListener("click", () => {
    if (history.state && history.state.section) history.back(); else showTab(null);
  });
  $("home").addEventListener("click", () => { if (currentTab) showTab(null); });
  window.addEventListener("popstate", (e) => {
    if ($("screen-help").hidden) return;
    const st = e.state || {};
    if (st.section === "remote" && st.r) {
      if (currentTab === "remote") { applyNav(st.r); return; }
      navRestoring++;
      try { applyNav(st.r, true); showTab("remote", false); } finally { navRestoring--; }
      return;
    }
    showTab(st.section || null, false);
  });

  // ---------- Remote navigation: every screen is a history entry, so Back retraces your steps ----------
  let navRestoring = 0;
  const navKey = (o) => (o ? (o.key || o.id || o.code || o.name || JSON.stringify(o)) + "" : "");
  function navState() {
    const r = remote;
    return { mode: r.mode, gcat: r.guide.category, vcat: r.vod.cat, scat: r.series.cat, show: r.series.show,
             dest: r.sports.dest, ev: r.sports.event, evCode: r.sports.eventCode,
             mc: mc.open ? { id: mc.id, code: mc.code, league: mc.league } : null };
  }
  function navPush() {
    if (navRestoring || currentTab !== "remote") return;
    const r = navState();
    const cur = history.state || {};
    if (cur.r && JSON.stringify(cur.r) === JSON.stringify(r)) return;
    if (cur.section !== "remote") return;
    history.pushState({ section: "remote", depth: (cur.depth || 0) + 1, r }, "");
  }
  function navBack(fallback) {
    if (history.state && history.state.section === "remote" && history.state.depth > 0) { history.back(); return; }
    fallback();
    if (history.state && history.state.section === "remote") history.replaceState({ ...history.state, r: navState() }, "");
  }
  function applyNav(r, quiet = false) {
    navRestoring++;
    try {
      const sp = remote.sports, g = remote.guide;
      if (!r.mc && mc.open) { mc.open = false; clearTimeout(mc.timer); }
      if (r.mode !== remote.mode) { if (quiet) remote.mode = r.mode; else remoteMode(r.mode); }
      if (navKey(r.gcat) !== navKey(g.category)) {
        if (r.gcat) openGuideCategory(r.gcat); else { g.category = null; g.channels = null; remoteRefreshEvery(0); }
      }
      for (const [kind, cat] of [["vod", r.vcat], ["series", r.scat]]) {
        const st = remote[kind];
        if (navKey(cat) !== navKey(st.cat)) { if (cat) openVodCategory(kind, cat); else { st.cat = null; st.titles = null; } }
      }
      if (navKey(r.show) !== navKey(remote.series.show)) {
        if (r.show) openShow(r.show); else { remote.series.show = null; remote.series.episodes = null; }
      }
      if (r.mode === "sports" && r.dest && navKey(r.dest) !== navKey(sp.dest)) hubOpen(r.dest);
      if (navKey(r.ev) !== navKey(sp.event)) {
        if (r.ev) openSportsEvent(r.ev, r.evCode); else { sp.event = null; sp.channels = null; }
      }
      if (r.mc && !(mc.open && mc.id === r.mc.id)) openMatchCentre(r.mc.id, r.mc);
      else if (!r.mc && remote.scrollBack != null && !quiet) { renderRemote(); window.scrollTo({ top: remote.scrollBack }); remote.scrollBack = null; }
      else if (!quiet) renderRemote();
    } finally { navRestoring--; }
  }

  function cardSummary(id) {
    if (!snapshot) return "";
    const cats = (k) => ((snapshot.categories || {})[k] || []);
    const shownOf = (k) => `${cats(k).filter((c) => c.shown).length} of ${cats(k).length} shown`;
    switch (id) {
      case "health": {
        const d = healthState.data;
        if (!d) return healthState.running ? "Checking…" : "Check their setup";
        if (d.error) return "Couldn't check";
        return d.problems ? `${d.problems} thing${d.problems === 1 ? "" : "s"} to sort out` : "Everything looks good";
      }
      case "playlists": {
        const list = snapshot.servers || [];
        const off = list.filter((x) => !x.enabled).length;
        return list.length ? `${list.length} playlist${list.length === 1 ? "" : "s"}${off ? ` · ${off} off` : ""}` : "None yet: add one";
      }
      case "live": case "vod": case "series": return cats(id).length ? shownOf(id) : "Nothing loaded yet";
      case "custom": {
        const n = (snapshot.customCategories || []).length;
        return n ? `${n} categor${n === 1 ? "y" : "ies"}` : "Make your own";
      }
      case "sports": return ((snapshot.sports || {}).master || {}).subtitle || "Sports and competitions";
      case "favourites": {
        const f = (snapshot.favourites || []).length, r = (snapshot.reminders || []).length;
        return `${f} favourite channel${f === 1 ? "" : "s"}${r ? ` · ${r} reminder${r === 1 ? "" : "s"}` : ""}`;
      }
      case "settings": return "Guide, themes, player";
      case "remote": { const np = snapshot.nowPlaying || {}; return np.active ? `On now: ${np.name}` : "Guide, Sports Hub, Movies, Series"; }
      case "selection": return "TV, Movies, Series, Sports Hub";
      case "copy": return "Copy your setup to theirs";
    }
    return "";
  }

  // The home screen (simplified 10 Nov 2026): the check-up (it flags problems), then four
  // places. Categories, Sports Hub, custom categories and favourites live one level down under
  // "Category & Sport Selection"; Copy Setup is on the Playlists page.
  const HOME = ["health", "playlists", "selection", "settings", "remote"];
  const SELECTION = ["live", "vod", "series", "sports", "custom", "favourites"];
  function sectionCard(sec) {
      const summary = cardSummary(sec.id);
      const alert = sec.id === "health" && healthState.data && healthState.data.problems;
      const card = el("button", { class: "home-card tint-" + sec.tint + (alert ? " alert" : "") + (sec.id === "health" ? " home-wide" : ""), type: "button", role: "listitem" },
        el("span", { class: "home-icon" }, svgUse(sec.icon)),
        el("span", { class: "home-text" }, el("span", { class: "home-title", text: sec.title }), el("span", { class: "home-sub", text: summary })),
        alert ? el("span", { class: "home-badge", text: String(healthState.data.problems) }) : null,
        el("span", { class: "home-chev", text: "›" }));
      card.addEventListener("click", () => showTab(sec.id));
      return card;
  }
  function renderSelection() {
    const panel = $("tab-selection");
    panel.replaceChildren(
      el("p", { class: "hint", text: "What shows on their TV: channel, film and series categories, the Sports Hub, their own categories and favourites." }),
      el("div", { class: "home-grid", role: "list" }, SELECTION.map((id) => sectionCard(SECTIONS.find((x) => x.id === id)))));
  }
  function renderHome() {
    const grid = $("home-grid");
    grid.replaceChildren(...HOME.map((id) => sectionCard(SECTIONS.find((x) => x.id === id))));
    if (currentTab === "selection") renderSelection();
  }
  function svgUse(href) {
    const ns = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(ns, "svg");
    const use = document.createElementNS(ns, "use");
    use.setAttribute("href", href);
    svg.append(use);
    return svg;
  }

  // ---------- rendering ----------
  function render() {
    if (!snapshot) return;
    const device = snapshot.device || {};
    $("device-title").textContent = `Connected to their ${device.platform || "device"}`;
    const icon = device.platform === "iPhone" ? "#i-iphone" : device.platform === "iPad" ? "#i-ipad" : "#i-tv";
    $("device-icon").firstElementChild.setAttribute("href", icon);
    $("device-sub").textContent = device.appVersion ? `TivEPG ${device.appVersion}` : "";
    const loading = snapshot.loading || {};
    $("loading-banner").hidden = !loading.active;
    $("loading-banner").textContent = "Their TV is loading: " + (loading.message || "playlists and guide") + ". Lists below update when it finishes.";

    renderServers();
    renderPlaylistTools();
    for (const kind of ["live", "vod", "series"]) {
      // A pending local edit wins over the snapshot until it's been sent.
      if (!catTimers[kind]) localCats[kind] = null;
      renderCategories(kind);
    }
    renderSports();
    // A refresh from their device must not wipe what the helper is typing or dragging.
    const busy = (id) => {
      const a = document.activeElement;
      return a && $(id).contains(a) && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName);
    };
    if (!busy("tab-favourites")) renderFavourites();
    if (!busy("tab-settings") && !Object.values(settingTimers).some(Boolean)) renderSettings();
    if (!busy("tab-remote")) renderRemote();
    if (!busy("tab-copy")) renderCopy();
    if (!busy("tab-custom")) renderCustom();
    if (!currentTab || currentTab === "selection") renderHome();
    if (!healthState.requested) runHealthCheck();
    else renderHealth();
  }

  // Playlists
  const openEditors = new Set();
  const editorCache = new Map();

  // Playlists page tools (10 Nov 2026), to troubleshoot from afar: the app's Playlist
  // Auto-Refresh picker, and the TV guide - when each playlist's guide last came in, Fetch
  // (Settings > TV Guide > Fetch) and Clear (wipes it; Fetch rebuilds). Copy Setup lives here too.
  function renderPlaylistTools() {
    const box = $("playlist-tools");
    const t = snapshot.playlistTools;
    box.replaceChildren();
    if (!t) return;                                         // an older app
    const ago = (sec) => {
      const m = Math.round((Date.now() / 1000 - sec) / 60);
      return m < 2 ? "just now" : m < 60 ? `${m} min ago` : m < 48 * 60 ? `${Math.round(m / 60)} h ago` : `${Math.round(m / 1440)} days ago`;
    };
    const when = (sec) => { const h = Math.round((sec - Date.now() / 1000) / 3600); return h <= 0 ? "soon" : h < 48 ? `in about ${h} h` : `in ${Math.round(h / 24)} days`; };

    // Auto-refresh
    const pick = el("select", { "aria-label": "How often their playlists refresh" },
      (t.refreshOptions || []).map((o) => { const op = el("option", { value: o, text: o }); op.selected = o === t.refresh; return op; }));
    pick.addEventListener("change", () => run("setPlaylistRefresh", { value: pick.value }, pick));
    const refreshSub = /manual/i.test(t.refresh || "") ? "They only refresh when reloaded by hand."
      : [t.lastRefresh ? `Last refreshed ${ago(t.lastRefresh)}` : null, t.nextRefresh ? `next ${when(t.nextRefresh)}` : null].filter(Boolean).join(" · ");
    box.append(el("h4", { class: "hub-section", text: "Playlist auto-refresh" }),
      el("div", { class: "card tool-card" }, el("div", { class: "opt-row" },
        el("div", { class: "grow" }, el("div", { class: "title", text: "Refresh their playlists" }), el("div", { class: "sub", text: refreshSub || "Keeps channel lists up to date." })),
        pick)));

    // TV guide
    const guides = (t.guides || []).slice().sort((a, b) => a.name.localeCompare(b.name));
    const status = t.epgClearing ? "Clearing the guide…" : t.epgLoading ? "Fetching the guide now…" : null;
    const fetch = el("button", { class: "btn btn-white", type: "button", text: t.epgLoading ? "Fetching…" : "Fetch guide" });
    fetch.disabled = !!(t.epgLoading || t.epgClearing);
    fetch.addEventListener("click", () => run("refreshGuide", {}, fetch));
    const clear = el("button", { class: "btn danger", type: "button", text: t.epgClearing ? "Clearing…" : "Clear guide" });
    clear.disabled = !!(t.epgLoading || t.epgClearing);
    clear.addEventListener("click", () => {
      if (confirm("Clear their whole TV guide? It stays empty until it's fetched again, which can take a few minutes.")) run("clearGuide", {}, clear);
    });
    box.append(el("h4", { class: "hub-section", text: "TV guide" }),
      el("div", { class: "card tool-card" },
        status ? el("div", { class: "tool-status" }, el("span", { class: "live-dot", text: "●" }), " " + status) : null,
        guides.length ? el("div", {}, guides.map((g) => {
          const old = Date.now() / 1000 - g.at > 36 * 3600;
          return el("div", { class: "mc-fact" }, el("span", { text: g.name }),
            el("span", { class: old ? "bad-text" : "", text: `Updated ${ago(g.at)}` }));
        })) : el("p", { class: "sub", text: status ? "" : "No guide stored yet." }),
        el("p", { class: "hint tool-hint", text: "If programmes are missing or wrong, Fetch first. If that doesn't fix it, Clear, then Fetch." }),
        el("div", { class: "row-actions" }, fetch, clear)));

    // Copy Setup
    const copy = el("button", { class: "item cat-row", type: "button" },
      el("div", { class: "grow" }, el("div", { class: "title", text: "Copy your setup to theirs" }),
        el("div", { class: "sub wrap-sub", text: "Playlists, categories, favourites and Sports Hub from your own device." })),
      el("span", { class: "chev", text: "›" }));
    copy.addEventListener("click", () => showTab("copy"));
    box.append(el("h4", { class: "hub-section", text: "Copy setup" }), el("div", { class: "list" }, copy));
  }

  function renderServers() {
    const list = $("server-list");
    list.replaceChildren();
    const servers = snapshot.servers || [];
    if (!servers.length) {
      list.append(el("p", { class: "empty", text: "No playlists yet. Add one below." }));
      $("add-server").hidden = false;
    }
    const enabledCount = servers.filter((s) => s.enabled).length;

    for (const s of servers) {
      const kindLabel = s.kind === "m3u" ? "Playlist link (M3U)" : s.kind === "manifest" ? "Add-on" : "Login (Xtream Codes)";
      const status = !s.enabled ? el("span", { class: "badge off", text: "Off" })
        : s.status === "expired" ? el("span", { class: "badge bad", text: "Expired" })
        : s.status === "suspended" ? el("span", { class: "badge bad", text: "Suspended" })
        : s.status === "active" ? el("span", { class: "badge good", text: "Working" }) : null;

      const toggle = el("input", { type: "checkbox", "aria-label": "Switch on or off" });
      toggle.checked = !!s.enabled;
      toggle.disabled = s.enabled && enabledCount <= 1;
      toggle.addEventListener("change", async () => {
        const r = await run("setServerEnabled", { id: s.id, enabled: toggle.checked });
        if (!r.ok) toggle.checked = !toggle.checked;
      });

      const card = el("div", { class: "server" },
        el("div", { class: "server-head" },
          el("div", { class: "grow" },
            el("div", { class: "server-name" }, s.name || "Playlist", status),
            el("div", { class: "server-meta", text: kindLabel + (s.username ? " · " + s.username : "") })),
          el("label", { class: "switch", title: "On or off" }, toggle, el("span"))));

      if (s.kind !== "manifest") {
        // Snapshots arrive whenever the device changes something (e.g. while it loads), so
        // reuse the open form unless this playlist itself changed: typing isn't wiped.
        const sig = JSON.stringify([s.name, s.url, s.username, s.password, s.epgURL]);
        let cached = editorCache.get(s.id);
        if (!cached || cached.sig !== sig) {
          cached = { sig, node: serverEditor(s) };
          editorCache.set(s.id, cached);
        }
        const editor = cached.node;
        editor.hidden = !openEditors.has(s.id);
        const editBtn = el("button", { class: "btn small", type: "button", text: editor.hidden ? "Fix login / edit" : "Close" });
        editBtn.addEventListener("click", () => {
          editor.hidden = !editor.hidden;
          editor.hidden ? openEditors.delete(s.id) : openEditors.add(s.id);
          editBtn.textContent = editor.hidden ? "Fix login / edit" : "Close";
        });
        card.append(el("div", { class: "row-actions" }, editBtn), editor);
      }
      list.append(card);
    }
  }

  function serverEditor(s) {
    const name = el("input", { value: s.name || "", maxlength: "60" });
    const url = el("input", { value: s.url || "", autocapitalize: "off", autocorrect: "off", spellcheck: "false" });
    const epg = el("input", { value: s.epgURL || "", autocapitalize: "off", autocorrect: "off", spellcheck: "false",
      placeholder: "Leave blank to use the playlist's own guide" });
    const box = el("div", { class: "server-edit" },
      el("label", { text: "Name" }), name,
      el("label", { text: s.kind === "m3u" ? "Playlist link" : "Server address" }), url);

    let user = null, pass = null;
    if (s.kind === "xtream") {
      user = el("input", { value: s.username || "", autocapitalize: "off", autocorrect: "off", spellcheck: "false", autocomplete: "off" });
      pass = el("input", { type: "password", value: s.password || "", autocapitalize: "off", autocorrect: "off", spellcheck: "false", autocomplete: "off" });
      const reveal = el("button", { class: "btn small", type: "button", text: "Show" });
      reveal.addEventListener("click", () => {
        pass.type = pass.type === "password" ? "text" : "password";
        reveal.textContent = pass.type === "password" ? "Show" : "Hide";
      });
      box.append(el("label", { text: "Username" }), user,
                 el("label", { text: "Password" }), el("div", { class: "pass-wrap" }, pass, reveal));
    }
    box.append(el("label", {}, "TV guide link ", el("span", { class: "muted", text: "(optional)" })), epg);

    const save = el("button", { class: "btn btn-white", type: "button", text: "Save and reload" });
    save.addEventListener("click", () => {
      const fields = { id: s.id, name: name.value, url: url.value, epgURL: epg.value };
      if (user) { fields.username = user.value; fields.password = pass.value; }
      run("updateServer", fields, save);
    });
    const remove = el("button", { class: "btn danger", type: "button", text: "Remove playlist" });
    remove.addEventListener("click", () => {
      if (confirm(`Remove "${s.name}" from their device? Its channels, guide and categories will be deleted. You can add it back later.`)) {
        openEditors.delete(s.id);
        run("removeServer", { id: s.id }, remove);
      }
    });
    box.append(el("div", { class: "row-actions" }, save, remove));
    return box;
  }

  $("add-server-toggle").addEventListener("click", () => { $("add-server").hidden = !$("add-server").hidden; });
  $("add-cancel").addEventListener("click", () => { $("add-server").hidden = true; });
  $("add-kind").addEventListener("change", () => {
    const m3u = $("add-kind").value === "m3u";
    $("add-login").hidden = m3u;
    $("add-url-label").textContent = m3u ? "Playlist link" : "Server address";
    $("add-url").placeholder = m3u ? "http://example.com/get.php?username=…&type=m3u_plus" : "http://example.com:8080";
  });
  $("add-save").addEventListener("click", async () => {
    const fields = {
      kind: $("add-kind").value, name: $("add-name").value, url: $("add-url").value,
      username: $("add-user").value, password: $("add-pass").value, epgURL: $("add-epg").value,
    };
    toast("Checking the login on their device. This can take up to a minute…");
    const r = await run("addServer", fields, $("add-save"));
    if (r.ok) {
      for (const id of ["add-name", "add-url", "add-user", "add-pass", "add-epg"]) $(id).value = "";
      $("add-server").hidden = true;
    }
  });
  $("reload-all").addEventListener("click", () => run("reload", {}, $("reload-all")));

  // ---------- reordering: drag by the ⠿ handle (mouse or touch), or the Top / Bottom buttons ----------
  function moveIndex(arr, from, to) {
    const out = arr.slice();
    const [x] = out.splice(from, 1);
    out.splice(to, 0, x);
    return out;
  }

  function dragHandle(label) {
    return el("span", { class: "handle", role: "button", tabindex: "-1", "aria-label": "Drag to reorder " + label, text: "⠿" });
  }

  function moveButtons(i, n, onMove) {
    const mk = (text, aria, to, cls) => {
      const b = el("button", { class: "btn small icon " + (cls || ""), type: "button", "aria-label": aria, title: aria, text });
      b.disabled = to === i || to < 0 || to >= n;
      b.addEventListener("click", () => onMove(i, to));
      return b;
    };
    return [mk("⤒", "Move to top", 0), mk("⤓", "Move to bottom", n - 1)];
  }

  // A bin: every list's Remove, compact enough for a phone.
  const BIN_SVG = '<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/></svg>';
  function binButton(label) {
    const b = el("button", { class: "btn small icon danger bin", type: "button", "aria-label": label, title: label });
    b.innerHTML = BIN_SVG;
    return b;
  }

  // Rows must each contain a .handle. onMove(from, to) is called once, on release.
  function sortable(rows, onMove) {
    rows.forEach((row, from) => {
      const grip = row.querySelector(".handle");
      if (!grip) return;
      grip.addEventListener("pointerdown", (down) => {
        down.preventDefault();
        grip.setPointerCapture(down.pointerId);
        const rects = rows.map((r) => r.getBoundingClientRect());
        const startY = down.clientY;
        let scrolled = 0;
        let to = from;
        row.classList.add("dragging");
        let scrollTimer = null;
        let lastY = startY;

        const update = () => {
          const dy = lastY - startY + scrolled;
          row.style.transform = `translateY(${dy}px)`;
          const centre = rects[from].top + rects[from].height / 2 + dy;
          to = from;
          for (let k = 0; k < rects.length; k++) {
            const mid = rects[k].top + rects[k].height / 2;
            if (k < from && centre < mid) { to = k; break; }
            if (k > from && centre > mid) to = k;
          }
          const h = rects.length > 1 ? Math.abs(rects[1].top - rects[0].top) : rects[from].height;
          rows.forEach((r, k) => {
            if (k === from) return;
            const shift = (from < to && k > from && k <= to) ? -h : (to < from && k >= to && k < from) ? h : 0;
            r.style.transform = shift ? `translateY(${shift}px)` : "";
          });
        };
        const autoScroll = () => {
          const edge = 90;
          const v = lastY < edge ? -14 : lastY > window.innerHeight - edge ? 14 : 0;
          if (v) { window.scrollBy(0, v); scrolled += v; update(); }
        };
        const onMovePtr = (e) => { lastY = e.clientY; update(); };
        const finish = () => {
          clearInterval(scrollTimer);
          grip.removeEventListener("pointermove", onMovePtr);
          grip.removeEventListener("pointerup", finish);
          grip.removeEventListener("pointercancel", finish);
          rows.forEach((r) => { r.style.transform = ""; r.classList.remove("dragging"); });
          if (to !== from) onMove(from, to);
        };
        scrollTimer = setInterval(autoScroll, 16);
        grip.addEventListener("pointermove", onMovePtr);
        grip.addEventListener("pointerup", finish);
        grip.addEventListener("pointercancel", finish);
      });
    });
  }

  // Categories — laid out like the app's Category settings: a "Display Order" pill (what's
  // shown, in order) and one pill per playlist (Select All / Clear / Order presets, then every
  // category to switch on or off).
  const CAT_TITLES = { live: "TV channel", vod: "movie", series: "series" };
  const SORT_MODES = [{ id: "playlist", title: "Playlist Order" }, { id: "alphabetical", title: "A–Z" }];
  const catView = { live: "order", vod: "order", series: "order" };

  function catsFor(kind) {
    if (!localCats[kind]) localCats[kind] = ((snapshot.categories || {})[kind] || []).map((c) => ({ ...c }));
    return localCats[kind];
  }
  // Groups are the app's: one per playlist, then all custom categories together, Trakt, add-ons.
  const sourceOf = (c) => c.group || c.key.slice(0, c.key.indexOf("|"));
  const GROUP_RANK = { custom: 1, trakt: 2, addons: 3 };

  function sourcesFor(kind) {
    const out = [];
    const seen = new Map();
    for (const c of catsFor(kind)) {
      const id = sourceOf(c);
      if (!seen.has(id)) { seen.set(id, { id, name: c.source || "Playlist", cats: [] }); out.push(seen.get(id)); }
      seen.get(id).cats.push(c);
    }
    // Each source lists its categories in the playlist's own order, whatever is switched on.
    for (const src of out) src.cats.sort((x, y) => (x.n ?? 0) - (y.n ?? 0));
    return out.sort((x, y) => (GROUP_RANK[x.id] || 0) - (GROUP_RANK[y.id] || 0));
  }

  function queueCategorySave(kind) {
    clearTimeout(catTimers[kind]);
    catTimers[kind] = setTimeout(async () => {
      const shown = catsFor(kind).filter((c) => c.shown).map((c) => c.key);
      const r = await command("setCategories", { kind, shown });
      catTimers[kind] = null;
      toast(r.ok ? "Saved on their device." : (r.message || "Couldn't save that."), !r.ok);
    }, 700);
  }

  // Switching one on adds it at the end of its group in Display Order, as the app does. The
  // playlist's own list doesn't move: tiles stay in playlist order.
  function setShown(kind, cats, on) {
    let order = catsFor(kind).filter((x) => x.shown);
    for (const c of cats) {
      if (c.shown === on) continue;
      c.shown = on;
      if (on) {
        const src = sourceOf(c);
        let at = -1;
        order.forEach((x, i) => { if (sourceOf(x) === src) at = i; });
        order.splice(at === -1 ? order.length : at + 1, 0, c);
      } else {
        order = order.filter((x) => x !== c);
      }
    }
    localCats[kind] = [...order, ...catsFor(kind).filter((x) => !x.shown)];
    renderCategories(kind);
    queueCategorySave(kind);
  }

  function pill(label, badge, active, onClick) {
    const b = el("button", { class: "subtab" + (active ? " active" : ""), type: "button" }, label,
      badge !== null ? el("span", { class: "subtab-badge", text: String(badge) }) : null);
    b.addEventListener("click", onClick);
    return b;
  }

  function renderCategories(kind) {
    const panel = $("tab-" + kind);
    const cats = catsFor(kind);
    const word = CAT_TITLES[kind];
    const keepFocus = document.activeElement && document.activeElement.dataset.search === kind;
    panel.replaceChildren();

    if (!cats.length) {
      panel.append(el("p", { class: "empty",
        text: `No ${word} categories yet. Add a playlist first, or wait for their device to finish loading.` }));
      return;
    }
    const sources = sourcesFor(kind);
    if (catView[kind] !== "order" && !sources.some((s) => s.id === catView[kind])) catView[kind] = "order";

    const bar = el("div", { class: "subtabs" },
      pill("Display Order", cats.filter((c) => c.shown).length, catView[kind] === "order", () => { catView[kind] = "order"; renderCategories(kind); }),
      sources.map((s) => pill(s.name, s.cats.filter((c) => c.shown).length, catView[kind] === s.id,
        () => { catView[kind] = s.id; renderCategories(kind); })));
    panel.append(bar);

    if (catView[kind] === "order") {
      renderDisplayOrder(kind, panel);
    } else {
      renderSource(kind, panel, sources.find((s) => s.id === catView[kind]));
    }
    if (keepFocus) {
      const search = panel.querySelector("input[data-search]");
      if (search) { search.focus(); search.setSelectionRange(search.value.length, search.value.length); }
    }
  }

  // Display Order, grouped exactly as the app shows it: Pinned, then Custom Categories and each
  // playlist. Things move within their group (that's how the app orders them).
  const openGroups = new Set();
  function renderDisplayOrder(kind, panel) {
    const all = catsFor(kind);
    const shown = all.filter((c) => c.shown);
    panel.append(el("p", { class: "hint", text: kind === "live"
      ? "Open a group, then drag ⠿ to reorder, or use ⤒ / ⤓ to move to the top or bottom of that group · 📌 pins it to the top of their guide · the bin switches it off"
      : "The rows on their " + (kind === "vod" ? "Movies" : "Series") + " page, top to bottom. Drag ⠿ to reorder, or use ⤒ / ⤓ to move to the top or bottom · the bin switches it off" }));
    if (!shown.length) {
      panel.append(el("p", { class: "empty", text: "Nothing is switched on. Pick categories from a playlist above." }));
    }

    // Movies and Series rails follow one overall order across playlists: one list, free moves.
    if (kind !== "live") return renderFlatOrder(kind, panel, all, shown);

    const groups = [];
    const pinned = ((snapshot.displayGroups || {})[kind] || []).find((g) => g.pinned);
    const pinnedKeys = new Set(pinned ? pinned.items : []);
    if (pinned && pinned.items.length) {
      const byKey = new Map(all.map((c) => [c.key, c]));
      groups.push({ id: "pinned", title: "Pinned", pinned: true,
        cats: pinned.items.map((k, i) => byKey.get(k) || { key: k, name: (pinned.names || [])[i] || "Category", source: "" }) });
    }
    const index = new Map();
    for (const c of shown) {
      const id = sourceOf(c);
      if (!index.has(id)) { index.set(id, groups.length); groups.push({ id, title: c.source || "Playlist", cats: [] }); }
      groups[index.get(id)].cats.push(c);
    }

    // Group order as the app has it (Pinned, Trakt, Addons, Custom, then playlists).
    const deviceOrder = ((snapshot.displayGroups || {})[kind] || []).map((g) => g.id);
    const rank = (g) => g.pinned ? -1 : (deviceOrder.indexOf(g.id) === -1 ? 999 : deviceOrder.indexOf(g.id));
    groups.sort((x, y) => rank(x) - rank(y));

    if (groups.length > 1) {
      const allOpen = groups.every((g) => openGroups.has(kind + ":" + g.id));
      const toggleAll = el("button", { class: "btn small", type: "button", text: allOpen ? "Collapse all" : "Expand all" });
      toggleAll.addEventListener("click", () => {
        for (const g of groups) allOpen ? openGroups.delete(kind + ":" + g.id) : openGroups.add(kind + ":" + g.id);
        renderCategories(kind);
      });
      panel.append(el("div", { class: "row-actions tight order-tools" }, toggleAll));
    }

    for (const g of groups) {
      // Each group opens and closes; "top" and "bottom" mean the top and bottom of that group.
      const gk = kind + ":" + g.id;
      const open = openGroups.has(gk);
      const head = el("button", { class: "group-head" + (open ? " open" : ""), type: "button", "aria-expanded": open ? "true" : "false" },
        el("span", { class: "chev" + (open ? " open" : ""), text: "›" }),
        el("span", { class: "grow group-title", text: g.title }),
        el("span", { class: "subtab-badge", text: String(g.cats.length) }));
      head.addEventListener("click", () => { open ? openGroups.delete(gk) : openGroups.add(gk); renderCategories(kind); });
      panel.append(head);
      if (!open) continue;
      const list = el("div", { class: "list group-list" });
      const move = (from, to) => {
        const next = moveIndex(g.cats, from, to);
        if (!g.pinned) {
          // Put the group's members back into the same slots of the overall order, in the new order.
          const members = new Set(g.cats);
          let k = 0;
          const order = all.filter((c) => c.shown).map((c) => (members.has(c) ? next[k++] : c));
          localCats[kind] = [...order, ...all.filter((c) => !c.shown)];
        } else {
          pinned.items = next.map((c) => c.key);
          pinned.names = next.map((c) => c.name);
        }
        renderCategories(kind);
        run("reorderGroup", { kind, group: g.id, keys: next.map((c) => c.key) });
      };
      const rows = g.cats.map((c, i) => {
        // In Pinned, the lit pin unpins; elsewhere the bin switches the category off.
        let remove;
        if (g.pinned) {
          remove = el("button", { class: "btn small icon pin-btn on", type: "button", "aria-label": "Unpin", title: "Unpin from the top of the guide", text: "📌" });
          remove.addEventListener("click", () => run("unpinCategory", { key: c.key }, remove));
        } else {
          remove = binButton("Switch off " + c.name);
          remove.addEventListener("click", () => setShown(kind, [c], false));
        }
        // Pin: puts it in Pinned at the top of their guide, as the pin in the app's Display Order.
        let pin = null;
        if (!g.pinned) {
          const isPinned = pinnedKeys.has(c.key);
          pin = el("button", { class: "btn small icon pin-btn" + (isPinned ? " on" : ""), type: "button",
            title: isPinned ? "Pinned: tap to unpin" : "Pin to the top of the guide",
            "aria-label": isPinned ? "Unpin" : "Pin", text: "📌" });
          pin.addEventListener("click", () => run(isPinned ? "unpinCategory" : "pinCategory", { key: c.key }, pin));
        }
        const row = el("div", { class: "item" }, dragHandle(c.name),
          el("span", { class: "num", text: String(i + 1) }),
          el("div", { class: "grow" }, el("div", { class: "title", text: c.name })),
          ...moveButtons(i, g.cats.length, move), pin, remove);
        list.append(row);
        return row;
      });
      sortable(rows, move);
      panel.append(list);
    }
  }

  function renderFlatOrder(kind, panel, all, shown) {
    if (!shown.length) return;
    const many = new Set(shown.map(sourceOf)).size > 1;
    const list = el("div", { class: "list" });
    const move = (from, to) => {
      const next = moveIndex(shown, from, to);
      localCats[kind] = [...next, ...all.filter((c) => !c.shown)];
      renderCategories(kind);
      run("reorderGroup", { kind, group: "all", keys: next.map((c) => c.key) });
    };
    const rows = shown.map((c, i) => {
      const remove = binButton("Switch off " + c.name);
      remove.addEventListener("click", () => setShown(kind, [c], false));
      const row = el("div", { class: "item" }, dragHandle(c.name),
        el("span", { class: "num", text: String(i + 1) }),
        el("div", { class: "grow" }, el("div", { class: "title", text: c.name }),
          many ? el("div", { class: "sub", text: c.source || "" }) : null),
        ...moveButtons(i, shown.length, move), remove);
      list.append(row);
      return row;
    });
    sortable(rows, move);
    panel.append(list);
  }

  function renderSource(kind, panel, source) {
    const search = el("input", { class: "search", placeholder: "Search categories", value: catSearch[kind] });
    search.dataset.search = kind;
    search.addEventListener("input", () => { catSearch[kind] = search.value; renderCategories(kind); });

    const selectAll = el("button", { class: "btn small", type: "button", text: "✓ Select All" });
    selectAll.addEventListener("click", () => setShown(kind, source.cats, true));
    const clear = el("button", { class: "btn small danger", type: "button", text: "✕ Clear" });
    clear.addEventListener("click", () => {
      if (confirm(`Switch off every ${source.name} category?`)) setShown(kind, source.cats, false);
    });

    const mode = ((snapshot.categorySortModes || {})[kind] || {})[source.id];
    const sortRow = el("div", { class: "sort-row" }, el("span", { class: "muted small-label", text: "Order" }),
      SORT_MODES.map((m) => {
        const b = el("button", { class: "subtab" + (mode === m.id ? " active" : ""), type: "button", text: m.title });
        b.addEventListener("click", async () => {
          b.disabled = true;
          const r = await command("setCategorySort", { kind, server: source.id, mode: m.id });
          b.disabled = false;
          toast(r.ok ? `${source.name} is now in ${m.title === "A–Z" ? "A–Z" : "playlist"} order.` : (r.message || "Couldn't do that."), !r.ok);
        });
        return b;
      }));

    const isPlaylist = !GROUP_RANK[source.id];
    panel.append(el("div", { class: "source-tools" }, search, el("div", { class: "row-actions tight" }, selectAll, clear)));
    if (isPlaylist) panel.append(sortRow);

    const q = catSearch[kind].trim().toLowerCase();
    if (source.id === "custom") {
      // Custom categories: switch on/off, or delete ones they no longer want (as the Category
      // Manager on the device does).
      const manage = el("button", { class: "btn small btn-white", type: "button", text: "Create or edit custom categories ›" });
      manage.addEventListener("click", () => showTab("custom"));
      panel.append(el("div", { class: "row-actions tight" }, manage));
      panel.append(el("p", { class: "hint", text: "Switch them on or off here. Delete removes one everywhere, including their other devices through iCloud." }));
      const list = el("div", { class: "list" });
      for (const c of source.cats.filter((x) => !q || x.name.toLowerCase().includes(q))) {
        const del = el("button", { class: "btn small danger", type: "button", text: "Delete" });
        del.addEventListener("click", () => {
          if (confirm(`Delete the custom category "${c.name}" from their device? This can't be undone.`)) {
            run("deleteCustomCategory", { id: c.customID }, del);
          }
        });
        list.append(el("div", { class: "item" },
          el("div", { class: "grow" }, el("div", { class: "title", text: c.name })),
          hubSwitch(c.shown ? "on" : "off", "Show " + c.name, async () => setShown(kind, [c], !c.shown)), del));
      }
      if (!list.children.length) list.append(el("p", { class: "empty", text: "No custom categories." }));
      panel.append(list);
      return;
    }
    const matches = source.cats.filter((c) => !q || c.name.toLowerCase().includes(q));
    const LIMIT = 300;
    const grid = el("div", { class: "cat-grid" });
    if (!matches.length) grid.append(el("p", { class: "empty", text: q ? `No categories match “${catSearch[kind]}”` : "No categories." }));
    for (const c of matches.slice(0, LIMIT)) {
      const tile = el("button", { class: "cat-tile" + (c.shown ? " on" : ""), type: "button", "aria-pressed": c.shown ? "true" : "false" },
        el("span", { class: "tick", text: c.shown ? "✓" : "" }), el("span", { class: "cat-name", text: c.name }));
      tile.addEventListener("click", () => setShown(kind, [c], !c.shown));
      grid.append(tile);
    }
    panel.append(grid);
    if (matches.length > LIMIT) panel.append(el("p", { class: "more", text: `${matches.length - LIMIT} more. Search to find them.` }));
  }

  // Sports Hub — the same page as Settings › Manage Sports: All Sports, Your Hub, then each
  // sport with its competitions. Every switch runs the same code on their device.
  const sportsOpen = new Set();
  let sportsReorder = false;

  function hubSwitch(state, label, onFlip) {
    const b = el("button", { class: "hub-switch " + state, type: "button", role: "switch",
      "aria-checked": state === "on" ? "true" : state === "mixed" ? "mixed" : "false", "aria-label": label });
    b.append(el("span"));
    b.addEventListener("click", async () => { b.disabled = true; await onFlip(); b.disabled = false; });
    return b;
  }

  function star(item) {
    if (!item.favouriteID) return null;
    const b = el("button", { class: "star" + (item.favourite ? " on" : ""), type: "button",
      "aria-label": (item.favourite ? "Unfavourite " : "Favourite ") + item.name, text: item.favourite ? "★" : "☆" });
    b.addEventListener("click", () => run("sportsFavouriteCompetition", { id: item.favouriteID, favourite: !item.favourite }));
    return b;
  }

  function hubRow({ title, subtitle, subtitleClass, depth = 0, expandKey, trailing, lead }) {
    const isOpen = expandKey && sportsOpen.has(expandKey);
    const label = el("div", { class: "grow" },
      el("div", { class: "title", text: title }),
      subtitle ? el("div", { class: "sub" + (subtitleClass ? " " + subtitleClass : ""), text: subtitle }) : null);
    let main = label;
    if (expandKey) {
      main = el("button", { class: "row-expander grow", type: "button", "aria-expanded": isOpen ? "true" : "false" },
        label, el("span", { class: "chev" + (isOpen ? " open" : ""), text: "›" }));
      main.addEventListener("click", () => { isOpen ? sportsOpen.delete(expandKey) : sportsOpen.add(expandKey); renderSports(); });
    }
    return el("div", { class: "hub-row depth-" + depth }, lead || null, main, ...(trailing || []));
  }

  // A competition opens to its teams, like the app's team picker: a switch to show or hide each
  // team in the Sports Hub and a star to favourite it. Loaded from their device when opened.
  const teamCache = new Map();
  const teamSearch = new Map();
  const teamKey = (code, competition) => "teams:" + code + "|" + competition;

  async function loadTeams(code, competition) {
    const key = teamKey(code, competition);
    teamCache.set(key, { loading: true });
    const r = await command("sportsTeams", { code, competition });
    teamCache.set(key, r.ok ? r : { error: r.message || "Couldn't load the teams." });
    renderSports();
  }

  async function teamAction(type, fields) {
    const r = await run(type, fields);
    if (r.ok && r.teams) teamCache.set(teamKey(fields.code, fields.competition), r);
    renderSports();
  }

  function teamRows(code, competition, depth) {
    const key = teamKey(code, competition);
    const data = teamCache.get(key);
    if (!data || data.loading) return [el("div", { class: "hub-row depth-" + depth }, el("div", { class: "sub", text: "Loading teams…" }))];
    if (data.error) return [el("div", { class: "hub-row depth-" + depth }, el("div", { class: "sub", text: data.error }))];

    const rows = [];
    const whole = el("button", { class: "btn small" + (data.competitionFavourite ? "" : " gold-btn"), type: "button",
      text: data.competitionFavourite ? "Remove Competition" : "★ Favourite Whole Competition" });
    whole.addEventListener("click", () => teamAction("sportsFavouriteCompetition",
      { id: competition, favourite: !data.competitionFavourite, code, competition }));
    rows.push(el("div", { class: "hub-row team-tools depth-" + depth },
      el("div", { class: "grow sub", text: "The switch shows or hides a team in the Sports Hub - a shown team includes its full schedule, whatever the competition. Tap the star to favourite a team." }),
      whole));

    const teams = data.teams || [];
    let list = teams;
    if (teams.length > 20) {
      const q = teamSearch.get(key) || "";
      const search = el("input", { class: "search team-search", placeholder: `Search ${teams.length} teams`, value: q });
      search.dataset.teamsearch = key;
      search.addEventListener("input", () => { teamSearch.set(key, search.value); renderSports(); });
      rows.push(el("div", { class: "hub-row depth-" + depth }, search));
      const needle = q.trim().toLowerCase();
      if (needle) list = teams.filter((t) => t.name.toLowerCase().includes(needle));
    }
    if (!teams.length) rows.push(el("div", { class: "hub-row depth-" + depth }, el("div", { class: "sub", text: "No teams available." })));
    for (const t of list) {
      const fav = el("button", { class: "star" + (t.favourite ? " on" : ""), type: "button",
        "aria-label": (t.favourite ? "Unfavourite " : "Favourite ") + t.name, text: t.favourite ? "★" : "＋" });
      fav.addEventListener("click", () => teamAction("sportsFavouriteTeam", { team: t.name, favourite: !t.favourite, code, competition }));
      rows.push(hubRow({ title: t.name, depth, subtitle: t.shown ? "Shown in hub" : "Hidden from hub",
        trailing: [fav, hubSwitch(t.shown ? "on" : "off", "Show " + t.name + " in Sports Hub",
          () => teamAction("sportsToggleTeam", { code, competition, team: t.name }))] }));
    }
    return rows;
  }

  function withTeams(rows, code, competition, depth) {
    const key = teamKey(code, competition);
    if (sportsOpen.has(key)) {
      if (!teamCache.has(key)) loadTeams(code, competition);
      rows.push(...teamRows(code, competition, depth + 1));
    }
    return rows;
  }

  function itemRows(item, depth) {
    const rows = [];
    if (item.kind === "competition") {
      rows.push(hubRow({ title: item.name, subtitle: item.subtitle, depth,
        subtitleClass: /favourited/.test(item.subtitle) ? "gold" : "",
        expandKey: teamKey(item.code, item.name),
        trailing: [star(item), hubSwitch(item.state, "Show " + item.name,
          () => run("sportsToggleCompetition", { code: item.code, competition: item.name }))] }));
      return withTeams(rows, item.code, item.name, depth);
    }
    // A tab with several competitions opens to them; a one-competition tab opens to its teams.
    const singleComp = !item.competitions && item.favouriteID ? item.favouriteID : null;
    const key = item.competitions ? "tab:" + item.code : singleComp ? teamKey(item.code, singleComp) : null;
    rows.push(hubRow({ title: item.name, subtitle: item.loading ? "Loading…" : item.subtitle, depth, expandKey: key,
      trailing: [star(item), hubSwitch(item.state, "Show " + item.name,
        () => run("sportsShowAll", { codes: [item.code], enabled: item.state !== "on", label: item.name }))] }));
    if (item.competitions && sportsOpen.has(key)) for (const c of item.competitions) rows.push(...itemRows(c, depth + 1));
    if (singleComp) withTeams(rows, item.code, singleComp, depth);
    return rows;
  }

  function renderSports() {
    const panel = $("tab-sports");
    const focusedTeamSearch = document.activeElement && document.activeElement.dataset.teamsearch;
    const sports = snapshot.sports || {};
    panel.replaceChildren();
    if (!sports.groups) {
      panel.append(el("p", { class: "empty", text: "Their device needs the latest TivEPG update to change the Sports Hub from here." }));
      return;
    }

    const master = sports.master || {};
    panel.append(el("div", { class: "hub-card" },
      hubRow({ title: "All Sports", subtitle: master.subtitle,
        trailing: [hubSwitch(master.state || "off", "Show every league in the Sports Hub",
          () => run("sportsShowAll", { codes: master.codes || [], enabled: master.state !== "on", label: "every sport" }))] })));

    panel.append(el("h4", { class: "hub-section", text: "Your Hub" }));
    panel.append(el("div", { class: "hub-card" }, (sports.builtIns || []).map((b) =>
      hubRow({ title: b.name, subtitle: b.subtitle,
        trailing: [hubSwitch(b.enabled ? "on" : "off", "Show " + b.name, () => run("sportsToggleBuiltIn", { code: b.code }))] }))));

    const head = el("div", { class: "hub-section-row" }, el("h4", { class: "hub-section", text: sports.grouped ? "Sports" : "Sports Hub Tabs" }));
    if (sports.grouped) {
      const reorder = el("button", { class: "btn small", type: "button", text: sportsReorder ? "Done Reordering" : "Reorder Sports" });
      reorder.addEventListener("click", () => { sportsReorder = !sportsReorder; renderSports(); });
      head.append(reorder);
    }
    panel.append(head);

    const groups = sports.groups;
    const card = el("div", { class: "hub-card" });
    const sportRowsForDrag = [];
    // Moves show straight away; their device saves the same order (Manage Sports' reorder).
    const moveSport = (from, to) => {
      sports.groups = moveIndex(groups, from, to);
      renderSports();
      run("sportsOrder", { groups: sports.groups.map((x) => x.id) });
    };
    groups.forEach((g, i) => {
      const key = "sport:" + g.id;
      let trailing = [hubSwitch(g.state, "Show " + g.name,
        () => run("sportsShowAll", { codes: g.codes, enabled: g.state !== "on", label: g.name }))];
      if (sportsReorder) trailing = moveButtons(i, groups.length, moveSport);
      const row = hubRow({ title: g.name, subtitle: g.subtitle, expandKey: sportsReorder ? null : key, trailing,
        lead: sportsReorder ? dragHandle(g.name) : null });
      sportRowsForDrag.push(row);
      card.append(row);
      if (!sportsReorder && sportsOpen.has(key)) for (const item of g.items) card.append(...itemRows(item, 1));
    });
    panel.append(card);
    if (sportsReorder) sortable(sportRowsForDrag, moveSport);

    // Favourites, as the Favourites page lists them.
    panel.append(el("h4", { class: "hub-section", text: "Favourite Competitions" }));
    const comps = el("div", { class: "hub-card" });
    if (!(sports.favouriteCompetitions || []).length) comps.append(el("p", { class: "empty flat", text: "No favourite competitions. Tap ☆ on a competition above." }));
    for (const c of sports.favouriteCompetitions || []) {
      const remove = binButton("Remove " + c.name);
      remove.addEventListener("click", () => run("sportsFavouriteCompetition", { id: c.id, favourite: false }));
      comps.append(hubRow({ title: c.name, trailing: [remove] }));
    }
    panel.append(comps);

    panel.append(el("h4", { class: "hub-section", text: "Favourite Teams" }));
    const teams = el("div", { class: "hub-card" });
    if (!(sports.favouriteTeams || []).length) teams.append(el("p", { class: "empty flat", text: "No favourite teams. They can star a team in the Sports Hub." }));
    for (const name of sports.favouriteTeams || []) {
      const remove = binButton("Remove " + name);
      remove.addEventListener("click", () => run("sportsRemoveTeam", { name }));
      teams.append(hubRow({ title: name, trailing: [remove] }));
    }
    panel.append(teams);

    if (focusedTeamSearch) {
      const again = panel.querySelector(`input[data-teamsearch="${CSS.escape(focusedTeamSearch)}"]`);
      if (again) { again.focus(); again.setSelectionRange(again.value.length, again.value.length); }
    }
    panel.append(el("p", { class: "hint foot-note",
      text: "A switch shows or hides that part of the Sports Hub - blue means only some of it is shown. Your favourites always appear in Favourites, whatever is hidden here." }));
  }

  // ---------- Check-up: what's wrong, with a Fix button where there is one ----------
  const healthState = { requested: false, running: false, data: null };

  async function runHealthCheck() {
    healthState.requested = true;
    healthState.running = true;
    renderHealth();
    const r = await command("healthCheck", {});
    healthState.running = false;
    healthState.data = r.ok ? r.health : { error: r.message };
    renderHealth();
  }

  async function healthFix(fix, button) {
    switch (fix.type) {
      case "addServer":
        showTab("playlists");
        $("add-server").hidden = false;
        $("add-server").scrollIntoView({ behavior: "smooth", block: "center" });
        return;
      case "editServer":
        openEditors.add(fix.id);
        renderServers();
        showTab("playlists");
        return;
      case "enableServer":
        await run("setServerEnabled", { id: fix.id, enabled: true }, button);
        break;
      case "refreshGuide":
        await run("refreshGuide", {}, button);
        break;
      case "reload":
        await run("reload", {}, button);
        break;
      default:
        return;
    }
    setTimeout(runHealthCheck, 4000);
  }

  function renderHealth() {
    const panel = $("tab-health");
    panel.replaceChildren();
    const data = healthState.data;
    const again = el("button", { class: "btn small", type: "button", text: healthState.running ? "Checking…" : "Check again" });
    again.disabled = healthState.running;
    again.addEventListener("click", runHealthCheck);

    const problems = data && data.problems || 0;
    if (!currentTab || currentTab === "selection") renderHome();

    let headline = "Checking their setup…";
    if (data && data.error) headline = data.error;
    else if (data) headline = problems ? `${problems} thing${problems === 1 ? "" : "s"} to sort out` : "Everything looks good";
    panel.append(el("div", { class: "health-head" },
      el("div", { class: "grow" },
        el("h3", { text: headline }),
        el("p", { class: "hint", text: "We check each playlist's login and expiry, the TV guide and the app version on their device." })),
      again));
    if (healthState.running && !data) { panel.append(el("div", { class: "spinner small-spin" })); return; }
    if (!data || !data.items) return;

    const order = { error: 0, warn: 1, info: 2, ok: 3 };
    const items = [...data.items].sort((a, b) => order[a.severity] - order[b.severity]);
    const list = el("div", { class: "hub-card" });
    for (const item of items) {
      const icon = { error: "!", warn: "!", info: "i", ok: "✓" }[item.severity] || "•";
      let action = null;
      if (item.fix && item.fix.type === "info") action = el("span", { class: "sub fix-note", text: item.fix.label });
      else if (item.fix) {
        action = el("button", { class: "btn small" + (item.severity === "error" ? " btn-white" : ""), type: "button", text: item.fix.label });
        action.addEventListener("click", () => healthFix(item.fix, action));
      }
      list.append(el("div", { class: "hub-row health-" + item.severity },
        el("span", { class: "health-dot", text: icon }),
        el("div", { class: "grow" }, el("div", { class: "title wrap", text: item.title }), el("div", { class: "sub", text: item.detail })),
        action));
    }
    panel.append(list);
  }

  // ---------- Favourites & Home ----------
  function channelSearchBox(placeholder, onResults) {
    const input = el("input", { class: "search", placeholder, autocomplete: "off" });
    let timer = null;
    input.addEventListener("input", () => {
      clearTimeout(timer);
      timer = setTimeout(async () => {
        const q = input.value.trim();
        if (q.length < 2) return onResults(null);
        const r = await command("searchChannels", { query: q });
        onResults(r.ok ? r.channels : []);
      }, 350);
    });
    return input;
  }

  let favSearchResults = null;
  function renderFavourites() {
    const panel = $("tab-favourites");
    const keepFocus = document.activeElement && document.activeElement.dataset.favsearch;
    const typed = keepFocus ? document.activeElement.value : "";
    panel.replaceChildren();

    // Favourite channels
    const favs = snapshot.favourites || [];
    panel.append(el("h4", { class: "hub-section", text: "Favourite Channels" }));
    const favList = el("div", { class: "list" });
    if (!favs.length) favList.append(el("p", { class: "empty", text: "No favourite channels yet. Find one below to add it." }));
    const moveFav = (from, to) => {
      snapshot.favourites = moveIndex(favs, from, to);
      renderFavourites();
      run("favouritesOrder", { ids: snapshot.favourites.map((f) => f.id) });
    };
    const favRows = favs.map((f, i) => {
      const remove = binButton("Remove " + f.name);
      remove.addEventListener("click", () => run("removeFavourite", { id: f.id }, remove));
      const row = el("div", { class: "item" }, dragHandle(f.name),
        el("span", { class: "num", text: String(i + 1) }),
        el("div", { class: "grow" }, chanTitle(f), el("div", { class: "sub", text: f.missing ? "Not in their playlists any more" : f.source })),
        ...moveButtons(i, favs.length, moveFav), remove);
      favList.append(row);
      return row;
    });
    sortable(favRows, moveFav);
    panel.append(favList);

    const search = channelSearchBox("Search their channels to add a favourite", (results) => { favSearchResults = results; renderFavourites(); });
    search.dataset.favsearch = "1";
    search.value = typed;
    const results = el("div", { class: "list" });
    for (const c of favSearchResults || []) {
      const add = el("button", { class: "btn small", type: "button", text: c.favourite ? "★ Favourite" : "+ Add" });
      add.disabled = c.favourite;
      add.addEventListener("click", async () => { await run("addFavourite", { server: c.server, channel: c.channel }, add); c.favourite = true; renderFavourites(); });
      results.append(el("div", { class: "item" }, el("div", { class: "grow" }, chanTitle(c), el("div", { class: "sub", text: c.source })), add));
    }
    if (favSearchResults && !favSearchResults.length) results.append(el("p", { class: "empty", text: "No channels match." }));
    panel.append(el("div", { class: "card" }, el("h3", { text: "Add a favourite channel" }), search, results));
    if (keepFocus) { search.focus(); search.setSelectionRange(search.value.length, search.value.length); }

    // Home rows
    const home = snapshot.home || [];
    const homeHead = el("div", { class: "hub-section-row" }, el("h4", { class: "hub-section", text: "Home Screen Rows" }));
    const reset = el("button", { class: "btn small", type: "button", text: "Reset to standard rows" });
    reset.addEventListener("click", () => { if (confirm("Put their Home screen back to the standard rows?")) run("homeReset", {}, reset); });
    homeHead.append(reset);
    panel.append(homeHead);
    const homeList = el("div", { class: "list" });
    const moveHome = (from, to) => {
      snapshot.home = moveIndex(home, from, to);
      renderFavourites();
      run("homeOrder", { ids: snapshot.home.map((h) => h.id) });
    };
    const homeRowsEls = home.map((h, i) => {
      const remove = binButton("Remove " + h.title);
      remove.disabled = home.length <= 1;
      remove.addEventListener("click", () => run("homeRemove", { id: h.id }, remove));
      const row = el("div", { class: "item" }, dragHandle(h.title),
        el("div", { class: "grow" }, el("div", { class: "title", text: h.title }), el("div", { class: "sub", text: h.kind })),
        ...moveButtons(i, home.length, moveHome), remove);
      homeList.append(row);
      return row;
    });
    sortable(homeRowsEls, moveHome);
    panel.append(homeList);
    panel.append(el("p", { class: "hint", text: "New rows are added on their device: Home › Customise." }));

    // Reminders
    const reminders = snapshot.reminders || [];
    panel.append(el("h4", { class: "hub-section", text: "Programme Reminders" }));
    const remList = el("div", { class: "list" });
    if (!reminders.length) remList.append(el("p", { class: "empty", text: "No reminders set." }));
    for (const r of reminders) {
      const when = new Date(r.start * 1000);
      const remove = binButton("Remove reminder");
      remove.addEventListener("click", () => run("removeReminder", { key: r.key }, remove));
      remList.append(el("div", { class: "item" },
        el("div", { class: "grow" }, el("div", { class: "title", text: r.title }),
          el("div", { class: "sub", text: `${r.channel} · ${when.toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" })} ${when.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}` })),
        remove));
    }
    panel.append(remList);
  }

  // ---------- Settings: the app's own Settings pages ----------
  const settingTimers = {};
  function renderSettings() {
    const panel = $("tab-settings");
    const list = snapshot.settings;
    panel.replaceChildren();
    if (!list) {
      panel.append(el("p", { class: "empty", text: "Their device needs the latest TivEPG update to change settings from here." }));
      return;
    }
    const platform = (snapshot.device || {}).platform || "device";
    panel.append(el("div", { class: "banner device-banner", text: `These settings are for their ${platform} only. Their other devices keep their own, as in the app. Changes apply straight away.` }));
    const sections = [];
    for (const s of list) {
      let sec = sections.find((x) => x.name === s.section);
      if (!sec) { sec = { name: s.section, items: [] }; sections.push(sec); }
      sec.items.push(s);
    }
    for (const sec of sections) {
      panel.append(el("h4", { class: "hub-section", text: sec.name }));
      const card = el("div", { class: "hub-card" });
      for (const s of sec.items) card.append(settingRow(s));
      panel.append(card);
    }
  }

  function settingRow(s) {
    const save = (value, delay = 0) => {
      s.value = value;
      clearTimeout(settingTimers[s.id]);
      settingTimers[s.id] = setTimeout(async () => {
        const r = await command("setSetting", { id: s.id, value });
        settingTimers[s.id] = null;
        toast(r.ok ? `${s.title}: saved.` : (r.message || "Couldn't change that."), !r.ok);
      }, delay);
    };
    const label = el("div", { class: "grow" }, el("div", { class: "title wrap", text: s.title }), s.subtitle ? el("div", { class: "sub", text: s.subtitle }) : null);

    if (s.kind === "toggle") {
      const sw = hubSwitch(s.value ? "on" : "off", s.title, async () => {
        save(!s.value);
        sw.className = "hub-switch " + (s.value ? "on" : "off");
        sw.setAttribute("aria-checked", s.value ? "true" : "false");
      });
      return el("div", { class: "hub-row" }, label, sw);
    }
    if (s.kind === "choice") {
      const options = s.options || [];
      let control;
      if (options.length <= 4) {
        control = el("div", { class: "seg" }, options.map((o) => {
          const b = el("button", { class: "subtab" + (o.value === s.value ? " active" : ""), type: "button", text: o.label });
          b.addEventListener("click", () => {
            save(o.value);
            for (const x of control.children) x.classList.toggle("active", x === b);
          });
          return b;
        }));
      } else {
        control = el("select", { class: "setting-select", "aria-label": s.title }, options.map((o) => {
          const opt = el("option", { value: o.value, text: o.label });
          if (o.value === s.value) opt.selected = true;
          return opt;
        }));
        control.addEventListener("change", () => save(control.value));
      }
      return el("div", { class: "hub-row setting-wide" }, label, control);
    }
    // number: − value + and a slider, with the app's own labels for every step
    const steps = s.labels || [];
    const indexOf = (v) => Math.round((v - s.min) / s.step);
    const valueAt = (i) => Math.round((s.min + i * s.step) * 1000) / 1000;
    const out = el("span", { class: "setting-value", text: s.label });
    const range = el("input", { type: "range", min: "0", max: String(Math.max(0, steps.length - 1)), step: "1", value: String(indexOf(s.value)), "aria-label": s.title });
    const set = (i, delay) => {
      i = Math.max(0, Math.min(steps.length - 1, i));
      range.value = String(i);
      out.textContent = steps[i] || "";
      save(valueAt(i), delay);
    };
    const minus = el("button", { class: "btn small icon", type: "button", "aria-label": "Less", text: "−" });
    const plus = el("button", { class: "btn small icon", type: "button", "aria-label": "More", text: "+" });
    minus.addEventListener("click", () => set(Number(range.value) - 1, 250));
    plus.addEventListener("click", () => set(Number(range.value) + 1, 250));
    range.addEventListener("input", () => set(Number(range.value), 400));
    return el("div", { class: "hub-row setting-wide" }, label, el("div", { class: "stepper" }, minus, out, plus, range));
  }

  // ---------- Remote: browse their guide and Sports Hub, and put things on their screen ----------
  // Browsing here never touches their screen (changing tab stops what's playing): only Watch
  // and the Tabs buttons do anything on their device.
  const remote = {
    mode: "guide",
    guide: { groups: null, open: new Set(["pinned"]), category: null, channels: null, filter: "",
             search: null, searchFor: "", searchTimer: null },
    sports: { dest: null, events: null, view: "fixtures", filter: "All", table: null, tableTried: false, ticker: null,
              event: null, eventCode: null, channels: null, picker: false, pickSport: null, pickQuery: "" },
    // Movies and Series: categories in their tab's order, then titles, then (series) episodes.
    vod: { cats: null, cat: null, titles: null, more: false, query: "", searching: false, filter: "" },
    series: { cats: null, cat: null, titles: null, more: false, query: "", searching: false, filter: "", show: null, episodes: null, season: null },
    timer: null,
  };
  const timeText = (t) => new Date(t * 1000).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  const dayText = (t) => {
    const d = new Date(t * 1000), today = new Date();
    const diff = Math.round((new Date(d.toDateString()) - new Date(today.toDateString())) / 86400000);
    return diff === 0 ? "Today" : diff === 1 ? "Tomorrow" : d.toLocaleDateString(undefined, { weekday: "long", day: "numeric", month: "short" });
  };

  function remoteRefreshEvery(ms, fn) {
    clearInterval(remote.timer);
    remote.timer = ms ? setInterval(() => { if (currentTab === "remote" && !document.hidden) fn(); }, ms) : null;
  }

  async function remoteMode(mode, fromBar = false) {
    // Leaving the match centre from the app bar: close it, or it stays drawn over every tab.
    if (fromBar && mc.open) { mc.open = false; clearTimeout(mc.timer); document.body.classList.remove("mc-open"); }
    remote.mode = mode;
    navPush();
    remoteRefreshEvery(0);
    if (mode === "guide") {
      if (remote.guide.category) openGuideCategory(remote.guide.category, false);
      else loadGuideGroups();
    } else if (mode === "sports") {
      hubOpen(remote.sports.dest || UPCOMING_DEST);
    } else if (mode === "vod" || mode === "series") {
      if (!remote[mode].cats) loadVodCategories(mode);
    } else if (mode === "live") {
      liveStart();
    }
    if (mode !== "live") liveStop();
    renderRemote();
  }

  async function loadGuideGroups() {
    const r = await command("guideCategories", {});
    remote.guide.groups = r.ok ? r.groups : [];
    renderRemote();
  }

  async function openGuideCategory(cat, follow = true) {
    remote.guide.category = cat;
    if (follow) { remote.guide.channels = null; navPush(); }
    renderRemote();
    const load = async () => {
      const w = guideWindow();
      remote.guide.window = w;
      const r = await command("guideChannels", { key: cat.key, from: w.from, to: w.to });
      if (remote.guide.category && remote.guide.category.key === cat.key) {
        remote.guide.channels = r.ok ? r.channels : [];
        if (!busy("tab-remote")) renderRemote();
      }
    };
    await load();
    remoteRefreshEvery(60000, load);
  }

  function busy(id) {
    const a = document.activeElement;
    return a && $(id).contains(a) && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName);
  }

  function crumb(parts) {
    // parts: [label, onClick|null]...
    return el("div", { class: "crumbs" }, parts.map(([label, go], i) => {
      if (!go) return el("span", { class: "crumb current", text: label });
      const b = el("button", { class: "crumb", type: "button", text: (i === 0 ? "‹ " : "") + label });
      b.addEventListener("click", go);
      return b;
    }));
  }

  // ---------- Artwork: logos, posters, stills ----------
  // The page loads no outside images (CSP: provider art is often plain http, and nothing here
  // calls anyone else), so their DEVICE sends small `data:` thumbnails over the encrypted link
  // (`thumbnails`, at most 10 a reply). Rows draw a placeholder with the first letter at once;
  // the picture drops in when it arrives. Cached for the visit, so re-renders are instant.
  const thumbs = { cache: new Map(), pending: new Map(), running: false, off: false };
  function art(url, kind, label) {
    const box = el("span", { class: `art art-${kind}`, "aria-hidden": "true" });
    const letter = String(label || "").replace(/^(the|a)\s+/i, "").trim().charAt(0).toUpperCase();
    box.append(el("span", { class: "art-letter", text: letter }));
    if (!url || thumbs.off) return box;
    const key = kind + "|" + url;
    box.dataset.art = key;
    const hit = thumbs.cache.get(key);
    if (hit) setArt(box, hit);
    else if (hit === undefined) { thumbs.pending.set(key, { url, kind }); loadThumbs(); }
    return box;
  }
  function setArt(box, src) {
    // Keeps anything laid over the picture (an episode's progress bar).
    box.querySelectorAll(".art-letter, img").forEach((n) => n.remove());
    box.prepend(el("img", { src, alt: "", decoding: "async" }));
    box.classList.add("has-img");
  }
  async function loadThumbs() {
    if (thumbs.running) return;
    thumbs.running = true;
    await new Promise((r) => setTimeout(r, 30));            // let the whole render queue up first
    while (thumbs.pending.size && !thumbs.off) {
      const first = thumbs.pending.values().next().value;
      const batch = [...thumbs.pending.entries()].filter(([, v]) => v.kind === first.kind).slice(0, 10);
      let r;
      try { r = await command("thumbnails", { kind: first.kind, urls: batch.map(([, v]) => v.url) }); }
      catch (_) { r = { ok: false }; }
      if (!r.ok) { thumbs.off = true; break; }               // an older app: placeholders it is
      const got = r.thumbs || {};
      let progressed = false;
      for (const [key, v] of batch) {
        if (!(v.url in got)) continue;                        // over the reply budget: next round
        progressed = true;
        thumbs.pending.delete(key);
        thumbs.cache.set(key, got[v.url]);
        if (!got[v.url]) continue;
        document.querySelectorAll(`[data-art="${CSS.escape(key)}"]`).forEach((b) => setArt(b, got[v.url]));
      }
      if (!progressed) for (const [key] of batch) { thumbs.pending.delete(key); thumbs.cache.set(key, ""); }
    }
    thumbs.running = false;
  }

  // Results from several playlists: one titled block per playlist (in the order they first
  // come), like the app's own sections. One playlist: just the list.
  const collapsedSources = new Set();
  function bySource(rows, makeRow, listClass = "list", collapsible = false) {
    const order = [], groups = new Map();
    for (const r of rows) {
      const k = r.source || "";
      if (!groups.has(k)) { groups.set(k, []); order.push(k); }
      groups.get(k).push(r);
    }
    if (order.length <= 1) return [el("div", { class: listClass }, rows.map(makeRow))];
    if (collapsible) return order.map((k) => {
      const shut = collapsedSources.has(k);
      const head = el("button", { class: "source-head source-toggle", type: "button", "aria-expanded": String(!shut) },
        el("span", { class: "source-name", text: k || "Other" }),
        el("span", { class: "subtab-badge", text: String(groups.get(k).length) }),
        el("span", { class: "source-chev", text: "›" }));
      const body = el("div", { class: listClass }, groups.get(k).map(makeRow));
      const sec = el("section", { class: "source-group" + (shut ? " collapsed" : "") }, head, body);
      head.addEventListener("click", () => {
        const now = !sec.classList.toggle("collapsed");
        if (now) collapsedSources.delete(k); else collapsedSources.add(k);
        head.setAttribute("aria-expanded", String(now));
      });
      return sec;
    });
    return order.map((k) => el("section", { class: "source-group" },
      el("div", { class: "source-head" },
        el("span", { class: "source-name", text: k || "Other" }),
        el("span", { class: "subtab-badge", text: String(groups.get(k).length) })),
      el("div", { class: listClass }, groups.get(k).map(makeRow))));
  }

  // A channel's name, with the catch-up (timeshift) mark when the channel can rewind.
  function chanTitle(c) {
    return el("div", { class: "title chan-name" }, el("span", { class: "chan-text", text: c.name }),
      c.catchup ? el("span", { class: "catchup-ico", role: "img", title: "Catch-up: can rewind and watch earlier programmes", "aria-label": "Catch-up" }) : null);
  }

  // The row that's on their screen says so ("Playing"), like the app's own lists.
  function isOnScreen(key) {
    const np = nowPlaying();
    return !!(np.active && np.key && np.key === key);
  }
  function channelRow(c, extra) {
    const on = isOnScreen(c.server + "|" + c.channel);
    const watch = el("button", { class: "btn small " + (on ? "btn-playing" : "btn-white"), type: "button", text: on ? "Playing" : "▶ Watch" });
    watch.addEventListener("click", () => run("playChannel", { server: c.server, channel: c.channel, ...(extra || {}) }, watch).then(() => setTimeout(pollPlayer, 1500)));
    let progress = null;
    if (c.nowStart && c.nowEnd) {
      const pct = Math.max(0, Math.min(100, ((Date.now() / 1000 - c.nowStart) / (c.nowEnd - c.nowStart)) * 100));
      const bar = el("span", { class: "prog-fill" });
      bar.style.width = pct + "%";
      progress = el("span", { class: "prog" }, bar);
    }
    return el("div", { class: "item chan with-art" },
      art(c.image, "logo", c.name),
      el("div", { class: "grow" },
        chanTitle(c),
        c.now ? el("div", { class: "now-line" }, el("span", { class: "now-title", text: c.now }),
          c.nowEnd ? el("span", { class: "sub", text: ` · until ${timeText(c.nowEnd)}` }) : null) : el("div", { class: "sub", text: c.source || "No guide information" }),
        progress,
        c.next ? el("div", { class: "sub", text: `Next: ${c.next} · ${timeText(c.nextStart)}` }) : null),
      watch);
  }

  function renderRemote() {
    const panel = $("tab-remote");
    document.body.classList.toggle("wide-guide", currentTab === "remote" && remote.mode === "guide" && !mc.open && guideIsGrid());
    const keepFocus = document.activeElement && document.activeElement.dataset.remotefilter;
    panel.replaceChildren();
    document.querySelectorAll(".epg-cat-scrim").forEach((n) => n.remove());
    document.body.classList.toggle("mc-open", !!mc.open);
    if (mc.open) { renderMatchCentre(panel); return; }

    // On their screen now, with the player's controls while something plays.
    const np = nowPlaying();
    renderNowPlaying(ensureDock());

    const modes = el("div", { class: "remote-modes", role: "tablist" },
      pill("📺 Guide", null, remote.mode === "guide", () => remoteMode("guide", true)),
      pill("🏆 Sports Hub", null, remote.mode === "sports", () => remoteMode("sports", true)),
      pill("📡 Live", null, remote.mode === "live", () => remoteMode("live", true)),
      tabOn("Movies") ? pill("🎬 Movies", null, remote.mode === "vod", () => remoteMode("vod", true)) : null,
      tabOn("Series") ? pill("🎞️ Series", null, remote.mode === "series", () => remoteMode("series", true)) : null,
      pill("Tabs", null, remote.mode === "goto", () => remoteMode("goto", true)));
    const scrollX = ($("remote-bar").firstChild || {}).scrollLeft || 0;
    $("remote-bar").replaceChildren(modes);
    modes.scrollLeft = scrollX;
    requestAnimationFrame(() => {
      const on = modes.querySelector(".active");
      if (on && (on.offsetLeft < modes.scrollLeft || on.offsetLeft + on.offsetWidth > modes.scrollLeft + modes.clientWidth)) on.scrollIntoView({ inline: "center", block: "nearest" });
    });

    if (remote.mode === "goto") {
      // Their tabs, as their app shows them (only the ones switched on).
      const tabs = snapshot.tabs || ["Home", "Guide", "Series", "Movies", "Sports Hub", "Settings"];
      panel.append(el("p", { class: "hint", text: np.active
        ? "Switches the tab on their screen. This stops what's playing."
        : "Switches the tab on their screen." }));
      const ICONS = { "Home": "🏠", "Guide": "📺", "Series": "🎞️", "Movies": "🎬", "Sports Hub": "🏆", "Settings": "⚙️" };
      const list = el("div", { class: "list" });
      for (const tab of tabs) {
        const here = snapshot.currentTab === tab;
        const row = el("button", { class: "item cat-row" + (here ? " current-tab" : ""), type: "button" },
          el("span", { class: "tab-ico", text: ICONS[tab] || "•" }),
          el("span", { class: "grow title", text: tab }),
          here ? el("span", { class: "subtab-badge", text: "On screen" }) : el("span", { class: "chev", text: "›" }));
        row.addEventListener("click", () => {
          if (here && !(np.active && np.fullScreen)) return;
          if (np.active && !confirm(`Switch them to ${tab}? This stops ${np.name}.`)) return;
          run("goTo", { tab }, row);
        });
        list.append(row);
      }
      panel.append(list);
      return;
    }

    document.body.classList.toggle("live-on", remote.mode === "live" && currentTab === "remote" && !mc.open);
    if (remote.mode === "live") { renderLive(panel); return; }
    if (remote.mode === "guide") renderRemoteGuide(panel);
    else if (remote.mode === "vod" || remote.mode === "series") renderRemoteVod(panel, remote.mode);
    else renderRemoteSports(panel);

    if (keepFocus) {
      const f = panel.querySelector("input[data-remotefilter]");
      if (f) { f.focus(); f.setSelectionRange(f.value.length, f.value.length); }
    }
  }


  // ---------- SportsHub Live: the player's L-frame, full screen, for a laptop or iPad ----------
  // The same frame the app draws around the picture (rail on the right, strip along the bottom,
  // scores band, goal alert), with the picture's space given to every live game in their hub.
  // Tap a game: its stats fill the rail. Data from the device (`liveBoard`: live games, the
  // LATEST GOALS board, today's results and fixtures, live tables) and `matchCentre` for a game.
  const live = { data: null, timer: null, round: 0, tables: [], seen: null, focus: null, focusData: null, tab: "Scores",
                 filter: "All", flash: null, flashTimer: null, wake: null, focusTimer: null };
  function liveStart() {
    clearTimeout(live.timer);
    const load = async () => {
      const wantTables = live.round % 4 === 0;
      live.round++;
      const r = await command("liveBoard", { tables: wantTables });
      if (remote.mode !== "live") return;
      if (r.ok) {
        // A goal nobody's seen yet (not on the first load): the alert, as the TV's.
        const ids = new Set((r.goals || []).map((g) => g.id));
        if (live.seen) {
          const fresh = (r.goals || []).filter((g) => !live.seen.has(g.id) && g.kind === "goal");
          if (fresh.length) liveFlash(fresh[0]);
        }
        live.seen = ids;
        live.data = r;
        if (r.tables) live.tables = r.tables;
      } else if (!live.data) live.data = { error: r.message || "Their app doesn't have SportsHub Live on the Remote yet. Update TivEPG on it." };
      if (currentTab === "remote" && !busy("tab-remote")) renderRemote();
      live.timer = setTimeout(load, document.hidden ? 60000 : 30000);
    };
    load();
    liveWake(true);
  }
  function liveStop() {
    clearTimeout(live.timer); clearTimeout(live.focusTimer); live.timer = null;
    liveWake(false);
  }
  // Keep a laptop awake while Live is up (Screen Wake Lock, where the browser has it).
  async function liveWake(on) {
    try {
      if (on && "wakeLock" in navigator && !live.wake) { live.wake = await navigator.wakeLock.request("screen"); live.wake.addEventListener("release", () => { live.wake = null; }); }
      if (!on && live.wake) { await live.wake.release(); live.wake = null; }
    } catch (_) {}
  }
  document.addEventListener("visibilitychange", () => { if (!document.hidden && remote.mode === "live" && currentTab === "remote") liveWake(true); });

  function liveFlash(g) {
    live.flash = g;
    clearTimeout(live.flashTimer);
    live.flashTimer = setTimeout(() => { live.flash = null; if (remote.mode === "live") renderRemote(); }, 6000);
  }
  async function liveFocus(ev) {
    live.focus = ev; live.focusData = null; live.tab = "Stats";
    renderRemote();
    clearTimeout(live.focusTimer);
    const load = async () => {
      if (!live.focus || live.focus.id !== ev.id) return;
      const r = await command("matchCentre", { fixture: ev.id, league: ev.league, table: false });
      if (!live.focus || live.focus.id !== ev.id) return;
      if (r.ok) live.focusData = r.match;
      if (remote.mode === "live" && !busy("tab-remote")) renderRemote();
      live.focusTimer = setTimeout(load, 20000);
    };
    load();
  }
  const liveColor = (c, f) => { const v = String(c || "").replace(/^#/, ""); return /^[0-9a-f]{6}$/i.test(v) ? "#" + v : f; };
  const liveShortLeague = (l) => { const s = String(l || ""); const w = s.split(/\s+/); return w.length > 1 ? w.map((x) => x[0]).join("").slice(0, 4).toUpperCase() : s.slice(0, 4).toUpperCase(); };

  function renderLive(panel) {
    const d = live.data;
    const frame = el("div", { class: "shl" });
    panel.append(frame);
    if (!d) { frame.append(el("div", { class: "shl-empty" }, el("p", { text: "Loading SportsHub Live…" }))); return; }
    if (d.error) { frame.append(el("div", { class: "shl-empty" }, el("p", { text: d.error }))); return; }
    const games = d.live || [];
    const np = nowPlaying();

    // ---- Centre: every live game, by league, with filters ----
    const centre = el("div", { class: "shl-centre" });
    const leagues = ["All", ...new Set(games.map((g) => g.league))];
    if (!leagues.includes(live.filter)) live.filter = "All";
    const fs = el("button", { class: "shl-fs", type: "button", title: "Full screen", text: "⛶ Full screen" });
    fs.addEventListener("click", () => {
      if (document.fullscreenElement) document.exitFullscreen();
      else (document.documentElement.requestFullscreen || document.documentElement.webkitRequestFullscreen || (() => {})).call(document.documentElement);
    });
    centre.append(el("div", { class: "shl-hdr" },
      el("span", { text: `SPORTSHUB LIVE · ${games.length ? games.length + " LIVE IN YOUR HUB" : "NOTHING LIVE RIGHT NOW"}` }),
      el("span", { class: "shl-hint", text: games.length ? "Tap a game for its stats" : "" }), fs));
    if (leagues.length > 2) {
      const chips = el("div", { class: "shl-filters" });
      for (const l of leagues) {
        const b = el("button", { class: live.filter === l ? "on" : "", type: "button", text: l });
        b.addEventListener("click", () => { live.filter = l; renderRemote(); });
        chips.append(b);
      }
      centre.append(chips);
    }
    const grid = el("div", { class: "shl-grid" });
    const shown = games.filter((g) => live.filter === "All" || g.league === live.filter);
    let lg = "";
    const tile = (g, kind) => {
      const lead = hubLead(g), trail = hubTrail(g);
      const [a, b] = hubScores(g);
      const t = el("button", { class: "shl-g" + (live.focus && live.focus.id === g.id ? " sel" : "") + (np.fixtureID && String(np.fixtureID) === String(g.id) ? " ontv" : "")
        + (live.flash && live.flash.leading && (live.flash.leading === lead.name || live.flash.trailing === lead.name) ? " hot" : ""), type: "button" });
      t.style.setProperty("--c1", liveColor(g.awayFirst ? g.awayColor : g.homeColor, "#3a5bd0"));
      t.style.setProperty("--c2", liveColor(g.awayFirst ? g.homeColor : g.awayColor, "#8a93a6"));
      t.append(el("div", { class: "shl-t1" }, el("span", { text: g.league }),
        el("span", { class: kind === "live" ? "mn" : "", text: kind === "live" ? hubClock(g) : kind === "done" ? hubDone(g) : timeText(g.kickoff) })));
      if (g.tournament) t.append(el("div", { class: "shl-rw" }, el("span", { text: g.home || g.league })));
      else t.append(el("div", {},
        el("div", { class: "shl-rw" }, hubCrest(lead.logo, lead.name, "xs"), el("span", { class: "nm", text: lead.name }), el("b", { text: kind === "upcoming" ? "" : a ?? "" })),
        el("div", { class: "shl-rw" }, hubCrest(trail.logo, trail.name, "xs"), el("span", { class: "nm", text: trail.name }), el("b", { text: kind === "upcoming" ? "" : b ?? "" }))));
      t.append(el("div", { class: "shl-last", text: np.fixtureID && String(np.fixtureID) === String(g.id) ? "● On their TV" : g.last || g.round || "" }));
      t.addEventListener("click", () => liveFocus(g));
      return t;
    };
    for (const g of shown) {
      if (g.league !== lg) { lg = g.league; grid.append(el("div", { class: "shl-lg" }, hubCrest(g.leagueLogo, g.league, "xs"), el("span", { text: g.league }))); }
      grid.append(tile(g, "live"));
    }
    if (!games.length) {
      // Nothing live: today's results and what's still to come keep the screen useful.
      const today = d.today || [], done = d.results || [];
      if (today.length) { grid.append(el("div", { class: "shl-lg" }, el("span", { text: "LATER TODAY" }))); today.slice(0, 18).forEach((g) => grid.append(tile(g, "upcoming"))); }
      if (done.length) { grid.append(el("div", { class: "shl-lg" }, el("span", { text: "RESULTS" }))); done.slice(0, 18).forEach((g) => grid.append(tile(g, "done"))); }
      if (!today.length && !done.length) grid.append(el("p", { class: "shl-none", text: "Nothing live or coming up today in their hub." }));
    }
    centre.append(grid);

    // ---- Rail ----
    const rail = el("aside", { class: "shl-rail" });
    rail.append(el("div", { class: "shl-ident" }, el("span", { class: "shl-mark", text: "T" }),
      el("span", { class: "shl-word" }, "SportsHub ", el("em", { text: "Live" })), el("span", { class: "shl-livetag", text: "LIVE" }),
      el("span", { class: "shl-clk", text: new Date().toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }) })));
    const f = live.focus;
    const tabs = f ? ["Stats", "Events", "Table"] : ["Scores", "Tables", "Latest"];
    if (!tabs.includes(live.tab)) live.tab = tabs[0];
    rail.append(el("div", { class: "shl-tabs" }, tabs.map((t) => {
      const b = el("button", { class: "shl-tab" + (live.tab === t ? " on" : ""), type: "button", text: t });
      b.addEventListener("click", () => { live.tab = t; renderRemote(); });
      return b;
    })));
    const body = el("div", { class: "shl-rbody" });
    rail.append(body);
    const goalRow = (g) => el("div", { class: "shl-ev" },
      el("span", { class: "m", text: g.minute || "" }),
      el("span", { class: "k " + (g.kind || "goal"), text: g.kind === "red" ? "" : g.kind === "goal" ? "⚽" : "•" }),
      el("div", {}, el("div", { text: g.scorer || "Goal" }), el("div", { class: "s", text: `${g.leading} ${g.score || "v"} ${g.trailing} · ${g.competition}` })));
    if (f) {
      const back = el("button", { class: "shl-back", type: "button", text: "‹ All live games" });
      back.addEventListener("click", () => { live.focus = null; live.focusData = null; clearTimeout(live.focusTimer); live.tab = "Scores"; renderRemote(); });
      const lead = hubLead(f), trail = hubTrail(f), [a, b] = hubScores(f);
      body.append(back, el("div", { class: "shl-gh" },
        el("span", { class: "mn", text: `${f.league} · ${f.state === "live" ? hubClock(f) : f.state === "finished" ? hubDone(f) : timeText(f.kickoff)}` }),
        el("span", { class: "nm", text: lead.name }), el("span", { class: "sc", text: f.state === "upcoming" ? "v" : `${a ?? ""}–${b ?? ""}` }), el("span", { class: "nm", text: trail.name })));
      const md = live.focusData;
      if (!md) body.append(el("p", { class: "shl-s", text: "Loading…" }));
      else if (live.tab === "Stats") mcStats(body, md);
      else if (live.tab === "Events") mcSummary(body, md);
      else {
        const t = (live.tables || []).find((x) => x.league === f.league);
        body.append(t ? liveTableEl(t, [lead.name, trail.name]) : el("p", { class: "shl-s", text: "No table for this one." }));
      }
      const watch = el("button", { class: "shl-watch", type: "button", text: "▶ Watch on TV" });
      watch.addEventListener("click", () => { remote.mode = "sports"; liveStop(); openSportsEvent(f, "UPCOMING"); });
      body.append(watch);
    } else if (live.tab === "Scores") {
      body.append(el("div", { class: "shl-sec", text: `ALL LIVE · ${games.length}` }));
      if (!games.length) body.append(el("p", { class: "shl-s", text: "Nothing live right now." }));
      for (const g of games) {
        const lead = hubLead(g), trail = hubTrail(g), [a, b] = hubScores(g);
        const r = el("button", { class: "shl-ev shl-score", type: "button" },
          el("div", {}, el("div", {}, `${lead.name} `, el("b", { text: `${a ?? ""}–${b ?? ""}` }), ` ${trail.name}`), el("div", { class: "s", text: g.league })),
          el("span", { class: "m live", text: hubClock(g) }));
        r.addEventListener("click", () => liveFocus(g));
        body.append(r);
      }
      if ((d.results || []).length) {
        body.append(el("div", { class: "shl-sec", text: "RESULTS TODAY" }));
        for (const g of d.results.slice(0, 20)) {
          const lead = hubLead(g), trail = hubTrail(g), [a, b] = hubScores(g);
          const r = el("button", { class: "shl-ev shl-score", type: "button" },
            el("div", {}, el("div", {}, `${lead.name} `, el("b", { text: `${a ?? ""}–${b ?? ""}` }), ` ${trail.name}`), el("div", { class: "s", text: g.league })),
            el("span", { class: "m", text: hubDone(g) }));
          r.addEventListener("click", () => liveFocus(g));
          body.append(r);
        }
      }
    } else if (live.tab === "Tables") {
      if (!live.tables.length) body.append(el("p", { class: "shl-s", text: "Tables load with the next update…" }));
      for (const t of live.tables) body.append(liveTableEl(t, []));
    } else {
      body.append(el("div", { class: "shl-sec", text: "LATEST GOALS" }));
      const gl = d.goals || [];
      if (!gl.length) body.append(el("p", { class: "shl-s", text: "No goals yet." }));
      gl.slice(0, 30).forEach((g) => body.append(goalRow(g)));
    }

    // ---- Strip: SportsHub Live block + the LATEST GOALS board, the scores band ----
    const strip = el("div", { class: "shl-strip" });
    const goalsTotal = games.reduce((n, g) => n + (Number(g.homeScore) || 0) + (Number(g.awayScore) || 0), 0);
    const nLeagues = new Set(games.map((g) => g.league)).size;
    const board = el("div", { class: "shl-board" },
      el("div", { class: "bh" }, el("span", { text: "P302" }), el("span", { text: "LATEST GOALS" }),
        el("span", { text: new Date().toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }) })));
    const gl = (d.goals || []).filter((g) => g.kind === "goal").slice(0, 5);
    if (!gl.length) board.append(el("div", { class: "br" }, el("span", { text: "No goals yet" })));
    gl.forEach((g, i) => board.append(el("div", { class: "br" },
      el("span", { class: "t", text: g.leading }), el("span", { class: "s", text: (g.score || "v").replace("–", "-") }), el("span", { class: "t", text: g.trailing }),
      el("span", { class: "w", text: `${g.scorer} ${g.minute}` }), el("span", { class: "nw", text: i === 0 && Date.now() / 1000 - g.at < 600 ? "NEW" : "" }))));
    strip.append(el("div", { class: "shl-stop" },
      el("div", { class: "shl-hub" }, el("div", { class: "t" }, "SportsHub ", el("em", { text: "Live" })),
        el("div", { class: "n" }, el("span", {}, el("b", { text: String(games.length) }), "live"), el("span", {}, el("b", { text: String(goalsTotal) }), "goals"), el("span", {}, el("b", { text: String(nLeagues) }), "leagues"))),
      board));
    const band = el("div", { class: "shl-band" }, el("div", { class: "bl", text: "● SCORES" }));
    const chips = () => [...games, ...(d.results || []).slice(0, 12)].map((g) => {
      const lead = hubLead(g), trail = hubTrail(g), [a, b] = hubScores(g);
      return el("span", { class: "shl-chip" }, el("span", { class: "lg", text: liveShortLeague(g.league) }),
        el("span", { class: "bar" }), `${shortTeam(lead.name)} `, el("b", { text: `${a ?? ""}–${b ?? ""}` }), ` ${shortTeam(trail.name)}`,
        el("span", { class: g.state === "live" ? "mn" : "ft", text: g.state === "live" ? hubClock(g) : hubDone(g) }));
    });
    const lane = el("div", { class: "shl-lane" }, el("div", { class: "run" }, chips()), el("div", { class: "run", "aria-hidden": "true" }, chips()));
    lane.style.setProperty("--dur", Math.max(30, (games.length + Math.min(12, (d.results || []).length)) * 6) + "s");
    band.append(el("div", { class: "shl-belt" }, lane));
    strip.append(band);
    if (live.flash) {
      const g = live.flash;
      strip.append(el("div", { class: "shl-flash" }, el("div", { class: "big", text: "GOAL" }),
        el("div", { class: "who" }, `${g.scorer} ${g.minute}`, el("small", { text: `${g.leading} ${g.score || ""} ${g.trailing} · ${g.competition}` }))));
    }

    frame.append(centre, rail, strip);
  }
  function liveTableEl(t, mine) {
    const box = el("div", { class: "shl-tbl" }, el("div", { class: "shl-sec", text: `${t.league}${t.live ? " · LIVE TABLE" : ""}`.toUpperCase() }));
    const tb = el("table", {});
    for (const r of t.rows) {
      tb.append(el("tr", { class: mine.includes(r.team) ? "me" : "" },
        el("td", { class: "rk", text: String(r.rank) }), el("td", {}, hubCrest(r.logo, r.team, "xs"), " ", r.team),
        el("td", { class: "n", text: String(r.played) }), el("td", { class: "p", text: String(r.points) })));
    }
    box.append(tb);
    return box;
  }

  // ---------- The playing controls: a remote for whatever is on ----------
  // Polled every few seconds while the Remote is open; the snapshot fills in between.
  const fmtTime = (sec) => {
    sec = Math.max(0, Math.floor(sec || 0));
    const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), x = sec % 60;
    return (h ? h + ":" + String(m).padStart(2, "0") : m) + ":" + String(x).padStart(2, "0");
  };
  function nowPlaying() {
    const fresh = remote.player && Date.now() - remote.playerAt < 8000;
    return (fresh ? remote.player : snapshot.nowPlaying) || {};
  }
  async function pollPlayer() {
    if (currentTab !== "remote" || document.hidden || remote.scrubbing) return;
    const r = await command("playerState", {});
    if (!r.ok || !r.player) return;
    const before = (remote.player || {}).active ? remote.player.key : null;
    remote.player = r.player;
    remote.playerAt = Date.now();
    // Something else went on (or it stopped): the lists' "Playing" moves with it.
    const after = r.player.active ? r.player.key : null;
    if (before !== after && !busy("tab-remote") && !remote.scrubbing) { renderRemote(); return; }
    const box = $("np-box");
    const a = document.activeElement;
    if (box && !(a && box.contains(a) && a.tagName === "SELECT")) renderNowPlaying(box);
  }
  function startPlayerPoll(on = true) {
    clearInterval(remote.playerTimer);
    remote.playerTimer = on ? setInterval(pollPlayer, 3000) : null;
    if (on) pollPlayer();
  }
  // A control: sends it, then reads the player straight back so the card catches up.
  async function control(fields, button) {
    await run("player", fields, button);
    setTimeout(pollPlayer, 700);
    setTimeout(pollPlayer, 2500);
  }
  function ctl(label, title, fields, cls) {
    const b = el("button", { class: "btn ctl " + (cls || ""), type: "button", "aria-label": title, title, text: label });
    b.addEventListener("click", () => control(fields, b));
    return b;
  }

  // ---------- Match centre: the app's match screen, on the phone ----------
  // `matchCentre` returns the device's own detail record. The match on THEIR screen comes held
  // to their picture (StreamSyncEngine.present on the device), so nothing here runs ahead of
  // their TV. Polled while open: 5s for a synced live match, 20s live, 60s otherwise.
  const mc = { open: false, id: null, code: null, league: null, data: null, table: null, synced: false, delay: null,
               tab: null, pickedTab: false, lineupSide: "home", innings: null, groupsAll: false, timer: null, error: null };

  function openMatchCentre(id, opts = {}) {
    Object.assign(mc, { open: true, id, code: opts.code || null, league: opts.league || null, data: null, table: null,
                        synced: false, delay: null, tab: null, pickedTab: false, lineupSide: "home", innings: null, groupsAll: false, error: null,
                        highlight: opts.highlight || null });
    remote.scrollBack = window.scrollY;
    navPush();
    renderRemote();
    window.scrollTo({ top: 0 });
    loadMatchCentre(true);
  }
  function closeMatchCentre() {
    mc.open = false;
    clearTimeout(mc.timer);
    renderRemote();
    if (remote.scrollBack) window.scrollTo({ top: remote.scrollBack });
  }
  async function loadMatchCentre(first = false) {
    clearTimeout(mc.timer);
    if (!mc.open) return;
    // Away from the Remote (or the page hidden): wait, don't keep asking their device.
    if (!first && (currentTab !== "remote" || document.hidden)) { mc.timer = setTimeout(() => loadMatchCentre(), 5000); return; }
    const id = mc.id;
    const r = await command("matchCentre", { fixture: id, code: mc.code, league: mc.league, table: first || !mc.table });
    if (!mc.open || mc.id !== id) return;
    if (r.ok) {
      mc.data = r.match;
      if (r.table) mc.table = r.table;
      mc.synced = !!r.synced;
      mc.delay = r.delay ?? null;
      if (r.highlight) mc.highlight = r.highlight;
      mc.error = null;
    } else if (!mc.data) {
      mc.error = r.message || "Couldn't load that match.";
    }
    if (currentTab === "remote" && !document.hidden && !busy("tab-remote")) renderRemote();
    const live = mc.data && mcState(mc.data) === "in";
    mc.timer = setTimeout(() => loadMatchCentre(), live ? (mc.synced ? 5000 : 20000) : 60000);
  }

  // ----- reading the record -----
  const mcState = (f) => (f.status && (f.status.state || (f.status.short === "FT" ? "post" : null))) || "pre";
  const mcIsLive = (f) => mcState(f) === "in";
  const mcIsDone = (f) => mcState(f) === "post";
  const isSport = (f, s) => String(f.sport || "").toLowerCase() === s;
  function mcStatusText(f) {
    const st = f.status || {};
    if (f.cricket) {
      if (f.cricket.inBreak && f.cricket.breakLabel) return f.cricket.breakLabel;
      if (mcIsLive(f)) return f.cricket.dayLabel || "Live";
    }
    if (mcIsLive(f)) {
      const d = String(st.description || st.detail || "");
      if (/half/i.test(d) && /time/i.test(d) || st.short === "HT") return "Half time";
      return st.clock && st.clock !== "0'" ? st.clock : (d || "Live");
    }
    if (mcIsDone(f)) return st.description && st.description.length < 14 ? st.description : "Full time";
    const t = Date.parse(f.startTime) / 1000;
    return isNaN(t) ? "" : `${dayText(t)} · ${timeText(t)}`;
  }
  const sideOf = (f, e) => {
    const id = String(e.teamId || "");
    if (id && f.home && String(f.home.id || "").replace(/^\D+-/, "") === id.replace(/^\D+-/, "")) return "home";
    if (id && f.away && String(f.away.id || "").replace(/^\D+-/, "") === id.replace(/^\D+-/, "")) return "away";
    if (e.team && f.home && e.team === f.home.name) return "home";
    if (e.team && f.away && e.team === f.away.name) return "away";
    return null;
  };
  const evKind = (e) => {
    const t = String(e.type || "").toLowerCase();
    if (/own goal/.test(t)) return "og";
    if (/penalty.*(scored|goal)/.test(t)) return "pen";
    if (/penalty.*(missed|saved)/.test(t)) return "penmiss";
    if (/goal|touchdown|field goal|try\b|home run/.test(t) || e.scoringPlay) return "goal";
    if (/red card|second yellow/.test(t)) return "red";
    if (/yellow/.test(t)) return "yellow";
    if (/substitution|sub\b/.test(t)) return "sub";
    if (/var|disallowed/.test(t)) return "var";
    return "other";
  };
  const EV_ICON = { goal: "⚽", pen: "⚽", og: "⚽", penmiss: "✕", red: "", yellow: "", sub: "⇄", var: "VAR", other: "•" };
  const minuteNum = (e) => {
    const m = String(e.time || "").match(/(\d+)(?:'?\s*\+\s*(\d+))?/);
    return m ? Number(m[1]) + (m[2] ? Number(m[2]) / 100 : 0) : 0;
  };
  function teamColor(t, fallback, key = "color") {
    const c = String((t && t[key]) || "").replace(/^#?/, "#");
    return /^#[0-9a-f]{6}$/i.test(c) && !/^#(000000|ffffff)$/i.test(c) ? c : fallback;
  }
  // The two sides' colours, the away one swapped when they'd read as the same (the app's
  // clash rule): its second colour, else a neutral blue.
  function mcColors(f) {
    const rgb = (h) => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
    const hsl = (h) => {
      const [r, g, b] = rgb(h).map((v) => v / 255), mx = Math.max(r, g, b), mn = Math.min(r, g, b), d = mx - mn;
      const hue = d === 0 ? 0 : mx === r ? ((g - b) / d) % 6 : mx === g ? (b - r) / d + 2 : (r - g) / d + 4;
      return { h: (hue * 60 + 360) % 360, s: d === 0 ? 0 : d / (1 - Math.abs(mx + mn - 1)) };
    };
    // Same at a glance: close in RGB, or the same hue family when both are strong colours
    // (United's red and Villa's claret are far apart in RGB and still both "red").
    const near = (a, b) => {
      const x = rgb(a), y = rgb(b);
      if (Math.hypot(x[0] - y[0], x[1] - y[1], x[2] - y[2]) < 120) return true;
      const p = hsl(a), q = hsl(b), dh = Math.min(Math.abs(p.h - q.h), 360 - Math.abs(p.h - q.h));
      return p.s > 0.35 && q.s > 0.35 && dh < 28;
    };
    const home = teamColor(f.home, "#1E7CFF");
    let away = teamColor(f.away, "#E5484D");
    if (near(home, away)) {
      const alt = teamColor(f.away, null, "altColor");
      away = alt && !near(home, alt) ? alt : near(home, "#5FB7E6") ? "#E8EDF5" : "#5FB7E6";
    }
    return { home, away };
  }
  // ESPN's stat labels as the app shows them.
  const STAT_NAMES = { "shots": "Shots", "on goal": "Shots on target", "corner kicks": "Corners", "on target %": "Shot accuracy",
    "effective tackles": "Tackles won", "effective clearances": "Clearances", "accurate passes": "Accurate passes" };
  const statName = (raw) => {
    const k = String(raw || "").toLowerCase();
    if (STAT_NAMES[k]) return STAT_NAMES[k];
    return raw === String(raw).toUpperCase() ? k.charAt(0).toUpperCase() + k.slice(1) : raw;
  };
  const shortName = (n) => String(n || "").split(" ").length > 1 ? String(n).split(" ").slice(-1)[0] : String(n || "");

  // ----- the screen -----
  function renderMatchCentre(panel) {
    panel.append(crumb([["Remote", () => navBack(closeMatchCentre)], ["Match centre", null]]));
    const f = mc.data;
    if (!f) {
      panel.append(el("p", { class: "empty", text: mc.error || "Loading the match…" }));
      return;
    }
    panel.append(mcHeader(f));
    const h = mc.highlight;
    if (h && h.clips && h.clips.length) {
      panel.append(el("div", { class: "card mc-card mc-highlights" },
        el("div", { class: "mc-card-title" }, hubPlayIcon(), " Highlights"),
        el("div", { class: "mc-hl-body" }, hlKitArt(h, "card"), el("div", { class: "mc-hl-sources" }, h.clips.map((c) => clipButtons(c, h))))));
    }
    const tabs = mcTabs(f);
    if (!mc.pickedTab || !tabs.some((t) => t.id === mc.tab)) mc.tab = mcDefaultTab(f, tabs);
    panel.append(el("div", { class: "mc-tabs" }, tabs.map((t) => {
      const b = el("button", { class: "mc-tab" + (t.id === mc.tab ? " active" : ""), type: "button", text: t.title });
      b.addEventListener("click", () => { mc.tab = t.id; mc.pickedTab = true; renderRemote(); });
      return b;
    })));
    const body = el("div", { class: "mc-body" });
    panel.append(body);
    ({ summary: mcSummary, stats: mcStats, scorecard: mcScorecard, lineups: mcLineups, table: mcTable, h2h: mcH2H })[mc.tab](body, f);
  }

  function mcTabs(f) {
    const tabs = [{ id: "summary", title: "Summary" }];
    const hasStats = f.stats && (f.stats.home || []).length;
    const matchTitle = mcIsLive(f) ? "Live" : mcIsDone(f) ? "Match" : "Stats";
    if (!f.cricket || !(f.cricket.scorecard || []).length) tabs.push({ id: "stats", title: hasStats || !f.cricket ? matchTitle : "Stats" });
    if (f.cricket && (f.cricket.scorecard || []).length) tabs.push({ id: "scorecard", title: "Scorecard" });
    if (f.lineups && ((f.lineups.home || []).length || (f.lineups.away || []).length)) tabs.push({ id: "lineups", title: "Lineups" });
    if (mcTableRows().length) tabs.push({ id: "table", title: /basketball|baseball|american football|hockey/.test(String(f.sport).toLowerCase()) ? "Standings" : "Table" });
    const adv = f.advanced || {};
    if ((adv.headToHead || []).length || Object.keys(adv.form || {}).length) tabs.push({ id: "h2h", title: "H2H & Form" });
    return tabs;
  }
  function mcDefaultTab(f, tabs) {
    const has = (id) => tabs.some((t) => t.id === id);
    if (f.cricket && mcIsLive(f) && !f.cricket.inBreak && has("scorecard")) return "scorecard";
    if (mcIsLive(f) && has("stats")) return "stats";
    if (mcIsDone(f) && has("lineups")) return "lineups";
    return "summary";
  }

  function mcHeader(f) {
    const { home: hc, away: ac } = mcColors(f);
    const head = el("div", { class: "mc-head" });
    head.style.setProperty("--home", hc);
    head.style.setProperty("--away", ac);
    const adv = f.advanced || {}, gi = adv.gameInfo || {};
    const round = gi.round ? (isNaN(gi.round) ? gi.round : `Matchweek ${gi.round}`) : (f.cricket && f.cricket.matchTitle) || "";
    head.append(el("div", { class: "mc-league" }, art(f.leagueLogo, "logo", f.league),
      el("span", { class: "grow", text: [f.league, round].filter(Boolean).join(" · ") })));

    const live = mcIsLive(f), done = mcIsDone(f), pre = !live && !done;
    // Cricket: each side's innings in cricket notation sits under its own name ("434/9d",
    // "114/3 (27.1 ov)"), the batting side's brighter.
    const cline = (side) => f.cricket && f.cricket[side] && f.cricket[side].scoreLine;
    const batting = f.cricket && String(f.cricket.battingTeamId || "");
    const team = (t, side) => el("div", { class: `mc-team ${side}` }, art(t.logo, "logo", t.name), el("div", { class: "mc-team-name", text: t.name }),
      f.cricket ? el("div", { class: "mc-cricket-line" + (batting && String(t.id) === batting ? " batting" : ""), text: cline(side) || "Yet to bat" }) : null);
    let middle;
    if (f.cricket) {
      middle = el("div", { class: "mc-mid" }, el("div", { class: "mc-vs", text: "v" }));
    } else if (pre) {
      const t = Date.parse(f.startTime) / 1000;
      middle = el("div", { class: "mc-mid" }, el("div", { class: "mc-kickoff", text: isNaN(t) ? "TBC" : timeText(t) }));
    } else {
      const s = f.score || {};
      middle = el("div", { class: "mc-mid" }, el("div", { class: "mc-score" },
        el("span", { text: String(s.home ?? 0) }), el("span", { class: "mc-dash", text: "–" }), el("span", { text: String(s.away ?? 0) })));
    }
    head.append(el("div", { class: "mc-board" }, team(f.home, "home"), middle, team(f.away, "away")));
    const statusCls = live ? (f.cricket && f.cricket.inBreak ? "mc-status brk" : "mc-status live") : "mc-status";
    head.append(el("div", { class: "mc-status-row" }, el("span", { class: statusCls, text: mcStatusText(f) })));
    if (f.cricket && (f.cricket.detail || f.cricket.summary)) head.append(el("div", { class: "mc-situation", text: f.cricket.detail || f.cricket.summary }));

    // Scorers under each side, the app's broadcast style.
    if (!f.cricket) {
      const goals = (f.events || f.timeline || []).filter((e) => ["goal", "pen", "og"].includes(evKind(e)));
      const col = (side) => el("div", { class: `mc-scorers ${side}` }, goals.filter((e) => {
        const s = sideOf(f, e);
        return evKind(e) === "og" ? s !== side && s : s === side;
      }).map((e) => el("div", { text: `${shortName(e.player)} ${e.time || ""}${evKind(e) === "pen" ? " (P)" : evKind(e) === "og" ? " (OG)" : ""}` })));
      if (goals.length) head.append(el("div", { class: "mc-scorer-row" }, col("home"), el("span", { class: "mc-ball", text: "⚽" }), col("away")));
    }
    if (mc.synced) head.append(el("div", { class: "mc-sync" }, el("span", { class: "mc-sync-dot" }),
      `Synced to their TV${mc.delay != null ? ` · ${Math.abs(mc.delay)}s ${mc.delay >= 0 ? "behind" : "ahead of"} the live data` : ""}`));
    return head;
  }

  // ----- Summary: key events, then the match facts -----
  function mcSummary(body, f) {
    const evs = (f.timeline && f.timeline.length ? f.timeline : f.events || []).filter((e) => evKind(e) !== "other" || e.scoringPlay);
    if (f.cricket) {
      const c = f.cricket;
      const card = el("div", { class: "card mc-card" }, el("div", { class: "mc-card-title", text: "Match" }));
      if (c.playerOfMatch && c.playerOfMatch.name) card.append(mcFact("Player of the match", [c.playerOfMatch.name, c.playerOfMatch.team].filter(Boolean).join(" · ")));
      if (c.toss) card.append(mcFact("Toss", c.toss.replace(/\s+,/g, ",")));
      if (c.series) card.append(mcFact("Series", c.series));
      if (c.hoursOfPlay) card.append(mcFact("Hours of play", c.hoursOfPlay));
      if (card.children.length > 1) body.append(card);
      const notes = c.dayNotes || [];
      if (notes.length) body.append(el("div", { class: "card mc-card" }, el("div", { class: "mc-card-title", text: "Day by day" }),
        ...notes.map((n) => el("div", { class: "mc-note", text: n.replace(/^day (\d+)\s*-\s*/i, "Day $1 · ") }))));
    } else if (evs.length) {
      const sorted = evs.slice().sort((a, b) => (a.period || 0) - (b.period || 0) || minuteNum(a) - minuteNum(b));
      const list = el("div", { class: "mc-timeline" });
      let lastPeriod = null;
      for (const e of sorted) {
        if (lastPeriod !== null && e.period !== lastPeriod) list.append(el("div", { class: "mc-period", text: isSport(f, "soccer") && lastPeriod === 1 ? "Half time" : `End of period ${lastPeriod}` }));
        lastPeriod = e.period;
        const side = sideOf(f, e), kind = evKind(e);
        const icon = el("span", { class: `mc-ev-icon ${kind}`, text: EV_ICON[kind] });
        let main = e.player || e.type, sub = kind === "sub" ? (e.assist ? `off: ${e.assist}` : "") : kind === "goal" && e.assist ? `assist: ${e.assist}` : kind === "pen" ? "Penalty" : kind === "og" ? "Own goal" : "";
        if (kind === "sub" && !e.assist && e.description) {
          const m = String(e.description).match(/(.+?) replaces (.+?)[.,]/i);
          if (m) { main = m[1].replace(/^Substitution,?\s*[^.]*\.\s*/i, ""); sub = `off: ${m[2]}`; }
        }
        const text = el("div", { class: "mc-ev-text" }, el("div", { class: "mc-ev-main", text: main }), sub ? el("div", { class: "sub", text: sub }) : null);
        const score = e.homeScore != null && e.awayScore != null ? el("span", { class: "mc-ev-score", text: `${e.homeScore}–${e.awayScore}` }) : null;
        list.append(el("div", { class: `mc-ev ${side || "mid"}` },
          el("div", { class: "mc-ev-side home" }, side === "home" ? [text, score] : null),
          el("div", { class: "mc-ev-min" }, el("span", { text: e.time || "" }), icon),
          el("div", { class: "mc-ev-side away" }, side === "away" ? [score, text] : null)));
      }
      if (mcIsDone(f)) list.append(el("div", { class: "mc-period", text: "Full time" }));
      body.append(el("div", { class: "card mc-card" }, el("div", { class: "mc-card-title", text: "Key events" }), list));
    } else {
      body.append(el("p", { class: "empty", text: mcIsLive(f) || mcIsDone(f) ? "No key events yet." : "Key events appear here once it starts." }));
    }

    // Recent form strip (the app's summary carries it too)
    const form = (f.advanced || {}).form || {};
    const formRow = (t) => {
      const key = Object.keys(form).find((k) => String(t.id || "").endsWith(k));
      const list = key ? form[key] : null;
      return list && list.length ? el("div", { class: "mc-form-row" }, art(t.logo, "logo", t.name), el("span", { class: "grow mc-form-name", text: t.name }),
        el("span", { class: "mc-form" }, list.slice(0, 5).map((x) => el("span", { class: `mc-wdl ${x.result}`, text: x.result })))) : null;
    };
    const fr = [formRow(f.home), formRow(f.away)].filter(Boolean);
    if (fr.length) body.append(el("div", { class: "card mc-card" }, el("div", { class: "mc-card-title", text: "Form" }), ...fr));

    // Venue + match facts
    const gi = (f.advanced || {}).gameInfo || {}, v = gi.venue || {};
    const facts = [];
    if (v.name) facts.push(["Venue", [v.name, v.city].filter(Boolean).join(", ")]);
    if (v.capacity) facts.push(["Capacity", Number(v.capacity).toLocaleString()]);
    if (gi.attendance) facts.push(["Attendance", Number(gi.attendance).toLocaleString()]);
    const ref = (gi.officials || []).map((o) => (typeof o === "string" ? o : o.name)).filter(Boolean);
    if (ref.length) facts.push(["Referee", ref[0]]);
    if (f.cricket && f.cricket.venue && !v.name) facts.push(["Venue", f.cricket.venue]);
    const t = Date.parse(f.startTime) / 1000;
    const startWord = f.cricket ? (mcIsDone(f) ? "Played" : "Start of play") : mcIsDone(f) ? "Played" : "Kick-off";
    if (!isNaN(t)) facts.push([startWord, `${dayText(t)} · ${timeText(t)}`]);
    if (facts.length || v.thumb) {
      const card = el("div", { class: "card mc-card mc-venue" });
      if (v.thumb) card.append(art(v.thumb, "venue", v.name));
      card.append(...facts.map(([k, val]) => mcFact(k, val)));
      body.append(card);
    }
  }
  const shortDate = (iso) => {
    const d = new Date(String(iso || "").slice(0, 10) + "T12:00:00");
    if (isNaN(d)) return iso || "";
    return d.toLocaleDateString(undefined, { day: "numeric", month: "short", ...(d.getFullYear() !== new Date().getFullYear() ? { year: "numeric" } : {}) });
  };
  const mcFact = (k, v) => el("div", { class: "mc-fact" }, el("span", { class: "sub", text: k }), el("span", { text: v }));

  // ----- Stats: bars in the app's order -----
  const STAT_ORDER = ["expected goals", "xg", "possession", "shots", "on goal", "shots on target", "big chances", "corner kicks", "corners",
    "fouls", "yellow cards", "red cards", "offsides", "saves", "passes", "pass completion %", "accurate passes", "tackles", "interceptions", "clearances", "crosses", "long balls", "blocked shots"];
  function mcStats(body, f) {
    const home = (f.stats && f.stats.home) || [], away = (f.stats && f.stats.away) || [];
    if (!home.length) {
      const t = Date.parse(f.startTime) / 1000;
      body.append(el("div", { class: "card mc-card mc-countdown" },
        el("div", { class: "mc-card-title", text: mcIsDone(f) ? "No statistics for this match" : "Statistics start at kick-off" }),
        !isNaN(t) && !mcIsDone(f) ? el("div", { class: "title-lg", text: `${dayText(t)} · ${timeText(t)}` }) : null));
      return;
    }
    const byLabel = (list) => new Map(list.map((s) => [String(s.label || s.name).toLowerCase(), s]));
    const hm = byLabel(home), am = byLabel(away);
    const labels = [...hm.keys()].filter((k) => am.has(k));
    labels.sort((a, b) => {
      const ia = STAT_ORDER.indexOf(a), ib = STAT_ORDER.indexOf(b);
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib);
    });
    const num = (s) => parseFloat(String(s.value).replace(/[^\d.\-]/g, "")) || 0;
    const fmt = (label, s) => {
      const n = num(s);
      if (/%|possession/.test(label)) return (n <= 1 && !/possession/.test(label) ? Math.round(n * 100) : Math.round(n)) + "%";
      return String(s.value);
    };
    const { home: hc, away: ac } = mcColors(f);
    const card = el("div", { class: "card mc-card mc-stats" },
      el("div", { class: "mc-stats-head" }, art(f.home.logo, "logo", f.home.name), el("span", { class: "mc-card-title grow", text: "Team stats" }), art(f.away.logo, "logo", f.away.name)));
    for (const label of labels.slice(0, 24)) {
      const h = hm.get(label), a = am.get(label);
      const hv = num(h), av = num(a), total = hv + av || 1;
      const hb = el("span", { class: "mc-bar-fill home" }), ab = el("span", { class: "mc-bar-fill away" });
      hb.style.width = (hv / total) * 100 + "%";
      ab.style.width = (av / total) * 100 + "%";
      hb.style.background = hc; ab.style.background = ac;
      if (hv < av) hb.classList.add("dim"); else if (av < hv) ab.classList.add("dim");
      card.append(el("div", { class: "mc-stat" },
        el("div", { class: "mc-stat-row" }, el("strong", { text: fmt(label, h) }), el("span", { class: "mc-stat-label", text: statName(h.label || h.name) }), el("strong", { text: fmt(label, a) })),
        el("div", { class: "mc-bar" }, el("span", { class: "mc-bar-half home" }, hb), el("span", { class: "mc-bar-half away" }, ab))));
    }
    body.append(card);
  }

  // ----- Line-ups: the pitch -----
  function posLine(code) {
    const c = String(code || "").toUpperCase();
    if (/^G/.test(c)) return 0;
    if (/^(CD|CB|D|LB|RB|LWB|RWB|SW|DEF)/.test(c)) return 1;
    if (/^(DM|CDM)/.test(c)) return 2;
    if (/^(AM|CAM|LAM|RAM)/.test(c)) return 4;
    if (/^(F|CF|ST|S|LW|RW|LF|RF|FW)/.test(c)) return 5;
    return 3;
  }
  function posX(code) {
    const c = String(code || "").toUpperCase();
    if (/^(LB|LWB|LM|LW|LF|LAM)/.test(c) || /-L$/.test(c) && /^L/.test(c)) return 0;
    if (/^(RB|RWB|RM|RW|RF|RAM)/.test(c)) return 4;
    if (/-L$/.test(c)) return 1;
    if (/-R$/.test(c)) return 3;
    return 2;
  }
  const mcWideMQ = window.matchMedia("(min-width: 900px)");
  const mcWide = () => mcWideMQ.matches;
  mcWideMQ.addEventListener("change", () => { if (mc.open && currentTab === "remote" && !busy("tab-remote")) renderRemote(); });
  function mcLineups(body, f) {
    const L = f.lineups || {};
    const sides = ["home", "away"].filter((s) => (L[s] || []).length);
    // Room for both: the two teams side by side, each pitch then its bench.
    if (mcWide() && sides.length === 2) {
      const grid = el("div", { class: "mc-two" });
      for (const s of sides) { const col = el("div", { class: "mc-col" }); mcLineupSide(col, f, s); grid.append(col); }
      body.append(grid);
      return;
    }
    if (!sides.includes(mc.lineupSide)) mc.lineupSide = sides[0];
    body.append(el("div", { class: "subtabs mc-side-pick" }, sides.map((s) => {
      const t = f[s];
      const b = el("button", { class: "subtab" + (mc.lineupSide === s ? " active" : ""), type: "button" }, art(t.logo, "logo", t.name), ` ${t.name}`);
      b.addEventListener("click", () => { mc.lineupSide = s; renderRemote(); });
      return b;
    })));
    if (sides.length) mcLineupSide(body, f, mc.lineupSide);
  }
  function mcLineupSide(body, f, side) {
    const L = f.lineups || {};
    const team = f[side], players = L[side] || [];
    const starters = players.filter((p) => p.starter !== false).slice(0, 11);
    const bench = players.filter((p) => !starters.includes(p));
    // Goals / cards / subs per player, from the (held) timeline.
    const evs = (f.timeline && f.timeline.length ? f.timeline : f.events || []);
    const marks = (p) => {
      const n = String(p.name || "").toLowerCase(), last = shortName(p.name).toLowerCase();
      const mine = evs.filter((e) => { const who = String(e.player || "").toLowerCase(); return who && (who === n || (last.length > 3 && who.endsWith(last))); });
      const out = [];
      for (const e of mine) {
        const k = evKind(e);
        if (["goal", "pen"].includes(k)) out.push(el("span", { class: "pm goal", text: "⚽" }));
        else if (k === "yellow") out.push(el("span", { class: "pm yellow" }));
        else if (k === "red") out.push(el("span", { class: "pm red" }));
      }
      if (p.subbedOut) out.push(el("span", { class: "pm off", text: "▼" }));
      if (p.subbedIn) out.push(el("span", { class: "pm on", text: "▲" }));
      return out;
    };
    const colour = mcColors(f)[side];
    const soccerish = isSport(f, "soccer") || starters.some((p) => /^(G|CD|CB|LB|RB|CM|CF|AM|DM)/i.test(p.position || ""));
    const formation = L[side + "Formation"];
    if (soccerish && starters.length >= 7) {
      const lines = new Map();
      for (const p of starters) {
        const ln = posLine(p.position);
        if (!lines.has(ln)) lines.set(ln, []);
        lines.get(ln).push(p);
      }
      const pitch = el("div", { class: "mc-pitch" }, el("div", { class: "mc-pitch-lines" }));
      pitch.style.setProperty("--kit", colour);
      const rows = [...lines.keys()].sort((a, b) => b - a);              // attack at the top
      rows.forEach((ln, i) => {
        const row = el("div", { class: "mc-pitch-row" });
        row.style.top = 8 + (i / Math.max(1, rows.length - 1)) * 80 + "%";
        lines.get(ln).sort((a, b) => posX(a.position) - posX(b.position)).forEach((p) => {
          row.append(el("div", { class: "mc-player" },
            el("span", { class: "mc-shirt" + (ln === 0 ? " gk" : ""), text: p.number || "" }, el("span", { class: "mc-marks" }, marks(p))),
            el("span", { class: "mc-player-name", text: shortName(p.name) })));
        });
        pitch.append(row);
      });
      body.append(el("div", { class: "card mc-card mc-pitch-card" },
        el("div", { class: "mc-card-title" }, `${team.name}${formation ? " · " + formation : ""}`), pitch));
    } else {
      body.append(el("div", { class: "card mc-card" }, el("div", { class: "mc-card-title", text: `${team.name} · starters` }),
        ...starters.map((p) => mcPlayerRow(p, marks(p)))));
    }
    if (bench.length) {
      body.append(el("div", { class: "card mc-card" }, el("div", { class: "mc-card-title", text: "Substitutes" }),
        ...bench.map((p) => mcPlayerRow(p, marks(p)))));
    }
  }
  const mcPlayerRow = (p, marks) => el("div", { class: "mc-player-row" },
    el("span", { class: "mc-num", text: p.number || "" }), el("span", { class: "grow", text: p.name }),
    el("span", { class: "mc-marks inline" }, marks), el("span", { class: "sub", text: /^sub/i.test(p.position || "") ? "" : p.position || "" }));

  // ----- Table -----
  function mcTableRows() {
    const t = mc.table;
    if (!t) return [];
    if (t.groups && t.groups.length) return t.groups;
    return t.table && t.table.length ? [{ name: "", table: t.table }] : [];
  }
  function mcTable(body, f) {
    const groups = mcTableRows();
    const ids = [f.home, f.away].map((t) => String(t.id || "").replace(/^\D+-/, ""));
    const names = [f.home.name, f.away.name];
    const ours = (r) => ids.includes(String(r.team.id || "").replace(/^\D+-/, "")) || names.includes(r.team.name);
    const mine = groups.filter((g) => g.table.some(ours));
    const shown = mc.groupsAll || !mine.length ? groups : mine;
    const noDraws = groups.every((g) => g.table.every((r) => !r.drawn));
    for (const g of shown) {
      const table = el("table", { class: "mc-league-table" },
        el("thead", {}, el("tr", {}, el("th", { text: "#" }), el("th", { class: "team", text: "Team" }), el("th", { text: "P" }),
          el("th", { text: "W" }), noDraws ? null : el("th", { text: "D" }), el("th", { text: "L" }), el("th", { text: isSport(f, "soccer") ? "GD" : "+/-" }), el("th", { text: "Pts" }))),
        el("tbody", {}, g.table.map((r) => el("tr", { class: ours(r) ? "ours" : "" },
          el("td", { text: String(r.rank) }),
          el("td", { class: "team" }, art(r.team.logo, "logo", r.team.name), el("span", { text: r.team.name })),
          el("td", { text: String(r.played) }), el("td", { text: String(r.won) }), noDraws ? null : el("td", { text: String(r.drawn) }),
          el("td", { text: String(r.lost) }), el("td", { text: (r.goalsDiff > 0 ? "+" : "") + Math.round(r.goalsDiff) }), el("td", { class: "pts", text: String(r.points) })))));
      body.append(el("div", { class: "card mc-card mc-table-card" }, g.name ? el("div", { class: "mc-card-title", text: g.name }) : null, table));
    }
    if (mine.length && mine.length < groups.length) {
      const b = el("button", { class: "btn small", type: "button", text: mc.groupsAll ? "Just their group" : "Every group" });
      b.addEventListener("click", () => { mc.groupsAll = !mc.groupsAll; renderRemote(); });
      body.append(el("div", { class: "row-actions center-row" }, b));
    }
  }

  // ----- H2H & Form -----
  function mcH2H(outer, f) {
    // Form for each team and the head to head sit side by side when there's room.
    const body = el("div", { class: "mc-grid" });
    outer.append(body);
    const adv = f.advanced || {};
    const form = adv.form || {};
    for (const t of [f.home, f.away]) {
      const key = Object.keys(form).find((k) => String(t.id || "").endsWith(k));
      const list = key ? form[key] : [];
      if (!list.length) continue;
      body.append(el("div", { class: "card mc-card" },
        el("div", { class: "mc-card-title" }, art(t.logo, "logo", t.name), ` ${t.name} · last ${list.length}`),
        ...list.map((x) => el("div", { class: "mc-form-game" }, el("span", { class: `mc-wdl ${x.result}`, text: x.result }),
          el("div", { class: "grow" }, el("div", { text: `v ${x.opponent}` }), el("div", { class: "sub", text: [x.league, shortDate(x.date)].filter(Boolean).join(" · ") })),
          el("strong", { text: x.score })))));
    }
    const h2h = adv.headToHead || [];
    if (h2h.length) {
      body.append(el("div", { class: "card mc-card" }, el("div", { class: "mc-card-title", text: "Head to head" }),
        ...h2h.map((g) => el("div", { class: "mc-form-game" },
          el("div", { class: "grow" }, el("div", {}, el("strong", { text: g.homeTeam }), ` ${g.score}`),
            el("div", { class: "sub", text: [g.league, shortDate(g.date)].filter(Boolean).join(" · ") })),
          g.winner ? el("span", { class: "subtab-badge", text: g.winner === "Draw" ? "Draw" : shortName(g.winner) }) : null))));
    }
  }

  // ----- Cricket scorecard -----
  function mcScorecard(body, f) {
    const cards = (f.cricket && f.cricket.scorecard) || [];
    if (!cards.length) { body.append(el("p", { class: "empty", text: "No scorecard yet." })); return; }
    const current = ((f.cricket.innings || []).find((i) => i.isCurrent) || {}).number;
    if (!cards.some((c) => c.number === mc.innings)) mc.innings = current || cards[cards.length - 1].number;
    body.append(el("div", { class: "subtabs" }, cards.map((c) => {
      const total = (f.cricket.innings || []).find((i) => i.number === c.number);
      const b = el("button", { class: "subtab" + (c.number === mc.innings ? " active" : ""), type: "button",
        text: `${shortName(c.teamName) || "Innings " + c.number}${total ? " " + (total.allOut ? total.runs : `${total.runs}/${total.wickets}`) : ""}` });
      b.addEventListener("click", () => { mc.innings = c.number; renderRemote(); });
      return b;
    })));
    const c = cards.find((x) => x.number === mc.innings);
    const bat = el("table", { class: "mc-cricket" },
      el("thead", {}, el("tr", {}, el("th", { class: "team", text: "Batter" }), el("th", { text: "R" }), el("th", { text: "B" }), el("th", { text: "4s" }), el("th", { text: "6s" }), el("th", { text: "SR" }))),
      el("tbody", {}, (c.batting || []).map((b) => el("tr", { class: b.out === false ? "notout" : "" },
        el("td", { class: "team" }, el("div", { text: b.name + (b.out === false ? "*" : "") }), b.dismissal ? el("div", { class: "sub", text: b.dismissal }) : null),
        el("td", { class: "pts", text: String(b.runs) }), el("td", { text: String(b.balls) }), el("td", { text: String(b.fours) }), el("td", { text: String(b.sixes) }), el("td", { text: b.strikeRate || "" })))));
    const bowl = el("table", { class: "mc-cricket" },
      el("thead", {}, el("tr", {}, el("th", { class: "team", text: "Bowler" }), el("th", { text: "O" }), el("th", { text: "M" }), el("th", { text: "R" }), el("th", { text: "W" }), el("th", { text: "Econ" }))),
      el("tbody", {}, (c.bowling || []).map((b) => el("tr", {},
        el("td", { class: "team", text: b.name }), el("td", { text: b.overs }), el("td", { text: String(b.maidens) }), el("td", { text: String(b.runs) }),
        el("td", { class: "pts", text: String(b.wickets) }), el("td", { text: b.economy || "" })))));
    body.append(el("div", { class: "card mc-card mc-table-card" }, el("div", { class: "mc-card-title", text: `${c.teamName || ""} batting` }), bat),
      el("div", { class: "card mc-card mc-table-card" }, el("div", { class: "mc-card-title", text: "Bowling" }), bowl));
  }

  // ---------- Catch-up scrub bar ----------
  // Right = live, left = as far back as the span shows (2h / 6h / 24h, capped at the channel's
  // catch-up window). Dragging shows the time and the programme there; letting go rewinds
  // their TV to it (`timeshiftTo`). The guide's programmes for the span come from the device
  // (`timeshiftGuide`), refreshed once a minute.
  const scrub = { span: null, channel: null, programmes: null, fetchedAt: 0, loading: false };
  const agoText = (sec) => {
    sec = Math.max(0, Math.round(sec));
    if (sec < 60) return "live";
    const h = Math.floor(sec / 3600), m = Math.round((sec % 3600) / 60);
    return (h ? `${h}h ${String(m).padStart(2, "0")}m` : `${m} min`) + " ago";
  };
  function scrubBar(np) {
    const windowSec = np.window || 86400;
    const behind = np.kind === "timeshift" ? Math.max(0, np.behind || 0) : 0;
    const spans = [2, 6, 24].map((h) => h * 3600).filter((s, i) => i === 0 || s <= windowSec);
    if (scrub.channel !== np.name) Object.assign(scrub, { channel: np.name, span: null, programmes: null, fetchedAt: 0 });
    if (!scrub.span || behind > scrub.span) scrub.span = spans.find((s) => s >= behind) || spans[spans.length - 1];
    const span = Math.min(scrub.span, windowSec);
    const now = Date.now() / 1000;
    if (!scrub.loading && (!scrub.programmes || now - scrub.fetchedAt > 60 || scrub.programmes.span !== span)) {
      scrub.loading = true;
      command("timeshiftGuide", { hours: span / 3600 }).then((r) => {
        scrub.loading = false;
        scrub.programmes = { span, list: r.ok ? r.programmes || [] : [] };
        scrub.fetchedAt = Date.now() / 1000;
        const box = $("np-box");
        if (box && !remote.scrubbing) renderNowPlaying(box);
      });
    }

    const wrap = el("div", { class: "scrub" });
    wrap.append(el("div", { class: "scrub-head" },
      el("span", { class: "scrub-title" }, el("span", { class: "catchup-ico", "aria-hidden": "true" }), " Catch-up"),
      el("div", { class: "seg small" }, spans.map((sp) => {
        const b = el("button", { class: "subtab" + (sp === span ? " active" : ""), type: "button", text: `${sp / 3600}h` });
        b.addEventListener("click", () => { scrub.span = sp; renderNowPlaying($("np-box")); });
        return b;
      }))));

    // The track: programme blocks under a range input (value = seconds from the left edge).
    const track = el("div", { class: "scrub-track" });
    const start = now - span;
    const progs = (scrub.programmes && scrub.programmes.span === span ? scrub.programmes.list : []);
    progs.forEach((p, i) => {
      const a = Math.max(p.start, start), b = Math.min(p.end, now);
      if (b <= a) return;
      const blk = el("span", { class: "scrub-prog" + (i % 2 ? " alt" : ""), title: p.title });
      blk.style.left = ((a - start) / span) * 100 + "%";
      blk.style.width = ((b - a) / span) * 100 + "%";
      if ((b - a) / span > 0.12) blk.append(el("span", { class: "scrub-prog-title", text: p.title }));
      track.append(blk);
    });
    const range = el("input", { type: "range", class: "scrub-range", min: "0", max: String(Math.round(span)), step: "15",
      value: String(Math.round(span - Math.min(behind, span))), "aria-label": "Catch-up position" });
    track.append(range);
    const label = el("div", { class: "scrub-label" });
    const describe = () => {
      const back = span - Number(range.value);
      const at = now - back;
      const prog = progs.find((p) => p.start <= at && p.end > at);
      label.replaceChildren(
        el("strong", { text: back < 60 ? "LIVE" : timeText(at) }),
        el("span", { class: "sub", text: back < 60 ? "" : ` · ${agoText(back)}` }),
        prog ? el("div", { class: "scrub-prog-now", text: prog.title }) : null);
    };
    describe();
    range.addEventListener("pointerdown", () => { remote.scrubbing = true; });
    range.addEventListener("touchstart", () => { remote.scrubbing = true; }, { passive: true });
    for (const ev of ["pointercancel", "blur"]) range.addEventListener(ev, () => { remote.scrubbing = false; });
    range.addEventListener("input", describe);
    range.addEventListener("change", async () => {
      remote.scrubbing = false;
      await control({ action: "timeshiftTo", behind: span - Number(range.value) });
    });
    wrap.append(label, track, el("div", { class: "seek-times" },
      el("span", { text: timeText(start) }), el("span", { class: "scrub-live", text: "LIVE" })));
    return wrap;
  }

  // Apple Music-style: a mini player docked at the bottom, tap to open the full controls sheet.
  function ensureDock() {
    let dock = $("np-dock");
    if (!dock) {
      const close = () => dock.classList.remove("open");
      const scrim = el("div", { class: "np-scrim" });
      scrim.addEventListener("click", close);
      const grab = el("button", { class: "np-grab", type: "button", "aria-label": "Close controls" }, el("span"));
      grab.addEventListener("click", close);
      dock = el("div", { id: "np-dock", hidden: "" }, scrim,
        el("div", { class: "np-sheet" }, grab, el("div", { id: "np-box" })),
        el("div", { class: "np-mini", id: "np-mini" }));
      document.body.append(dock);
      document.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
    }
    return $("np-box");
  }
  function renderMini(np) {
    const mini = $("np-mini");
    if (!mini) return;
    mini.replaceChildren();
    const kind = np.kind === "vod" ? "🎬" : np.fixture ? "🏆" : "📺";
    const info = el("button", { class: "np-mini-info", type: "button", "aria-label": "Open the player controls" },
      np.image ? art(np.image, np.kind === "vod" ? "poster" : "logo", np.name) : el("span", { class: "np-mini-art", text: kind }),
      el("span", { class: "grow" },
        el("span", { class: "np-mini-title", text: np.name || "Playing" }),
        el("span", { class: "np-mini-sub" },
          np.kind === "live" ? el("span", { class: "live-dot", text: "LIVE" }) : null,
          " " + (np.fixture ? np.fixture + (np.score ? "  " + np.score : "") : np.now || (np.kind === "timeshift" ? "Catch-up" : np.fullScreen ? "Full screen" : "In the app")))));
    info.addEventListener("click", () => $("np-dock").classList.add("open"));
    const stop = el("button", { class: "np-mini-btn", type: "button", "aria-label": "Stop", text: "■" });
    stop.addEventListener("click", () => run("stopPlayback", {}, stop).then(() => setTimeout(pollPlayer, 500)));
    mini.append(info, ctl(np.paused ? "▶" : "❚❚", np.paused ? "Play" : "Pause", { action: "playPause" }, "np-mini-btn"), stop);
    if (np.kind === "vod" && np.duration > 0) {
      const bar = el("span", { class: "np-mini-prog" }); bar.style.width = (np.position / np.duration * 100) + "%"; mini.append(bar);
    } else if (np.nowStart && np.nowEnd) {
      const bar = el("span", { class: "np-mini-prog" });
      bar.style.width = Math.max(0, Math.min(100, ((Date.now() / 1000 - np.nowStart) / (np.nowEnd - np.nowStart)) * 100)) + "%"; mini.append(bar);
    }
  }

  function renderNowPlaying(box) {
    const np = nowPlaying();
    box.replaceChildren();
    const dock = $("np-dock");
    const show = !!np.active && currentTab === "remote";
    if (dock) { dock.hidden = !show; if (!show) dock.classList.remove("open"); }
    document.body.classList.toggle("has-dock", show);
    if (!np.active) return;
    renderMini(np);
    const card = el("div", { class: "card now-playing" }, el("div", { class: "sub", text: "ON THEIR SCREEN NOW" }));
    box.append(card);
    const stop = el("button", { class: "btn small danger", type: "button", text: "Stop" });
    stop.addEventListener("click", () => run("stopPlayback", {}, stop).then(() => setTimeout(pollPlayer, 500)));
    const where = np.fullScreen ? "Full screen" : `In the ${snapshot.currentTab || "app"}`;
    const kindText = np.kind === "vod" ? "" : np.kind === "timeshift" ? "Catch-up" : "Live";
    card.append(el("div", { class: "row-actions tight np-row" },
      el("div", { class: "grow" },
        el("div", { class: "title-lg", text: np.name }),
        el("div", { class: "sub" },
          kindText ? el("span", { class: np.kind === "live" ? "live-dot" : "tag", text: kindText.toUpperCase() }) : null,
          ` ${where}${np.paused ? " · Paused" : ""}`)),
      stop));
    if (np.fixture) {
      const open = np.fixtureID ? el("button", { class: "btn small", type: "button", text: "Match centre ›" }) : null;
      if (open) open.addEventListener("click", () => openMatchCentre(np.fixtureID));
      card.append(el("div", { class: "np-fixture row-actions tight" },
        el("span", { class: "grow", text: `🏆 ${np.fixture}${np.score ? "  " + np.score : ""}` }), open));
    }

    // Where it's up to
    if (np.kind === "vod" && np.duration > 0) {
      const range = el("input", { type: "range", class: "seek", min: "0", max: "1000", value: String(Math.round((np.position / np.duration) * 1000)) });
      const left = el("span", { text: fmtTime(np.position) });
      range.addEventListener("pointerdown", () => { remote.scrubbing = true; });
      for (const ev of ["pointercancel", "blur"]) range.addEventListener(ev, () => { remote.scrubbing = false; });
      range.addEventListener("input", () => { left.textContent = fmtTime((range.value / 1000) * np.duration); });
      range.addEventListener("change", async () => {
        remote.scrubbing = false;
        await control({ action: "seek", fraction: range.value / 1000 });
      });
      card.append(range, el("div", { class: "seek-times" }, left, el("span", { text: "-" + fmtTime(np.duration - np.position) })));
    } else if (np.kind === "timeshift") {
      card.append(el("div", { class: "sub", text: np.at
        ? `Watching from ${timeText(np.at)} · ${Math.round((np.behind || 0) / 60)} min behind live` : "Opening catch-up…" }));
    } else if (np.now) {
      const pct = np.nowStart && np.nowEnd ? Math.max(0, Math.min(100, ((Date.now() / 1000 - np.nowStart) / (np.nowEnd - np.nowStart)) * 100)) : 0;
      const bar = el("span", { class: "prog-fill" });
      bar.style.width = pct + "%";
      card.append(el("div", { class: "now-line" }, el("span", { class: "now-title", text: np.now }),
        np.nowEnd ? el("span", { class: "sub", text: ` · until ${timeText(np.nowEnd)}` }) : null),
        el("span", { class: "prog" }, bar),
        np.next ? el("div", { class: "sub", text: `Next: ${np.next} · ${timeText(np.nextStart)}` }) : null);
    }

    // Catch-up: scrub anywhere in the window (their app's timeshift), programmes drawn under it.
    if (np.catchup && np.kind !== "vod") card.append(scrubBar(np));

    // Transport
    const canRewind = np.kind !== "live" || np.catchup;
    const back = np.kind === "vod" ? 10 : 30;
    card.append(el("div", { class: "transport" },
      np.kind !== "vod" && np.catchup ? ctl("⏮", "Start this programme from the beginning", { action: "startOver" }) : null,
      canRewind ? ctl(`↺ ${back}`, `Back ${back} seconds`, { action: "skip", seconds: -back }) : null,
      ctl(np.paused ? "▶" : "❚❚", np.paused ? "Play" : "Pause", { action: "playPause" }, "ctl-main"),
      np.kind !== "live" ? ctl("30 ↻", "Forward 30 seconds", { action: "skip", seconds: 30 }) : null,
      np.kind === "timeshift" ? ctl("LIVE", "Back to live", { action: "goLive" }, "ctl-live") : null));

    if (np.canStep) {
      card.append(el("div", { class: "row-actions tight ctl-row" },
        ctl("▼ Channel", "Previous channel", { action: "channel", step: -1 }, "small"),
        ctl("Channel ▲", "Next channel", { action: "channel", step: 1 }, "small")));
    }

    // The player's own options
    const opts = el("div", { class: "np-options" });
    const toggleRow = (title, sub, on, onFields, offFields, disabled) => {
      const input = el("input", { type: "checkbox", role: "switch", "aria-label": title });
      input.checked = !!on;
      input.disabled = !!disabled;
      input.addEventListener("change", () => control(on ? offFields : onFields, input));
      return el("div", { class: "opt-row" + (disabled ? " disabled" : "") },
        el("div", { class: "grow" }, el("div", { class: "title", text: title }), sub ? el("div", { class: "sub", text: sub }) : null),
        el("label", { class: "switch" }, input, el("span")));
    };
    opts.append(toggleRow("Full screen", np.fullScreen ? "" : "It's playing in the app's small player.", np.fullScreen, { action: "fullScreen", open: true }, { action: "fullScreen", open: false }));
    if (np.kind !== "vod") {
      opts.append(toggleRow("SportsHub Live", np.fixture ? "Live stats, scores and tables around the picture." : "Scores and tables around the picture.",
        !!np.sportsLive, { action: "sportsLive", open: true }, { action: "sportsLive", open: false }, !np.fullScreen));
      if (!np.fullScreen) opts.lastChild.querySelector(".sub").textContent = "Put it full screen first.";
    }
    if (np.kind === "live" && np.engine) {
      const seg = el("div", { class: "seg" }, ["KSPlayer", "AVKit"].map((name) => {
        const b = el("button", { class: "subtab" + (np.engine === name ? " active" : ""), type: "button", text: name });
        b.addEventListener("click", () => { if (np.engine !== name) control({ action: "engine", avkit: name === "AVKit" }, b); });
        return b;
      }));
      opts.append(el("div", { class: "opt-row" }, el("div", { class: "grow" }, el("div", { class: "title", text: "Player" }),
        el("div", { class: "sub", text: "If this channel stutters or won't play, try the other one." })), seg));
    }
    const picker = (title, tracks, withOff, action) => {
      const sel = el("select", { class: "track-select", "aria-label": title });
      if (withOff) sel.append(el("option", { value: "", text: "Off" }));
      for (const t of tracks) {
        const o = el("option", { value: String(t.id), text: t.name });
        if (t.on) o.selected = true;
        sel.append(o);
      }
      sel.addEventListener("change", () => { control({ action, id: sel.value === "" ? null : Number(sel.value) }); sel.blur(); });
      return el("div", { class: "opt-row" }, el("div", { class: "grow title", text: title }), sel);
    };
    if ((np.audio || []).length > 1) opts.append(picker("Sound", np.audio, false, "audio"));
    if ((np.subtitles || []).length) opts.append(picker("Subtitles", np.subtitles, true, "subtitles"));
    const restart = el("button", { class: "btn small", type: "button", text: "↻ Restart stream" });
    restart.addEventListener("click", () => control({ action: "restart" }, restart));
    opts.append(el("div", { class: "row-actions tight" }, restart));
    card.append(opts);
  }

  // ---------- Movies and Series ----------
  const tabOn = (name) => !snapshot.tabs || snapshot.tabs.includes(name);

  async function loadVodCategories(kind) {
    const r = await command("vodCategories", { kind });
    remote[kind].cats = r.ok ? r.categories : [];
    if (remote.mode === kind) renderRemote();
  }

  async function openVodCategory(kind, cat) {
    const st = remote[kind];
    Object.assign(st, { cat, titles: null, more: false, show: null, episodes: null, filter: "" });
    navPush();
    renderRemote();
    const r = await command("vodTitles", { kind, key: cat.key, offset: 0 });
    if (st.cat !== cat) return;
    st.titles = r.ok ? r.titles : [];
    st.more = !!(r.ok && r.more);
    renderRemote();
  }

  async function loadMoreTitles(kind, button) {
    const st = remote[kind];
    const cat = st.cat;
    button.disabled = true;
    const r = await command("vodTitles", { kind, key: cat.key, offset: st.titles.length });
    if (st.cat !== cat || !r.ok) return;
    st.titles = st.titles.concat(r.titles);
    st.more = !!r.more;
    renderRemote();
  }

  let vodSearchTimer = null;
  function searchVod(kind, query) {
    const st = remote[kind];
    st.query = query;
    clearTimeout(vodSearchTimer);
    if (query.trim().length < 2) { st.searching = false; st.titles = st.cat ? st.titles : null; renderRemote(); return; }
    vodSearchTimer = setTimeout(async () => {
      st.searching = true;
      const r = await command("vodTitles", { kind, query: query.trim() });
      if (st.query !== query) return;
      Object.assign(st, { cat: null, titles: r.ok ? r.titles : [], more: false, show: null, episodes: null });
      renderRemote(); // keeps the search box focused
    }, 450);
  }

  async function openShow(show) {
    const st = remote.series;
    Object.assign(st, { show, episodes: null, season: null });
    navPush();
    renderRemote();
    const r = await command("seriesEpisodes", { id: show.id });
    if (st.show !== show) return;
    st.episodes = r.ok ? r.episodes : [];
    st.cover = r.ok ? r.cover || show.image : show.image;
    if (!r.ok) toast(r.message || "Couldn't load the episodes.", true);
    // Open on the season they're part-way through, else the first.
    const watching = st.episodes.find((e) => e.progress && e.progress < 0.95);
    st.season = watching ? watching.season : (st.episodes[0] || {}).season;
    renderRemote();
  }

  function playButtons(id, item) {
    const on = isOnScreen(id);
    const play = el("button", { class: "btn small " + (on ? "btn-playing" : "btn-white"), type: "button",
      text: on ? "Playing" : item.progress ? "▶ Resume" : "▶ Play" });
    play.addEventListener("click", () => run("playVOD", { id }, play).then(() => setTimeout(pollPlayer, 1500)));
    if (!item.progress) return [play];
    const fromStart = el("button", { class: "btn small icon", type: "button", text: "⏮", "aria-label": "Play from the start", title: "Play from the start" });
    fromStart.addEventListener("click", () => run("playVOD", { id, fromStart: true }, fromStart).then(() => setTimeout(pollPlayer, 1500)));
    return [fromStart, play];
  }

  function progressBar(p) {
    if (!p) return null;
    const bar = el("span", { class: "prog-fill" });
    bar.style.width = Math.round(p * 100) + "%";
    return el("span", { class: "prog" }, bar);
  }

  function renderRemoteVod(panel, kind) {
    const st = remote[kind];
    const word = kind === "vod" ? "film" : "series";
    const tabName = kind === "vod" ? "Movies" : "Series";

    const search = el("input", { class: "search", placeholder: kind === "vod" ? "Search all their films" : "Search all their series", value: st.query });
    search.dataset.remotefilter = "1";
    search.addEventListener("input", () => searchVod(kind, search.value));
    const searching = st.query.trim().length >= 2;

    // Episodes of one series
    if (kind === "series" && st.show) {
      const back = searching ? "Search" : st.cat ? st.cat.name : "Series";
      panel.append(crumb([[back, () => navBack(() => { st.show = null; st.episodes = null; renderRemote(); })], [st.show.name, null]]));
      panel.append(el("div", { class: "card show-head" }, art(st.cover || st.show.image, "poster", st.show.name),
        el("div", { class: "grow" }, el("div", { class: "title-lg", text: st.show.name }),
          el("div", { class: "sub", text: [st.show.category, st.show.year, st.show.source].filter(Boolean).join(" · ") }))));
      if (!st.episodes) { panel.append(el("p", { class: "empty", text: "Loading episodes…" })); return; }
      if (!st.episodes.length) { panel.append(el("p", { class: "empty", text: "Their provider didn't list any episodes for this one." })); return; }
      const seasons = [...new Set(st.episodes.map((e) => e.season))];
      if (seasons.length > 1) {
        panel.append(el("div", { class: "subtabs" }, seasons.map((n) =>
          pill(n ? `Season ${n}` : "Episodes", null, st.season === n, () => { st.season = n; renderRemote(); }))));
      }
      const list = el("div", { class: "list" });
      for (const ep of st.episodes.filter((e) => seasons.length <= 1 || e.season === st.season)) {
        const still = art(ep.image || st.cover, "still", st.show.name);
        if (ep.progress) still.append(progressBar(ep.progress));
        list.append(el("div", { class: "item episode" },
          still,
          el("div", { class: "grow" },
            el("div", { class: "title clamp2", text: ep.episode ? `${ep.episode}. ${ep.title}` : ep.title }),
            ep.duration ? el("div", { class: "sub", text: ep.duration }) : null,
            ep.plot ? el("div", { class: "plot", text: ep.plot }) : null,
            el("div", { class: "row-actions tight" }, ...playButtons(ep.id, ep)))));
      }
      panel.append(list);
      return;
    }

    // Categories
    if (!st.cat && !searching) {
      panel.append(el("p", { class: "hint", text: `Their ${tabName} rows, in the same order. Browsing here doesn't change their screen; Play puts it on full screen.` }));
      panel.append(search);
      if (!st.cats) { panel.append(el("p", { class: "empty", text: "Loading…" })); return; }
      if (!st.cats.length) { panel.append(el("p", { class: "empty", text: `No ${word} categories are switched on.` })); return; }
      const many = new Set(st.cats.map((c) => c.source)).size > 1;
      const list = el("div", { class: "list" });
      for (const c of st.cats) {
        const row = el("button", { class: "item cat-row", type: "button" },
          el("div", { class: "grow" }, el("div", { class: "title", text: c.name }),
            !c.browsable ? el("div", { class: "sub", text: "Open this one on their device" }) : many ? el("div", { class: "sub", text: c.source }) : null),
          c.browsable ? el("span", { class: "chev", text: "›" }) : null);
        row.disabled = !c.browsable;
        if (c.browsable) row.addEventListener("click", () => openVodCategory(kind, c));
        list.append(row);
      }
      panel.append(list);
      return;
    }

    // Titles (a category, or search results)
    if (searching) {
      panel.append(search);
    } else {
      panel.append(crumb([[tabName, () => navBack(() => { st.cat = null; st.titles = null; renderRemote(); })], [st.cat.name, null]]));
    }
    if (!st.titles) { panel.append(el("p", { class: "empty", text: searching ? "Searching…" : "Loading…" })); return; }
    if (!st.titles.length) { panel.append(el("p", { class: "empty", text: searching ? "Nothing matches." : "Nothing in this category." })); return; }
    const titleRow = (t) => {
      const info = el("div", { class: "grow" },
        el("div", { class: "title clamp2", text: t.name }),
        // Search spans every category: say which one it's in (the app's row name).
        searching && t.category ? el("div", { class: "cat-line", text: t.category }) : null,
        t.year || t.resume ? el("div", { class: "sub", text: [t.year, t.resume ? `stopped at ${fmtTime(t.resume)}` : ""].filter(Boolean).join(" · ") }) : null,
        progressBar(t.progress));
      const poster = art(t.image, "poster", t.name);
      if (kind === "series") {
        const row = el("button", { class: "item cat-row with-art", type: "button" }, poster, info, el("span", { class: "chev", text: "›" }));
        row.addEventListener("click", () => openShow(t));
        return row;
      }
      info.append(el("div", { class: "row-actions tight vod-actions" }, ...playButtons(t.id, t)));
      return el("div", { class: "item chan with-art" }, poster, info);
    };
    panel.append(...(searching ? bySource(st.titles, titleRow) : [el("div", { class: "list" }, st.titles.map(titleRow))]));
    if (st.more) {
      const more = el("button", { class: "btn", type: "button", text: "Show more" });
      more.addEventListener("click", () => loadMoreTitles(kind, more));
      panel.append(el("div", { class: "row-actions center-row" }, more));
    }
  }

  function filterBox(placeholder) {
    const f = el("input", { class: "search", placeholder, value: remote.guide.filter });
    f.dataset.remotefilter = "1";
    f.addEventListener("input", () => {
      const g = remote.guide;
      g.filter = f.value;
      // The box searches every channel on their device, as the guide's own search.
      {
        clearTimeout(g.searchTimer);
        const q = f.value.trim().toLowerCase();
        if (q.length >= 2 && q !== g.searchFor) {
          g.searchTimer = setTimeout(async () => {
            const r = await command("guideSearch", { query: q });
            if (remote.guide.filter.trim().toLowerCase() !== q) return;
            g.searchFor = q;
            g.search = r.ok ? { channels: r.channels || [], more: !!r.more } : { error: r.message || "Couldn't search their channels." };
            if (currentTab === "remote" && remote.mode === "guide") renderRemote();
          }, 350);
        }
      }
      renderRemote();
    });
    return f;
  }

  // ---------- Guide: the Apple TV guide, without its player ----------
  // Category pills across the top (the drawer's categories, in their order), then the grid:
  // channel column on the left, half-hour time header, programme cells laid out by time, the
  // "on now" card in the guide's accent and a now-line. Scrolls both ways. Wears their guide
  // theme. Browsing never changes their screen; a programme's Watch puts the channel on.
  const EPG_THEMES = {
    midnight: ["#232B3D", "#161B29", "#161922", "#0D0F16", "#298FFF", "#0F61F5", "#0D42D1", "#4DCCFF", "#0D1426", "#141F33"],
    midnightDeep: ["#1A2138", "#0F1424", "#141930", "#0A0D1A", "#4C6FFF", "#3454E8", "#2138B8", "#8FA5FF", "#080B18", "#111730"],
    blackout: ["#0A0A0B", "#050506", "#060607", "#020203", "#2E3137", "#22252A", "#17191D", "#E9ECF0", "#000000", "#0A0A0C"],
    night: ["#2A2420", "#1C1815", "#1E1A17", "#141110", "#8A5F2E", "#6E4A22", "#52361A", "#C0925A", "#141110", "#1F1A16"],
    slate: ["#414247", "#2C2D31", "#313236", "#202124", "#7A7F87", "#656A72", "#52565D", "#DADDE2", "#26272B", "#33343A"],
    obsidian: ["#1E1F22", "#131416", "#17181A", "#0E0F10", "#4A505A", "#3A3F47", "#2C3037", "#8A939D", "#0E0F11", "#191A1D"],
    onyxAmber: ["#221F1B", "#141210", "#191714", "#0E0D0B", "#D9932F", "#B8761E", "#8F5A14", "#E8B45E", "#0D0B09", "#181512"],
    deepTeal: ["#17262B", "#0D181C", "#111C20", "#091214", "#2FB6C4", "#1E8E9C", "#146A76", "#5FD3DE", "#081316", "#0F2126"],
    forest: ["#1E2A22", "#121A15", "#16201A", "#0C120F", "#4E8F63", "#3B7150", "#2A533A", "#8FC9A1", "#0A120D", "#131F17"],
    aubergine: ["#241C2E", "#15101C", "#1B1522", "#0F0B15", "#B067A8", "#8C4E85", "#693A64", "#C98BC2", "#0E0A14", "#1A1424"],
  };
  function applyEPGTheme(node) {
    const t = EPG_THEMES[hubSetting("epgTheme", "midnight")] || EPG_THEMES.midnight;
    const names = ["surf1", "surf2", "end1", "end2", "live1", "live2", "live3", "accent", "head1", "head2"];
    names.forEach((n, i) => node.style.setProperty("--e-" + n, t[i]));
    return node;
  }
  const GUIDE_HOURS = 8;
  function guideWindow() {
    const now = Date.now() / 1000;
    const from = Math.floor(now / 1800) * 1800 - 1800;     // the half hour before the last one
    return { from, to: from + GUIDE_HOURS * 3600 };
  }
  const guideMQ = window.matchMedia("(min-width: 700px)");
  const guideIsGrid = () => guideMQ.matches;
  guideMQ.addEventListener("change", () => {
    if (currentTab === "remote" && remote.mode === "guide" && !mc.open && !busy("tab-remote")) renderRemote();
  });
  const guidePxPerMin = () => (window.matchMedia("(min-width: 900px)").matches ? 7 : 4.5);

  function guideCategoriesFlat(g) {
    const out = [], seen = new Set();
    for (const grp of g.groups || []) for (const c of grp.items) if (!seen.has(c.key)) { seen.add(c.key); out.push(c); }
    return out;
  }

  function renderRemoteGuide(panel) {
    const g = remote.guide;
    if (!g.groups) { panel.append(el("p", { class: "empty", text: "Loading their guide…" })); if (g.groups === null) loadGuideGroups(); g.groups = g.groups || undefined; return; }
    const cats = guideCategoriesFlat(g);
    if (!cats.length) { panel.append(el("p", { class: "empty", text: "No TV channel categories are switched on." })); return; }
    // Opens on their first category, as the guide does.
    if (!g.category) {
      panel.append(el("p", { class: "empty", text: "Loading their guide…" }));
      g.channels = null;
      setTimeout(() => { if (!g.category) openGuideCategory(cats[0], false); }, 0);
      return;
    }

    const shell = applyEPGTheme(el("div", { class: "epg" }));
    panel.append(shell);
    shell.append(filterBox("Search all channels"));

    const q = g.filter.trim().toLowerCase();
    if (q.length >= 2) {
      const list = el("div", { class: "list" });
      const res = g.searchFor === q ? g.search : null;
      if (!res) list.append(el("p", { class: "empty", text: "Searching their channels…" }));
      else if (res.error) list.append(el("p", { class: "empty", text: res.error }));
      else if (!res.channels.length) list.append(el("p", { class: "empty", text: "No channels match." }));
      else list.append(...bySource(res.channels, (c) => channelRow(c), "group-stack"));
      if (res && res.more) list.append(el("p", { class: "hint", text: "Showing the first 80. Type more of the name to narrow it down." }));
      shell.append(list);
      return;
    }

    // Category: a drop-down (the guide's category drawer). Scrolls; each playlist's group
    // folds away so a long list can be skipped; remembers which groups are folded.
    const curGroup = (g.groups || []).find((grp) => grp.items.some((c) => c.key === g.category.key));
    const catBtn = el("button", { class: "epg-cat-btn" + (g.catMenu ? " open" : ""), type: "button", "aria-haspopup": "listbox", "aria-expanded": g.catMenu ? "true" : "false" },
      el("span", { class: "epg-cat-text" },
        curGroup ? el("span", { class: "epg-cat-group", text: curGroup.title }) : null,
        el("span", { class: "epg-cat-name", text: g.category.name })),
      el("span", { class: "epg-cat-caret", text: "▾" }));
    catBtn.addEventListener("click", () => { g.catMenu = !g.catMenu; g.catQuery = ""; g.catScroll = null; g.catFocus = false; renderRemote(); });
    shell.append(catBtn);
    if (g.catMenu) document.body.append(guideCategoryMenu(g));
    // The picked programme: title, time, channel and Watch.
    if (g.picked) shell.append(guidePickedCard(g.picked));

    if (!g.channels) { shell.append(el("div", { class: guideIsGrid() ? "epg-grid loading" : "", }, el("p", { class: "empty", text: "Loading channels and what's on…" }))); return; }
    if (!g.channels.length) { shell.append(el("p", { class: "empty", text: "No channels in this category." })); return; }
    // Big screens (iPad, computer): the TV guide grid. Phones: a list with now and next,
    // channel names allowed to wrap so long ones stay readable.
    if (guideIsGrid()) shell.append(guideGrid(g));
    else shell.append(el("div", { class: "gl" }, g.channels.map((c) => guideListRow(c))));
  }

  const guideClosed = (() => { try { return new Set(JSON.parse(localStorage.getItem("rh-guide-closed") || "[]")); } catch (_) { return new Set(); } })();
  const saveGuideClosed = () => { try { localStorage.setItem("rh-guide-closed", JSON.stringify([...guideClosed])); } catch (_) {} };
  function guideCategoryMenu(g) {
    const close = () => { g.catMenu = false; renderRemote(); };
    const scrim = el("div", { class: "epg-cat-scrim" });
    scrim.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
    scrim.addEventListener("click", (e) => { if (e.target === scrim) close(); });
    const q = (g.catQuery || "").trim().toLowerCase();
    const find = el("input", { class: "search", placeholder: "Find a category", value: g.catQuery || "", "aria-label": "Find a category" });
    find.dataset.catfind = "1";
    find.addEventListener("input", () => { g.catQuery = find.value; g.catFocus = true; renderRemote(); });
    const groups = (g.groups || []).map((grp) => ({ grp, items: grp.items.filter((c) => !q || c.name.toLowerCase().includes(q)) })).filter((x) => x.items.length);
    const allOpen = groups.every(({ grp }) => !guideClosed.has(grp.id));
    const toggleAll = el("button", { class: "btn small", type: "button", text: allOpen ? "Collapse all" : "Expand all" });
    toggleAll.addEventListener("click", () => {
      for (const { grp } of groups) allOpen ? guideClosed.add(grp.id) : guideClosed.delete(grp.id);
      saveGuideClosed(); renderRemote();
    });
    const x = el("button", { class: "btn small icon", type: "button", "aria-label": "Close", text: "✕" });
    x.addEventListener("click", close);
    const list = el("div", { class: "epg-cat-list", role: "listbox" });
    if (!groups.length) list.append(el("p", { class: "empty", text: "No categories match." }));
    for (const { grp, items } of groups) {
      const open = q ? true : !guideClosed.has(grp.id);
      const head = el("button", { class: "epg-cat-head" + (open ? " open" : ""), type: "button", "aria-expanded": open ? "true" : "false" },
        el("span", { class: "chev" + (open ? " open" : ""), text: "›" }),
        el("span", { class: "grow", text: grp.title }),
        el("span", { class: "subtab-badge", text: String(items.length) }));
      head.addEventListener("click", () => { guideClosed.has(grp.id) ? guideClosed.delete(grp.id) : guideClosed.add(grp.id); saveGuideClosed(); renderRemote(); });
      list.append(head);
      if (!open) continue;
      for (const c of items) {
        const on = c.key === g.category.key;
        const row = el("button", { class: "epg-cat-row" + (on ? " on" : ""), type: "button", role: "option", "aria-selected": on ? "true" : "false" },
          el("span", { class: "grow", text: c.name }), on ? el("span", { class: "epg-cat-tick", text: "✓" }) : null);
        row.addEventListener("click", () => { g.catMenu = false; if (!on) { g.scroll = null; g.picked = null; openGuideCategory(c); } else renderRemote(); });
        list.append(row);
      }
    }
    const saved = g.catScroll;
    requestAnimationFrame(() => {
      if (saved != null) list.scrollTop = saved;
      else { const on = list.querySelector(".on"); if (on) on.scrollIntoView({ block: "center" }); }
      if (g.catQuery !== undefined && document.activeElement !== find && g.catFocus) find.focus();
    });
    list.addEventListener("scroll", () => { g.catScroll = list.scrollTop; }, { passive: true });
    find.addEventListener("focus", () => { g.catFocus = true; });
    find.addEventListener("blur", () => { g.catFocus = false; });
    const keepCaret = g.catFocus;
    if (keepCaret) requestAnimationFrame(() => { find.focus(); find.setSelectionRange(find.value.length, find.value.length); });
    scrim.append(el("div", { class: "epg-cat-menu" },
      el("div", { class: "epg-cat-menu-head" }, el("strong", { text: "Categories" }), toggleAll, x),
      find, list));
    return scrim;
  }

  // A phone guide row: logo, the name (wraps to two lines), what's on now with its progress
  // and end time, next on one line, and a round ▶ instead of a wide Watch button so the text
  // gets the width.
  function guideListRow(c) {
    const on = isOnScreen(c.server + "|" + c.channel);
    const play = el("button", { class: "gl-play" + (on ? " on" : ""), type: "button",
      "aria-label": on ? `${c.name} is playing` : `Watch ${c.name}`, title: on ? "Playing" : "Watch" });
    play.append(on ? el("span", { class: "gl-eq", "aria-hidden": "true" }, el("i"), el("i"), el("i")) : el("span", { class: "gl-tri", "aria-hidden": "true" }));
    play.addEventListener("click", () => run("playChannel", { server: c.server, channel: c.channel }, play).then(() => setTimeout(pollPlayer, 1500)));
    const now = Date.now() / 1000;
    let bar = null;
    if (c.nowStart && c.nowEnd) {
      const fill = el("span", { class: "gl-fill" });
      fill.style.width = Math.max(0, Math.min(100, ((now - c.nowStart) / (c.nowEnd - c.nowStart)) * 100)) + "%";
      bar = el("span", { class: "gl-bar" }, fill);
    }
    return el("div", { class: "gl-row" + (on ? " playing" : "") },
      art(c.image, "logo", c.name),
      el("div", { class: "gl-main" },
        el("div", { class: "gl-name" }, el("span", { class: "gl-name-text", text: c.name }),
          c.catchup ? el("span", { class: "catchup-ico", role: "img", title: "Catch-up", "aria-label": "Catch-up" }) : null),
        c.now
          ? el("div", { class: "gl-now" }, el("span", { class: "gl-now-title", text: c.now }))
          : el("div", { class: "gl-none", text: "No guide information" }),
        bar || c.nowEnd ? el("div", { class: "gl-meta" }, bar, c.nowEnd ? el("span", { class: "gl-left", text: minsLeft(c.nowEnd) }) : null) : null,
        c.next ? el("div", { class: "gl-next" }, el("span", { class: "gl-next-time", text: timeText(c.nextStart) }), el("span", { class: "gl-next-title", text: c.next })) : null),
      play);
  }
  function minsLeft(end) {
    const m = Math.max(0, Math.round((end - Date.now() / 1000) / 60));
    return m >= 60 ? `${Math.floor(m / 60)}h ${m % 60}m left` : `${m}m left`;
  }

  function guidePickedCard(p) {
    const now = Date.now() / 1000;
    const live = p.s <= now && p.e > now;
    const on = isOnScreen(p.c.server + "|" + p.c.channel);
    const watch = el("button", { class: "btn small " + (on ? "btn-playing" : "btn-white"), type: "button", text: on ? "Playing" : live || !p.t ? "▶ Watch" : "▶ Watch channel" });
    watch.addEventListener("click", () => run("playChannel", { server: p.c.server, channel: p.c.channel }, watch).then(() => setTimeout(pollPlayer, 1500)));
    const close = el("button", { class: "btn small icon", type: "button", "aria-label": "Close", text: "✕" });
    close.addEventListener("click", () => { remote.guide.picked = null; renderRemote(); });
    return el("div", { class: "epg-picked" + (live ? " live" : "") },
      art(p.c.image, "logo", p.c.name),
      el("div", { class: "grow" },
        el("div", { class: "epg-picked-title", text: p.t || p.c.name }),
        el("div", { class: "sub" },
          live ? el("span", { class: "live-dot", text: "LIVE" }) : null,
          (live ? " " : "") + (p.s ? `${dayText(p.s) === "Today" ? "" : dayText(p.s) + " · "}${timeText(p.s)}–${timeText(p.e)} · ` : "") + p.c.name)),
      watch, close);
  }

  function guideGrid(g) {
    const w = g.window || guideWindow();
    const ppm = guidePxPerMin();
    const width = ((w.to - w.from) / 60) * ppm;
    const now = Date.now() / 1000;
    const x = (t) => ((Math.max(w.from, Math.min(w.to, t)) - w.from) / 60) * ppm;

    const scroller = el("div", { class: "epg-grid" });
    const inner = el("div", { class: "epg-inner" });
    inner.style.width = `calc(var(--epg-chan) + ${width}px)`;

    // Time header (sticky top), with the corner (sticky both).
    const head = el("div", { class: "epg-head" });
    const corner = el("div", { class: "epg-corner", text: dayText(now) });
    const times = el("div", { class: "epg-times" });
    times.style.width = width + "px";
    for (let t = w.from; t < w.to; t += 1800) {
      const tick = el("span", { class: "epg-tick", text: timeText(t) });
      tick.style.left = x(t) + "px";
      tick.style.width = 30 * ppm + "px";
      times.append(tick);
    }
    head.append(corner, times);
    inner.append(head);

    const body = el("div", { class: "epg-body" });
    for (const c of g.channels) {
      const row = el("div", { class: "epg-row" });
      const chan = el("button", { class: "epg-chan" + (isOnScreen(c.server + "|" + c.channel) ? " playing" : ""), type: "button", title: c.name },
        art(c.image, "logo", c.name),
        el("span", { class: "epg-chan-name" }, el("span", { class: "chan-text", text: c.name }),
          c.catchup ? el("span", { class: "catchup-ico", role: "img", "aria-label": "Catch-up" }) : null));
      chan.addEventListener("click", () => { g.picked = { c, t: c.now || "", s: c.nowStart, e: c.nowEnd }; renderRemote(); });
      const lane = el("div", { class: "epg-lane" });
      lane.style.width = width + "px";
      const progs = c.progs || [];
      if (!progs.length) {
        const cell = el("button", { class: "epg-cell empty-cell", type: "button", text: "No information available" });
        cell.style.left = "0px"; cell.style.width = width + "px";
        cell.addEventListener("click", () => { g.picked = { c, t: "", s: 0, e: 0 }; renderRemote(); });
        lane.append(cell);
      }
      for (const p of progs) {
        const left = x(p.s), right = x(p.e);
        if (right - left < 2) continue;
        const live = p.s <= now && p.e > now, ended = p.e <= now;
        const picked = g.picked && g.picked.c === c && g.picked.s === p.s;
        const cell = el("button", { class: "epg-cell" + (live ? " live" : ended ? " ended" : "") + (picked ? " picked" : ""), type: "button" },
          el("span", { class: "epg-cell-title", text: p.t }),
          el("span", { class: "epg-cell-time", text: `${timeText(p.s)} – ${timeText(p.e)}` }));
        cell.style.left = left + "px";
        cell.style.width = (right - left) + "px";
        if (live) {
          const bar = el("span", { class: "epg-cell-prog" });
          bar.style.width = Math.max(0, Math.min(100, ((now - p.s) / (p.e - p.s)) * 100)) + "%";
          cell.append(bar);
        }
        cell.addEventListener("click", () => { g.picked = { c, t: p.t, s: p.s, e: p.e }; renderRemote(); });
        lane.append(cell);
      }
      row.append(chan, lane);
      body.append(row);
    }
    // The now-line, across every row.
    const line = el("div", { class: "epg-now" });
    line.style.left = `calc(var(--epg-chan) + ${x(now)}px)`;
    body.append(line);
    inner.append(body);
    scroller.append(inner);

    // Keep where they were across refreshes; first time, put "now" near the left.
    const saved = g.scroll;
    requestAnimationFrame(() => {
      if (saved && saved.key === g.category.key) { scroller.scrollLeft = saved.left; scroller.scrollTop = saved.top; }
      else scroller.scrollLeft = Math.max(0, x(now) - 30 * ppm);
    });
    scroller.addEventListener("scroll", () => { g.scroll = { key: g.category.key, left: scroller.scrollLeft, top: scroller.scrollTop }; }, { passive: true });
    return scroller;
  }

  // ---------- Sports Hub: the app's own hub ----------
  // Drawn the way their app draws it: on a computer the Apple TV layout (ticker, competition
  // header, Fixtures / Results shelf, wide match cards with the league crest bay, the table
  // beside the list); on a phone the iPhone layout (status rail cards, a Table tab, the
  // competition picker as a sheet). Browsing never changes their screen; only Watch does.
  const hubMQ = window.matchMedia("(min-width: 900px)");
  const hubIsTV = () => hubMQ.matches;
  hubMQ.addEventListener("change", () => {
    if (currentTab === "remote" && remote.mode === "sports" && !mc.open && !busy("tab-remote")) renderRemote();
  });
  const UPCOMING_DEST = { code: "UPCOMING", name: "Upcoming", place: true };
  const HIGHLIGHTS_DEST = { code: "HIGHLIGHTS", name: "Highlights", place: true };
  const hubKey = (d) => d.code + "|" + (d.competition || "");
  const hubSetting = (id, fallback) => {
    const s = (snapshot.settings || []).find((x) => x.id === id);
    return s && s.value !== undefined ? s.value : fallback;
  };

  // The app's eight hub themes (SportsHubTheme specs): ground top/mid/foot, card, panel,
  // chrome, hairline + alpha, accent, then the text ramp. They follow the theme picked on
  // their device; League Colours wears Default here (the page has no league palette).
  const HUB_THEMES = {
    graphite: ["#131922", "#0E1219", "#080B11", "#1E2530", "#101216", "#08090C", "255,255,255", 0.10, "#6E86A8", "#ECEAE7", "#B8BDC7", "#8B909C", "#666B77"],
    midnight: ["#161C2B", "#101523", "#090C15", "#222B40", "#111726", "#070A12", "175,198,255", 0.12, "#5B8FE0", "#E8EBF2", "#B2BCD0", "#848EA4", "#606A80"],
    blackout: ["#0A0A0B", "#060607", "#030304", "#16171A", "#0A0A0C", "#000000", "255,255,255", 0.08, "#7C8490", "#E4E2DF", "#AAAEB6", "#7E828B", "#5A5E67"],
    onyxAmber: ["#1B1815", "#141210", "#0C0B09", "#28231D", "#151210", "#0A0908", "255,223,176", 0.11, "#C08A45", "#EFE9E0", "#C2B8A9", "#948B7E", "#6B645B"],
    deepTeal: ["#11242A", "#0B1A1F", "#060F13", "#1B333B", "#0C1C21", "#050C0F", "168,232,242", 0.12, "#3FA8B8", "#E4EDEF", "#AAC0C6", "#7D9299", "#5A6D73"],
    forest: ["#122016", "#0D1710", "#070D09", "#1D2F23", "#0D1810", "#060B07", "182,239,196", 0.11, "#4E9A63", "#E7EBE5", "#AEBCAF", "#808E82", "#5D6A5F"],
    aubergine: ["#1D1726", "#15101C", "#0C0912", "#2B2338", "#150F1D", "#0A0710", "227,198,234", 0.11, "#A173B0", "#EBE6EF", "#B9AFC3", "#8B8296", "#665F70"],
    slate: ["#272A31", "#1D2026", "#14161A", "#3A3F49", "#212429", "#101216", "255,255,255", 0.14, "#8AA2C4", "#F2F1EE", "#C8CCD4", "#9BA0AB", "#767B86"],
  };
  // Set through the CSSOM: the page's CSP (style-src 'self') refuses style="" attributes.
  function applyHubTheme(node) {
    const t = HUB_THEMES[hubSetting("sportsHubTheme", "graphite")] || HUB_THEMES.graphite;
    const vars = { g1: t[0], g2: t[1], g3: t[2], card: t[3], panel: t[4], chrome: t[5],
      line: `rgba(${t[6]},${t[7]})`, "line-2": `rgba(${t[6]},${(t[7] * 1.6).toFixed(2)})`, wash: t[6],
      accent: t[8], t1: t[9], t2: t[10], t3: t[11], t4: t[12] };
    for (const [k, v] of Object.entries(vars)) node.style.setProperty("--h-" + k, v);
    return node;
  }

  // Every competition shown in their hub, by sport (the picker's columns), as the switcher.
  function hubSports() {
    const out = [];
    for (const g of (snapshot.sports || {}).groups || []) {
      const items = [];
      for (const it of g.items || []) {
        if (it.shown === false && !(it.competitions || []).some((c) => c.shown !== false)) continue;
        if (it.competitions) {
          items.push({ code: it.code, name: it.name, logo: it.logo, sport: g.name, all: true });
          for (const c of it.competitions) if (c.shown !== false) items.push({ code: c.code, competition: c.name, name: c.name, logo: c.logo, sport: g.name });
        } else {
          items.push({ code: it.code, competition: it.kind === "competition" ? it.name : undefined, name: it.name, logo: it.logo, sport: g.name });
        }
      }
      // A sport's All page is named for the sport ("All Football"), as in the app.
      const alls = items.filter((i) => i.all);
      for (const i of alls) i.label = alls.length === 1 ? `All ${g.name}` : `All ${i.name}`;
      if (items.length) out.push({ id: g.id, name: g.name, items });
    }
    return out;
  }

  function hubEnsure() {
    const sp = remote.sports;
    if (!sp.dest) hubOpen(UPCOMING_DEST);
  }

  async function hubOpen(dest) {
    const sp = remote.sports;
    const changed = !sp.dest || hubKey(sp.dest) !== hubKey(dest);
    sp.dest = dest;
    sp.event = null;
    sp.channels = null;
    sp.picker = false;
    navPush();
    if (changed) {
      sp.events = null; sp.table = null; sp.tableTried = false; sp.filter = "All";
      if (dest.place || sp.view === "table") sp.view = "fixtures";
    }
    renderRemote();
    if (dest.code === "HIGHLIGHTS") {
      const loadHl = async () => {
        const r = await command("hubHighlights", {});
        if (!sp.dest || sp.dest.code !== "HIGHLIGHTS") return;
        sp.hl = r.ok ? r : { error: r.message || "Their app doesn't have Highlights on the Remote yet. Update TivEPG on it." };
        if (!busy("tab-remote") && !sp.picker && !sp.event) renderRemote();
      };
      await loadHl();
      remoteRefreshEvery(5 * 60000, loadHl);
      return;
    }
    let round = 0;
    const load = async () => {
      const key = hubKey(dest);
      const wantsTicker = hubSetting("sportsHubShowLiveTicker", true) !== false && dest.code !== "UPCOMING";
      // The table every fifth round (~4 min): it moves with the scores, not by the second.
      const wantsTable = dest.code !== "UPCOMING" && !dest.all && round % 5 === 0;
      round++;
      const [ev, tick, table] = await Promise.all([
        command("hubEvents", { code: dest.code, competition: dest.competition, ...(sp.view === "results" ? { view: "results" } : {}) }),
        wantsTicker ? command("hubEvents", { code: "UPCOMING" }) : null,
        wantsTable ? command("hubTable", { code: dest.code, competition: dest.competition }) : null,
      ]);
      if (!sp.dest || hubKey(sp.dest) !== key) return;
      sp.events = ev && ev.ok ? ev.events : [];
      if (dest.code === "UPCOMING") sp.ticker = sp.events;
      else if (tick && tick.ok) sp.ticker = tick.events;
      if (table) { sp.tableTried = true; if (table.ok && table.table) sp.table = table.table; }
      if (!busy("tab-remote") && !sp.picker && !sp.event) renderRemote();
    };
    await load();
    remoteRefreshEvery(45000, load);
  }

  async function openSportsEvent(ev, code) {
    const sp = remote.sports;
    // A result isn't something to watch: open the match, its stats and its highlights, as the
    // app's fixture screen does for a finished game.
    if (ev.state === "finished") {
      openMatchCentre(ev.id, { code: code || (sp.dest || UPCOMING_DEST).code, league: ev.league, highlight: ev.highlight });
      return;
    }
    sp.event = ev;
    sp.eventCode = code || (sp.dest || UPCOMING_DEST).code;
    sp.channels = null;
    navPush();
    renderRemote();
    window.scrollTo({ top: 0, behavior: "smooth" });
    const r = await command("hubEventChannels", { code: sp.eventCode, fixture: ev.id });
    if (sp.event === ev) { sp.channels = r.ok ? r.channels : []; renderRemote(); }
  }

  // ----- small pieces -----
  const hubLead = (ev) => ev.awayFirst
    ? { name: ev.away, logo: ev.awayLogo, score: ev.awayScore }
    : { name: ev.home, logo: ev.homeLogo, score: ev.homeScore };
  const hubTrail = (ev) => ev.awayFirst
    ? { name: ev.home, logo: ev.homeLogo, score: ev.homeScore }
    : { name: ev.away, logo: ev.awayLogo, score: ev.awayScore };
  function hubScores(ev) {
    // Older apps send only "2–1" (home first).
    let h = ev.homeScore, a = ev.awayScore;
    if ((h === undefined || a === undefined) && ev.score) {
      const m = String(ev.score).match(/(\d+)\D+(\d+)/);
      if (m) { h = +m[1]; a = +m[2]; }
    }
    return ev.awayFirst ? [a, h] : [h, a];
  }
  const hubIsAmerican = (ev) => /american football|basketball|baseball|hockey/i.test(ev.sport || "")
    || /^(NFL|NBA|MLB|NHL|WNBA|NCAAF|NCAAB)$/i.test(ev.league || "");
  const hubDone = (ev) => (hubIsAmerican(ev) ? "FINAL" : "FT");
  const hubClock = (ev) => {
    const l = String(ev.label || ev.status || "").trim();
    return !l || /^(live|in ?play|inprogress)$/i.test(l) ? "LIVE" : l.replace(/^in progress$/i, "LIVE");
  };
  function hubSoon(ev) {
    const mins = Math.round((ev.kickoff * 1000 - Date.now()) / 60000);
    if (mins <= 0) return "Starting";
    if (mins < 60) return `In ${mins} min`;
    if (mins < 6 * 60) return `In ${Math.floor(mins / 60)}h ${String(mins % 60).padStart(2, "0")}m`;
    return "";
  }
  const hubShortDate = (t) => new Date(t * 1000).toLocaleDateString(undefined, { weekday: "short", day: "numeric", month: "short" });
  const hubCrest = (url, label, cls = "") => {
    const a = art(url, "logo", label);
    a.classList.add("hub-crest");
    if (cls) a.classList.add(...cls.split(" "));
    return a;
  };
  const hubPlaying = (ev) => {
    const np = nowPlaying();
    return np.active && np.fixtureID && String(np.fixtureID) === String(ev.id);
  };

  // ----- the screen -----
  function renderRemoteSports(panel) {
    const sp = remote.sports;
    const groups = (snapshot.sports || {}).groups || [];
    if (!groups.length) { panel.append(el("p", { class: "empty", text: "Their Sports Hub hasn't loaded yet." })); return; }
    if (!sp.dest) { setTimeout(hubEnsure, 0); sp.dest = UPCOMING_DEST; }
    const tv = hubIsTV();
    const hub = applyHubTheme(el("div", { class: "hub " + (tv ? "hub-tv" : "hub-ios") }));
    panel.append(hub);

    if (sp.event) { hubEventPage(hub, tv); return; }

    // Ticker, header and the shelf stay pinned under the app bar while the list scrolls.
    const top = el("div", { class: "hub-top" });
    hub.append(top);
    if (hubSetting("sportsHubShowLiveTicker", true) !== false && sp.ticker && sp.ticker.length) top.append(hubTicker(sp.ticker));
    top.append(hubHeader(tv));
    if (sp.dest.code === "HIGHLIGHTS") { renderHighlights(hub, tv); if (sp.picker) hub.append(hubPicker(tv)); return; }
    const dest = sp.dest;
    const evs = sp.events;
    const hasTable = !!(sp.table && hubTableGroups(sp.table).length);

    // The shelf: Upcoming filters by sport; a competition has Fixtures / Results (and on the
    // phone, Table, which the TV layout keeps beside the list instead).
    if (dest.code === "UPCOMING") {
      const sports = [...new Set((evs || []).map(hubSportName).filter(Boolean))];
      if (sports.length > 1) {
        const strip = el("div", { class: "hub-shelf hub-chips" });
        for (const s of ["All", ...sports]) {
          const b = el("button", { class: "hub-chip" + (sp.filter === s ? " on" : ""), type: "button", text: s });
          b.addEventListener("click", () => { sp.filter = s; renderRemote(); });
          strip.append(b);
        }
        top.append(strip);
      }
    } else {
      const tabs = [["fixtures", hubIsAmerican({ league: dest.code, sport: dest.sport }) ? "Schedule" : "Fixtures"], ["results", "Results"]];
      if (!tv && hasTable) tabs.push(["table", /basketball|baseball|american|hockey/i.test(dest.sport || "") ? "Standings" : "Table"]);
      const shelf = el("div", { class: "hub-shelf hub-tabs", role: "tablist" });
      for (const [id, title] of tabs) {
        const b = el("button", { class: "hub-tab" + (sp.view === id ? " on" : ""), type: "button", role: "tab", "aria-selected": sp.view === id ? "true" : "false", text: title });
        b.addEventListener("click", () => {
          const reload = (id === "results") !== (sp.view === "results");
          sp.view = id;
          if (reload) { sp.events = null; hubOpen(dest); } else renderRemote();
        });
        shelf.append(b);
      }
      top.append(shelf);
    }

    const body = el("div", { class: "hub-body" + (tv && hasTable ? " with-table" : "") });
    hub.append(body);
    const list = el("div", { class: "hub-list" });
    body.append(list);
    if (tv && hasTable) {
      body.append(el("aside", { class: "hub-side" },
        el("div", { class: "hub-side-head", text: /basketball|baseball|american|hockey/i.test(dest.sport || "") ? "Standings" : "Table" }),
        hubTableEl(sp.table, window.innerWidth < 1300)));
    }

    if (sp.view === "table" && !tv && dest.code !== "UPCOMING") {
      if (hasTable) list.append(hubTableEl(sp.table, false));
      else list.append(hubEmpty(sp.tableTried ? "No table for this competition." : "Loading the table…"));
    } else {
      hubFixtureList(list, tv, hasTable);
    }

    if (sp.picker) hub.append(hubPicker(tv));
  }

  const hubSportName = (ev) => {
    const s = String(ev.sport || "").trim();
    if (!s) return "";
    if (/soccer/i.test(s)) return "Football";
    if (/^football$/i.test(s) || /american football/i.test(s)) return "American Football";
    return s.charAt(0).toUpperCase() + s.slice(1);
  };
  const hubEmpty = (text, sub) => el("div", { class: "hub-empty" },
    el("div", { class: "hub-empty-title", text }), sub ? el("div", { class: "hub-empty-sub", text: sub }) : null);

  function hubFixtureList(list, tv, hasTable) {
    const sp = remote.sports;
    const dest = sp.dest;
    if (!sp.events) { list.append(hubSkeleton(tv)); return; }
    let evs = sp.events;
    const upcoming = dest.code === "UPCOMING";
    if (upcoming) { if (sp.filter && sp.filter !== "All") evs = evs.filter((e) => hubSportName(e) === sp.filter); }
    else if (sp.view === "results") evs = evs.filter((e) => e.state === "finished");
    else evs = evs.filter((e) => e.state !== "finished");
    if (!evs.length) {
      list.append(hubEmpty(upcoming ? "Nothing live or coming up" : sp.view === "results" ? "No recent results" : "No fixtures this week",
        upcoming ? "Live now and the next 24 hours, from every competition in their hub." : null));
      return;
    }
    // The crest bay / league line shows when the list spans competitions, as in the app.
    const many = upcoming || dest.all || !dest.competition && new Set(evs.map((e) => e.league)).size > 1;
    const showCrest = tv ? !hasTable || many : many;
    let head = "";
    for (const ev of evs) {
      // Upcoming keeps the app's own groups (and order); a competition goes live, then by day.
      const h = upcoming && ev.group ? ev.group : ev.state === "live" ? "Live now" : dayText(ev.kickoff);
      if (h !== head) {
        head = h;
        const isLive = /^live/i.test(h);
        list.append(el("div", { class: "hub-day" + (isLive ? " live" : "") },
          isLive ? el("span", { class: "hub-pulse" }) : null, el("span", { text: h })));
      }
      list.append(tv ? hubCardTV(ev, showCrest) : hubCardPhone(ev, showCrest));
      if (ev.highlight && ev.highlight.clips && ev.highlight.clips.length) {
        const b = el("button", { class: "hl-result-btn", type: "button" }, hubPlayIcon(), el("span", { text: "Highlights" }),
          el("span", { class: "hl-result-src", text: ev.highlight.clips[0].label || "" }));
        b.addEventListener("click", () => openClipSheet(ev.highlight));
        list.append(b);
      }
    }
  }

  function hubSkeleton(tv) {
    const box = el("div", { class: "hub-skeleton" });
    box.append(el("div", { class: "hub-day sk" }, el("span", { class: "sk-bar w1" })));
    for (let i = 0; i < (tv ? 4 : 5); i++) box.append(el("div", { class: "fx " + (tv ? "fx-tv" : "fx-ios") + " sk-card" }));
    return box;
  }

  // ----- Ticker (LiveScoreStrip): today's whole card, on a belt -----
  function hubTicker(events) {
    const today = new Date().toDateString();
    const day = events.filter((e) => e.state === "live" || new Date(e.kickoff * 1000).toDateString() === today);
    if (!day.length) return null;
    const rank = (e) => (e.state === "live" ? 0 : e.state === "upcoming" ? 1 : 2);
    day.sort((a, b) => rank(a) - rank(b) || a.kickoff - b.kickoff);
    const live = day.filter((e) => e.state === "live").length;
    const chips = () => {
      const out = [];
      let league = "";
      for (const e of day.slice(0, 40)) {
        if (e.league !== league) {
          league = e.league;
          out.push(el("span", { class: "tk-league" }, hubCrest(e.leagueLogo, e.league, "xs"), el("span", { text: e.league })));
        }
        const [a, b] = hubScores(e);
        const lead = hubLead(e), trail = hubTrail(e);
        const chip = e.tournament
          ? el("button", { class: "tk-chip", type: "button", tabindex: "-1" }, el("span", { class: "tk-team", text: e.home || e.league }),
            e.state === "live" ? el("span", { class: "tk-clock", text: "LIVE" }) : e.state === "finished" ? el("span", { class: "tk-ft", text: "FINAL" }) : el("span", { class: "tk-time", text: timeText(e.kickoff) }))
          : el("button", { class: "tk-chip" + (e.state === "live" ? " live" : ""), type: "button", tabindex: "-1" },
          el("span", { class: "tk-team", text: shortTeam(lead.name) }),
          e.state === "upcoming" ? el("span", { class: "tk-time", text: timeText(e.kickoff) })
            : el("span", { class: "tk-score", text: `${a ?? ""}–${b ?? ""}` }),
          el("span", { class: "tk-team", text: shortTeam(trail.name) }),
          e.state === "live" ? el("span", { class: "tk-clock", text: hubClock(e) })
            : e.state === "finished" ? el("span", { class: "tk-ft", text: hubDone(e) }) : null);
        chip.addEventListener("click", () => openSportsEvent(e, "UPCOMING"));
        out.push(chip);
      }
      return out;
    };
    const lane = el("div", { class: "tk-lane" }, el("div", { class: "tk-run" }, chips()), el("div", { class: "tk-run", "aria-hidden": "true" }, chips()));
    lane.style.setProperty("--tk-dur", Math.max(30, day.length * 5) + "s");
    return el("div", { class: "hub-ticker" },
      el("div", { class: "tk-badge" + (live ? " live" : "") }, live ? el("span", { class: "hub-pulse" }) : null, el("span", { text: live ? `${live} LIVE` : "TODAY" })),
      el("div", { class: "tk-window" }, lane));
  }
  const shortTeam = (n) => {
    const s = String(n || "");
    return s.length > 14 && s.includes(" ") ? s.split(" ").filter((w) => !/^(fc|afc|cf|sc)$/i.test(w)).slice(0, 2).join(" ") : s;
  };

  // ----- Header (HubLeagueHeader): crest, SPORT · N LIVE, name ▾, the places switch -----
  function hubHeader(tv) {
    const sp = remote.sports;
    const dest = sp.dest;
    const live = (sp.events || []).filter((e) => e.state === "live").length;
    const place = dest.code === "UPCOMING";
    const logo = dest.logo || (!place && (sp.events || []).find((e) => e.leagueLogo) || {}).leagueLogo;
    const crest = place ? el("span", { class: "hub-place-ico", "aria-hidden": "true" }, dest.code === "HIGHLIGHTS" ? hubPlayIcon() : hubCalendarIcon()) : hubCrest(logo, dest.name, "head");
    const eyebrow = (place ? "Sports Hub" : dest.sport || "Sports Hub").toUpperCase() + (live ? ` · ${live} LIVE` : "");
    const title = el("button", { class: "hub-title", type: "button", "aria-haspopup": "dialog" },
      el("span", { class: "hub-title-text", text: dest.label || dest.name }), el("span", { class: "hub-caret", text: "▾" }));
    title.addEventListener("click", () => { sp.picker = true; sp.pickQuery = ""; sp.pickSport = dest.sport || null; renderRemote(); });
    const up = el("button", { class: "hub-seg" + (place ? " on" : ""), type: "button", title: "Upcoming" },
      hubCalendarIcon(), el("span", { text: "Upcoming" }));
    up.addEventListener("click", () => hubOpen(UPCOMING_DEST));
    const hlOn = dest.code === "HIGHLIGHTS";
    const hl = el("button", { class: "hub-seg" + (hlOn ? " on" : ""), type: "button", title: "Highlights" },
      hubPlayIcon(), el("span", { text: "Highlights" }));
    hl.addEventListener("click", () => hubOpen(HIGHLIGHTS_DEST));
    return el("div", { class: "hub-head" },
      crest,
      el("div", { class: "hub-head-text" },
        el("div", { class: "hub-eyebrow" + (live ? " live" : ""), text: eyebrow }),
        title),
      el("div", { class: "hub-places" }, up, hl),
      tv ? el("div", { class: "hub-clock", text: new Date().toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" }) }) : null);
  }
  function hubCalendarIcon() {
    const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    s.setAttribute("viewBox", "0 0 24 24");
    s.innerHTML = '<rect x="3.5" y="5" width="17" height="15.5" rx="3" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M3.5 10h17M8 3v4M16 3v4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><circle cx="12" cy="15" r="1.6" fill="currentColor"/>';
    return s;
  }

  function hubPlayIcon() {
    const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    s.setAttribute("viewBox", "0 0 24 24");
    s.innerHTML = '<rect x="3" y="5" width="18" height="14" rx="3.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M10 9.2v5.6l4.8-2.8z" fill="currentColor"/>';
    return s;
  }

  // ----- Highlights (the tvOS Highlights tab) -----
  // Billboard on top (the picked game: kit-split art, crests, score bug, its sources), then
  // rails: LATEST, YOUR TEAMS, one per competition in their hub's order. Cards are the app's
  // club art (kit split + crests + score bug), NEW on the left edge, the league tag on the
  // mixed rails. Picking a card moves it to the billboard, as focus does on the TV.
  const hlColor = (c, fallback) => {
    const v = String(c || "").replace(/^#/, "");
    return /^[0-9a-f]{6}$/i.test(v) ? "#" + v : fallback;
  };
  function hlKitArt(h, size) {
    const box = el("div", { class: "hl-art hl-art-" + size });
    if (h.event) {
      box.classList.add("event");
      box.append(hubCrest(h.leagueLogo, h.league, "hl-crest"));
      return box;
    }
    const left = el("span", { class: "hl-kit left" }), right = el("span", { class: "hl-kit right" });
    left.style.background = hlColor(h.home.color, "#2b3a55");
    right.style.background = hlColor(h.away.color, "#55402b");
    box.append(left, right,
      el("span", { class: "hl-crest-slot l" }, hubCrest(h.home.logo, h.home.name, "hl-crest")),
      el("span", { class: "hl-crest-slot r" }, hubCrest(h.away.logo, h.away.name, "hl-crest")));
    if (h.score) box.append(el("span", { class: "hl-bug", text: h.score }));
    return box;
  }
  const hlWatched = (h) => (h.clips || []).some((c) => c.watched);
  function hlCard(h, tagLeague) {
    const sp = remote.sports;
    const picked = sp.hlPick && sp.hlPick.id === h.id;
    const card = el("button", { class: "hl-card" + (picked ? " picked" : "") + (hlWatched(h) ? " watched" : ""), type: "button" });
    const art = hlKitArt(h, "card");
    if (h.new && !hlWatched(h)) art.append(el("span", { class: "hl-new", text: "NEW" }));
    if (tagLeague && (h.short || h.league)) art.append(el("span", { class: "hl-tag", text: h.short || h.league }));
    if (hlWatched(h)) art.append(el("span", { class: "hl-tick", text: "✓" }));
    card.append(art,
      el("span", { class: "hl-cap" }, el("span", { class: "hl-cap-title", text: h.title }),
        el("span", { class: "hl-cap-sub", text: [dayText(h.kickoff), h.venue].filter(Boolean).join(" · ") })));
    card.addEventListener("click", () => {
      sp.hlPick = h;
      renderRemote();
      const bb = document.querySelector(".hl-billboard");
      if (bb) bb.scrollIntoView({ behavior: "smooth", block: "nearest" });
    });
    return card;
  }
  function hlRail(title, sub, items, tagLeague, logo) {
    if (!items || !items.length) return null;
    const rail = el("div", { class: "hl-rail-track" });
    let day = "";
    for (const h of items) {
      const d = dayText(h.kickoff);
      if (!tagLeague && d !== day) { day = d; rail.append(el("span", { class: "hl-spine", text: d.toUpperCase() })); }
      rail.append(hlCard(h, tagLeague));
    }
    return el("section", { class: "hl-rail" },
      el("div", { class: "hl-rail-head" }, logo ? hubCrest(logo, title, "xs") : null,
        el("span", { class: "hl-rail-title", text: title }), sub ? el("span", { class: "hl-rail-sub", text: sub }) : null),
      rail);
  }
  function hlBillboard(h) {
    const bb = el("div", { class: "hl-billboard" });
    const wash = el("div", { class: "hl-bb-wash" });
    wash.style.setProperty("--hl-home", hlColor(h.home && h.home.color, "#20304a"));
    wash.style.setProperty("--hl-away", hlColor(h.away && h.away.color, "#3a2a20"));
    bb.append(wash);
    const plays = el("div", { class: "hl-bb-sources" });
    for (const c of h.clips || []) plays.append(clipButtons(c, h));
    bb.append(el("div", { class: "hl-bb-body" },
      hlKitArt(h, "hero"),
      el("div", { class: "hl-bb-text" },
        el("div", { class: "hl-bb-league" }, hubCrest(h.leagueLogo, h.league, "xs"), el("span", { text: (h.league || "").toUpperCase() })),
        el("div", { class: "hl-bb-title", text: h.title }),
        el("div", { class: "hl-bb-sub", text: [h.event ? null : h.score ? "FULL TIME" : null, dayText(h.kickoff), h.venue].filter(Boolean).join(" · ") }),
        plays)));
    return bb;
  }
  function clipButtons(c, h) {
    const tvBtn = el("button", { class: "btn small btn-white", type: "button", text: "▶ Play on TV" });
    tvBtn.addEventListener("click", () => run("playHighlight", { url: c.url }, tvBtn));
    const here = c.noEmbed || !c.id ? null : el("button", { class: "btn small", type: "button", text: "Play here" });
    if (here) here.addEventListener("click", () => playClipHere(c, h));
    return el("div", { class: "hl-src" }, el("span", { class: "hl-src-label", text: (c.watched ? "✓ " : "") + (c.label || "Highlights") }), tvBtn, here);
  }
  // Results' "Highlights": the same sources in a sheet.
  function openClipSheet(h) {
    const scrim = el("div", { class: "hl-sheet-scrim" });
    const close = () => scrim.remove();
    scrim.addEventListener("click", (e) => { if (e.target === scrim) close(); });
    const x = el("button", { class: "btn small icon", type: "button", "aria-label": "Close", text: "✕" });
    x.addEventListener("click", close);
    scrim.append(el("div", { class: "hl-sheet" }, el("div", { class: "hl-sheet-head" }, el("strong", { text: h.title }), x),
      ...(h.clips || []).map((c) => clipButtons(c, h))));
    document.body.append(scrim);
  }
  // YouTube's own embedded player (privacy-enhanced domain), never a re-hosted copy.
  function playClipHere(c, h) {
    const scrim = el("div", { class: "hl-player-scrim" });
    const close = () => scrim.remove();
    const x = el("button", { class: "btn small icon hl-player-x", type: "button", "aria-label": "Close", text: "✕" });
    x.addEventListener("click", close);
    scrim.addEventListener("click", (e) => { if (e.target === scrim) close(); });
    const frame = el("iframe", { class: "hl-player", src: `https://www.youtube-nocookie.com/embed/${encodeURIComponent(c.id)}?autoplay=1&rel=0&playsinline=1`,
      title: h.title, allow: "autoplay; encrypted-media; picture-in-picture; fullscreen", allowfullscreen: "", referrerpolicy: "strict-origin-when-cross-origin" });
    scrim.append(el("div", { class: "hl-player-box" }, frame, x));
    document.body.append(scrim);
  }
  function renderHighlights(hub, tv) {
    const sp = remote.sports;
    const d = sp.hl;
    if (!d) { hub.append(hubSkeleton(tv)); return; }
    if (d.error) { hub.append(hubEmpty("Highlights aren't available", d.error)); return; }
    const all = [...(d.latest || []), ...(d.favourites || []), ...(d.rows || []).flatMap((r) => r.items)];
    if (!all.length) { hub.append(hubEmpty("No highlights yet", "Official highlights from their competitions show here a little after full time.")); return; }
    if (!sp.hlPick || !all.some((h) => h.id === sp.hlPick.id)) sp.hlPick = all[0];
    else sp.hlPick = all.find((h) => h.id === sp.hlPick.id);
    const page = el("div", { class: "hl-page" + (tv ? " tv" : "") });
    page.append(hlBillboard(sp.hlPick));
    const newest = (d.latest || [])[0];
    page.append(hlRail("Latest", newest ? "Newest from your competitions" : "", d.latest, true));
    page.append(hlRail("Your Teams", "", d.favourites, true));
    for (const r of d.rows || []) page.append(hlRail(r.title, `${r.group ? r.group + " · " : ""}${r.count} game${r.count === 1 ? "" : "s"}`, r.items, false, r.logo));
    hub.append(page);
  }

  // ----- Cards (StunningFixtureCard) -----
  function hubCardTV(ev, showCrest) {
    const live = ev.state === "live", done = ev.state === "finished";
    const lead = hubLead(ev), trail = hubTrail(ev);
    const [a, b] = hubScores(ev);
    const card = el("button", { class: "fx fx-tv" + (live ? " live" : "") + (done ? " done" : "") + (hubPlaying(ev) ? " playing" : ""), type: "button" });
    if (ev.round) card.append(el("span", { class: "fx-notch", text: String(ev.round).toUpperCase() }));
    if (ev.tournament) {
      card.append(el("div", { class: "fx-tourn" },
        el("div", { class: "fx-tourn-name", text: ev.home || ev.league }),
        el("div", { class: "fx-tourn-sub" }, live ? el("span", { class: "fx-chip live", text: hubClock(ev) }) : done ? el("span", { class: "fx-chip", text: hubDone(ev) }) : el("span", { text: `${dayText(ev.kickoff)} · ${timeText(ev.kickoff)}` }))));
    } else {
      const win = (x, y) => done && x !== undefined && y !== undefined && x > y;
      card.append(
        el("div", { class: "fx-side lead" + (win(a, b) ? " win" : "") }, el("span", { class: "fx-name", text: lead.name }), hubCrest(lead.logo, lead.name, "team")),
        el("div", { class: "fx-centre" },
          live || done ? [
            el("span", { class: "fx-chip" + (live ? " live" : ""), text: live ? hubClock(ev) : hubDone(ev) }),
            a !== undefined ? el("div", { class: "fx-score" }, el("span", { text: String(a) }), el("span", { class: "dash", text: "-" }), el("span", { text: String(b) })) : null,
          ] : [
            ev.awayFirst ? el("span", { class: "fx-at", text: "@" }) : null,
            el("div", { class: "fx-time", text: timeText(ev.kickoff) }),
            hubSoon(ev) ? el("div", { class: "fx-when", text: hubSoon(ev) }) : null,
          ]),
        el("div", { class: "fx-side trail" + (win(b, a) ? " win" : "") }, hubCrest(trail.logo, trail.name, "team"), el("span", { class: "fx-name", text: trail.name })));
    }
    if (showCrest) card.append(el("div", { class: "fx-bay" }, hubCrest(ev.leagueLogo, ev.league, "bay")));
    if (hubPlaying(ev)) card.append(el("span", { class: "fx-on", text: "On their TV" }));
    card.addEventListener("click", () => openSportsEvent(ev));
    return card;
  }

  function hubCardPhone(ev, showLeague) {
    const live = ev.state === "live", done = ev.state === "finished";
    const lead = hubLead(ev), trail = hubTrail(ev);
    const [a, b] = hubScores(ev);
    const rail = el("div", { class: "fx-rail" },
      live ? [el("span", { class: "fx-live", text: "LIVE" }), hubClock(ev) !== "LIVE" ? el("span", { class: "fx-clock", text: hubClock(ev) }) : el("span", { class: "fx-dot" })]
        : done ? [el("span", { class: "fx-ft", text: "FT" }), el("span", { class: "fx-date", text: new Date(ev.kickoff * 1000).toLocaleDateString(undefined, { day: "numeric", month: "short" }) })]
          : el("span", { class: "fx-ko", text: timeText(ev.kickoff) }));
    const row = (t, s, o) => {
      const win = done && s !== undefined && o !== undefined && s > o;
      return el("div", { class: "fx-team" + (win ? " win" : "") + (done && !win ? " lost" : "") },
        el("span", { class: "fx-disc" }, hubCrest(t.logo, t.name, "phone")),
        el("span", { class: "fx-name", text: t.name }),
        (live || done) && s !== undefined ? el("span", { class: "fx-pts", text: String(s) }) : null);
    };
    const teams = ev.tournament
      ? el("div", { class: "fx-teams" }, el("div", { class: "fx-team" }, el("span", { class: "fx-disc" }, hubCrest(ev.leagueLogo, ev.league, "phone")), el("span", { class: "fx-name", text: ev.home || ev.league })),
        ev.round ? el("div", { class: "fx-tourn-line", text: String(ev.round).toUpperCase() }) : null)
      : el("div", { class: "fx-teams" }, row(lead, a, b), el("div", { class: "fx-rule" }), row(trail, b, a));
    const leagueBits = showLeague
      ? [hubCrest(ev.leagueLogo, ev.league, "xs"), el("span", { class: "fx-league", text: ev.league }), ev.round && !ev.tournament ? el("span", { class: "fx-round", text: "· " + String(ev.round).toUpperCase() }) : null]
      : ev.round && !ev.tournament ? [el("span", { class: "fx-league", text: String(ev.round) })] : [];
    const card = el("button", { class: "fx fx-ios" + (live ? " live" : "") + (done ? " done" : "") + (hubPlaying(ev) ? " playing" : ""), type: "button" },
      el("div", { class: "fx-main" }, rail, teams),
      el("div", { class: "fx-bar" },
        el("span", { class: "fx-bar-left" }, leagueBits),
        el("span", { class: "fx-bar-right" }, hubPlaying(ev) ? el("span", { class: "fx-on", text: "On their TV" }) : null,
          live ? null : el("span", { text: done ? new Date(ev.kickoff * 1000).toLocaleDateString(undefined, { weekday: "short" }) : hubShortDate(ev.kickoff) }),
          el("span", { class: "fx-chev", text: "›" }))));
    card.addEventListener("click", () => openSportsEvent(ev));
    return card;
  }

  // ----- A match: the hero, Match centre, then where to watch it -----
  function hubEventPage(hub, tv) {
    const sp = remote.sports;
    const ev = sp.event;
    const dest = sp.dest || UPCOMING_DEST;
    const back = el("button", { class: "hub-back", type: "button", text: "‹ " + (dest.label || dest.name) });
    back.addEventListener("click", () => navBack(() => { sp.event = null; sp.channels = null; renderRemote(); }));
    const live = ev.state === "live", done = ev.state === "finished";
    const lead = hubLead(ev), trail = hubTrail(ev);
    const [a, b] = hubScores(ev);
    const side = (t, cls) => el("div", { class: "hx-team " + cls }, hubCrest(t.logo, t.name, "big"), el("div", { class: "hx-name", text: t.name }));
    const mid = el("div", { class: "hx-mid" },
      live || done ? [el("span", { class: "fx-chip" + (live ? " live" : ""), text: live ? hubClock(ev) : hubDone(ev) }),
        a !== undefined ? el("div", { class: "hx-score", text: `${a} - ${b}` }) : null]
        : [el("div", { class: "hx-time", text: timeText(ev.kickoff) }), el("div", { class: "hx-when", text: dayText(ev.kickoff) })]);
    const mcBtn = el("button", { class: "btn small hx-mc", type: "button", text: "Match centre ›" });
    mcBtn.addEventListener("click", () => openMatchCentre(ev.id, { code: sp.eventCode || dest.code, league: ev.league }));
    hub.append(el("div", { class: "hub-head hub-head-back" }, back));
    hub.append(el("div", { class: "hx" },
      el("div", { class: "hx-league" }, hubCrest(ev.leagueLogo, ev.league, "xs"), el("span", { text: ev.league + (ev.round ? " · " + ev.round : "") })),
      ev.tournament ? el("div", { class: "hx-row" }, el("div", { class: "hx-tourn", text: ev.home || ev.league }), mid)
        : el("div", { class: "hx-row" }, side(lead, "lead"), mid, side(trail, "trail")),
      el("div", { class: "hx-actions" }, mcBtn)));

    const watch = el("div", { class: "hub-watch" }, el("div", { class: "hub-day" }, el("span", { text: "Watch" })));
    hub.append(watch);
    if (!sp.channels) { watch.append(hubEmpty("Finding the channels showing it…")); return; }
    if (!sp.channels.length) { watch.append(hubEmpty("None of their channels are showing this one.")); return; }
    watch.append(el("p", { class: "hint", text: "Best match first, the same list as Watch in their Sports Hub. It plays full screen on their TV." }));
    watch.append(...bySource(sp.channels, (c) => channelRow(c, { fixture: ev.id, code: sp.eventCode || dest.code }), "list", true));
  }

  // ----- Table -----
  function hubTableGroups(t) {
    if (!t) return [];
    if (t.groups && t.groups.length) return t.groups.filter((g) => g.table && g.table.length);
    return t.table && t.table.length ? [{ name: "", table: t.table }] : [];
  }
  function hubTableEl(t, compact) {
    const groups = hubTableGroups(t);
    const box = el("div", { class: "hub-table" + (compact ? " compact" : "") });
    const noDraws = groups.every((g) => g.table.every((r) => !r.drawn));
    const soccer = /soccer|football/i.test(t.sport || "") && !/american/i.test(t.sport || "");
    for (const g of groups) {
      const rows = g.table.map((r) => el("tr", {},
        el("td", { class: "rk", text: String(r.rank) }),
        el("td", { class: "team" }, hubCrest(r.team.logo, r.team.name, "row"), el("span", { text: r.team.name })),
        el("td", { text: String(r.played) }),
        compact ? null : [el("td", { text: String(r.won) }), noDraws ? null : el("td", { text: String(r.drawn) }), el("td", { text: String(r.lost) })],
        el("td", { text: (r.goalsDiff > 0 ? "+" : "") + Math.round(r.goalsDiff || 0) }),
        el("td", { class: "pts", text: String(r.points) })));
      box.append(el("div", { class: "hub-table-group" },
        g.name ? el("div", { class: "hub-table-name", text: g.name }) : null,
        el("table", {},
          el("thead", {}, el("tr", {}, el("th", { class: "rk", text: "#" }), el("th", { class: "team", text: "Team" }), el("th", { text: "P" }),
            compact ? null : [el("th", { text: "W" }), noDraws ? null : el("th", { text: "D" }), el("th", { text: "L" })],
            el("th", { text: soccer ? "GD" : "+/-" }), el("th", { class: "pts", text: "Pts" }))),
          el("tbody", {}, rows))));
    }
    return box;
  }

  // ----- The competition picker (HubCompetitionSwitcher): sports, then their competitions -----
  function hubPicker(tv) {
    const sp = remote.sports;
    const sports = hubSports();
    if (!sp.pickSport || !sports.some((s) => s.name === sp.pickSport)) sp.pickSport = sports[0] ? sports[0].name : null;
    const close = () => { sp.picker = false; renderRemote(); };
    const grid = el("div", { class: "pk-grid" });
    const fillGrid = () => {
      const q = (sp.pickQuery || "").trim().toLowerCase();
      const items = q ? sports.flatMap((s) => s.items).filter((i) => (i.label || i.name).toLowerCase().includes(q))
        : ((sports.find((s) => s.name === sp.pickSport) || {}).items || []);
      const cur = sp.dest ? hubKey(sp.dest) : "";
      grid.replaceChildren(...items.map((it) => {
        const t = el("button", { class: "pk-tile" + (hubKey(it) === cur ? " on" : ""), type: "button" },
          hubCrest(it.logo, it.name, "tile"), el("span", { class: "pk-name", text: it.label || it.name }),
          q ? el("span", { class: "pk-sport", text: it.sport }) : null);
        t.addEventListener("click", () => hubOpen(it));
        return t;
      }));
      if (!items.length) grid.append(el("p", { class: "pk-none", text: q ? "No competition by that name in their hub." : "Nothing shown for this sport." }));
    };
    fillGrid();
    const search = el("input", { class: "pk-search", type: "search", placeholder: "Search competitions", value: sp.pickQuery || "", autocomplete: "off" });
    search.addEventListener("input", () => { sp.pickQuery = search.value; fillGrid(); });
    const sportBtn = (name, onClick, on) => {
      const b = el("button", { class: "pk-sport-btn" + (on ? " on" : ""), type: "button", text: name });
      b.addEventListener("click", onClick);
      return b;
    };
    const upBtn = sportBtn("Upcoming", () => hubOpen(UPCOMING_DEST), false);
    upBtn.classList.add("place");
    const column = el("div", { class: "pk-sports" }, upBtn,
      sports.map((s) => sportBtn(s.name, () => { sp.pickSport = s.name; sp.pickQuery = ""; search.value = ""; column.querySelectorAll(".pk-sport-btn").forEach((n) => n.classList.toggle("on", n.textContent === s.name && !n.classList.contains("place"))); fillGrid(); }, s.name === sp.pickSport)));
    const x = el("button", { class: "pk-close", type: "button", "aria-label": "Close", text: tv ? "Close" : "Done" });
    x.addEventListener("click", close);
    const sheet = el("div", { class: "pk-sheet", role: "dialog", "aria-label": "Competitions" },
      el("div", { class: "pk-top" }, el("div", { class: "pk-title", text: "Competitions" }), x),
      search,
      el("div", { class: "pk-body" }, column, grid));
    const dim = el("div", { class: "pk-dim" }, sheet);
    dim.addEventListener("click", (e) => { if (e.target === dim) close(); });
    dim.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
    setTimeout(() => { if (tv) search.focus({ preventScroll: true }); }, 0);
    return dim;
  }

  // ---------- Copy Setup: read your own device, write theirs ----------
  // Your setup lives on your own device, not on a server, so this page connects to it too, for
  // a moment, with its own Remote Help number. Nothing is stored anywhere.
  // What iCloud shares between someone's own devices is copied by default. Device settings
  // (guide size, player, themes, tabs) belong to one screen, so they only copy between the same
  // kind of device, and only when ticked.
  const copyState = { setup: null, busy: false, error: "", playlists: null, sent: false,
    parts: new Set(["categories", "custom", "favourites", "home", "sports"]) };

  // Same as the app's `RemoteHelpTools.matchKey`: one playlist on two devices.
  function matchKey(kind, url, username) {
    let host = (url || "").toLowerCase();
    try { host = new URL(url).hostname.toLowerCase(); } catch {}
    return kind === "m3u" ? "m3u|" + (url || "").toLowerCase().trim() : "x|" + host + "|" + (username || "").toLowerCase();
  }
  const COPY_PARTS = [
    ["categories", "TV channel, movie and series categories", "Which are shown, their order and pins, for the playlists ticked above.", "channels"],
    ["custom", "Custom categories", "Your own categories, with their channels from the playlists ticked above.", "channels"],
    ["favourites", "Favourite channels", "From the playlists ticked above.", "channels"],
    ["home", "Home screen rows", "The rows and their order.", "channels"],
    ["sports", "Sports Hub", "Shown sports and competitions, favourite teams and competitions.", "shared"],
    ["settings", "Device settings", "Guide size, themes, player options and which tabs show.", "device"],
  ];

  async function fetchSetup(sourceCode) {
    const kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const pub = b64e(await crypto.subtle.exportKey("raw", kp.publicKey));
    return new Promise((resolve, reject) => {
      let key = null;
      let settled = false;
      const parts = new Map();
      const sock = new WebSocket(`${RELAY}?code=${sourceCode}&role=helper&hid=${hid}`);
      const finish = (fn, value) => { if (settled) return; settled = true; clearTimeout(timer); try { sock.close(); } catch {} fn(value); };
      const timer = setTimeout(() => finish(reject, new Error("Your device didn't answer. Is Remote Help open on it?")), 45000);
      const send = async (obj) => {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const c = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, te.encode(JSON.stringify(obj)));
        sock.send(JSON.stringify({ t: "enc", id: String(Math.random()), i: 0, n: 1, iv: b64e(iv), c: b64e(c) }));
      };
      sock.onmessage = async (event) => {
        if (event.data === "pong") return;
        let msg; try { msg = JSON.parse(event.data); } catch { return; }
        if (msg.t === "peer" && msg.state === "joined") sock.send(JSON.stringify({ t: "hello", pub }));
        else if (msg.t === "hello") {
          const peer = await crypto.subtle.importKey("raw", b64d(msg.pub), { name: "ECDH", namedCurve: "P-256" }, false, []);
          const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, kp.privateKey, 256);
          const hk = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
          key = await crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: te.encode("tivepg-remote-help:" + sourceCode), info: te.encode("TivEPG Remote Help v1") },
            hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
          await send({ type: "hi", name: (helperName || "You") + " (copying your setup)" });
          await send({ type: "exportSetup", req: "copy-1" });
        } else if (msg.t === "enc" && key) {
          const got = parts.get(msg.id) || [];
          got[msg.i] = msg.c;
          if (got.filter((p) => p !== undefined).length < msg.n) { parts.set(msg.id, got); return; }
          parts.delete(msg.id);
          try {
            const plain = JSON.parse(td.decode(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(msg.iv) }, key, b64d(got.join("")))));
            if (plain.type === "result" && plain.req === "copy-1") {
              plain.ok && plain.setup ? finish(resolve, plain.setup) : finish(reject, new Error(plain.message || "Your device couldn't share its setup. Update TivEPG on it."));
            }
          } catch (e) { /* the snapshot it also sends isn't needed here */ }
        }
      };
      sock.onclose = (event) => {
        const why = { 4003: "That number is already in use by someone else.", 4004: "That number didn't work. Check it on your device's Remote Help screen.", 4029: "Too many tries. Wait a minute." };
        finish(reject, new Error(why[event.code] || "Couldn't connect to your device."));
      };
    });
  }

  function renderCopy() {
    const panel = $("tab-copy");
    panel.replaceChildren();
    panel.append(el("p", { class: "hint", text: "Copy your own TivEPG setup onto their device. Your setup is on your own device, so this page connects to it for a moment too. Nothing is stored." }));

    if (!copyState.setup) {
      const code2 = el("input", { class: "code-input small-code", inputmode: "numeric", maxlength: "7", placeholder: "000 000", "aria-label": "Your device's number" });
      code2.addEventListener("input", () => {
        const d = code2.value.replace(/\D/g, "").slice(0, 6);
        code2.value = d.length > 3 ? d.slice(0, 3) + " " + d.slice(3) : d;
      });
      const go = el("button", { class: "btn btn-white", type: "button", text: copyState.busy ? "Getting your setup…" : "Get my setup" });
      go.disabled = copyState.busy;
      go.addEventListener("click", async () => {
        const digits = code2.value.replace(/\D/g, "");
        if (digits.length !== 6) { copyState.error = "The number has 6 digits."; return renderCopy(); }
        if (digits === code) { copyState.error = "That's their device's number. Use the one on YOUR device."; return renderCopy(); }
        copyState.busy = true; copyState.error = ""; renderCopy();
        try { copyState.setup = await fetchSetup(digits); }
        catch (e) { copyState.error = e.message; }
        copyState.busy = false;
        renderCopy();
      });
      panel.append(el("ol", { class: "how copy-steps" },
        el("li", {}, el("span", { class: "how-num", text: "1" }), el("div", {}, el("b", { text: "On YOUR iPhone, iPad, Mac or Apple TV" }), el("p", { text: "Open TivEPG › Settings › Remote Help. It shows a number." }))),
        el("li", {}, el("span", { class: "how-num", text: "2" }), el("div", {}, el("b", { text: "Type that number here" }), code2, go,
          copyState.error ? el("p", { class: "error", text: copyState.error }) : null))));
      return;
    }

    const s = copyState.setup;
    const count = (k) => (s.categories && s.categories[k] || []).length;
    panel.append(el("div", { class: "banner ok-banner", text: `Got your setup from your ${s.from || "device"}: ${(s.servers || []).length} playlist(s), ${count("live") + count("vod") + count("series")} categories, ${(s.favourites || []).length} favourite channels. You can press Stop on your device now.` }));
    const target = (snapshot.device || {}).platform || "device";
    const sameKind = (s.from || "") === target;
    if (!sameKind) copyState.parts.delete("settings");

    // 1. Which playlists. One already on their device only needs ticking to bring its
    // categories and favourites; a new one is added with its login.
    const theirs = new Set((snapshot.servers || []).map((x) => matchKey(x.kind, x.url, x.username)));
    const sources = (s.servers || []).filter((x) => x.m);
    if (!copyState.playlists) copyState.playlists = new Set(sources.map((x) => x.m));
    panel.append(el("h4", { class: "hub-section", text: "1 · Which playlists" }));
    panel.append(el("p", { class: "hint", text: "A playlist's categories and favourites only work with that playlist, so tick the ones to bring across." }));
    const plCard = el("div", { class: "hub-card" });
    if (!sources.length) plCard.append(el("p", { class: "empty flat", text: "Your device has no playlists to copy." }));
    for (const pl of sources) {
      const have = theirs.has(pl.m);
      const box = el("input", { type: "checkbox", id: "pl-" + pl.m });
      box.checked = copyState.playlists.has(pl.m);
      box.addEventListener("change", () => { box.checked ? copyState.playlists.add(pl.m) : copyState.playlists.delete(pl.m); renderCopy(); });
      plCard.append(el("label", { class: "hub-row copy-row", for: "pl-" + pl.m }, box,
        el("div", { class: "grow" },
          el("div", { class: "title wrap" }, pl.name || "Playlist", el("span", { class: "badge " + (have ? "good" : "off"), text: have ? "On their device" : "New" })),
          el("div", { class: "sub", text: have ? "Already on their device, nothing to log in to." : `Will be added to their device with your ${pl.kind === "m3u" ? "playlist link" : "login"}.` }))));
    }
    panel.append(plCard);

    const anyPlaylist = copyState.playlists.size > 0;
    const addingNew = sources.some((x) => copyState.playlists.has(x.m) && !theirs.has(x.m));
    const section = (kind, heading, note) => {
      panel.append(el("h4", { class: "hub-section", text: heading }));
      if (note) panel.append(el("p", { class: "hint", text: note }));
      const card = el("div", { class: "hub-card" });
      for (const [id, title, detail, k] of COPY_PARTS) {
        if (k !== kind) continue;
        const blocked = (id === "settings" && !sameKind) || (k === "channels" && id !== "home" && !anyPlaylist);
        const box = el("input", { type: "checkbox", id: "copy-" + id });
        box.checked = copyState.parts.has(id) && !blocked;
        box.disabled = blocked;
        box.addEventListener("change", () => { box.checked ? copyState.parts.add(id) : copyState.parts.delete(id); });
        card.append(el("label", { class: "hub-row copy-row" + (blocked ? " dim" : ""), for: "copy-" + id }, box,
          el("div", { class: "grow" }, el("div", { class: "title wrap", text: title }),
            el("div", { class: "sub", text: blocked && k === "channels" ? "Tick a playlist above first."
              : blocked ? `Only copied between the same kind of device. Yours is ${s.from && /^[aeiou]/i.test(s.from) ? "an" : "a"} ${s.from || "different device"}, theirs is ${/^[aeiou]/i.test(target) ? "an" : "a"} ${target}.`
              : detail }))));
      }
      panel.append(card);
    };
    section("channels", "2 · What goes with them", addingNew
      ? "New playlists need to load on their device first. These are copied by themselves once they have."
      : "For the playlists ticked above.");
    section("shared", "3 · Also copy", "The same things iCloud keeps in step across someone's own devices.");
    section("device", `4 · Just this ${target}`, "Sizes and player options suit one screen, so these aren't shared unless you tick them.");
    const apply = el("button", { class: "btn btn-white", type: "button", text: "Copy to their device" });
    apply.addEventListener("click", async () => {
      if (!copyState.parts.size && !copyState.playlists.size) return toast("Tick at least one thing to copy.", true);
      if (copyState.parts.has("settings") && !confirm(`This replaces this ${target}'s settings and themes with yours. Carry on?`)) return;
      apply.disabled = true;
      apply.textContent = "Copying…";
      const parts = [...copyState.parts].filter((p) => p === "home" || p === "sports" || p === "settings" || anyPlaylist);
      const r = await command("importSetup", { setup: s, parts, playlists: [...copyState.playlists] });
      copyState.sent = r.ok;
      apply.disabled = false;
      apply.textContent = "Copy to their device";
      toast(r.message || (r.ok ? "Copied." : "Couldn't copy."), !r.ok);
    });
    const restart = el("button", { class: "btn", type: "button", text: "Use a different device" });
    restart.addEventListener("click", () => { copyState.setup = null; copyState.playlists = null; copyState.sent = false; renderCopy(); });
    if (copyState.sent && snapshot.copyFinished) {
      panel.append(el("div", { class: "banner ok-banner", text: "Finished on their device: " + snapshot.copyFinished }));
    }
    panel.append(el("div", { class: "row-actions" }, apply, restart));
  }

  // ---------- Custom Categories (the app's Category Manager) ----------
  const customEdit = { id: null, channels: null, results: null, query: "" };

  async function openCustomEditor(id) {
    customEdit.id = id;
    customEdit.channels = null;
    customEdit.results = null;
    renderCustom();
    const r = await command("customCategoryChannels", { id });
    if (customEdit.id === id) { customEdit.channels = r.ok ? r.channels : []; renderCustom(); }
  }

  async function customAction(type, fields, button) {
    const r = await run(type, fields, button);
    if (r.ok && r.channels && r.customID === customEdit.id) customEdit.channels = r.channels;
    renderCustom();
    return r;
  }

  function renderCustom() {
    const panel = $("tab-custom");
    const keepFocus = document.activeElement && document.activeElement.dataset.customsearch;
    panel.replaceChildren();
    const list = snapshot.customCategories;
    if (!list) {
      panel.append(el("p", { class: "empty", text: "Their device needs the latest TivEPG update to manage custom categories from here." }));
      return;
    }

    const editing = customEdit.id && list.find((c) => c.id === customEdit.id);
    if (editing) return renderCustomEditor(panel, editing, keepFocus);
    customEdit.id = null;

    // Create
    const name = el("input", { placeholder: "e.g. Sports, Kids, News", maxlength: "40", "aria-label": "New category name" });
    const opt = el("input", { type: "checkbox", id: "new-opt" });
    const create = el("button", { class: "btn btn-white", type: "button", text: "Create" });
    const doCreate = async () => {
      const r = await run("createCustomCategory", { name: name.value, optimised: opt.checked }, create);
      if (r.ok && r.customID) {
        snapshot.customCategories = [...list, { id: r.customID, name: name.value.trim(), count: 0, optimised: opt.checked }];
        openCustomEditor(r.customID);
      }
    };
    create.addEventListener("click", doCreate);
    name.addEventListener("keydown", (e) => e.key === "Enter" && doCreate());
    panel.append(el("div", { class: "card" },
      el("h3", { text: "New custom category" }),
      el("p", { class: "hint", text: "Pick any channels from any of their playlists and group them under one name. It shows in their TV guide straight away." }),
      name,
      el("label", { class: "check-row", for: "new-opt" }, opt, el("span", {}, el("b", { text: "Optimised" }), " · each channel shows once, with its other versions (HD, FHD, backups) tucked under it")),
      el("div", { class: "row-actions" }, create)));

    // Existing
    panel.append(el("h4", { class: "hub-section", text: `Their custom categories (${list.length})` }));
    const rows = el("div", { class: "list" });
    if (!list.length) rows.append(el("p", { class: "empty", text: "None yet." }));
    for (const c of list) {
      const edit = el("button", { class: "btn small", type: "button", text: "Edit" });
      edit.addEventListener("click", () => openCustomEditor(c.id));
      const del = el("button", { class: "btn small danger", type: "button", text: "Delete" });
      del.addEventListener("click", () => {
        if (confirm(`Delete "${c.name}" from their device? This can't be undone.`)) run("deleteCustomCategory", { id: c.id }, del);
      });
      rows.append(el("div", { class: "item" },
        el("div", { class: "grow" }, el("div", { class: "title", text: c.name }),
          el("div", { class: "sub", text: `${c.count} channel${c.count === 1 ? "" : "s"}${c.optimised ? " · Optimised" : ""}` })),
        edit, del));
    }
    panel.append(rows);
  }

  function renderCustomEditor(panel, cat, keepFocus) {
    const done = el("button", { class: "btn small", type: "button", text: "‹ All custom categories" });
    done.addEventListener("click", () => { customEdit.id = null; renderCustom(); });
    panel.append(el("div", { class: "row-actions tight" }, done));

    const name = el("input", { value: cat.name, maxlength: "40", "aria-label": "Category name" });
    const save = el("button", { class: "btn", type: "button", text: "Rename" });
    save.addEventListener("click", async () => {
      const r = await customAction("renameCustomCategory", { id: cat.id, name: name.value }, save);
      if (r.ok) cat.name = name.value.trim();
    });
    panel.append(el("div", { class: "card" }, el("h3", { text: cat.name }), el("div", { class: "pass-wrap" }, name, save)));

    // Channels in it
    const channels = customEdit.channels;
    panel.append(el("h4", { class: "hub-section", text: channels ? `Channels (${channels.length})` : "Channels" }));
    const list = el("div", { class: "list" });
    if (!channels) list.append(el("p", { class: "empty", text: "Loading…" }));
    else if (!channels.length) list.append(el("p", { class: "empty", text: "No channels yet. Search below to add some." }));
    else {
      const move = (from, to) => {
        customEdit.channels = moveIndex(channels, from, to);
        renderCustom();
        customAction("customCategoryOrder", { id: cat.id, keys: customEdit.channels.map((c) => c.key) });
      };
      const rows = channels.map((ch, i) => {
        const remove = binButton("Remove " + ch.name);
        remove.addEventListener("click", () => customAction("customCategoryRemove", { id: cat.id, server: ch.server, channel: ch.channel }, remove));
        const row = el("div", { class: "item" }, dragHandle(ch.name),
          el("span", { class: "num", text: String(i + 1) }),
          el("div", { class: "grow" }, chanTitle(ch),
            el("div", { class: "sub", text: ch.missing ? "Not in their playlists any more" : ch.source })),
          ...moveButtons(i, channels.length, move), remove);
        list.append(row);
        return row;
      });
      sortable(rows, move);
    }
    panel.append(list);

    // Add channels
    const search = channelSearchBox("Search their channels to add, e.g. Sky Sports", (results) => { customEdit.results = results; renderCustom(); });
    search.dataset.customsearch = "1";
    search.value = keepFocus ? customEdit.query : "";
    search.addEventListener("input", () => { customEdit.query = search.value; });
    const results = el("div", { class: "list" });
    const inCat = new Set((channels || []).map((c) => c.key));
    for (const r of customEdit.results || []) {
      const key = r.server + "|" + r.channel;
      const add = el("button", { class: "btn small btn-white", type: "button", text: inCat.has(key) ? "Added" : "+ Add" });
      add.disabled = inCat.has(key);
      add.addEventListener("click", () => customAction("customCategoryAdd", { id: cat.id, server: r.server, channel: r.channel }, add));
      const all = el("button", { class: "btn small", type: "button", text: "+ All versions", title: "Also adds this channel's HD/FHD/backup versions from every playlist" });
      all.addEventListener("click", () => customAction("customCategoryAdd", { id: cat.id, server: r.server, channel: r.channel, variants: true }, all));
      results.append(el("div", { class: "item" },
        el("div", { class: "grow" }, chanTitle(r), el("div", { class: "sub", text: r.source })), add, all));
    }
    if (customEdit.results && !customEdit.results.length) results.append(el("p", { class: "empty", text: "No channels match." }));
    panel.append(el("div", { class: "card" }, el("h3", { text: "Add channels" }), search, results));
    if (keepFocus) { search.focus(); search.setSelectionRange(search.value.length, search.value.length); }
  }

  // ---------- start ----------
  // "#123456" = a shared link (they still type their name); "#123456;own;From" = the app's own
  // "Connect to …" on the same Apple account: join at once, as From, and open the Remote.
  const hashParts = decodeURIComponent(location.hash.slice(1)).split(";");
  const fromLink = (hashParts[0] || "").replace(/\D/g, "").slice(0, 6);
  const ownDevice = fromLink.length === 6 && hashParts[1] === "own";
  if (fromLink.length === 6) $("code").value = fromLink.slice(0, 3) + " " + fromLink.slice(3);
  $("name").value = localStorage.getItem("rh-name") || "";
  if (!window.crypto || !crypto.subtle || !("WebSocket" in window)) {
    $("join-error").textContent = "This browser is too old for Remote Help. Try the latest Safari, Chrome, Edge or Firefox.";
    $("join-error").hidden = false;
    $("join").disabled = true;
  } else if (ownDevice) {
    $("name").value = (hashParts[2] || "").slice(0, 30) || $("name").value || "Your other device";
    document.body.classList.add("own-device");
    startJoin();
  } else if (fromLink.length === 6) {
    $("name").focus();
  } else {
    $("code").focus();
  }
})();
