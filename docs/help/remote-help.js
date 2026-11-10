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
        4008: "Remote Help ended after 30 minutes. They can start it again for a new number.",
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
      if ($("screen-help").hidden) { show("help"); history.replaceState({ section: null }, ""); showTab(null, false); }
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
    if (helperName) localStorage.setItem("rh-name", helperName);
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
    { id: "remote", title: "Remote", icon: "#i-remote", tint: "blue" },
    { id: "copy", title: "Copy Setup", icon: "#i-copy", tint: "grey" },
  ];

  function showTab(name, push = true) {
    currentTab = name;
    const section = SECTIONS.find((x) => x.id === name);
    $("home-grid").hidden = !!name;
    document.querySelector(".device-head").hidden = !!name;
    $("section-bar").hidden = !name;
    $("section-title").textContent = section ? section.title : "";
    for (const panel of document.querySelectorAll(".tab-panel")) panel.hidden = panel.id !== "tab-" + name;
    if (push) history.pushState({ section: name }, "");
    if (name === "remote") remoteMode(remote.mode === "goto" ? "goto" : remote.mode);
    else if (typeof remoteRefreshEvery === "function") remoteRefreshEvery(0);
    window.scrollTo({ top: 0 });
    if (!name) renderHome();
  }
  $("back").addEventListener("click", () => history.back());
  window.addEventListener("popstate", (e) => {
    if ($("screen-help").hidden) return;
    showTab(e.state && e.state.section ? e.state.section : null, false);
  });

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
      case "remote": { const np = snapshot.nowPlaying || {}; return np.active ? `On now: ${np.name}` : "Nothing playing"; }
      case "copy": return "Copy your setup to theirs";
    }
    return "";
  }

  function renderHome() {
    const grid = $("home-grid");
    grid.replaceChildren(...SECTIONS.map((sec) => {
      const summary = cardSummary(sec.id);
      const alert = sec.id === "health" && healthState.data && healthState.data.problems;
      const card = el("button", { class: "home-card tint-" + sec.tint + (alert ? " alert" : ""), type: "button", role: "listitem" },
        el("span", { class: "home-icon" }, svgUse(sec.icon)),
        el("span", { class: "home-text" }, el("span", { class: "home-title", text: sec.title }), el("span", { class: "home-sub", text: summary })),
        alert ? el("span", { class: "home-badge", text: String(healthState.data.problems) }) : null,
        el("span", { class: "home-chev", text: "›" }));
      card.addEventListener("click", () => showTab(sec.id));
      return card;
    }));
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
    if (!currentTab) renderHome();
    if (!healthState.requested) runHealthCheck();
    else renderHealth();
  }

  // Playlists
  const openEditors = new Set();
  const editorCache = new Map();

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

  // ---------- reordering: drag by the ⠿ handle (mouse or touch), or the Top / ▲ / ▼ / Bottom buttons ----------
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
    return [mk("⤒", "Move to top", 0), mk("▲", "Move up", i - 1, "fine"), mk("▼", "Move down", i + 1, "fine"), mk("⤓", "Move to bottom", n - 1)];
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
    panel.append(el("p", { class: "hint", text: "Open a group, then drag ⠿ to reorder, or use ⤒ / ⤓ to move to the top or bottom of that group · Remove switches it off" }));
    if (!shown.length) {
      panel.append(el("p", { class: "empty", text: "Nothing is switched on. Pick categories from a playlist above." }));
    }

    const groups = [];
    const pinned = ((snapshot.displayGroups || {})[kind] || []).find((g) => g.pinned);
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
        const remove = el("button", { class: "btn small danger", type: "button", text: g.pinned ? "Unpin" : "Remove" });
        remove.addEventListener("click", () => g.pinned ? run("unpinCategory", { key: c.key }, remove) : setShown(kind, [c], false));
        const row = el("div", { class: "item" }, dragHandle(c.name),
          el("span", { class: "num", text: String(i + 1) }),
          el("div", { class: "grow" }, el("div", { class: "title", text: c.name })),
          ...moveButtons(i, g.cats.length, move), remove);
        list.append(row);
        return row;
      });
      sortable(rows, move);
      panel.append(list);
    }
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
      const remove = el("button", { class: "btn small", type: "button", text: "Remove" });
      remove.addEventListener("click", () => run("sportsFavouriteCompetition", { id: c.id, favourite: false }));
      comps.append(hubRow({ title: c.name, trailing: [remove] }));
    }
    panel.append(comps);

    panel.append(el("h4", { class: "hub-section", text: "Favourite Teams" }));
    const teams = el("div", { class: "hub-card" });
    if (!(sports.favouriteTeams || []).length) teams.append(el("p", { class: "empty flat", text: "No favourite teams. They can star a team in the Sports Hub." }));
    for (const name of sports.favouriteTeams || []) {
      const remove = el("button", { class: "btn small", type: "button", text: "Remove" });
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
    if (!currentTab) renderHome();

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
      const remove = el("button", { class: "btn small danger", type: "button", text: "Remove" });
      remove.addEventListener("click", () => run("removeFavourite", { id: f.id }, remove));
      const row = el("div", { class: "item" }, dragHandle(f.name),
        el("span", { class: "num", text: String(i + 1) }),
        el("div", { class: "grow" }, el("div", { class: "title", text: f.name }), el("div", { class: "sub", text: f.missing ? "Not in their playlists any more" : f.source })),
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
      results.append(el("div", { class: "item" }, el("div", { class: "grow" }, el("div", { class: "title", text: c.name }), el("div", { class: "sub", text: c.source })), add));
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
      const remove = el("button", { class: "btn small danger", type: "button", text: "Remove" });
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
      const remove = el("button", { class: "btn small danger", type: "button", text: "Remove" });
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
  // Picking Guide or Sports Hub switches their device to it too, and choosing a guide category
  // moves their guide to it, so you're both looking at the same thing.
  const remote = {
    mode: "guide",
    guide: { groups: null, open: new Set(["pinned"]), category: null, channels: null, filter: "" },
    sports: { group: null, item: null, events: null, event: null, channels: null },
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

  async function remoteMode(mode) {
    remote.mode = mode;
    remoteRefreshEvery(0);
    if (mode === "guide") {
      command("goTo", { tab: "Guide" });
      if (remote.guide.category) openGuideCategory(remote.guide.category, false);
      else loadGuideGroups();
    } else if (mode === "sports") {
      command("goTo", { tab: "Sports Hub" });
      if (remote.sports.item) openSportsItem(remote.sports.item);
    }
    renderRemote();
  }

  async function loadGuideGroups() {
    const r = await command("guideCategories", {});
    remote.guide.groups = r.ok ? r.groups : [];
    renderRemote();
  }

  async function openGuideCategory(cat, follow = true) {
    remote.guide.category = cat;
    if (follow) remote.guide.channels = null;
    renderRemote();
    const load = async (followTV) => {
      const r = await command("guideChannels", { key: cat.key, follow: followTV });
      if (remote.guide.category && remote.guide.category.key === cat.key) {
        remote.guide.channels = r.ok ? r.channels : [];
        if (!busy("tab-remote")) renderRemote();
      }
    };
    await load(follow);
    remoteRefreshEvery(60000, () => load(false));
  }

  async function openSportsItem(item) {
    remote.sports.item = item;
    remote.sports.event = null;
    remote.sports.channels = null;
    if (!remote.sports.events || remote.sports.events.code !== item.code + "|" + (item.competition || "")) remote.sports.events = null;
    renderRemote();
    const load = async () => {
      const r = await command("hubEvents", { code: item.code, competition: item.competition });
      if (remote.sports.item === item) {
        remote.sports.events = { code: item.code + "|" + (item.competition || ""), list: r.ok ? r.events : [] };
        if (!busy("tab-remote")) renderRemote();
      }
    };
    await load();
    remoteRefreshEvery(45000, load);
  }

  async function openSportsEvent(ev) {
    remote.sports.event = ev;
    remote.sports.channels = null;
    renderRemote();
    const r = await command("hubEventChannels", { code: remote.sports.item.code, fixture: ev.id });
    if (remote.sports.event === ev) { remote.sports.channels = r.ok ? r.channels : []; renderRemote(); }
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

  function channelRow(c, extra) {
    const watch = el("button", { class: "btn small btn-white", type: "button", text: "▶ Watch" });
    watch.addEventListener("click", () => run("playChannel", { server: c.server, channel: c.channel, ...(extra || {}) }, watch));
    let progress = null;
    if (c.nowStart && c.nowEnd) {
      const pct = Math.max(0, Math.min(100, ((Date.now() / 1000 - c.nowStart) / (c.nowEnd - c.nowStart)) * 100));
      const bar = el("span", { class: "prog-fill" });
      bar.style.width = pct + "%";
      progress = el("span", { class: "prog" }, bar);
    }
    return el("div", { class: "item chan" },
      el("div", { class: "grow" },
        el("div", { class: "title", text: c.name }),
        c.now ? el("div", { class: "now-line" }, el("span", { class: "now-title", text: c.now }),
          c.nowEnd ? el("span", { class: "sub", text: ` · until ${timeText(c.nowEnd)}` }) : null) : el("div", { class: "sub", text: c.source || "No guide information" }),
        progress,
        c.next ? el("div", { class: "sub", text: `Next: ${c.next} · ${timeText(c.nextStart)}` }) : null),
      watch);
  }

  function renderRemote() {
    const panel = $("tab-remote");
    const keepFocus = document.activeElement && document.activeElement.dataset.remotefilter;
    panel.replaceChildren();

    // On their screen now
    const np = snapshot.nowPlaying || {};
    const stop = el("button", { class: "btn small danger", type: "button", text: "Stop" });
    stop.addEventListener("click", () => run("stopPlayback", {}, stop));
    panel.append(el("div", { class: "card now-playing" },
      el("div", { class: "sub", text: "ON THEIR SCREEN NOW" }),
      el("div", { class: "row-actions tight np-row" },
        el("div", { class: "grow title-lg", text: np.active ? np.name : "Nothing playing" }),
        np.active ? stop : null)));

    const modes = el("div", { class: "subtabs remote-modes" },
      pill("📺 Guide", null, remote.mode === "guide", () => remoteMode("guide")),
      pill("🏆 Sports Hub", null, remote.mode === "sports", () => remoteMode("sports")),
      pill("Go to…", null, remote.mode === "goto", () => remoteMode("goto")));
    panel.append(modes);

    if (remote.mode === "goto") {
      panel.append(el("p", { class: "hint", text: "Opens that part of the app on their screen." }));
      panel.append(el("div", { class: "row-actions" }, [["Home", "Home"], ["Guide", "Guide"], ["Sports Hub", "Sports Hub"], ["Movies", "Movies"], ["Series", "Series"], ["Settings", "Settings"]].map(([tab, label]) => {
        const b = el("button", { class: "btn", type: "button", text: label });
        b.addEventListener("click", () => run("goTo", { tab }, b));
        return b;
      })));
      return;
    }

    if (remote.mode === "guide") renderRemoteGuide(panel);
    else renderRemoteSports(panel);

    if (keepFocus) {
      const f = panel.querySelector("input[data-remotefilter]");
      if (f) { f.focus(); f.setSelectionRange(f.value.length, f.value.length); }
    }
  }

  function filterBox(placeholder) {
    const f = el("input", { class: "search", placeholder, value: remote.guide.filter });
    f.dataset.remotefilter = "1";
    f.addEventListener("input", () => { remote.guide.filter = f.value; renderRemote(); });
    return f;
  }

  function renderRemoteGuide(panel) {
    const g = remote.guide;
    if (!g.category) {
      if (!g.groups) { panel.append(el("p", { class: "empty", text: "Loading their guide…" })); if (g.groups === null) loadGuideGroups(); g.groups = g.groups || undefined; return; }
      panel.append(el("p", { class: "hint", text: "Their guide's categories, in the same order. Pick one and their guide moves to it." }));
      panel.append(filterBox("Find a category"));
      const q = g.filter.trim().toLowerCase();
      if (!g.groups.length) panel.append(el("p", { class: "empty", text: "No TV channel categories are switched on." }));
      for (const grp of g.groups) {
        const items = grp.items.filter((c) => !q || c.name.toLowerCase().includes(q));
        if (q && !items.length) continue;
        const open = q || g.open.has(grp.id);
        const head = el("button", { class: "group-head" + (open ? " open" : ""), type: "button" },
          el("span", { class: "chev" + (open ? " open" : ""), text: "›" }),
          el("span", { class: "grow group-title", text: grp.title }),
          el("span", { class: "subtab-badge", text: String(items.length) }));
        head.addEventListener("click", () => { g.open.has(grp.id) ? g.open.delete(grp.id) : g.open.add(grp.id); renderRemote(); });
        panel.append(head);
        if (!open) continue;
        const list = el("div", { class: "list group-list" });
        for (const c of items) {
          const row = el("button", { class: "item cat-row", type: "button" }, el("span", { class: "grow title", text: c.name }), el("span", { class: "chev", text: "›" }));
          row.addEventListener("click", () => { g.filter = ""; openGuideCategory(c); });
          list.append(row);
        }
        panel.append(list);
      }
      return;
    }

    panel.append(crumb([["Categories", () => { g.category = null; g.channels = null; remoteRefreshEvery(0); renderRemote(); }], [g.category.name, null]]));
    if (!g.channels) { panel.append(el("p", { class: "empty", text: "Loading channels and what's on…" })); return; }
    panel.append(filterBox("Find a channel or programme"));
    const q = g.filter.trim().toLowerCase();
    const list = el("div", { class: "list" });
    const rows = g.channels.filter((c) => !q || c.name.toLowerCase().includes(q) || (c.now || "").toLowerCase().includes(q));
    if (!rows.length) list.append(el("p", { class: "empty", text: q ? "Nothing matches." : "No channels in this category." }));
    for (const c of rows) list.append(channelRow(c));
    panel.append(list);
  }

  function renderRemoteSports(panel) {
    const sp = remote.sports;
    const sports = snapshot.sports || {};
    const groups = sports.groups || [];
    if (!groups.length) { panel.append(el("p", { class: "empty", text: "Their Sports Hub hasn't loaded yet." })); return; }

    // 1. Sport
    if (!sp.group) {
      panel.append(el("p", { class: "hint", text: "Pick a sport, then a competition, then the match." }));
      const list = el("div", { class: "list" });
      for (const g of groups) {
        const row = el("button", { class: "item cat-row", type: "button" },
          el("div", { class: "grow" }, el("div", { class: "title", text: g.name }), el("div", { class: "sub", text: g.subtitle })),
          el("span", { class: "chev", text: "›" }));
        row.addEventListener("click", () => { sp.group = g.id; renderRemote(); });
        list.append(row);
      }
      panel.append(list);
      return;
    }
    const group = groups.find((g) => g.id === sp.group);
    if (!group) { sp.group = null; return renderRemote(); }
    const back = () => { sp.group = null; sp.item = null; sp.events = null; remoteRefreshEvery(0); renderRemote(); };

    // 2. Competition (a tab with several competitions lists them)
    if (!sp.item) {
      panel.append(crumb([["Sports", back], [group.name, null]]));
      const items = [];
      for (const it of group.items) {
        if (it.competitions) for (const c of it.competitions) items.push({ code: c.code, competition: c.name, name: c.name });
        else items.push({ code: it.code, competition: it.kind === "competition" ? it.name : undefined, name: it.name });
      }
      const list = el("div", { class: "list" });
      for (const it of items) {
        const row = el("button", { class: "item cat-row", type: "button" }, el("span", { class: "grow title", text: it.name }), el("span", { class: "chev", text: "›" }));
        row.addEventListener("click", () => openSportsItem(it));
        list.append(row);
      }
      panel.append(list);
      return;
    }

    // 3. Events
    if (!sp.event) {
      panel.append(crumb([["Sports", back], [group.name, () => { sp.item = null; sp.events = null; remoteRefreshEvery(0); renderRemote(); }], [sp.item.name, null]]));
      if (!sp.events) { panel.append(el("p", { class: "empty", text: "Loading matches…" })); return; }
      const evs = sp.events.list;
      if (!evs.length) { panel.append(el("p", { class: "empty", text: "No matches in the next week." })); return; }
      let lastHead = "";
      const list = el("div", { class: "list" });
      for (const ev of evs) {
        const head = ev.state === "live" ? "Live now" : ev.state === "finished" ? "Results" : dayText(ev.kickoff);
        if (head !== lastHead) { list.append(el("h4", { class: "hub-section" + (head === "Live now" ? " live-head" : ""), text: head })); lastHead = head; }
        const right = ev.state === "upcoming" ? timeText(ev.kickoff) : `${ev.score || ""} ${ev.state === "live" ? (ev.status === "LIVE" ? "" : ev.status) : "FT"}`.trim();
        const row = el("button", { class: "item cat-row event-row" + (ev.state === "live" ? " live" : ""), type: "button" },
          el("div", { class: "grow" },
            el("div", { class: "title", text: `${ev.home} v ${ev.away}` }),
            group.items.length > 1 || sp.item.competition ? null : el("div", { class: "sub", text: ev.league })),
          ev.state === "live" ? el("span", { class: "live-dot", text: "LIVE" }) : null,
          el("span", { class: "event-right", text: right }),
          el("span", { class: "chev", text: "›" }));
        row.addEventListener("click", () => openSportsEvent(ev));
        list.append(row);
      }
      panel.append(list);
      return;
    }

    // 4. Channels for the match
    const ev = sp.event;
    panel.append(crumb([["Sports", back], [sp.item.name, () => { sp.event = null; sp.channels = null; renderRemote(); }], [`${ev.home} v ${ev.away}`, null]]));
    panel.append(el("div", { class: "card event-card" },
      el("div", { class: "title-lg", text: `${ev.home} v ${ev.away}` }),
      el("div", { class: "sub", text: ev.state === "upcoming" ? `${dayText(ev.kickoff)} · ${timeText(ev.kickoff)}` : `${ev.score || ""} · ${ev.state === "live" ? "Live now" : "Finished"}` })));
    if (!sp.channels) { panel.append(el("p", { class: "empty", text: "Finding the channels showing it…" })); return; }
    if (!sp.channels.length) { panel.append(el("p", { class: "empty", text: "None of their channels are showing this one." })); return; }
    panel.append(el("p", { class: "hint", text: "Best match first, the same list as Watch in their Sports Hub." }));
    const list = el("div", { class: "list" });
    for (const c of sp.channels) list.append(channelRow(c, { fixture: ev.id, code: sp.item.code }));
    panel.append(list);
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
        const remove = el("button", { class: "btn small danger", type: "button", text: "Remove" });
        remove.addEventListener("click", () => customAction("customCategoryRemove", { id: cat.id, server: ch.server, channel: ch.channel }, remove));
        const row = el("div", { class: "item" }, dragHandle(ch.name),
          el("span", { class: "num", text: String(i + 1) }),
          el("div", { class: "grow" }, el("div", { class: "title", text: ch.name }),
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
        el("div", { class: "grow" }, el("div", { class: "title", text: r.name }), el("div", { class: "sub", text: r.source })), add, all));
    }
    if (customEdit.results && !customEdit.results.length) results.append(el("p", { class: "empty", text: "No channels match." }));
    panel.append(el("div", { class: "card" }, el("h3", { text: "Add channels" }), search, results));
    if (keepFocus) { search.focus(); search.setSelectionRange(search.value.length, search.value.length); }
  }

  // ---------- start ----------
  const fromLink = location.hash.replace(/\D/g, "").slice(0, 6);
  if (fromLink.length === 6) $("code").value = fromLink.slice(0, 3) + " " + fromLink.slice(3);
  $("name").value = localStorage.getItem("rh-name") || "";
  if (!window.crypto || !crypto.subtle || !("WebSocket" in window)) {
    $("join-error").textContent = "This browser is too old for Remote Help. Try the latest Safari, Chrome, Edge or Firefox.";
    $("join-error").hidden = false;
    $("join").disabled = true;
  } else if (fromLink.length === 6) {
    $("name").focus();
  } else {
    $("code").focus();
  }
})();
