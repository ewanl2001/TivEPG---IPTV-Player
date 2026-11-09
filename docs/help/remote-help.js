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
  let localCompetitions = null;

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
      if ($("screen-help").hidden) show("help");
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
  let currentTab = "playlists";
  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => {
      currentTab = tab.dataset.tab;
      for (const t of document.querySelectorAll(".tab")) t.classList.toggle("active", t === tab);
      for (const name of ["playlists", "live", "vod", "series", "sports"]) $("tab-" + name).hidden = name !== currentTab;
    });
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
    localCompetitions = null;
    renderSports();
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

  // Categories
  const CAT_TITLES = { live: "TV channel", vod: "movie", series: "series" };

  function catsFor(kind) {
    if (!localCats[kind]) localCats[kind] = ((snapshot.categories || {})[kind] || []).map((c) => ({ ...c }));
    return localCats[kind];
  }

  function queueCategorySave(kind) {
    clearTimeout(catTimers[kind]);
    catTimers[kind] = setTimeout(async () => {
      const shown = catsFor(kind).filter((c) => c.shown).map((c) => c.key);
      const r = await command("setCategories", { kind, shown });
      catTimers[kind] = null;
      if (!r.ok) toast(r.message || "Couldn't save that.", true);
      else toast("Saved on their device.");
    }, 700);
  }

  function renderCategories(kind) {
    const panel = $("tab-" + kind);
    const cats = catsFor(kind);
    const shown = cats.filter((c) => c.shown);
    const hidden = cats.filter((c) => !c.shown);
    const word = CAT_TITLES[kind];
    const keepFocus = document.activeElement && document.activeElement.dataset.search === kind;
    panel.replaceChildren();

    if (!cats.length) {
      panel.append(el("p", { class: "empty",
        text: `No ${word} categories yet. Add a playlist first, or wait for their device to finish loading.` }));
      return;
    }
    panel.append(el("p", { class: "hint",
      text: `Choose which ${word} categories they see, and the order they appear in. Changes save by themselves.` }));

    const update = () => { renderCategories(kind); queueCategorySave(kind); };
    const move = (cat, delta) => {
      const all = catsFor(kind);
      const order = all.filter((c) => c.shown);
      const i = order.indexOf(cat);
      const j = i + delta;
      if (j < 0 || j >= order.length) return;
      [order[i], order[j]] = [order[j], order[i]];
      localCats[kind] = [...order, ...all.filter((c) => !c.shown)];
      update();
    };

    // Shown column
    const showAll = el("button", { class: "btn small", type: "button", text: "Show all" });
    showAll.addEventListener("click", () => { catsFor(kind).forEach((c) => (c.shown = true)); update(); });
    const hideAll = el("button", { class: "btn small", type: "button", text: "Hide all" });
    hideAll.addEventListener("click", () => {
      if (confirm(`Hide every ${word} category?`)) { catsFor(kind).forEach((c) => (c.shown = false)); update(); }
    });

    const shownList = el("div", { class: "list" });
    if (!shown.length) shownList.append(el("p", { class: "empty", text: "Nothing is showing. Pick some from the list." }));
    shown.forEach((c, index) => {
      const up = el("button", { class: "btn small icon", type: "button", title: "Move up", "aria-label": "Move up", text: "↑" });
      const down = el("button", { class: "btn small icon", type: "button", title: "Move down", "aria-label": "Move down", text: "↓" });
      const hide = el("button", { class: "btn small", type: "button", text: "Hide" });
      up.disabled = index === 0;
      down.disabled = index === shown.length - 1;
      up.addEventListener("click", () => move(c, -1));
      down.addEventListener("click", () => move(c, 1));
      hide.addEventListener("click", () => { c.shown = false; update(); });
      shownList.append(el("div", { class: "item" },
        el("span", { class: "num", text: String(index + 1) }),
        el("div", { class: "grow" }, el("div", { class: "title", text: c.name }), el("div", { class: "sub", text: c.source })),
        up, down, hide));
    });

    // Hidden column, searchable (a playlist can have thousands)
    const search = el("input", { class: "search", placeholder: "Search categories", value: catSearch[kind] });
    search.dataset.search = kind;
    search.addEventListener("input", () => { catSearch[kind] = search.value; renderCategories(kind); });
    const q = catSearch[kind].trim().toLowerCase();
    const matches = hidden.filter((c) => !q || c.name.toLowerCase().includes(q) || (c.source || "").toLowerCase().includes(q));
    const LIMIT = 200;
    const hiddenList = el("div", { class: "list" });
    if (!hidden.length) hiddenList.append(el("p", { class: "empty", text: "Everything is showing." }));
    else if (!matches.length) hiddenList.append(el("p", { class: "empty", text: "No matches." }));
    for (const c of matches.slice(0, LIMIT)) {
      const add = el("button", { class: "btn small", type: "button", text: "Show" });
      add.addEventListener("click", () => { c.shown = true; update(); });
      hiddenList.append(el("div", { class: "item dim" },
        el("div", { class: "grow" }, el("div", { class: "title", text: c.name }), el("div", { class: "sub", text: c.source })),
        add));
    }
    if (matches.length > LIMIT) hiddenList.append(el("p", { class: "more", text: `${matches.length - LIMIT} more. Search to find them.` }));

    panel.append(el("div", { class: "cat-columns" },
      el("div", {},
        el("div", { class: "cat-head" }, el("h3", { text: `Showing (${shown.length})` }), el("div", { class: "row-actions" }, showAll, hideAll)),
        shownList),
      el("div", {},
        el("div", { class: "cat-head" }, el("h3", { text: `Hidden (${hidden.length})` })),
        search, hiddenList)));

    if (keepFocus) { search.focus(); search.setSelectionRange(search.value.length, search.value.length); }
  }

  // Sports Hub
  function renderSports() {
    const sports = snapshot.sports || {};
    if (!localCompetitions) localCompetitions = (sports.competitions || []).map((c) => ({ ...c }));
    const comps = localCompetitions;
    const list = $("competition-list");
    list.replaceChildren();
    if (!comps.length) list.append(el("p", { class: "empty", text: "The Sports Hub hasn't loaded on their device yet." }));

    let saveTimer = null;
    const save = () => {
      clearTimeout(saveTimer);
      saveTimer = setTimeout(async () => {
        const r = await command("setCompetitions", { items: comps.map((c) => ({ code: c.code, enabled: !!c.enabled })) });
        toast(r.ok ? "Saved on their device." : (r.message || "Couldn't save that."), !r.ok);
      }, 600);
    };

    comps.forEach((c, index) => {
      const box = el("input", { type: "checkbox", "aria-label": "Show " + c.name });
      box.checked = !!c.enabled;
      box.addEventListener("change", () => { c.enabled = box.checked; save(); });
      const up = el("button", { class: "btn small icon", type: "button", "aria-label": "Move up", text: "↑" });
      const down = el("button", { class: "btn small icon", type: "button", "aria-label": "Move down", text: "↓" });
      up.disabled = index === 0;
      down.disabled = index === comps.length - 1;
      const swap = (d) => { [comps[index], comps[index + d]] = [comps[index + d], comps[index]]; renderSports(); save(); };
      up.addEventListener("click", () => swap(-1));
      down.addEventListener("click", () => swap(1));
      list.append(el("div", { class: "item" + (c.enabled ? "" : " dim") },
        el("label", { class: "switch" }, box, el("span")),
        el("div", { class: "grow" }, el("div", { class: "title", text: c.name }), c.group ? el("div", { class: "sub", text: c.group }) : null),
        up, down));
    });

    const teams = [...(sports.favouriteTeams || [])];
    const leagues = [...(sports.favouriteLeagues || [])];
    const saveFavs = () => run("setFavourites", { teams, leagues });
    const favList = (target, items, emptyText) => {
      target.replaceChildren();
      if (!items.length) target.append(el("p", { class: "empty", text: emptyText }));
      items.forEach((name, i) => {
        const remove = el("button", { class: "btn small", type: "button", text: "Remove" });
        remove.addEventListener("click", () => { items.splice(i, 1); favList(target, items, emptyText); saveFavs(); });
        target.append(el("div", { class: "item" }, el("div", { class: "grow" }, el("div", { class: "title", text: name })), remove));
      });
    };
    favList($("team-list"), teams, "No favourite teams. They can add them by pressing the star on a team in the Sports Hub.");
    favList($("league-list"), leagues, "No favourite competitions.");
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
