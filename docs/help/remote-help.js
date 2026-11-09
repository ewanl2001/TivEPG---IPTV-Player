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
  const sourceOf = (c) => c.key.slice(0, c.key.indexOf("|"));

  function sourcesFor(kind) {
    const out = [];
    const seen = new Map();
    for (const c of catsFor(kind)) {
      const id = sourceOf(c);
      if (!seen.has(id)) { seen.set(id, { id, name: c.source || "Playlist", cats: [] }); out.push(seen.get(id)); }
      seen.get(id).cats.push(c);
    }
    return out;
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

  // Switching one on adds it at the end of its playlist's block, as the app does.
  function setShown(kind, cats, on) {
    const all = catsFor(kind);
    for (const c of cats) {
      if (c.shown === on) continue;
      c.shown = on;
      if (on) {
        const src = sourceOf(c);
        const shownOrder = all.filter((x) => x.shown && x !== c);
        let at = -1;
        shownOrder.forEach((x, i) => { if (sourceOf(x) === src) at = i; });
        shownOrder.splice(at === -1 ? shownOrder.length : at + 1, 0, c);
        localCats[kind] = [...shownOrder, ...all.filter((x) => !x.shown)];
      }
    }
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

  function renderDisplayOrder(kind, panel) {
    const all = catsFor(kind);
    const shown = all.filter((c) => c.shown);
    panel.append(el("p", { class: "hint", text: "Drag ⠿ to reorder, or use ⤒ top / ⤓ bottom · Remove hides it" }));
    const list = el("div", { class: "list" });
    if (!shown.length) list.append(el("p", { class: "empty", text: "Nothing is switched on. Pick categories from a playlist above." }));
    const move = (from, to) => {
      const order = moveIndex(all.filter((c) => c.shown), from, to);
      localCats[kind] = [...order, ...all.filter((c) => !c.shown)];
      renderCategories(kind);
      queueCategorySave(kind);
    };
    const rows = shown.map((c, i) => {
      const remove = el("button", { class: "btn small danger", type: "button", text: "Remove" });
      remove.addEventListener("click", () => setShown(kind, [c], false));
      const row = el("div", { class: "item" },
        dragHandle(c.name),
        el("span", { class: "num", text: String(i + 1) }),
        el("div", { class: "grow" }, el("div", { class: "title", text: c.name }), el("div", { class: "sub", text: c.source })),
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

    panel.append(
      el("div", { class: "source-tools" }, search, el("div", { class: "row-actions tight" }, selectAll, clear)),
      sortRow);

    const q = catSearch[kind].trim().toLowerCase();
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
