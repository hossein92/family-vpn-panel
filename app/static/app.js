// Family VPN admin panel — progressive enhancement only (every action works without JS).
(function () {
  "use strict";
  const $ = (s, el = document) => el.querySelector(s);
  const $$ = (s, el = document) => Array.from(el.querySelectorAll(s));

  // Mobile navigation
  const toggle = $("#nav-toggle");
  if (toggle) {
    toggle.addEventListener("click", () => document.body.classList.toggle("nav-open"));
    $(".scrim")?.addEventListener("click", () => document.body.classList.remove("nav-open"));
  }

  // Table search: <input data-filter="#tableId">
  $$("input[data-filter]").forEach((inp) => {
    const table = $(inp.dataset.filter);
    if (!table) return;
    const rows = $$("tbody tr", table).filter((r) => !r.classList.contains("empty-row"));
    inp.addEventListener("input", () => {
      const q = inp.value.trim().toLowerCase();
      let shown = 0;
      rows.forEach((r) => {
        const hit = !q || r.textContent.toLowerCase().includes(q);
        r.classList.toggle("hidden", !hit);
        if (hit) shown++;
      });
      const counter = $(inp.dataset.count || "#_none");
      if (counter) counter.textContent = shown;
    });
  });

  // Confirmation dialogs: <form data-confirm="message" data-confirm-title=".." data-confirm-ok="Revoke">
  const dlg = $("#confirm-dialog");
  let pending = null;
  $$("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (ev) => {
      if (form.dataset.confirmed === "1" || !dlg || !dlg.showModal) return;
      ev.preventDefault();
      pending = form;
      $("#confirm-title").textContent = form.dataset.confirmTitle || "Are you sure?";
      $("#confirm-text").textContent = form.dataset.confirm;
      const ok = $("#confirm-ok");
      ok.textContent = form.dataset.confirmOk || "Confirm";
      ok.className = "btn " + (form.dataset.confirmDanger === "0" ? "primary" : "danger-solid");
      dlg.showModal();
    });
  });
  if (dlg) {
    $("#confirm-ok").addEventListener("click", () => {
      dlg.close();
      if (pending) { pending.dataset.confirmed = "1"; pending.requestSubmit ? pending.requestSubmit() : pending.submit(); }
    });
    $("#confirm-cancel").addEventListener("click", () => { pending = null; dlg.close(); });
  }

  // Revoke form: enable the button only when the CN is typed exactly
  $$("input[data-must-equal]").forEach((inp) => {
    const btn = $(inp.dataset.target);
    const check = () => { btn.disabled = inp.value.trim() !== inp.dataset.mustEqual; };
    inp.addEventListener("input", check);
    check();
  });

  // Generic dialog openers: <button data-open="#dialogId">
  $$("[data-open]").forEach((b) => b.addEventListener("click", () => $(b.dataset.open)?.showModal()));
  $$("dialog [data-close]").forEach((b) => b.addEventListener("click", () => b.closest("dialog").close()));

  // Policy editor: show time inputs only for "blocked during a window"
  $$("select[data-window]").forEach((sel) => {
    const box = $(sel.dataset.window);
    const sync = () => box && box.classList.toggle("hidden", sel.value !== "window");
    sel.addEventListener("change", sync);
    sync();
  });

  // Schedule editor: add / remove window rows and presets
  const rowsBox = $("#window-rows");
  if (rowsBox) {
    const tpl = $("#window-template");
    const renumber = () => $$(".window-row", rowsBox).forEach((row, i) => {
      $$("[data-name]", row).forEach((el) => { el.name = `w${i}_${el.dataset.name}`; });
    });
    const addRow = (days, start, end) => {
      const node = tpl.content.firstElementChild.cloneNode(true);
      $$("input[type=checkbox]", node).forEach((c) => { c.checked = days.includes(parseInt(c.value, 10)); });
      $("[data-name=start]", node).value = start;
      $("[data-name=end]", node).value = end;
      rowsBox.appendChild(node);
      renumber();
    };
    rowsBox.addEventListener("click", (ev) => {
      const btn = ev.target.closest("[data-remove-row]");
      if (btn) { btn.closest(".window-row").remove(); renumber(); }
    });
    renumber();
    $("#add-window")?.addEventListener("click", () => addRow([0, 1, 2, 3, 4], "06:30", "21:30"));
    $$("[data-preset]").forEach((b) => b.addEventListener("click", () => {
      rowsBox.innerHTML = "";
      JSON.parse(b.dataset.preset).forEach((w) => addRow(w.days, w.start, w.end));
    }));
  }

  // Live pages: refresh while visible (connections, dashboard)
  const live = document.body.dataset.autorefresh;
  if (live) {
    const secs = parseInt(live, 10) || 15;
    let timer = setInterval(() => { if (!document.hidden && !$("dialog[open]")) location.reload(); }, secs * 1000);
    $("#pause-refresh")?.addEventListener("click", (ev) => {
      clearInterval(timer); timer = null;
      ev.currentTarget.textContent = "Auto-refresh paused"; ev.currentTarget.disabled = true;
    });
  }

  // Copy-to-clipboard: <button data-copy="#el">
  $$("[data-copy]").forEach((b) => b.addEventListener("click", async () => {
    const el = $(b.dataset.copy);
    try { await navigator.clipboard.writeText(el.textContent.trim()); b.textContent = "Copied"; } catch (e) { /* ignore */ }
  }));

  // Auto-submit selects: <select data-autosubmit>
  $$("select[data-autosubmit]").forEach((s) => s.addEventListener("change", () => s.form.submit()));
})();
