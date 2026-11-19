// SG9 – Hell/Dunkel/System-Umschalter. Wird im <head> geladen, damit nichts aufblitzt.
(function () {
  "use strict";
  var KEY = "sg9-theme";
  function get() {
    try { return localStorage.getItem(KEY) || "system"; } catch (e) { return "system"; }
  }
  function apply(mode) {
    var root = document.documentElement;
    if (mode === "light" || mode === "dark") root.setAttribute("data-theme", mode);
    else root.removeAttribute("data-theme");
  }
  function set(mode) {
    try { localStorage.setItem(KEY, mode); } catch (e) {}
    apply(mode);
    document.querySelectorAll("[data-theme-switch]").forEach(render);
    window.dispatchEvent(new CustomEvent("sg9-theme", { detail: mode }));
  }
  var ICONS = {
    system: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
    light: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>',
    dark: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/></svg>'
  };
  var LABELS = { system: "System", light: "Hell", dark: "Dunkel" };
  function render(el) {
    var cur = get();
    var compact = el.hasAttribute("data-compact");
    el.className = "seg";
    el.setAttribute("role", "group");
    el.setAttribute("aria-label", "Darstellung");
    el.innerHTML = ["system", "light", "dark"].map(function (m) {
      return '<button type="button" data-mode="' + m + '" aria-pressed="' + (m === cur) + '" title="' + LABELS[m] + '">' +
        ICONS[m] + (compact ? "" : "<span>" + LABELS[m] + "</span>") + "</button>";
    }).join("");
    el.querySelectorAll("button").forEach(function (b) { b.onclick = function () { set(b.getAttribute("data-mode")); }; });
  }
  apply(get());
  window.SG9Theme = { get: get, set: set, render: render };
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("[data-theme-switch]").forEach(render);
  });
})();
