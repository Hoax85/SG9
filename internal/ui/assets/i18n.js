// SG9 – Sprachen (Deutsch, English, Français, Italiano).
// Die Seiten sind auf Deutsch geschrieben. Dieses Skript ersetzt alle Texte auf der Seite
// anhand der Übersetzungstabelle, auch Meldungen vom Server und später eingefügte Inhalte.
// Wird im <head> geladen; bis die Übersetzung da ist, bleibt die Seite kurz unsichtbar.
(function () {
  "use strict";
  var KEY = "sg9-lang";
  var NAMES = { de: "Deutsch", en: "English", fr: "Français", it: "Italiano" };
  var SHORT = { de: "DE", en: "EN", fr: "FR", it: "IT" };
  var LOCALES = { de: "de-CH", en: "en-GB", fr: "fr-CH", it: "it-CH" };
  var SKIP = "script,style,textarea,code,pre,.mono,.name,[data-noi18n],[contenteditable]";

  function detect() {
    var list = (navigator.languages && navigator.languages.length ? navigator.languages : [navigator.language || "de"]);
    for (var i = 0; i < list.length; i++) {
      var l = String(list[i]).slice(0, 2).toLowerCase();
      if (NAMES[l]) return l;
    }
    return "en";
  }
  function get() {
    try { var s = localStorage.getItem(KEY); if (NAMES[s]) return s; } catch (e) {}
    return detect();
  }
  var lang = get();
  var root = document.documentElement;
  root.lang = lang;

  var exact = null, pats = [];
  function tr(s) {
    if (!exact || s == null) return s;
    var str = String(s);
    var key = str.replace(/\s+/g, " ").trim();
    if (!key) return str;
    var out = exact[key];
    if (out === undefined) {
      for (var i = 0; i < pats.length; i++) {
        var m = key.match(pats[i][0]);
        if (m) {
          out = pats[i][1].replace(/\$(\d+)/g, function (_, n) { var g = m[+n]; return g === undefined ? "" : (exact[g] !== undefined ? exact[g] : g); });
          break;
        }
      }
    }
    if (out === undefined) return str;
    var lead = str.match(/^\s*/)[0], trail = str.match(/\s*$/)[0];
    return lead + out + trail;
  }
  function skip(el) { return el && el.closest && el.closest(SKIP); }
  function text(node) {
    if (node.__sg9 === node.data) return;
    if (skip(node.parentElement)) return;
    var t = tr(node.data);
    if (t !== node.data) node.data = t;
    node.__sg9 = node.data;
  }
  var ATTRS = ["placeholder", "title", "aria-label", "alt"];
  function attrs(el) {
    if (el.closest(".name,[data-noi18n]")) return;
    for (var i = 0; i < ATTRS.length; i++) {
      var v = el.getAttribute(ATTRS[i]);
      if (v) {
        var t = v.indexOf("\n") >= 0 ? v.split("\n").map(tr).join("\n") : tr(v); // mehrzeilige Platzhalter zeilenweise
        if (t !== v) el.setAttribute(ATTRS[i], t);
      }
    }
  }
  function walk(n) {
    if (n.nodeType === 3) { text(n); return; }
    if (n.nodeType !== 1 && n.nodeType !== 11) return;
    if (n.nodeType === 1) {
      attrs(n);
      if (n.matches(SKIP)) return;
    }
    var w = document.createTreeWalker(n, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT, {
      acceptNode: function (x) {
        if (x.nodeType === 1 && x.matches(SKIP)) { attrs(x); return NodeFilter.FILTER_REJECT; } // Text nicht, Platzhalter schon
        return NodeFilter.FILTER_ACCEPT;
      }
    });
    var x;
    while ((x = w.nextNode())) { if (x.nodeType === 3) text(x); else attrs(x); }
  }
  var titleDone = "";
  function title() {
    if (document.title && document.title !== titleDone) { document.title = tr(document.title); titleDone = document.title; }
  }

  function start() {
    walk(document.body || root);
    title();
    new MutationObserver(function (list) {
      for (var i = 0; i < list.length; i++) {
        var m = list[i];
        if (m.type === "characterData") text(m.target);
        else if (m.type === "attributes") { if (m.target.nodeType === 1) attrs(m.target); }
        else for (var j = 0; j < m.addedNodes.length; j++) walk(m.addedNodes[j]);
      }
      title();
    }).observe(root, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS });
  }

  function set(l) {
    if (!NAMES[l]) return;
    try { localStorage.setItem(KEY, l); } catch (e) {}
    location.reload();
  }
  function render(el) {
    el.className = "lang-switch";
    el.innerHTML = '<select aria-label="Sprache / Language" data-noi18n>' + Object.keys(NAMES).map(function (l) {
      return '<option value="' + l + '"' + (l === lang ? " selected" : "") + ">" + SHORT[l] + " · " + NAMES[l] + "</option>";
    }).join("") + "</select>";
    el.querySelector("select").onchange = function (e) { set(e.target.value); };
  }
  // Neben jeden Hell/Dunkel-Schalter einen Sprachschalter setzen
  function addSwitches() {
    document.querySelectorAll("[data-theme-switch]").forEach(function (t) {
      if (t.nextElementSibling && t.nextElementSibling.classList.contains("lang-switch")) return;
      var s = document.createElement("span");
      render(s);
      t.parentNode.insertBefore(s, t.nextSibling);
    });
  }

  window.SG9I18n = { lang: lang, locale: LOCALES[lang], t: tr, set: set, names: NAMES };
  // Dialoge des Browsers ebenfalls übersetzen
  ["alert", "confirm", "prompt"].forEach(function (f) {
    var orig = window[f];
    window[f] = function (m, d) { return orig.call(window, tr(m), d); };
  });

  document.addEventListener("DOMContentLoaded", function () {
    addSwitches();
    new MutationObserver(addSwitches).observe(document.body, { childList: true, subtree: true });
  });
  if (lang === "de") return;

  root.style.visibility = "hidden";
  var shown = false;
  function show() { if (!shown) { shown = true; root.style.visibility = ""; } }
  setTimeout(show, 1500);
  fetch("/assets/i18n/" + lang + ".json").then(function (r) { return r.json(); }).then(function (d) {
    exact = d.exact || {};
    pats = (d.patterns || []).map(function (p) { return [new RegExp(p[0]), p[1]]; });
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () { start(); show(); });
    else { start(); show(); }
  }).catch(show);
})();
