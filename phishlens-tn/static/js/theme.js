/* Theme handling. Loaded in <head> so the saved theme is applied before first paint. */
(function () {
  "use strict";
  var KEY = "phishlens-theme";
  var root = document.documentElement;

  function preferred() {
    try {
      var saved = localStorage.getItem(KEY);
      if (saved === "light" || saved === "dark") return saved;
    } catch (e) { /* storage unavailable */ }
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }

  function apply(theme) {
    root.setAttribute("data-theme", theme);
    var button = document.getElementById("theme-toggle");
    if (button) {
      button.setAttribute("aria-pressed", String(theme === "light"));
      button.setAttribute("aria-label", theme === "light" ? "Use dark theme" : "Use light theme");
    }
  }

  apply(preferred());

  document.addEventListener("DOMContentLoaded", function () {
    var button = document.getElementById("theme-toggle");
    apply(root.getAttribute("data-theme") || "dark");
    if (!button) return;
    button.addEventListener("click", function () {
      var next = root.getAttribute("data-theme") === "light" ? "dark" : "light";
      apply(next);
      try { localStorage.setItem(KEY, next); } catch (e) { /* ignore */ }
    });
  });
})();
