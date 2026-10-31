// Applies the saved theme before first paint to avoid a flash of the wrong
// theme. Kept as a file (not inline) so the CSP can forbid inline scripts.
try {
  var t = localStorage.getItem("strxeye.theme") || "system";
  if (t === "system") t = matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  document.documentElement.dataset.theme = t;
} catch (e) {
  /* storage unavailable: keep the default dark theme */
}
