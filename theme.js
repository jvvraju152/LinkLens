// Applies the saved colour theme before the page paints, and marks the page as script-enabled so the small-screen menu
// only hides the links when a script is there to open it. Kept as a separate file so the Content-Security-Policy can
// forbid inline scripts.
document.documentElement.classList.add("js");
try { var t = localStorage.getItem("theme"); if (t) document.documentElement.dataset.theme = t; } catch (e) {}
