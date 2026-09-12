// app.js — the only first-party script on the control plane's pages.
//
// Deliberately tiny and dependency-free. The pages are server-rendered and htmx
// carries the interactivity; this exists for the one thing that has no
// server-side equivalent, copying a command to the clipboard.
//
// No eval, no Function constructor, no inline handlers and no dynamic code: the
// pages' Content-Security-Policy is script-src 'self' with no 'unsafe-eval', so
// anything that needed either would simply not run.
(function () {
  "use strict";

  function copyText(text) {
    // The async clipboard API needs a secure context, which a control plane
    // behind TLS has but a local http:// dev instance does not. Falling back to
    // a hidden textarea keeps the button useful in both.
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "-1000px";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy") ? resolve() : reject(new Error("copy refused"));
      } catch (e) {
        reject(e);
      } finally {
        document.body.removeChild(ta);
      }
    });
  }

  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-copy]");
    if (!btn) return;
    ev.preventDefault();

    var sel = btn.getAttribute("data-copy");
    var src = sel ? document.querySelector(sel) : null;
    var text = src ? src.textContent : "";
    if (!text) return;

    var original = btn.textContent;
    copyText(text).then(
      function () {
        btn.textContent = "Copied";
      },
      function () {
        // Never claim success we did not have: the operator can still select the
        // text by hand, which is what they would have done anyway.
        btn.textContent = "Press Ctrl/Cmd+C";
      }
    );
    window.setTimeout(function () {
      btn.textContent = original;
    }, 2000);
  });
})();
