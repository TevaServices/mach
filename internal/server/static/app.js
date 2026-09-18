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

  // Refusals are 4xx with an HTML body, retargeted by the server through
  // HX-Retarget. htmx's default response handling does not swap non-2xx, so
  // without this a refused action is a silently swallowed response: a duplicate
  // org, an org removed while it still has machines, and a bad E2E mode all
  // produced no visible feedback at all, on pages whose whole point is that an
  // operator can see what happened.
  //
  // htmx resolves HX-Retarget/HX-Reswap before firing this event, so opting in
  // here lets htmx's own swap path do the work — including the out-of-band
  // processing and the afterSwap hooks — rather than reimplementing target
  // resolution in this file.
  //
  // The gate is the HX-Retarget header rather than the status code: only a
  // response that names a destination is swapped, so a 500 from some path that
  // still writes text/plain cannot be pasted into the page as markup.
  document.addEventListener("htmx:beforeSwap", function (evt) {
    var d = evt.detail;
    if (!d || !d.xhr || !d.xhr.getResponseHeader) return;
    if (d.xhr.status < 400) return;
    if (!d.xhr.getResponseHeader("HX-Retarget")) return;
    d.shouldSwap = true;
    d.isError = false;
  });

  // A poll that fires in a hidden tab is pure waste: it costs the control plane
  // a request and the machine a wake-up, and nobody sees the result. htmx has no
  // visibility handling of its own, so a backgrounded fleet page would poll every
  // five seconds forever.
  //
  // Scoped to the periodic refresh and NOT to every request: an operator can
  // click Block and switch away in the same moment, and cancelling that request
  // would silently drop an action they believe they took.
  document.addEventListener("htmx:beforeRequest", function (evt) {
    if (!document.hidden) return;
    var elt = evt.detail && evt.detail.elt;
    if (!elt || !elt.getAttribute) return;
    var trigger = elt.getAttribute("hx-trigger") || "";
    if (trigger.indexOf("every") !== -1) evt.preventDefault();
  });
})();
