// secrets.js — the secrets page's browser-side sealing.
//
// The value typed into the push form must never reach the control plane
// unsealed, and html/template already keeps it off every request: the input
// has no name, so the browser cannot submit it. This script is what makes the
// form work at all: it loads the page's seal wasm (mach-seal.wasm —
// internal/e2e compiled for js/wasm, not a second implementation of the
// format), seals the value to the machine's E2E public key in the browser,
// and posts only the sealed blob the server's shared push core accepts.
//
// Trust-on-first-use sits here the way it does in the console (console/pins.go):
// the first push to a machine records the key's fingerprint in this browser's
// localStorage, and a later push against a DIFFERENT key refuses loudly,
// naming both fingerprints, until a human types the machine's name to accept
// the new one. The limits are the console's limits and are stated in
// SECURITY-NOTES.md: a key substituted before the first push to that machine
// wins silently, and a browser that cannot store the pin announces that it is
// pinless rather than failing invisibly.
//
// Everything the script writes into the page goes through textContent or
// element construction — nothing here ever builds markup from the page data
// or the response. And everything it reads back is resolved from the CURRENT
// document at submit time: the push response swaps the region out from under
// the form, so no element reference captured here can be trusted one swap
// later.
"use strict";

(() => {
	const PIN_PREFIX = "mach-e2e-pin/";
	let wasmReady = false;

	// pinKey reads and writes the machine's pin. A browser that refuses
	// storage (private mode, quota) reports null, and the caller says so:
	// sealing proceeds without a pin, visibly, rather than pretending.
	const readPin = (machine) => {
		try {
			return window.localStorage.getItem(PIN_PREFIX + machine);
		} catch (e) {
			return null;
		}
	};
	const writePin = (machine, fp) => {
		try {
			window.localStorage.setItem(PIN_PREFIX + machine, fp);
			return true;
		} catch (e) {
			return false;
		}
	};

	const callWasm = (fn, args) => {
		if (!wasmReady || typeof window[fn] !== "function") {
			return { error: "the seal support failed to load; reload the page, or use `mach secrets push <machine> NAME --value-file -`" };
		}
		let out;
		try {
			out = window[fn].apply(null, args);
		} catch (e) {
			return { error: "the seal support threw: " + (e && e.message ? e.message : "unknown") };
		}
		if (!out || typeof out.error !== "string") {
			return { error: "the seal support returned an unusable answer" };
		}
		return out;
	};

	const fingerprint = (pubHex) => callWasm("machFingerprint", [pubHex]);

	// rePinChallenge is the deliberate remedy for a key change: the operator
	// must type the machine's name, the way a machine delete must be typed —
	// a legitimate re-enrollment and a substituted key look identical, and
	// this page has no way to tell them apart (see SECURITY-NOTES.md).
	const rePinChallenge = (form, machine, oldFp, newFp) => {
		setNote(form,
			"The E2E key for " + machine + " changed since you last pushed from this browser. " +
			"Pinned " + oldFp + "; the control plane now advertises " + newFp + ". " +
			"A machine that re-enrolled looks the same as a substituted key; push nothing until you know which it is. " +
			"To accept the new key, type the machine name into the field below and push again.",
			true);
		if (!document.getElementById("re-pin-check")) {
			const wrap = document.createElement("p");
			wrap.id = "re-pin-check";
			const label = document.createElement("label");
			const text = document.createElement("span");
			text.className = "muted";
			text.textContent = "Re-pin: type the machine name ";
			const input = document.createElement("input");
			input.id = "re-pin-input";
			input.type = "text";
			input.autocomplete = "off";
			label.appendChild(text);
			label.appendChild(input);
			wrap.appendChild(label);
			const actions = form.querySelector(".row-actions");
			form.insertBefore(wrap, actions);
		}
	};

	const clearRePin = () => {
		const el = document.getElementById("re-pin-check");
		if (el) {
			el.remove();
		}
	};

	// sealAndCheck runs the pin check and the seal against the current page's
	// machine data, or returns a string explaining why it refused. The
	// mismatch path renders its own challenge and returns "" — a deliberate
	// stop, not an error.
	const sealAndCheck = (container, machine, name, value) => {
		let sealInfo = {};
		try {
			sealInfo = JSON.parse(container.dataset.machSeal || "{}");
		} catch (e) {
			return "the page's machine data could not be read; reload the page";
		}
		const mi = sealInfo[machine];
		if (!mi) {
			return machine + " is not a machine of your orgs — push secrets from a console whose key is scoped to it, or ask for membership";
		}
		if (!mi.pub_e2e) {
			return "cannot seal to " + machine + ": " + (mi.reason || "no E2E key advertised");
		}
		const fpRes = fingerprint(mi.pub_e2e);
		if (fpRes.error) {
			return "could not fingerprint " + machine + "'s key: " + fpRes.error;
		}
		const fp = fpRes.fingerprint;
		const pinned = readPin(machine);
		let pinNote = "";
		if (pinned && pinned !== fp) {
			const rePinInput = document.getElementById("re-pin-input");
			if (rePinInput && rePinInput.value === machine) {
				// The typed name is the deliberate acceptance. The new key
				// becomes the pin, and the operator answered for it.
				if (!writePin(machine, fp)) {
					return "the new key is accepted, but this browser could not store the pin; every later push will re-ask";
				}
				clearRePin();
				pinNote = "Re-pinned " + machine + " to " + fp + ". ";
			} else {
				rePinChallenge(container.querySelector("#secret-push-form"), machine, pinned, fp);
				return "";
			}
		} else if (!pinned) {
			if (writePin(machine, fp)) {
				pinNote = "Pinned the E2E key for " + machine + " (" + fp + "). A later change is refused until you re-pin it here. ";
			} else {
				pinNote = "Pinned the E2E key for " + machine + " (" + fp + ") for this page-load only; this browser cannot store pins, so later pushes cannot detect a key change. ";
			}
		} else {
			clearRePin();
		}
		const out = callWasm("machSeal", [mi.pub_e2e, name, mi.org, value]);
		if (out.error) {
			return out.error;
		}
		if (!out.sealed) {
			return "the seal produced nothing";
		}
		out.pinNote = pinNote;
		return out;
	};

	// post delivers the sealed blob. htmx is the normal path: it swaps the
	// refreshed region, processes the out-of-band notice, and follows the
	// server's HX-Retarget on a refusal. Without htmx the script falls back
	// to fetch + reload, which is no prettier than it sounds but leaves the
	// data correct on both outcomes.
	const post = (form, machine, name, sealed) => {
		const csrf = form.querySelector('input[name="csrf"]');
		const values = { machine: machine, name: name, sealed: sealed };
		if (csrf) {
			values.csrf = csrf.value;
		}
		if (window.htmx && typeof window.htmx.ajax === "function") {
			return window.htmx.ajax("POST", form.getAttribute("action"), {
				target: "#secrets-main",
				swap: "outerHTML",
				headers: { "HX-Request": "true" },
				values: values,
			});
		}
		const body = new URLSearchParams(values);
		return fetch(form.getAttribute("action"), {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded", "HX-Request": "true" },
			body: body.toString(),
		}).then(() => window.location.reload());
	};

	// setNote writes into the CURRENT form's note element. textContent only:
	// machine names and error strings reach here from the page data and the
	// server, and no path in this script builds markup out of them.
	const setNote = (form, text, bad) => {
		const note = form ? form.querySelector("#seal-note") : null;
		if (!note) {
			return;
		}
		note.textContent = text;
		note.className = bad ? "error" : "muted";
	};

	// One delegated, capture-phase submit listener, so it survives the region
	// being swapped out from under the form and wins over any native handler.
	document.addEventListener("submit", (e) => {
		const form = e.target instanceof Element ? e.target.closest("#secret-push-form") : null;
		if (!form) {
			return;
		}
		e.preventDefault();
		const machineInput = form.querySelector('input[name="machine"]');
		const nameInput = form.querySelector('input[name="name"]');
		const valueInput = form.querySelector("#secret-value");
		const machine = machineInput && machineInput.value ? machineInput.value.trim() : "";
		const name = nameInput && nameInput.value ? nameInput.value.trim() : "";
		const value = valueInput ? valueInput.value : "";
		if (!machine || !name || !value) {
			setNote(form, "Machine, name and value are all required.", true);
			return;
		}
		const bytes = new TextEncoder().encode(value).length;
		if (bytes < 8 || bytes > 4096) {
			setNote(form, "Secret value must be 8..4096 bytes (yours is " + bytes + ").", true);
			return;
		}
		const container = form.closest("#secrets-main");
		if (!container) {
			setNote(form, "This form is not on the secrets page anymore; reload it.", true);
			return;
		}
		const res = sealAndCheck(container, machine, name, value);
		if (res === "") {
			return; // the re-pin challenge is on screen; this submit stops
		}
		if (typeof res === "string") {
			setNote(form, res, true);
			return;
		}
		post(form, machine, name, res.sealed).then((ok) => {
			if (ok === false) {
				setNote(form, "The control plane refused the push; the error is above.", true);
			} else {
				setNote(form, res.pinNote + "Sealed and pushed " + name + " to " + machine + "; the control plane cannot read what was sent.", false);
			}
		}).catch(() => {
			setNote(form, "The push could not be delivered; nothing was changed by this browser. Try again.", true);
		});
	}, true);

	// Load the wasm. wasm_exec.js registers the Go runtime before this runs
	// (both are deferred, in order, only on this page). A failure leaves the
	// form unable to seal — the server refuses a sealless push with the CLI
	// fallback message, which is the fail-closed answer.
	const start = () => {
		const container = document.getElementById("secrets-main");
		if (!container) {
			return;
		}
		const asset = container.dataset.machAsset || "";
		const go = new Go();
		WebAssembly.instantiateStreaming(fetch("/static/mach-seal.wasm?v=" + encodeURIComponent(asset)), go.importObject)
			.then((res) => go.run(res.instance))
			.then(() => {
				wasmReady = true;
			const form = document.getElementById("secret-push-form");
			setNote(form, "Seal support loaded. Values you type are sealed in this browser; the first push to a machine pins its key here.", false);
		})
			.catch((err) => {
				const form = document.getElementById("secret-push-form");
				setNote(form, "The seal support failed to load (" + (err && err.message ? err.message : "unknown") + ") — pushing from the browser is disabled. Use `mach secrets push <machine> NAME --value-file -`.", true);
			});
	};
	start();
})();