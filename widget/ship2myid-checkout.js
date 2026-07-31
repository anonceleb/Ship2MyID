/**
 * <s2id-checkout> — the drop-in checkout component SHIP2MYID_DEMO_SPEC.md §6.3
 * calls `<S2IDCheckout/>`, and packages/sdk/src/client.ts's checkout() doc
 * comment calls "Mirrors <S2IDCheckout/>'s onGrant payload."
 *
 * Closes the one gap README.md's Phase 3 status names explicitly: "this repo
 * has no bundler or frontend framework yet, and faking one in a static demo
 * page would be worse than stating the gap." A native custom element needs
 * neither — one <script> tag, one HTML tag, on any merchant page, styled
 * nothing like Ship2MyID's own site.
 *
 * Usage:
 *   <script src="/widget/ship2myid-checkout.js"></script>
 *   <s2id-checkout merchant-id="alba-goods.example" weight-kg="2" carrier="MER-POST"></s2id-checkout>
 *   <script>
 *     document.querySelector('s2id-checkout')
 *       .addEventListener('s2id-grant', (e) => {
 *         // e.detail is exactly packages/sdk's CheckoutResult:
 *         // { s2id, capabilityId, geoBucket, serviceLevel, estimatedDelivery, verifiedHuman }
 *       });
 *   </script>
 *
 * Pass an `endpoint` attribute to POST { merchantId, weightKg, carrier,
 * destinationKind } to a real hosted MerchantClient-backed API and this
 * component relays that response verbatim — nothing below is re-derived
 * once a real endpoint answers. Ship2MyID has no hosted API yet (see
 * README's Milestone 1 status), so omitting `endpoint` runs the same
 * derivation packages/identity (pairwise S2ID) and packages/capability
 * (single-use grant) define, entirely in this browser tab — and the
 * component labels that mode on-screen rather than silently standing in
 * for a real integration.
 */
(() => {
  const enc = new TextEncoder();

  // ---- crypto helpers (mirrors packages/identity/src/pairwise.ts) --------
  async function hmac(keyBytes, msg) {
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(msg)));
  }
  function b32(bytes, chars) {
    const A = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let out = "";
    for (let i = 0; i < chars; i++) out += A[bytes[i % bytes.length] % A.length];
    return out;
  }
  async function deriveS2ID(root, relyingParty, prefix = "MER") {
    const mac = await hmac(root, "s2id/pairwise/" + relyingParty);
    const body = b32(mac, 12);
    return `${prefix}-${body.slice(0, 4)}-${body.slice(4, 8)}-${body.slice(8, 12)}`;
  }

  const DEST_LABELS = { door: "Home", "access-point": "Access point", locker: "Locker" };
  const GEO_BUCKETS = ["MRD-48", "MRD-22", "MRD-91"];

  /**
   * Local demo transport — same derivation, same shape as the real
   * MerchantClient.checkout(), run client-side with no network hop because
   * there is no hosted platform to call yet. Tier is fixed at 2 (a
   * simulated passkey verification), matching the same default policy
   * (minTierToShip: 2) merchant-console.html's initPolicy() mints against,
   * so numbers stay consistent with the rest of the demo.
   */
  async function localDemoCheckout({ merchantId, destinationKind }) {
    await new Promise((r) => setTimeout(r, 350)); // feels like a real round-trip, isn't one
    const root = crypto.getRandomValues(new Uint8Array(32));
    const s2id = await deriveS2ID(root, merchantId);
    const tier = 2;
    const eta = new Date(Date.now() + (2 + Math.floor(Math.random() * 4)) * 24 * 3600 * 1000);
    return {
      s2id,
      capabilityId: crypto.randomUUID(),
      geoBucket: GEO_BUCKETS[Math.floor(Math.random() * GEO_BUCKETS.length)],
      serviceLevel: "Standard",
      estimatedDelivery: eta.toLocaleDateString(undefined, { month: "short", day: "numeric" }),
      verifiedHuman: tier >= 1,
      _destinationKind: destinationKind,
    };
  }

  /** Real transport — POSTs to a hosted MerchantClient-backed endpoint and trusts its response verbatim. */
  async function remoteCheckout(endpoint, payload) {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`checkout request rejected: http ${res.status}`);
    return res.json();
  }

  const STYLE = `
    :host{
      all:initial; display:block; box-sizing:border-box;
      font-family:system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;
      --s2id-accent: var(--s2id-accent-override, #2451B6);
      --s2id-ink:#161616; --s2id-ink-soft:rgba(22,22,22,.62); --s2id-ink-faint:rgba(22,22,22,.4);
      --s2id-border:rgba(22,22,22,.16); --s2id-bg:#fff; --s2id-bg-raised:#F5F6FA;
      max-width:380px;
    }
    *{box-sizing:border-box;}
    .card{border:1px solid var(--s2id-border); border-radius:10px; padding:18px; background:var(--s2id-bg); color:var(--s2id-ink);}
    .label{font-size:11px; letter-spacing:.05em; text-transform:uppercase; color:var(--s2id-ink-faint); margin-bottom:8px; font-weight:600;}
    .chips{display:flex; gap:6px; margin-bottom:14px; flex-wrap:wrap;}
    .chip{
      font:inherit; font-size:12.5px; font-weight:600; padding:7px 12px; border-radius:20px;
      border:1px solid var(--s2id-border); background:transparent; color:var(--s2id-ink-soft); cursor:pointer;
    }
    .chip.selected{background:var(--s2id-accent); border-color:var(--s2id-accent); color:#fff;}
    .go{
      width:100%; font:inherit; font-size:14px; font-weight:700; padding:12px 16px; border-radius:8px;
      border:none; background:var(--s2id-accent); color:#fff; cursor:pointer; display:flex; align-items:center; justify-content:center; gap:8px;
    }
    .go[disabled]{opacity:.55; cursor:default;}
    .foot{margin-top:10px; font-size:10.5px; color:var(--s2id-ink-faint); text-align:center;}
    .foot.demo{color:#9A6B00;}
    .ticket{margin-top:2px;}
    .row{display:flex; justify-content:space-between; padding:6px 0; border-bottom:1px solid var(--s2id-border); font-size:12.5px;}
    .row:last-child{border-bottom:none;}
    .row .k{color:var(--s2id-ink-faint); text-transform:uppercase; font-size:10px; letter-spacing:.05em;}
    .row .v{font-weight:600; text-align:right;}
    .s2id{font-weight:800; font-size:17px; margin-bottom:10px; font-variant-numeric:tabular-nums;}
    .ok-badge{display:inline-block; font-size:10px; font-weight:700; letter-spacing:.05em; text-transform:uppercase; color:#1F6F43; border:1px solid currentColor; padding:2px 7px; border-radius:20px; margin-bottom:10px;}
    .err{color:#B3261E; font-size:12.5px; margin-bottom:10px;}
    .spinner{width:14px; height:14px; border-radius:50%; border:2px solid rgba(255,255,255,.5); border-top-color:#fff; animation:s2spin .7s linear infinite;}
    @keyframes s2spin{to{transform:rotate(360deg);}}
    .powered{display:flex; align-items:center; gap:5px; margin-top:12px; font-size:10.5px; color:var(--s2id-ink-faint);}
    .powered svg{flex-shrink:0;}
  `;

  class S2IDCheckout extends HTMLElement {
    static get observedAttributes() {
      return ["merchant-id", "weight-kg", "carrier", "endpoint"];
    }

    constructor() {
      super();
      this._shadow = this.attachShadow({ mode: "open" });
      this._destination = "door";
      this._state = "idle"; // idle | pending | granted | error
      this._result = null;
      this._mode = null;
      this._error = null;
      /** Set to a function to receive the CheckoutResult directly, mirroring client.ts's onGrant doc comment. Prefer the `s2id-grant` event for most integrations. */
      this.onGrant = null;
    }

    connectedCallback() {
      this._render();
    }

    attributeChangedCallback() {
      if (this._shadow.childNodes.length) this._render();
    }

    _setDestination(v) {
      this._destination = v;
      this._render();
    }

    async _runCheckout() {
      this._state = "pending";
      this._error = null;
      this._render();

      const merchantId = this.getAttribute("merchant-id") || "unknown-merchant";
      const weightKg = Number(this.getAttribute("weight-kg") || "1");
      const carrier = this.getAttribute("carrier") || "MER-POST";
      const endpoint = this.getAttribute("endpoint");
      const payload = { merchantId, weightKg, carrier, destinationKind: this._destination };

      try {
        let result;
        if (endpoint) {
          result = await remoteCheckout(endpoint, payload);
          this._mode = "live";
        } else {
          result = await localDemoCheckout(payload);
          this._mode = "demo";
        }
        this._result = result;
        this._state = "granted";
        this._render();
        this.dispatchEvent(new CustomEvent("s2id-grant", { detail: result, bubbles: true, composed: true }));
        if (typeof this.onGrant === "function") this.onGrant(result);
      } catch (err) {
        this._state = "error";
        this._error = err && err.message ? err.message : String(err);
        this._render();
        this.dispatchEvent(new CustomEvent("s2id-error", { detail: this._error, bubbles: true, composed: true }));
      }
    }

    _render() {
      const s = this._shadow;
      s.innerHTML = `<style>${STYLE}</style><div class="card"></div>`;
      const card = s.querySelector(".card");

      if (this._state === "granted" && this._result) {
        const r = this._result;
        card.innerHTML = `
          <span class="ok-badge">Shipment authorized</span>
          <div class="ticket">
            <div class="s2id">${r.s2id}</div>
            <div class="row"><span class="k">Destination</span><span class="v">${DEST_LABELS[r._destinationKind] || DEST_LABELS[this._destination]}</span></div>
            <div class="row"><span class="k">Service</span><span class="v">${r.serviceLevel}</span></div>
            <div class="row"><span class="k">Estimated delivery</span><span class="v">${r.estimatedDelivery}</span></div>
            <div class="row"><span class="k">Verified human</span><span class="v">${r.verifiedHuman ? "Yes" : "No"}</span></div>
          </div>
          <div class="foot ${this._mode === "demo" ? "demo" : ""}">
            ${this._mode === "demo"
              ? "Demo transport — derived locally, no endpoint configured."
              : "Delivered by your configured Ship2MyID endpoint."}
          </div>
          ${this._poweredBadge()}
        `;
        return;
      }

      card.innerHTML = `
        <div class="label">Deliver to</div>
        <div class="chips">
          ${["door", "access-point", "locker"].map(v => `
            <button class="chip ${v === this._destination ? "selected" : ""}" data-dest="${v}">${DEST_LABELS[v]}</button>
          `).join("")}
        </div>
        ${this._state === "error" ? `<div class="err">${this._error}</div>` : ""}
        <button class="go" ${this._state === "pending" ? "disabled" : ""}>
          ${this._state === "pending" ? `<span class="spinner"></span> Verifying…` : "Verify &amp; ship — no address needed"}
        </button>
        ${this._poweredBadge()}
      `;
      card.querySelectorAll("[data-dest]").forEach((btn) => {
        btn.addEventListener("click", () => this._setDestination(btn.dataset.dest));
      });
      card.querySelector(".go").addEventListener("click", () => this._runCheckout());
    }

    _poweredBadge() {
      if (this.hasAttribute("no-badge")) return "";
      return `
        <div class="powered">
          <svg width="12" height="12" viewBox="0 0 12 12"><circle cx="6" cy="6" r="5.4" fill="none" stroke="currentColor" stroke-width="1.1"/><path d="M3.6 6l1.6 1.6L8.4 4" fill="none" stroke="currentColor" stroke-width="1.1"/></svg>
          <span>Powered by Ship2MyID</span>
        </div>
      `;
    }
  }

  if (!customElements.get("s2id-checkout")) {
    customElements.define("s2id-checkout", S2IDCheckout);
  }
})();
