/**
 * SauronID Embeddable SDK
 * Drop-in replacement for "Login with Google/Facebook" buttons.
 * ZKP-based: sites receive proofs of identity claims, never raw data.
 *
 * Usage:
 *   <script src="https://your-domain/sdk/sauron.js"></script>
 *   <div data-sauron-site="YourSite"
 *        data-sauron-claims="first_name,nationality"
 *        data-sauron-api="http://localhost:3001"></div>
 *
 *   Or programmatically:
 *   const sdk = new SauronID({ siteName, claims, apiUrl, onSuccess, onError });
 *   sdk.render(document.getElementById('login-area'));
 */
(function (global) {
  'use strict';

  // ── Simple browser fingerprint (no deps) ──────────────────────────────────
  function getFingerprint() {
    var parts = [
      navigator.userAgent,
      screen.width + 'x' + screen.height,
      screen.colorDepth,
      new Intl.DateTimeFormat().resolvedOptions().timeZone,
      navigator.language,
      navigator.hardwareConcurrency || 0,
      navigator.platform || '',
    ].join('|');
    var h = 0;
    for (var i = 0; i < parts.length; i++) {
      h = Math.imul(31, h) + parts.charCodeAt(i) | 0;
    }
    return (h >>> 0).toString(16);
  }

  // ── Styles ────────────────────────────────────────────────────────────────
  var CSS = `
    .sauron-btn {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 11px 20px;
      background: #0f172a;
      color: #f8fafc;
      border: 1px solid #1e293b;
      border-radius: 10px;
      font-family: system-ui, -apple-system, sans-serif;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.15s, box-shadow 0.15s;
      user-select: none;
      white-space: nowrap;
    }
    .sauron-btn:hover { background: #1e293b; box-shadow: 0 2px 8px rgba(0,0,0,0.15); }
    .sauron-btn:active { background: #334155; }
    .sauron-btn:disabled { opacity: 0.5; cursor: not-allowed; }
    .sauron-btn svg { flex-shrink: 0; }
    .sauron-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 12px;
      background: #f0fdf4;
      border: 1px solid #bbf7d0;
      border-radius: 20px;
      font-family: system-ui, sans-serif;
      font-size: 13px;
      color: #166534;
    }
    .sauron-badge-dot { width: 8px; height: 8px; border-radius: 50%; background: #22c55e; }
  `;

  var ICON_SVG = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="10" stroke="#6366f1" stroke-width="2"/><circle cx="12" cy="12" r="4" fill="#6366f1"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4" stroke="#6366f1" stroke-width="2" stroke-linecap="round"/></svg>';
  var CHECK_SVG = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M20 6L9 17l-5-5" stroke="#22c55e" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/></svg>';

  function injectStyles() {
    if (document.getElementById('sauron-sdk-css')) return;
    var style = document.createElement('style');
    style.id = 'sauron-sdk-css';
    style.textContent = CSS;
    document.head.appendChild(style);
  }

  // ── SauronID constructor ──────────────────────────────────────────────────
  function SauronID(config) {
    this.config = Object.assign({
      apiUrl: 'http://localhost:3001',
      portalUrl: 'http://localhost:3000',
      claims: ['first_name', 'last_name', 'nationality'],
      buttonText: 'Continue with SauronID',
      theme: 'dark',
      silentAuth: true,
      onSuccess: function () {},
      onError: function (err) { console.error('[SauronID]', err); },
      onLoading: function () {},
      onIdle: function () {},
    }, config);
    this._fp = getFingerprint();
    this._storageKey = 'sauron_device_' + this.config.siteName;
  }

  // ── Render button into element ────────────────────────────────────────────
  SauronID.prototype.render = function (el) {
    injectStyles();
    this._container = el;

    // Try silent auth first if device token exists
    if (this.config.silentAuth) {
      var saved = this._loadDeviceToken();
      if (saved) {
        this._silentAuth(saved, el);
        return;
      }
    }

    this._renderButton(el);
  };

  SauronID.prototype._renderButton = function (el) {
    el.innerHTML = '';
    var btn = document.createElement('button');
    btn.className = 'sauron-btn';
    btn.innerHTML = ICON_SVG + '<span>' + this.config.buttonText + '</span>';
    btn.onclick = this._handleClick.bind(this);
    el.appendChild(btn);
    this._btn = btn;
  };

  SauronID.prototype._renderBadge = function (el, name) {
    el.innerHTML = '';
    var badge = document.createElement('div');
    badge.className = 'sauron-badge';
    badge.innerHTML = '<div class="sauron-badge-dot"></div>' + CHECK_SVG +
      '<span>Verified' + (name ? ' as ' + name : '') + ' via SauronID</span>';
    el.appendChild(badge);
  };

  SauronID.prototype._setLoading = function (on) {
    if (this._btn) {
      this._btn.disabled = on;
      this._btn.querySelector('span').textContent = on ? 'Connecting...' : this.config.buttonText;
    }
    if (on) this.config.onLoading();
    else this.config.onIdle();
  };

  // ── Silent auth via device token ──────────────────────────────────────────
  SauronID.prototype._silentAuth = function (deviceToken, el) {
    var self = this;
    this._setLoading(true);
    if (el) { el.innerHTML = '<span style="font-size:13px;color:#94a3b8;font-family:system-ui">Signing in...</span>'; }

    fetch(this.config.apiUrl + '/auth/device/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_token: deviceToken,
        site_name: this.config.siteName,
        fingerprint: self._fp,
      }),
    })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (!data.valid) {
        self._clearDeviceToken();
        self._renderButton(el || self._container);
        self._setLoading(false);
        return;
      }
      // Retrieve KYC with consent_token
      return self._retrieveProfile(data.consent_token);
    })
    .then(function (profile) {
      if (!profile) return;
      self._renderBadge(el || self._container, profile.first_name);
      self.config.onSuccess(profile);
    })
    .catch(function (err) {
      self._clearDeviceToken();
      self._renderButton(el || self._container);
      self._setLoading(false);
    });
  };

  // ── Click handler — open consent popup ───────────────────────────────────
  SauronID.prototype._handleClick = async function () {
    var self = this;
    self._setLoading(true);
    try {
      // 1. Request consent from backend
      var reqRes = await fetch(self.config.apiUrl + '/kyc/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          site_name: self.config.siteName,
          requested_claims: self.config.claims,
        }),
      });
      if (!reqRes.ok) throw new Error('Failed to initiate consent request');
      var reqData = await reqRes.json();
      var request_id = reqData.request_id;
      var consent_url = reqData.consent_url;

      // 2. Append origin to consent URL for secure postMessage
      var myOrigin = window.location.origin;
      var popupUrl = consent_url + (consent_url.includes('?') ? '&' : '?') +
        'origin=' + encodeURIComponent(myOrigin);

      // 3. Open popup
      var popup = window.open(popupUrl, 'sauron_consent',
        'width=460,height=640,top=100,left=' + Math.round((screen.width - 460) / 2));
      if (!popup) {
        throw new Error('Popup blocked. Please allow popups for this site and try again.');
      }

      // 4. Wait for postMessage
      var consent_token = await new Promise(function (resolve, reject) {
        var timeout = setTimeout(function () {
          window.removeEventListener('message', handler);
          reject(new Error('Consent timed out'));
        }, 5 * 60 * 1000);

        function handler(event) {
          if (event.origin !== myOrigin) return;
          if (event.data && event.data.request_id !== request_id) return;
          clearTimeout(timeout);
          window.removeEventListener('message', handler);
          if (event.data && event.data.type === 'sauron_consent') {
            resolve(event.data.consent_token);
          } else {
            reject(new Error('User denied consent'));
          }
        }
        window.addEventListener('message', handler);
      });

      // 5. Retrieve profile
      var profile = await self._retrieveProfile(consent_token);

      // 6. Issue device token for future silent auth
      try {
        var dtRes = await fetch(self.config.apiUrl + '/auth/device/issue', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            consent_token: consent_token,
            site_name: self.config.siteName,
            fingerprint: self._fp,
          }),
        });
        if (dtRes.ok) {
          var dtData = await dtRes.json();
          self._saveDeviceToken(dtData.device_token);
        }
      } catch (_) { /* non-critical */ }

      // 7. Update UI + callback
      self._renderBadge(self._container, profile.first_name);
      self.config.onSuccess(profile);

    } catch (err) {
      self._setLoading(false);
      self.config.onError(err);
    }
  };

  // ── Retrieve profile from consent token ──────────────────────────────────
  SauronID.prototype._retrieveProfile = async function (consent_token) {
    var res = await fetch(this.config.apiUrl + '/kyc/retrieve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        consent_token: consent_token,
        site_name: this.config.siteName,
      }),
    });
    if (!res.ok) throw new Error('Profile retrieval failed');
    var data = await res.json();
    return data.profile || data;
  };

  // ── Device token storage ──────────────────────────────────────────────────
  SauronID.prototype._saveDeviceToken = function (token) {
    try { localStorage.setItem(this._storageKey, token); } catch (_) {}
  };
  SauronID.prototype._loadDeviceToken = function () {
    try { return localStorage.getItem(this._storageKey); } catch (_) { return null; }
  };
  SauronID.prototype._clearDeviceToken = function () {
    try { localStorage.removeItem(this._storageKey); } catch (_) {}
  };

  // ── Logout ────────────────────────────────────────────────────────────────
  SauronID.prototype.logout = function () {
    this._clearDeviceToken();
    if (this._container) this._renderButton(this._container);
  };

  // ── Auto-init via data attributes ─────────────────────────────────────────
  SauronID.autoInit = function () {
    document.querySelectorAll('[data-sauron-site]').forEach(function (el) {
      var siteName = el.getAttribute('data-sauron-site');
      var claimsRaw = el.getAttribute('data-sauron-claims') || '';
      var claims = claimsRaw ? claimsRaw.split(',').map(function (s) { return s.trim(); }) : [];
      var apiUrl = el.getAttribute('data-sauron-api') || 'http://localhost:3001';
      var btnText = el.getAttribute('data-sauron-text') || 'Continue with SauronID';

      var sdk = new SauronID({
        siteName: siteName,
        claims: claims.length ? claims : ['first_name', 'last_name', 'nationality'],
        apiUrl: apiUrl,
        buttonText: btnText,
        onSuccess: function (profile) {
          var ev = new CustomEvent('sauronid:success', { detail: profile, bubbles: true });
          el.dispatchEvent(ev);
        },
        onError: function (err) {
          var ev = new CustomEvent('sauronid:error', { detail: err.message, bubbles: true });
          el.dispatchEvent(ev);
        },
      });
      sdk.render(el);
    });
  };

  global.SauronID = SauronID;

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', SauronID.autoInit);
  } else {
    SauronID.autoInit();
  }

})(window);
