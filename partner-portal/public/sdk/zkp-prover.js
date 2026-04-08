(function (global) {
  'use strict';

  function toDateInt(date) {
    var y = date.getUTCFullYear().toString().padStart(4, '0');
    var m = (date.getUTCMonth() + 1).toString().padStart(2, '0');
    var d = date.getUTCDate().toString().padStart(2, '0');
    return parseInt(y + m + d, 10);
  }

  function normalizeDob(value) {
    if (typeof value === 'number') return value;
    if (typeof value === 'string') {
      var cleaned = value.replace(/-/g, '');
      var parsed = parseInt(cleaned, 10);
      if (!Number.isNaN(parsed)) return parsed;
    }
    return null;
  }

  function normalizeInt(value, fallback) {
    if (typeof value === 'number' && Number.isFinite(value)) return Math.trunc(value);
    if (typeof value === 'string') {
      var parsed = parseInt(value, 10);
      if (!Number.isNaN(parsed)) return parsed;
    }
    return fallback;
  }

  function ensureSnarkjs(cdnUrl) {
    if (global.snarkjs && global.snarkjs.groth16) {
      return Promise.resolve(global.snarkjs);
    }

    if (global.__sauronSnarkjsPromise) {
      return global.__sauronSnarkjsPromise;
    }

    global.__sauronSnarkjsPromise = new Promise(function (resolve, reject) {
      var script = document.createElement('script');
      script.src = cdnUrl;
      script.async = true;
      script.onload = function () {
        if (global.snarkjs && global.snarkjs.groth16) {
          resolve(global.snarkjs);
        } else {
          reject(new Error('snarkjs loaded but groth16 API missing'));
        }
      };
      script.onerror = function () {
        reject(new Error('Failed to load snarkjs from CDN: ' + cdnUrl));
      };
      document.head.appendChild(script);
    });

    return global.__sauronSnarkjsPromise;
  }

  async function fetchCredential(apiUrl, userSession) {
    var res = await fetch(apiUrl + '/user/credential', {
      method: 'GET',
      headers: {
        'x-sauron-session': userSession,
      },
    });
    if (!res.ok) {
      throw new Error('Failed to fetch credential');
    }
    var data = await res.json();
    if (!data || !data.credential) {
      throw new Error('Credential payload missing');
    }
    return data.credential;
  }

  function buildAgeInput(credential, minAge) {
    var subject = credential.credentialSubject || {};
    var metadata = credential.zkpMetadata || {};
    var proof = credential.proof || {};
    var proofValue = proof.proofValue || {};

    var dob = normalizeDob(subject.dateOfBirth);
    if (!dob) throw new Error('Credential dateOfBirth missing or invalid');

    var issuerPubKeyAx = metadata.issuerPubKeyAx;
    var issuerPubKeyAy = metadata.issuerPubKeyAy;
    if (!issuerPubKeyAx || !issuerPubKeyAy) {
      throw new Error('Credential issuer public key metadata missing');
    }

    if (!proofValue.R8x || !proofValue.R8y || !proofValue.S) {
      throw new Error('Credential EdDSA proofValue missing');
    }

    return {
      dateOfBirth: String(dob),
      issuerSigR8x: String(proofValue.R8x),
      issuerSigR8y: String(proofValue.R8y),
      issuerSigS: String(proofValue.S),
      ageThreshold: String(minAge),
      currentDate: String(toDateInt(new Date())),
      issuerPubKeyAx: String(issuerPubKeyAx),
      issuerPubKeyAy: String(issuerPubKeyAy),
    };
  }

  async function fetchProofMaterial(apiUrl, credentialHash, leafIndex) {
    var res = await fetch(apiUrl + '/zkp/proof_material', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credential_hash: credentialHash || null,
        leaf_index: typeof leafIndex === 'number' ? leafIndex : null,
      }),
    });
    if (!res.ok) {
      throw new Error('Failed to fetch proof material');
    }
    return res.json();
  }

  function buildCredentialInput(credential, proofMaterial, opts) {
    var subject = credential.credentialSubject || {};
    var metadata = credential.zkpMetadata || {};
    var proof = credential.proof || {};
    var proofValue = proof.proofValue || {};

    if (!proofMaterial || !Array.isArray(proofMaterial.pathElements) || !Array.isArray(proofMaterial.pathIndices)) {
      throw new Error('Invalid proof material payload');
    }

    if (!proofValue.R8x || !proofValue.R8y || !proofValue.S) {
      throw new Error('Credential EdDSA proofValue missing');
    }

    var requiredNationality = opts.requiredNationalityHash || '0';
    return {
      dateOfBirth: String(normalizeDob(subject.dateOfBirth) || 19900101),
      nationality: String(subject.nationality || '0'),
      documentNumber: String(subject.documentNumber || '0'),
      expiryDate: String(normalizeInt(subject.expiryDate, 20301231)),
      issuerId: String(subject.issuerId || '1'),

      issuerSigR8x: String(proofValue.R8x),
      issuerSigR8y: String(proofValue.R8y),
      issuerSigS: String(proofValue.S),

      merklePathElements: proofMaterial.pathElements.map(function (v) { return String(v); }),
      merklePathIndices: proofMaterial.pathIndices.map(function (v) { return String(v); }),

      currentDate: String(toDateInt(new Date())),
      ageThreshold: String(opts.minAge || 18),
      requiredNationality: String(requiredNationality),
      merkleRoot: String(proofMaterial.merkleRoot),
      issuerPubKeyAx: String(metadata.issuerPubKeyAx || '0'),
      issuerPubKeyAy: String(metadata.issuerPubKeyAy || '0'),
    };
  }

  async function generateAgePresentation(opts) {
    var snarkjs = await ensureSnarkjs(opts.snarkjsCdn);
    var credential = opts.credential || await fetchCredential(opts.apiUrl, opts.userSession);
    var input = buildAgeInput(credential, opts.minAge || 18);

    var result = await snarkjs.groth16.fullProve(
      input,
      opts.wasmUrl,
      opts.zkeyUrl
    );

    return {
      proof: result.proof,
      circuit: 'AgeVerification',
      public_signals: result.publicSignals,
      credential: credential,
    };
  }

  async function generateCredentialPresentation(opts) {
    var snarkjs = await ensureSnarkjs(opts.snarkjsCdn);
    var credential = opts.credential || await fetchCredential(opts.apiUrl, opts.userSession);
    var metadata = credential.zkpMetadata || {};
    var proofMaterial = await fetchProofMaterial(opts.apiUrl, metadata.credentialHash || null, metadata.leafIndex);
    var input = buildCredentialInput(credential, proofMaterial, opts);

    var result = await snarkjs.groth16.fullProve(
      input,
      opts.wasmUrl,
      opts.zkeyUrl
    );

    return {
      proof: result.proof,
      circuit: 'CredentialVerification',
      public_signals: result.publicSignals,
      credential: credential,
      proof_material: proofMaterial,
    };
  }

  global.SauronZKProver = {
    ensureSnarkjs: ensureSnarkjs,
    fetchCredential: fetchCredential,
    generateCredentialPresentation: generateCredentialPresentation,
    generateAgePresentation: generateAgePresentation,
  };
})(window);
