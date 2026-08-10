# The CDN in front of this instance can serve modified client code, and an extension is the fix

**Labels:** security, threat-model, enhancement

## Summary

Warp Gate's encryption is sound and the server never holds a key. The residual risk is not
the transport, it is the **delivery of the client**. `warpgate.fysh.site` sits behind
Cloudflare, which terminates TLS. Cloudflare can therefore return a modified `app.js`,
`crypto.js` or `link.js` to any visitor it chooses, and that modified code would run as
first party on the real origin.

Nothing in the current design detects this. In particular the Content-Security-Policy does
not, and cannot: the policy's job is to stop code from *other* origins, and substituted
first-party code is not from another origin. `THREAT-MODEL.md` already says this in the
section on the CDN, and it is worth restating as an issue because it is the single
remaining way to break the product's central promise.

## This is not hypothetical on this instance

Cloudflare's JS Detections feature already injects a 938-byte `<script>` carrying
`__CF$cv$params` into `/app` before `</body>`, loading
`/cdn-cgi/challenge-platform/scripts/jsd/main.js`. It is added by the CDN, not by this
repository.

Today that specific injection is inert, and this is measured rather than assumed:
`tests/cdn-injection.test.mjs` loads `/app` in a real browser, waits, and asserts that
`window.__CF$cv$params` is undefined and that no iframe exists, with a control proving the
same probe reports the opposite once a global and an iframe do exist. It is blocked because
the gate is served with `script-src 'self'`, no nonce, and no `'unsafe-inline'`.

That is a good result and it is also the wrong thing to take comfort from. The injection
being blocked proves the CSP works against an inline script. It proves nothing about the
case that matters, which is the same party serving a modified `js/app.js` from
`warpgate.fysh.site` itself, where the CSP is satisfied by construction.

## Scope of the exposure

An attacker in this position could:

- exfiltrate the room secret, which is deliberately kept out of the address bar but is in
  memory in the page;
- capture plaintext before it is encrypted, or after it is decrypted;
- suppress or forge the SAS verification code, so that reading the words aloud stops
  being evidence of anything;
- do all of the above to one targeted visitor and to nobody else, which is what makes it
  hard to catch by ordinary means.

It requires the CDN operator, or anyone who compels or compromises them. It is not a
remote attack by an arbitrary third party.

## Proposed fix: ship the client as a browser extension

Move the client out of the network delivery path entirely.

An extension is installed once, is reviewed by the store, and updates only through the
store's signed channel. The server is reduced to what it was always supposed to be: a
signalling introducer holding no keys and, now, no ability to change the code that holds
them. Per-request substitution stops being possible, because there is no per-request
delivery.

What it changes:

- **Removes:** the CDN, the host, and anyone who compromises either, from the set of
  parties who can alter the cryptography.
- **Does not remove:** the metadata the signalling server can see. Who connected to whom,
  when, and from which address is unchanged, and the extension must say so plainly in its
  own UI rather than implying it is a privacy upgrade in every dimension.

Design constraints for the implementation:

- Manifest V3, no build step, no dependencies, matching the rest of this repository.
- No remote code and no remote resources of any kind. MV3 forbids remote code already;
  do not weaken the extension page CSP to work around anything.
- The signalling origin must be configurable, defaulting to `https://warpgate.fysh.site`.
  The premise of the whole change is that the server is untrusted, so being able to point
  it elsewhere is part of the design and not a loosening of it.

Known open questions, to be answered against the code rather than assumed:

1. Does the server validate `Origin` on `/api/*`? An extension page presents
   `chrome-extension://<id>`, so a same-origin check would block signalling outright.
2. What does the streaming download path (`public/sw.js`, `public/js/download.js`) depend
   on? Service worker scope and registration are origin-sensitive.
3. Does any client module assume a same-origin document URL, in particular the handling of
   the gate link and the fragment that carries the room secret?

## Why not the alternatives

- **Subresource Integrity.** The hashes live in the HTML, which is served by the same
  party that would be substituting the scripts. It moves the problem, it does not solve it.
- **Removing the CDN.** This narrows the set of parties from two to one. The host can still
  serve whatever it likes. It is an improvement and not an answer.
- **Asking users to compare a hash.** Nobody does this, and a client that has already been
  substituted can lie about its own hash.

## Acceptance

- An installable extension that runs the client from its own package, with the parts that
  do not yet work named explicitly rather than stubbed.
- Its UI states what it protects against and what it does not.
- `THREAT-MODEL.md` updated to describe the extension as the mitigation for this row, with
  the metadata exposure still listed as unmitigated.
