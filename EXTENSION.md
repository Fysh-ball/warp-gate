# Warp Gate as a browser extension

There is an MV3 browser extension in `extension/`. It ships the Warp Gate client inside the
package instead of downloading it, which closes the one gap `THREAT-MODEL.md` says no header
can close: the party that terminates TLS in front of the server can serve modified
JavaScript to a targeted visitor, and a modified `app.js` from the same origin defeats every
guarantee the product makes.

The full account is in **`extension/README.md`**: what was built, what was rejected, what is
verified, what is not, and the follow-ups it needs in `public/`. This file exists only so
the extension is discoverable from the repository root.

The short version:

- The whole client is copied into `extension/`, and four files are patched so the network
  destination is explicit rather than inherited from `location`. `extension/js/endpoint.js`
  is the only place that knows where the signalling server is.
- The signalling origin is configurable and defaults to `https://warpgate.fysh.site`. The
  server is the untrusted party in this design, so retargeting it is the feature.
- **No `server/` change was needed.** The `Sec-Fetch-Site` guard in `server/signal.js` does
  not fire for an extension-initiated request, and there is no `Origin` check anywhere. If
  one is ever added, the extension breaks and will need `chrome-extension://` allowed.
- The streaming download is lost: Chromium will not let an extension page register a service
  worker. Above 500 MB on a browser without `showSaveFilePicker`, a receive is not possible.
- No second peer was driven, so the WebRTC handshake and transfers are argued rather than
  measured in the extension's own test.

```
node extension/extension.test.mjs      # 35 checks in a real browser against a local server
node extension/drift-check.mjs         # is the copied client still in step with public/?
node extension/sync-from-public.mjs    # re-copy public/ and re-apply the patches
```
