# Warp Gate threat model

Written to be precise rather than reassuring. If something is not protected, it says so.

## The construction, in one paragraph

A 128-bit room secret is generated in the creating browser and never sent to the
server: it lives in the URL fragment, which browsers do not transmit, and it reaches
the other device by QR code or by a link you share. The room id the server sees is
derived from that secret through HKDF, so it reveals nothing. Both devices perform an
ephemeral ECDH P-256 exchange, mix the room secret into the key schedule as the HKDF
salt, and prove to each other that they hold the same secret before any data flows.
All application data, and all signalling, is AES-256-GCM under keys derived from that
schedule.

## Protected against

| Threat | How | Residual risk |
|---|---|---|
| The server operator reading messages or files | Payload keys come from ECDH plus a secret the server never receives | None, provided the link was shared out of band |
| The server being compromised | It holds no plaintext and no keys at any point. There is no storage layer to breach | None |
| The server or Cloudflare learning peer IP addresses from the SDP | Signalling payloads are encrypted under a key derived from the room secret, so the relay sees only `{n, c}` | Cloudflare still sees the two client IPs from the HTTP connections themselves |
| An active man in the middle at the signalling layer | The key schedule mixes the room secret, and both sides exchange an explicit key confirmation before the UI reports "connected" | Someone who obtains the link is not a man in the middle; they are a participant |
| Recording traffic now to decrypt later | Session keys need the ephemeral ECDH secret, which dies with the tab | None for message and file content |
| Tampering with any payload | AEAD on every frame; a single altered bit fails authentication and the frame is dropped | None |
| Replaying a captured frame | A strictly increasing per-direction counter, bound into both the nonce and the authenticated data | None |
| Passing a file chunk off as a chat message | The frame type is authenticated, so relabelling breaks the tag | None |
| Guessing a room code to read traffic | The room id is derived from a 128-bit secret; holding the id does not yield the secret, and key confirmation fails | Guessing can deny service, see below |
| A third device joining | Rooms lock at two participants, each holding an unguessable capability token | None |
| Data outliving the session | State is a single in-memory map. No database, no disk, no logs. A restart destroys every room | None |
| A session being reused after expiry | Two TTLs plus a sweeper, and the room is deleted on sever | None |

## Not protected against

These are real limits, not hypotheticals.

- **A compromised device, browser or extension** on either end. Everything is visible there.
- **The other person.** Anyone holding the link is a legitimate participant. They can save,
  screenshot, and forward anything you send. There is no way to prevent this and Warp Gate
  does not pretend to.
- **The two peers learning each other's IP address.** This is inherent to a direct
  connection and is the property most at odds with using Warp Gate between identities you
  want kept apart. It is stated in the onboarding for that reason.
- **Cloudflare metadata**, when served through a tunnel: client IPs, timing, room ids,
  request sizes and session duration. Cloudflare terminates TLS in that topology. The
  payloads it carries are ciphertext, but the metadata is real. The same applies to the
  STUN server, which is deliberately Cloudflare's: it learns each device's public
  address, which Cloudflare already observes from the signalling connection itself. The
  point of choosing it is that it adds no party that was not already there.
- **Your real address, even behind a proxy.** WebRTC discovers the network address of
  the interface it actually sends from. Loading the page through a proxy does not
  change that, which is why the onboarding says Warp Gate is confidential, not
  anonymous.
- **Traffic analysis.** Nothing is padded, delayed or covered. Message and file sizes and
  timings are observable to anyone watching the network.
- **Browser memory hygiene.** The operating system may page a tab's memory to disk. No
  web application can prevent that.
- **Clipboard clearing.** Best effort only. Other applications may already have taken a
  copy, and no browser guarantees a clipboard can be cleared.
- **Anonymity.** Warp Gate is confidential, not anonymous.
- **Denial of service.** Someone who guesses a room id can occupy the second slot and stop
  the intended device joining. They learn nothing, and key confirmation fails, but they
  can be a nuisance. Re-create the gate if it happens.

## Design decisions worth knowing

**There is no password option.** A short password that a human speaks aloud, hashed into
a key, can be attacked offline by exactly the adversary such a password is meant to stop.
Doing it properly needs a PAKE such as CPace, and no reviewed browser implementation was
available under this project's no-dependency constraint. A 128-bit secret carried by the
link and the QR code is strictly stronger, and the optional five digit verification code
covers the "say it aloud" case.

**There is no whole-file hash.** Every chunk is individually authenticated and bound to
its position in the sequence, so a file-level hash would add no security property. What
is checked at the end is that the reassembled byte and chunk counts match what was sent.

**There is no relay in this version.** If a direct connection cannot be established, Warp
Gate says so and stops, rather than silently routing through a server. A future relay
would carry ciphertext only, and would be labelled in the interface when in use.

**Key material is non-extractable.** Session keys are `CryptoKey` objects the browser
will not export, so the raw bytes never enter JavaScript memory. Dropping the reference
on sever is the strongest erasure a browser offers, since a JavaScript byte array cannot
be reliably wiped.
