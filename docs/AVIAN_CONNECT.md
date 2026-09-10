# Avian Connect — Protocol Specification (Phase 1)

Avian Connect is the dApp connection surface of Avian FlightDeck. It lets an external web
application ask the user's wallet for their address and for a signature over a login challenge,
without the dApp ever seeing key material.

Phase 1 is **login-grade only**: connect, accounts, message signing, network identification.
There is no transaction signing, no PSBT signing, and no asset support in this phase — those
methods return `UNSUPPORTED_METHOD`.

The wallet endpoint is a single URL:

```
https://flightdeck.avn.network/connect
```

Two transports share that URL: a **popup** transport (desktop) and a **redirect** transport
(mobile / in-app browsers where popups are unreliable).

---

## 1. Security model

- **Keys never leave the wallet.** A dApp only ever receives an address, optionally a compressed
  public key (hex), and base64 signatures. Mnemonics, private keys, xprvs, and decrypted secrets
  are never placed in a `postMessage` payload or a redirect fragment.
- **Every signature requires two user actions**: an explicit approval screen showing the origin
  and the verbatim message, plus wallet authentication (password or biometric). "Remembering" a
  site skips the *connect* screen only — it never skips the *sign* screen and never skips
  authentication.
- **Origins are pinned per request.** In popup mode the wallet learns the origin from
  `MessageEvent.origin` of the first message from its opener and replies only to that origin —
  never `"*"`. In redirect mode the wallet requires `req.origin` to equal the origin of
  `redirect_uri`, so a site can only receive answers at its own origin.
- **Fragment, not query.** Redirect responses are returned in the URL fragment
  (`#avianconnect=…`), which browsers do not send to servers, keeping signatures out of server
  logs, proxies, and `Referer` headers.
- **The wallet is the source of truth for the origin.** Any `origin` a dApp writes into a request
  is only used in redirect mode, and only after being matched against `redirect_uri`. It is never
  trusted in popup mode.
- **Origins must be `https:`.** Plaintext `http:` is accepted only for `localhost`, `127.0.0.1`
  and `[::1]` so the demo and local development work. This applies to both transports: a popup
  message from a plaintext origin is ignored, and a plaintext `redirect_uri` is refused.

### What origin attestation does and does not give you

In popup mode the browser attests the origin: the value comes from `MessageEvent.origin` and
cannot be forged by page script. In redirect mode there is no equivalent browser attestation —
the wallet can only guarantee that the response is *delivered to* the origin named in the
request. A malicious site can therefore truthfully identify itself and receive its own answers,
but it cannot impersonate another site and receive that site's answers.

---

## 2. Envelopes

All messages are JSON objects carrying the version tag `avianConnect: 1`.

### 2.1 Request (dApp → wallet)

```jsonc
{
  "avianConnect": 1,
  "id": "a3f1c9d2",       // string, 1..128 chars, echoed back verbatim
  "method": "signMessage",
  "params": { "message": "…" },  // optional, object
  "origin": "https://realm.example"  // required in redirect mode, ignored in popup mode
}
```

Rules:

- `avianConnect` must be exactly the number `1`.
- `id` must be a non-empty string of at most 128 characters. Generate a fresh, unguessable id per
  request; the wallet echoes it so a dApp can match replies.
- `method` must be a non-empty string of at most 64 characters.
- `params`, when present, must be a plain object (not an array, not `null`).
- Anything else is rejected with `INVALID_REQUEST`.

### 2.2 Response (wallet → dApp)

Exactly one of `result` or `error` is present.

```jsonc
{ "avianConnect": 1, "id": "a3f1c9d2", "result": { "signature": "H9x…" } }
```

```jsonc
{ "avianConnect": 1, "id": "a3f1c9d2", "error": { "code": "USER_REJECTED", "message": "User rejected the request" } }
```

### 2.3 Events (popup transport only)

Events are unsolicited wallet → dApp messages. They carry no `id`.

```jsonc
{ "avianConnect": 1, "event": "accountsChanged", "data": { "accounts": ["R9…"] } }
```

| Event             | `data`                                    | Meaning                                                     |
| ----------------- | ----------------------------------------- | ----------------------------------------------------------- |
| `accountsChanged` | `{ accounts: string[] }`                  | The accounts exposed to this origin changed (wallet switch, revocation). An empty array means the origin no longer has access. |
| `networkChanged`  | `{ network: string, genesisHash: string \| null }` | The active network changed. Phase 1 is mainnet-only, so this is emitted for completeness. |
| `disconnect`      | `{ reason: string }`                      | The wallet is tearing the session down (window closing, permission revoked). |

The redirect transport is single-shot — one request, one navigation back — so it carries no
events.

---

## 3. Methods (phase 1)

### `connect()`

Requests access to an account.

- **params**: none
- **result**: `{ address: string, publicKey?: string }`

The first call from an origin shows the connect approval screen, where the user picks which
wallet to expose and may tick "remember this site". Origins the user chose to remember resolve
silently on later calls. Origins that were approved without "remember" must approve again on the
next call.

`publicKey` (compressed, hex) is included only when the wallet already knows it for the exposed
address. The wallet learns it by recovering it from a signature the user has already authorised,
so it is typically absent on the first `connect()` and present afterwards. Treat it as optional.

### `getAccounts()`

- **params**: none
- **result**: `string[]`

Returns exactly the accounts the user exposed to *this* origin, never the wallet's full account
list. Requires an existing permission; otherwise `ORIGIN_NOT_APPROVED`.

### `signMessage({ message })`

- **params**: `{ message: string }` — non-empty, at most 8192 characters
- **result**: `{ signature: string }` — base64

Signs with the exposed account using the Avian message prefix
(`\x16Raven Signed Message:\n`), producing a signature verifiable by Avian Core and by
FlightDeck's Message Utilities → Verify tab.

Requires an existing permission, an explicit per-signature approval screen showing the origin and
the full untruncated message, and wallet authentication. There is no way to pre-approve
signatures.

A dApp login challenge should include the origin, a server nonce, and an expiry, e.g.:

```
realm.example wants you to sign in with your Avian address:
R9xy…

Nonce: 6f1a…
Issued At: 2026-08-10T12:00:00Z
```

### `signPsbt({ psbt, broadcast? })`

- **params**: `{ psbt: string, broadcast?: boolean }` — a base64 PSBT (BIP174), at most 100000
  characters
- **result**: `{ psbt: string, complete: boolean, signedInputs: number, broadcast: boolean, txid?: string, broadcastError?: string }`

The wallet signs the inputs the connected account owns with Avian's
`SIGHASH_ALL | SIGHASH_FORKID` (`0x41`) sighash and hands the updated PSBT back. `complete` is true
when every input is now signed; `signedInputs` is how many this wallet added.

**Broadcasting is opt-in.** With `broadcast: true` the wallet finalises and sends the transaction
once its own signature completes it, returning the `txid` and recording the spend in local history
— so the completing signer of a swap sees the result in their wallet instead of an unchanged
balance. Without the flag (the default) the wallet signs only and the dApp broadcasts.

Withholding a broadcast is not a security boundary: once the signature is handed over the dApp can
broadcast whenever it likes. What protects the user is the approval screen, which states plainly
whether the transaction will be *signed* or *signed and sent* — those are different consents, and
the flag changes what the user is shown.

A requested broadcast is **best-effort and never loses the signature**. If it fails, the result
carries `broadcast: false` and a `broadcastError`, with the signed PSBT still in `psbt`, so the dApp
can retry or send it itself. Two cases to expect:

| `broadcastError` | Meaning |
| --- | --- |
| `The transaction still needs other signatures` | our signature did not complete it; nothing was sent |
| a node error such as `missing-inputs` | the inputs are already spent — in a marketplace, another buyer took the listing first |

Asset inputs are **never** signed here (spending an Avian asset as a bare transfer would burn it),
and they are surfaced in the approval screen. Selling an asset has its own method,
[`signAssetListing`](#signassetlistingpsbt), whose sighash bounds what the signature can authorise;
a `SIGHASH_ALL` signature over a site-supplied transaction carries no such guarantee, which is why
this method stays closed to assets.

Requires an existing permission, an explicit per-request approval screen that **decodes the PSBT**
— showing each input and output, the total moved, the network fee, any asset, and how many inputs
the wallet will sign — and wallet authentication. There is no way to pre-approve signing. A PSBT
that does not parse is rejected without a prompt. The wallet does not select inputs or set the fee
for `signPsbt`; it signs exactly the transaction the dApp presents, so the dApp is responsible for
building a correct PSBT (see the wallet's own unsigned-PSBT export for the format).

### `createAssetListing({ assetName, priceSats, amount? })`

- **params**: `{ assetName: string, priceSats: number, amount?: string }`
- **result**: `{ psbt, assetName, assetAmount, priceSats, payTo, assetUtxo: { txid, vout } }`

**The wallet builds the listing.** A dApp says *what* to sell and *for how much*; it never supplies
a PSBT. The wallet owns the UTXOs, so it is the side that knows which output holds the asset — and
a request that can only name an asset and a price has almost no surface to attack with, where a
site-supplied PSBT is arbitrary structure the wallet must reason about.

The wallet selects the asset UTXO, builds one input and one output, signs with
`SIGHASH_SINGLE | SIGHASH_FORKID | SIGHASH_ANYONECANPAY` (`0xc3`) and finalises. SINGLE commits to
the output at the signed input's index; ANYONECANPAY commits to that input alone. The seller
therefore commits to exactly *"I spend this asset UTXO and I am paid this amount"*, and a buyer can
append payment inputs, an asset destination and change without invalidating the signature.

`amount` is the `10^8`-scaled quantity as a **decimal string** (JSON has no bigint). Omit it for a
unique, or any asset the account holds as a single output.

**Partial sales are refused.** The listed output must hold exactly the amount being sold. Since
SINGLE covers only `output[0]`, asset change returning the remainder to the seller would be
uncommitted — a buyer could drop it, take the whole output and still pay only the listed price.
Selling part of a larger holding needs that output split first, in its own transaction.

Other refusals: an asset the account does not hold; a holding spread across several outputs with no
`amount` given; a price that is not a positive whole number of satoshis. The wallet also re-reads
the asset name out of the signed output script and refuses if it does not match the request, so a
misfiltering server cannot cause the wrong item to be listed.

`assetUtxo` identifies the output the listing spends, so a dApp can tell a live listing from one
whose asset has since moved.

**A listing is deliberately unbalanced and must never be broadcast on its own.** Its only input is
the asset UTXO, which carries 0 AVN, while its only output pays the asking price — so it spends
nothing and pays out everything, and the buyer's inputs are what make it balance. Core's PSBT screen
does not understand half-finished swaps: it reports "fully signed and ready for broadcast" (meaning
every input has a `final_scriptSig`) and offers a Broadcast button, with the nonsensical negative fee
shown as `Pays transaction fee: -500.00000000 AVN`.

Broadcasting it anyway is harmless — the network refuses it outright:

```
testmempoolaccept → allowed: false
  bad-txns-in-belowout, value in (0.00) < value out (500.00)
```

Worth knowing that this rejection is on **value**, before script evaluation, so no signature is
verified by it. Neither `finalizepsbt` reporting `complete: true` nor Core's "fully signed" says
anything about whether a listing's signature is valid — both are structural claims. Only a completed
swap exercises the signature.

Requires an existing permission, an approval screen naming the asset and price, and wallet
authentication. Remembering a site never covers a sale.

### `completeAssetListing({ psbt })`

- **params**: `{ psbt: string, broadcast?: boolean }` — a seller-signed listing, at most 100000
  characters. `broadcast` defaults to **true** here: an unsent swap only widens the race to lose it.
  Pass `false` to get the completed, signed transaction back without sending it — for inspecting it
  with `testmempoolaccept` before anything is irreversible.
- **result**: `{ psbt, broadcast, txid?, broadcastError?, assetName, assetAmount, pricePaidSats, feeSats }`

**The buyer's wallet completes the swap.** It decodes the seller's listing, funds it from the
connected account, appends the asset destination and change, signs its own inputs and broadcasts,
returning the `txid`.

Everything shown to the buyer is decoded from the seller-signed bytes, never from what the dApp
claims: **a site cannot show one price and have the buyer pay another.** The seller's input and
payment output keep positions 0 and 0 — their signature commits to those positions — and everything
the buyer adds is appended.

Refused when: the PSBT is not a one-in/one-out listing; the seller has not signed it; the input is
not an asset; the buyer cannot cover the price plus fee; or the listing belongs to the buyer (cancel
it rather than buying from yourself).

A failed broadcast returns `broadcast: false` with a `broadcastError` and the completed PSBT, so the
dApp can retry. **A marketplace race lands here**: if another buyer took the listing first, its
asset UTXO is spent and the broadcast fails with `missing-inputs`. The buyer pays nothing.

### What a marketplace still does

Orchestration and integrity, no PSBT carpentry:

1. Hand the seller's client `{ assetName, priceSats }` → `createAssetListing` → index the returned
   signed PSBT, cross-checked against the request using the returned `assetName` and `priceSats`.
2. Serve a stored listing PSBT to a buyer → `completeAssetListing` → confirm via the returned
   `txid`.

The wallet re-derives the truth at both ends, so an indexing mistake cannot make anyone sign or pay
something they were not shown.

### `getNetwork()`

- **params**: none
- **result**: `{ network: "mainnet", genesisHash: string | null }`

`genesisHash` is the mainnet genesis block hash as reported by the ElectrumX server the wallet is
connected to (`server.features` → `genesis_hash`), cached locally once learned. It is `null` when
the wallet has never been able to reach a server to learn it — dApps that pin a genesis hash
should treat `null` as "unknown", not as a mismatch.

This method identifies the chain and exposes nothing about the user, so it is the one method that
does not require a permission.

Phase 1 is mainnet-only; testnet is out of scope.

### `disconnect()`

- **params**: none
- **result**: `{ disconnected: true }`

Revokes this origin's permission. Idempotent — disconnecting an origin that was never connected
succeeds. In popup mode the wallet also emits a `disconnect` event.

### Unknown methods

Any method not listed above — including `sendTransaction` and asset operations — returns
`UNSUPPORTED_METHOD`. These are phase 2+ work.

---

## 4. Errors

| Code                  | When                                                                    |
| --------------------- | ----------------------------------------------------------------------- |
| `USER_REJECTED`       | The user declined an approval screen, cancelled authentication, or closed the wallet window. |
| `ACCOUNT_CHANGED`     | The user switched wallets instead of answering. **Not a refusal** — rebuild the request against the new account and send it again. |
| `ORIGIN_NOT_APPROVED` | The method needs a permission this origin does not have.                |
| `WALLET_LOCKED`       | The wallet is locked, or has no wallet set up yet.                      |
| `UNSUPPORTED_METHOD`  | Unknown method, or a method deferred to a later phase.                  |
| `INVALID_REQUEST`     | Malformed envelope, bad params, or a transport-level mismatch such as `redirect_uri` disagreeing with `req.origin`. |

Error messages are human-readable and may change; branch on `code`, not on `message`.

---

## 5. Popup transport (desktop)

1. The dApp opens `https://flightdeck.avn.network/connect` with `window.open`.
2. The dApp posts its request to the popup **repeatedly** (e.g. every 250 ms) until it receives a
   reply. There is no "wallet ready" broadcast, because broadcasting one would require posting to
   `"*"`; retrying instead keeps every wallet-originated message targeted at a known origin.
3. The wallet ignores any message whose `source` is not its opener. The first well-formed envelope
   from the opener pins the session origin to that message's `MessageEvent.origin`. Messages from
   any other origin are ignored for the lifetime of the window.
   Resending is safe: requests are deduplicated by `id`, so a retry that arrives while an approval
   screen is open is dropped, and a retry that arrives after the answer is replayed from the
   wallet's record rather than re-prompting the user. Reusing an `id` for a *different* request
   therefore returns the first answer — always generate a fresh one.
4. The wallet replies with `window.opener.postMessage(response, pinnedOrigin)`.
5. The dApp keeps the popup open to receive events and to issue further requests, or closes it.
   If the user closes the wallet window with a request outstanding, the wallet sends
   `USER_REJECTED` for the pending request and a `disconnect` event where it can.

Minimal client:

```js
const popup = window.open('https://flightdeck.avn.network/connect', 'avian-connect',
  'width=460,height=720');

function call(method, params) {
  const id = crypto.randomUUID();
  const req = { avianConnect: 1, id, method, params };
  return new Promise((resolve, reject) => {
    const onMessage = (e) => {
      if (e.source !== popup) return;                       // must come from the popup
      if (e.origin !== 'https://flightdeck.avn.network') return; // must be the wallet's origin
      const msg = e.data;
      if (!msg || msg.avianConnect !== 1 || msg.id !== id) return;
      clearInterval(timer);
      window.removeEventListener('message', onMessage);
      msg.error ? reject(msg.error) : resolve(msg.result);
    };
    window.addEventListener('message', onMessage);
    const timer = setInterval(
      () => popup.postMessage(req, 'https://flightdeck.avn.network'),
      250,
    );
  });
}

const { address } = await call('connect');
const { signature } = await call('signMessage', { message: `Login to realm.example\nNonce: ${nonce}` });
```

A dApp **must** check both `e.source` and `e.origin` on every inbound message, exactly as above.

---

## 6. Redirect transport (mobile)

The dApp navigates the browser to:

```
https://flightdeck.avn.network/connect?req=<base64url(JSON request)>&redirect_uri=<urlencoded>
```

- `req` is the base64url encoding (RFC 4648 §5, unpadded) of the UTF-8 JSON request, and **must**
  include an `origin` field.
- `redirect_uri` must be an absolute `https:` URL (`http:` is allowed only for `localhost`
  development) whose origin equals `req.origin`. On mismatch the wallet shows an error and never
  redirects.

After the user approves or rejects, the wallet navigates to:

```
<redirect_uri>#avianconnect=<base64url(JSON response)>
```

Any fragment already present on `redirect_uri` is replaced. The response is the same envelope as
in popup mode. The dApp reads it on load:

```js
const raw = new URLSearchParams(location.hash.slice(1)).get('avianconnect');
if (raw) {
  const res = JSON.parse(new TextDecoder().decode(
    Uint8Array.from(atob(raw.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)),
  ));
  history.replaceState(null, '', location.pathname + location.search); // scrub the fragment
}
```

Each navigation carries exactly one request. To connect and then sign, perform two round trips —
and the user must choose to **remember** the site on the connect screen, because a one-shot
approval authorises only the request it was given and cannot outlive the navigation. If they do
not, the `connect()` still returns an address, but the follow-up `signMessage()` arrives at a
wallet with no record of the site and fails with `ORIGIN_NOT_APPROVED`. The connect screen says so
when it is reached over this transport.

---

## 7. Permissions

The wallet stores one record per origin in its local preferences (IndexedDB):

```ts
{ origin: string, accounts: string[], grantedAt: number, lastUsedAt: number }
```

- `origin` is a normalised scheme + host + port, lowercased, with no trailing slash.
- `accounts` holds only the addresses the user chose to expose to that origin.
- Records exist only for origins the user chose to **remember**. A one-shot approval authorises a
  single request and is not persisted.
- The user can review and revoke every record in **Settings → Connected Sites**. Revoking emits
  `accountsChanged` with an empty array (popup transport) and forces the next `connect()` to prompt
  again.

Permissions are per-origin, not per-wallet: switching the active wallet does not grant a site
access to the newly active wallet. The exposed accounts stay exactly as the user set them, and the
site is told via `accountsChanged`.

---

### Changing which wallet a site uses

A grant pins one account, and `connect` returns it without prompting for as long as the site is
remembered — that is what "remember this site" buys. But a user with several wallets will sometimes
be asked to sign with the wrong one, and revoking the site just to switch is a poor answer.

Every approval screen therefore offers **Use a different wallet** when more than one exists. Taking
it hides the approval, shows the account picker, moves the grant to the chosen account, emits
`accountsChanged`, and only then **rejects the pending request** with `USER_REJECTED`. The site
should re-read the account and ask again.

`ACCOUNT_CHANGED` exists so this does not read as a decline. A dApp that treats every error as a
refusal will tell the user "you declined the request" when they did the opposite, and stop. The
right handling is to read the new account (from the `accountsChanged` event or `getAccounts`),
rebuild the request against it, and send it again — for a login that means a fresh message naming
the new wallet, since the old one names the old.

That order matters: answering a request ends the wallet session — the redirect transport navigates
back to the dApp, and a popup is usually closed by the dApp as soon as it has a response — so a
rejection sent before the picker would take the picker down with it. Dismissing the picker without
choosing puts the original approval back, unanswered.

The request is rejected rather than quietly re-pointed at the new wallet: the site asked a specific
account to sign, and a signature from a different one would fail whatever check it does against the
address `connect` handed it. A dApp that handles `accountsChanged` and retries will see this as a
normal account switch.

## 8. Versioning

`avianConnect: 1` is the phase-1 wire version. Additive changes (new methods, new optional result
fields, new event types) keep version `1`; a dApp must ignore unknown fields and unknown event
names. A breaking change would bump the number, and the wallet would then accept both for a
transition period.
