# Local changes to mtg

Based on github.com/9seconds/mtg/v2 v2.3.0. The upstream license and source
notices stay in place.

- `mtglib/dispatch.go` (NEW FILE, the only change): exposes the internal
  FakeTLS secret-match as a multi-secret dispatch so one TCP listener can
  serve several per-user secrets - the panel's MTProto inbound model (one
  inbound = one port = N users, each user one 16-byte secret).

  Upstream `mtglib.Proxy` is single-secret by construction (`ProxyOpts.Secret`
  is one `Secret`), and the FakeTLS reader lives under `mtglib/internal/...`
  so an importer cannot reuse it. The patch adds two exported names:

  - `TryDispatch(conn essentials.Conn, secrets map[string]Secret, skew time.Duration) (DispatchResult, bool)` -
    reads the ClientHello frames from the wire ONCE, replays them to
    `fake.ReadClientHello` once per candidate key (record framing, HMAC
    digest, SNI list and timestamp skew all checked per candidate, exactly
    as `Proxy.doFakeTLSHandshake` does for its single secret), and returns
    the matching user together with a conn that first replays the buffered
    hello bytes then reads the live socket - the multi-candidate equivalent
    of upstream's `connRewind.Rewind()`, replayable any number of times
    because the prefix is an independent reader rather than a drained
    buffer. `ok=false` means no secret matched: caller closes.
  - `DispatchResult{User string; Conn essentials.Conn; ClientHello *fake.ClientHello}`.

  Frame reassembly (`readClientHelloFrames`) mirrors upstream's
  `fragmentedHandshakeReader` record for record (handshake records only,
  version 3,1, same fragment cap), with two hardening deltas: a zero-length
  or >MaxRecordSize record is rejected (upstream would io.CopyN it), and
  reading stops the moment the reassembled stream covers the full handshake
  message, so bytes after the hello stay on the wire. This file is why the
  fork exists: without it, a multi-user listener would have to guess the
  user from the obfuscated2 frame, which is encrypted under a key derived
  FROM the secret - without the secret you cannot even find the DC.

The matched per-user `*mtglib.Proxy` (one per user, sharing one Network, one
AntiReplayCache and one event stream) then runs its own unmodified
`ServeConn(rewoundConn)`. Everything else in this tree is upstream v2.3.0
verbatim.

Compare this change against upstream when upgrading the module. This module
is selected by the root go.mod replace directive.
