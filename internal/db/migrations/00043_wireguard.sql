-- +goose Up
-- WireGuard as a real inbound protocol - fully userspace (wireguard-go over
-- a gVisor stack, see internal/nodecore/wg and its transport fork): no
-- kernel module, no tun device, no NET_ADMIN, so a node in an unprivileged
-- container serves it exactly like a host install. Per-user credential is
-- a Curve25519 keypair in proxies.settings (proxysettings.WireguardSettings,
-- shared with amnezia when that slice lands); the tunnel IP is DERIVED per
-- inbound from the user's numeric id (never stored - two wireguard
-- inbounds with different subnets share the same key material). The three
-- inbound-level columns here are NULL for every non-wireguard row, same
-- convention as snell_psk:
--   wg_server_private_key: the endpoint's own key, base64 std; the public
--     key is DERIVED on read (never stored) and exposed on the DTO/links.
--     Rotating it invalidates every client conf (vpn-ui behavior too).
--   wg_subnet: the per-inbound tunnel space users get /32s from; NULL
--     means the Go default 10.7.0.0/24.
--   wg_mtu: NULL = node default 1408 (sing-box's own userspace-stack
--     default; 1420 costs gVisor header room).
ALTER TABLE inbounds DROP CONSTRAINT inbounds_protocol_check;
ALTER TABLE inbounds ADD CONSTRAINT inbounds_protocol_check
    CHECK (protocol IN ('vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'snell', 'anytls', 'hysteria', 'naive', 'shadowtls', 'sshvpn', 'mtproto', 'wireguard'));

ALTER TABLE proxies DROP CONSTRAINT proxies_type_check;
ALTER TABLE proxies ADD CONSTRAINT proxies_type_check
    CHECK (type IN ('vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'snell', 'anytls', 'hysteria', 'naive', 'shadowtls', 'sshvpn', 'mtproto', 'wireguard'));

ALTER TABLE inbounds ADD COLUMN wg_server_private_key TEXT;
ALTER TABLE inbounds ADD COLUMN wg_subnet TEXT;
ALTER TABLE inbounds ADD COLUMN wg_mtu INTEGER
    CHECK (wg_mtu IS NULL OR (wg_mtu >= 1200 AND wg_mtu <= 1500));

-- +goose Down
ALTER TABLE inbounds DROP COLUMN wg_mtu;
ALTER TABLE inbounds DROP COLUMN wg_subnet;
ALTER TABLE inbounds DROP COLUMN wg_server_private_key;
ALTER TABLE proxies DROP CONSTRAINT proxies_type_check;
ALTER TABLE proxies ADD CONSTRAINT proxies_type_check
    CHECK (type IN ('vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'snell', 'anytls', 'hysteria', 'naive', 'shadowtls', 'sshvpn', 'mtproto'));
ALTER TABLE inbounds DROP CONSTRAINT inbounds_protocol_check;
ALTER TABLE inbounds ADD CONSTRAINT inbounds_protocol_check
    CHECK (protocol IN ('vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'snell', 'anytls', 'hysteria', 'naive', 'shadowtls', 'sshvpn', 'mtproto'));
