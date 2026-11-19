-- +goose Up
-- MTProto proxy as a real inbound protocol - a FakeTLS-camouflaged MTProto
-- relay (vendored github.com/9seconds/mtg/v2, see third_party/mtg/PATCHES.md)
-- served entirely in-process like sshvpn: no daemon, no tunnel IPs, no UDP.
-- Per-user credential is a 16-byte secret in proxies.settings (hex, generated
-- by proxysettings); the only inbound-level setting is the FakeTLS SNI the
-- listener emulates, stored here (nullable - NULL means the Go default,
-- www.google.com, same convention as snell_v6_mode).
ALTER TABLE inbounds DROP CONSTRAINT inbounds_protocol_check;
ALTER TABLE inbounds ADD CONSTRAINT inbounds_protocol_check
    CHECK (protocol IN ('vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'snell', 'anytls', 'hysteria', 'naive', 'shadowtls', 'sshvpn', 'mtproto'));

ALTER TABLE proxies DROP CONSTRAINT proxies_type_check;
ALTER TABLE proxies ADD CONSTRAINT proxies_type_check
    CHECK (type IN ('vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'snell', 'anytls', 'hysteria', 'naive', 'shadowtls', 'sshvpn', 'mtproto'));

ALTER TABLE inbounds ADD COLUMN mtproto_tls_domain TEXT;

-- +goose Down
ALTER TABLE inbounds DROP COLUMN mtproto_tls_domain;
ALTER TABLE proxies DROP CONSTRAINT proxies_type_check;
ALTER TABLE proxies ADD CONSTRAINT proxies_type_check
    CHECK (type IN ('vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'snell', 'anytls', 'hysteria', 'naive', 'shadowtls', 'sshvpn'));
ALTER TABLE inbounds DROP CONSTRAINT inbounds_protocol_check;
ALTER TABLE inbounds ADD CONSTRAINT inbounds_protocol_check
    CHECK (protocol IN ('vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'snell', 'anytls', 'hysteria', 'naive', 'shadowtls', 'sshvpn'));
