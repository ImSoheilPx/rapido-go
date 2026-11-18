-- +goose Up
-- SSHVPN as a real inbound protocol - an SSH server (golang.org/x/crypto/ssh,
-- already a dependency for the panel's own node SSH management) whose
-- authenticated "direct-tcpip" channels are proxied like any other inbound,
-- with UDP carried over the same SSH session (see internal/nodecore/sshvpn's
-- own doc comment for the wire protocol). Unlike every other fork in
-- internal/nodecore this one is NOT a copy of a sing-box inbound - sing-box
-- itself has no SSH server at all, only an outbound - so this protocol gets
-- its own options struct (internal/nodecore/sshvpn/option.go) rather than a
-- sing-box option type, and its own provider registration.
--
-- Users authenticate with the panel-issued username + password pair already
-- carried by nodeConfigUserSpec.Name/Password - no new per-user columns.
-- Inbound-level settings: none beyond the shared listen port; host key is
-- generated per inbound at start (never persisted), so no new inbound-level
-- columns either. Only the protocol CHECK constraints change.
ALTER TABLE inbounds DROP CONSTRAINT inbounds_protocol_check;
ALTER TABLE inbounds ADD CONSTRAINT inbounds_protocol_check
    CHECK (protocol IN ('vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'snell', 'anytls', 'hysteria', 'naive', 'shadowtls', 'sshvpn'));

ALTER TABLE proxies DROP CONSTRAINT proxies_type_check;
ALTER TABLE proxies ADD CONSTRAINT proxies_type_check
    CHECK (type IN ('vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'snell', 'anytls', 'hysteria', 'naive', 'shadowtls', 'sshvpn'));

-- +goose Down
ALTER TABLE proxies DROP CONSTRAINT proxies_type_check;
ALTER TABLE proxies ADD CONSTRAINT proxies_type_check
    CHECK (type IN ('vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'snell', 'anytls', 'hysteria', 'naive', 'shadowtls'));

ALTER TABLE inbounds DROP CONSTRAINT inbounds_protocol_check;
ALTER TABLE inbounds ADD CONSTRAINT inbounds_protocol_check
    CHECK (protocol IN ('vmess', 'vless', 'trojan', 'shadowsocks', 'hysteria2', 'tuic', 'snell', 'anytls', 'hysteria', 'naive', 'shadowtls'));
