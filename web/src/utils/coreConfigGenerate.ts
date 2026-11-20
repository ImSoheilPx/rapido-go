// Secrets the Core Config forms can fill in, so an admin never has to reach for
// a terminal to add an inbound. Everything comes from the browser's CSPRNG.

const randomBytes = (length: number): Uint8Array => crypto.getRandomValues(new Uint8Array(length));

const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

const base64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

const base64Url = (bytes: Uint8Array) => base64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export const generatePassword = (): string => base64Url(randomBytes(18));

/** 16 bytes as hex: comfortably inside Snell's 12-255 byte range. */
export const generateSnellPsk = (): string => hex(randomBytes(16));

/** 8 bytes as hex, the longest short ID Reality takes. */
export const generateShortId = (): string => hex(randomBytes(8));

/** A shadowsocks-2022 key: standard base64 of exactly the bytes the method wants. */
export const generateSs2022Key = (bytes: number): string => base64(randomBytes(bytes));

/** Reality's X25519 key pair, in the unpadded base64url form sing-box reads. Null where the
 * browser has no X25519 or no secure context, which the form reports instead of guessing. */
/** WireGuard's X25519 key pair, standard base64 of 32 bytes each - the exact
 * shape `wg genkey`/`wg pubkey` produce and this panel's Go side mints. Null
 * where the browser has no X25519 (same fallback as Reality's generator). */
export const generateWgKeyPair = async (): Promise<{ privateKey: string; publicKey: string } | null> => {
  try {
    const pair = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    return { privateKey: base64(pkcs8.slice(-32)), publicKey: base64(raw) };
  } catch {
    return null;
  }
};

export const generateRealityKeyPair = async (): Promise<{ privateKey: string; publicKey: string } | null> => {
  try {
    const pair = (await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"])) as CryptoKeyPair;
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    return { privateKey: base64Url(pkcs8.slice(-32)), publicKey: base64Url(raw) };
  } catch {
    return null;
  }
};
