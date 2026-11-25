(() => {
  const SRP_MODULUS_FINGERPRINT = "248097092b458509c508dac0350585c4e9518f26";
  const SRP_MODULUS_KEY = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEXAHLgxYJKwYBBAHaRw8BAQdAFurWXXwjTemqjD7CXjXVyKf0of7n9Ctm
L8v9enkzggHNEnByb3RvbkBzcnAubW9kdWx1c8J3BBAWCgApBQJcAcuDBgsJ
BwgDAgkQNQWFxOlRjyYEFQgKAgMWAgECGQECGwMCHgEAAPGRAP9sauJsW12U
MnTQUZpsbJb53d0Wv55mZIIiJL2XulpWPQD/V6NglBd96lZKBmInSXX/kXat
Sv+y0io+LR8i2+jV+AbOOARcAcuDEgorBgEEAZdVAQUBAQdAeJHUz1c9+KfE
kSIgcBRE3WuXC4oj5a2/U3oASExGDW4DAQgHwmEEGBYIABMFAlwBy4MJEDUF
hcTpUY8mAhsMAAD/XQD8DxNI6E78meodQI+wLsrKLeHn32iLvUqJbVDhfWSU
WO4BAMcm1u02t4VKw++ttECPt+HUgPUq5pqQWe5Q2cW4TMsE
=Y4Mw
-----END PGP PUBLIC KEY BLOCK-----`;
  const WIDTH = 256;
  const encoder = new TextEncoder();

  function concatBytes(...parts) {
    const length = parts.reduce((sum, part) => sum + part.length, 0);
    const result = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
      result.set(part, offset);
      offset += part.length;
    }
    return result;
  }

  function bytesToBase64(bytes) {
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(offset, Math.min(offset + 0x8000, bytes.length)));
    }
    return btoa(binary);
  }

  function base64ToBytes(value) {
    const binary = atob(String(value || ""));
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes;
  }

  function bigintFromLittleEndian(bytes) {
    let hex = "";
    for (let index = bytes.length - 1; index >= 0; index -= 1) {
      hex += bytes[index].toString(16).padStart(2, "0");
    }
    return BigInt(`0x${hex || "0"}`);
  }

  function bigintToLittleEndian(value, length = WIDTH) {
    if (value < 0n) throw new Error("SRP tạo ra một giá trị số không hợp lệ.");
    const bytes = new Uint8Array(length);
    let rest = value;
    for (let index = 0; index < length; index += 1) {
      bytes[index] = Number(rest & 255n);
      rest >>= 8n;
    }
    if (rest !== 0n) throw new Error("SRP tạo ra một giá trị vượt quá kích thước cho phép.");
    return bytes;
  }

  function modulo(value, modulus) {
    const remainder = value % modulus;
    return remainder < 0n ? remainder + modulus : remainder;
  }

  function modPow(base, exponent, modulus) {
    let result = 1n;
    let factor = modulo(base, modulus);
    let power = exponent;
    while (power > 0n) {
      if (power & 1n) result = (result * factor) % modulus;
      factor = (factor * factor) % modulus;
      power >>= 1n;
    }
    return result;
  }

  async function pmHash(bytes) {
    const output = new Uint8Array(256);
    for (let index = 0; index < 4; index += 1) {
      const input = concatBytes(bytes, Uint8Array.of(index));
      output.set(new Uint8Array(await crypto.subtle.digest("SHA-512", input)), index * 64);
    }
    return output;
  }

  function bcryptSalt(bytes) {
    const alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    return bytesToBase64(bytes)
      .slice(0, 22)
      .replace(/[A-Za-z0-9+/]/g, (character) => alphabet["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(character)]);
  }

  async function verifyAndReadModulus(armored) {
    const openpgp = globalThis.openpgp;
    if (!openpgp?.readKey || !openpgp?.readCleartextMessage || !openpgp?.verify) {
      throw new Error("Thư viện xác minh khóa Proton chưa được nạp.");
    }
    const publicKey = await openpgp.readKey({ armoredKey: SRP_MODULUS_KEY });
    if (publicKey.getFingerprint().toLowerCase() !== SRP_MODULUS_FINGERPRINT) {
      throw new Error("Khóa xác minh SRP Proton không khớp.");
    }
    const message = await openpgp.readCleartextMessage({ cleartextMessage: String(armored || "") });
    const verified = await openpgp.verify({ message, verificationKeys: publicKey });
    if (!verified.signatures.length) throw new Error("Proton không ký modulus SRP.");
    await Promise.all(verified.signatures.map((signature) => signature.verified));
    const modulusBytes = base64ToBytes(String(verified.data).trim());
    if (modulusBytes.length !== WIDTH) throw new Error("Kích thước modulus SRP Proton không hợp lệ.");
    const modulus = bigintFromLittleEndian(modulusBytes);
    if (modulus.toString(2).length !== WIDTH * 8 || (modulus & 1n) !== 1n) {
      throw new Error("Modulus SRP Proton không hợp lệ.");
    }
    return { bytes: modulusBytes, value: modulus };
  }

  async function createProof(info, username, password) {
    if (!username || !password) throw new Error("Vui lòng nhập username và mật khẩu Proton.");
    if (!globalThis.bcrypt?.hashSync) throw new Error("Thư viện SRP bcrypt chưa được nạp.");
    const version = Number(info?.Version);
    if (version !== 3 && version !== 4) {
      throw new Error("Tài khoản đang dùng phiên bản xác thực Proton cũ. Hãy đăng nhập Proton trên web rồi thử lại.");
    }

    const modulus = await verifyAndReadModulus(info.Modulus);
    const serverEphemeralBytes = base64ToBytes(info.ServerEphemeral);
    const salt = base64ToBytes(info.Salt);
    if (serverEphemeralBytes.length !== WIDTH || !salt.length) {
      throw new Error("Proton trả về dữ liệu thử thách SRP không hợp lệ.");
    }

    const N = modulus.value;
    const g = 2n;
    const serverEphemeral = bigintFromLittleEndian(serverEphemeralBytes);
    if (serverEphemeral % N === 0n) throw new Error("Thử thách SRP từ Proton không hợp lệ.");

    const random = crypto.getRandomValues(new Uint8Array(32));
    random[31] |= 0x80;
    const a = bigintFromLittleEndian(random);
    const A = modPow(g, a, N);
    const ABytes = bigintToLittleEndian(A);
    const gBytes = bigintToLittleEndian(g);
    const k = bigintFromLittleEndian(await pmHash(concatBytes(gBytes, modulus.bytes)));
    const u = bigintFromLittleEndian(await pmHash(concatBytes(ABytes, serverEphemeralBytes)));
    if (u === 0n) throw new Error("Thử thách SRP từ Proton không hợp lệ.");

    const extendedSalt = concatBytes(salt, encoder.encode("proton")).subarray(0, 16);
    // Proton hashes with the $2y$ marker and then feeds the complete bcrypt
    // string into PMHash. The marker is part of that input, so $2b$ yields a
    // different SRP verifier even though both variants use bcrypt.
    const bcryptHash = globalThis.bcrypt.hashSync(password, `$2y$10$${bcryptSalt(extendedSalt)}`);
    const passwordKey = bigintFromLittleEndian(await pmHash(concatBytes(encoder.encode(bcryptHash), modulus.bytes)));
    const verifier = modPow(g, passwordKey, N);
    const base = modulo(serverEphemeral - k * verifier, N);
    const sharedSecret = modPow(base, a + u * passwordKey, N);
    const sharedKey = bigintToLittleEndian(sharedSecret);
    const clientProof = await pmHash(concatBytes(ABytes, serverEphemeralBytes, sharedKey));
    const expectedServerProof = await pmHash(concatBytes(ABytes, clientProof, sharedKey));

    return {
      ClientEphemeral: bytesToBase64(ABytes),
      ClientProof: bytesToBase64(clientProof),
      expectedServerProof,
    };
  }

  function verifyServerProof(expected, actualBase64) {
    const actual = base64ToBytes(actualBase64);
    if (expected.length !== actual.length) return false;
    let difference = 0;
    for (let index = 0; index < expected.length; index += 1) difference |= expected[index] ^ actual[index];
    return difference === 0;
  }

  globalThis.FreetonProtonSRP = { createProof, verifyServerProof };
})();
