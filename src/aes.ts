/**
 * @description aes cbc hash-128
 */
export class AESCBC {
  #key?: ArrayBuffer | Uint8Array;
  #cryptoKey?: CryptoKey;
  constructor(key: ArrayBuffer | Uint8Array | CryptoKey) {
    if (key instanceof CryptoKey) {
      this.#cryptoKey = key;
    } else {
      this.#key = key;
    }
  }
  static parseKey(serverKey: ArrayBuffer):Promise<CryptoKey> {
    return crypto.subtle.importKey(
      "raw",
      serverKey,
      { name: "AES-CBC", length: 128 },
      true,
      ["encrypt", "decrypt"],
    );
  }
  private async initCryptoKey(force = false) {
    if (this.#cryptoKey && !force) {
      return;
    }
    this.#cryptoKey = await crypto.subtle.importKey(
      "raw",
      this.#key!,
      { name: "AES-CBC", length: 128 },
      true,
      ["encrypt", "decrypt"],
    );
  }
  async encrypt(
    plaintext: ArrayBuffer | Uint8Array,
    iv: ArrayBuffer | Uint8Array,
  ):Promise<ArrayBuffer> {
    if (!this.#cryptoKey) {
      await this.initCryptoKey();
    }
    return crypto.subtle.encrypt(
      { name: "AES-CBC", iv },
      this.#cryptoKey!,
      plaintext,
    );
  }

  async decrypt(
    ciphertext: ArrayBuffer | Uint8Array,
    iv: ArrayBuffer | Uint8Array,
  ):Promise<ArrayBuffer> {
    if (!this.#cryptoKey) {
      await this.initCryptoKey();
    }
    return crypto.subtle.decrypt(
      { name: "AES-CBC", iv },
      this.#cryptoKey!,
      ciphertext,
    );
  }
}
