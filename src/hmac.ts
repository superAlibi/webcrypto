/**
 * hmac hash-256 算法
 * HS256
 */
export class HMAC {
  #cryptoKey?: CryptoKey;
  #key?: ArrayBuffer;
  constructor(key: ArrayBuffer | Uint8Array | CryptoKey) {
    if (key instanceof CryptoKey) {
      this.#cryptoKey = key;
    } else {
      this.#key = key;
    }
  }
  private async initCryptoKey(force = false) {
    if (this.#cryptoKey && !force) {
      return;
    }
    if (!this.#key) {
      throw new Error("意外的初始化:无密钥");
    }
    this.#cryptoKey = await crypto.subtle.importKey(
      "raw",
      this.#key,
      { name: "HMAC", hash: { name: "SHA-256" } },
      true,
      ["sign", "verify"],
    );
  }
  public exportKey(key: CryptoKey):Promise<ArrayBuffer> {
    return crypto.subtle.exportKey("raw", key);
  }
  static async GenerateKey():Promise<CryptoKey> {
    const key = await crypto.subtle.generateKey(
      {
        name: "HMAC",
        hash: { name: "SHA-256" },
      },
      true,
      ["sign", "verify"],
    );
    return key;
  }
  static parseKey(serverKey: ArrayBuffer):Promise<CryptoKey> {
    return crypto.subtle.importKey(
      "raw",
      serverKey,
      {
        name: "HMAC",
        hash: { name: "SHA-256" },
      },
      false,
      ["sign", "verify"],
    );
  }
  static async sign(key: CryptoKey, data: ArrayBuffer):Promise<ArrayBuffer> {
    const signature = await crypto.subtle.sign(
      "HMAC",
      key, // 私钥
      data,
    );
    return signature;
  }
  public async sign(data: ArrayBuffer):Promise<ArrayBuffer> {
    await this.initCryptoKey();

    return HMAC.sign(this.#cryptoKey!, data);
  }
  static async verify(
    publicKey: CryptoKey | ArrayBuffer | Uint8Array,
    signature: ArrayBuffer,
    data: ArrayBuffer,
  ):Promise<boolean> {
    if (publicKey instanceof ArrayBuffer) {
      publicKey = await HMAC.parseKey(publicKey);
    }
    const isValid = await crypto.subtle.verify(
      "HMAC",
      publicKey as CryptoKey,
      signature,
      data,
    );
    return isValid;
  }
  public async verify(signature: ArrayBuffer, data: ArrayBuffer):Promise<boolean> {
    await this.initCryptoKey();
    return HMAC.verify(this.#cryptoKey!, signature, data);
  }
}
