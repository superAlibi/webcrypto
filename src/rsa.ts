/**
 * RSA-OAEP sha-256
 * modulusLength 2048
 */
export class RSAOAEP {
  #cryptoKeyPair?: CryptoKeyPair;
  /**
   * 解析私钥
   * @param privateKey
   * @returns
   */
  static parsePrivateKey(privateKey: ArrayBuffer | Uint8Array) {
    return crypto.subtle.importKey(
      "pkcs8",
      privateKey,
      {
        name: "RSA-OAEP",
        hash: `SHA-256`,
      },
      false,
      ["sign"],
    );
  }
  static parsePublicKey(key: ArrayBuffer) {
    return crypto.subtle.importKey(
      "spki",
      key,
      {
        name: "RSA-OAEP",
        hash: {
          name: "SHA-256",
        },
      },
      true,
      ["encrypt"],
    );
  }
  static GenerateKeyPair() {
    return crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: {
          name: "SHA-256",
        },
      },
      true,
      ["encrypt", "decrypt"],
    );
  }
  private async initCryptKey(force = false) {
    if (this.#cryptoKeyPair && !force) return;
    return this.#cryptoKeyPair = await RSAOAEP.GenerateKeyPair();
  }
  async exportPublicKey() {
    await this.initCryptKey();

    return crypto.subtle.exportKey(
      "spki",
      this.#cryptoKeyPair!.publicKey,
    ) as Promise<ArrayBuffer>;
  }
  async publicKey() {
    await this.initCryptKey();

    return this.#cryptoKeyPair!.publicKey;
  }

  static async encrypt(
    publickKey: ArrayBuffer | Uint8Array | CryptoKey,
    data: ArrayBuffer,
  ) {
    if ((publickKey instanceof ArrayBuffer)) {
      publickKey = await RSAOAEP.parsePublicKey(publickKey);
    }
    return crypto.subtle.encrypt(
      {
        name: "RSA-OAEP",
      },
      publickKey as CryptoKey,
      data,
    );
  }
  async encrypt(data: ArrayBuffer) {
    await this.initCryptKey();

    return RSAOAEP.encrypt(this.#cryptoKeyPair!.publicKey, data);
  }
  static decrypt(privateKey: CryptoKey, data: ArrayBuffer) {
    return crypto.subtle.decrypt(
      {
        name: "RSA-OAEP",
      },
      privateKey,
      data,
    );
  }
  async decrypt(data: ArrayBuffer) {
    if (!this.#cryptoKeyPair) {
      await this.initCryptKey();
    }
    return RSAOAEP.decrypt(this.#cryptoKeyPair!.privateKey, data);
  }
}
/**
 * RSA-PSS sha-256
 * modulusLength: 2048
 * 用于签名和验证签名
 */
export class RSAPSS {
  #cryptoKeyPair?: CryptoKeyPair;
  static GenerateKey() {
    return crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        hash: {
          name: "SHA-256",
        },
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      },
      true,
      ["sign", "verify"],
    );
  }
  /**
   * 解析公钥
   */
  static parsePublickKey(publicKey: ArrayBuffer | Uint8Array) {
    return crypto.subtle.importKey(
      "spki",
      publicKey,
      {
        name: "RSA-PSS",
        hash: `SHA-256`,
      },
      false,
      ["verify"],
    );
  }
  private async initCryptoPair(force = false) {
    if (this.#cryptoKeyPair && !force) return;
    return this.#cryptoKeyPair = await RSAPSS.GenerateKey();
  }
  static async sign(privateKey: CryptoKey, data: ArrayBuffer) {
    const signature = await crypto.subtle.sign(
      {
        name: "RSA-PSS",
        saltLength: 32, // 根据PSS标准设置盐长度
      },
      privateKey as CryptoKey, // 私钥
      data,
    );
    return signature;
  }
  async sign(data: ArrayBuffer) {
    await this.initCryptoPair();

    return RSAPSS.sign(this.#cryptoKeyPair!.privateKey, data);
  }
  static async verify(
    publicKey: CryptoKey | ArrayBuffer | Uint8Array,
    signature: ArrayBuffer,
    data: ArrayBuffer,
  ) {
    if (publicKey instanceof ArrayBuffer) {
      publicKey = await RSAPSS.parsePublickKey(publicKey);
    }
    const isValid = await crypto.subtle.verify(
      {
        name: "RSA-PSS",
        saltLength: 32, // 根据PSS标准设置盐长度
      },
      publicKey as CryptoKey, // 私钥
      signature,
      data,
    );
    return isValid;
  }
  async verify(signature: ArrayBuffer, data: ArrayBuffer) {
    await this.initCryptoPair();

    return RSAPSS.verify(this.#cryptoKeyPair!.publicKey, signature, data);
  }
}
/**
 * RSASSA-PKCS1-v1_5
 * modulusLength: 2048
 * hash: SHA-256
 * 用于签名和验证签名
 * @alias RS256
 */
export class RSASSA_PKCS_1v1$5 {
  #cryptoKeyPair?: CryptoKeyPair;
  async exportPublicKey() {
    await this.initCryptoPair();
    return crypto.subtle.exportKey(
      "spki",
      this.#cryptoKeyPair!.publicKey,
    );
  }
  static GenerateKey() {
    return crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: {
          name: "SHA-256",
        },
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      },
      true,
      ["sign", "verify"],
    );
  }
  static parsePublickKey(publicKey: ArrayBuffer | Uint8Array) {
    return crypto.subtle.importKey(
      "spki",
      publicKey,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: `SHA-256`,
      },
      false,
      ["verify"],
    );
  }
  private async initCryptoPair(force = false) {
    if (this.#cryptoKeyPair && !force) return;
    return this.#cryptoKeyPair = await RSASSA_PKCS_1v1$5.GenerateKey();
  }
  static sign(privateKey: CryptoKey, data: ArrayBuffer) {
    return crypto.subtle.sign(
      {
        name: "RSASSA-PKCS1-v1_5",
      },
      privateKey,
      data,
    );
  }
  static verify(
    publicKey: CryptoKey,
    signature: ArrayBuffer,
    data: ArrayBuffer,
  ) {
    return crypto.subtle.verify(
      {
        name: "RSASSA-PKCS1-v1_5",
      },
      publicKey,
      signature,
      data,
    );
  }
  async sign(data: ArrayBuffer) {
    await this.initCryptoPair();

    return RSASSA_PKCS_1v1$5.sign(this.#cryptoKeyPair!.privateKey, data);
  }
  async verify(signature: ArrayBuffer, data: ArrayBuffer) {
    await this.initCryptoPair();
    return RSASSA_PKCS_1v1$5.verify(
      this.#cryptoKeyPair!.publicKey,
      signature,
      data,
    );
  }
}
