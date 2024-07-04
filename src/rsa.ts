/**
 * RSA-OAEP sha-256
 * modulusLength 2048
 */
export class RSAOAEP {
  #cryptoKeyPair?: CryptoKeyPair;
  /**
   * 解析公钥
   * @param key 公钥arraybuffer
   * @returns
   */
  static parsePublicKey(key: ArrayBuffer): Promise<CryptoKey> {
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
  /**
   * 生成共私钥对,但并不重写内部的密钥对
   * @returns
   */
  static GenerateKeyPair(): Promise<CryptoKeyPair> {
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
  /**
   * 初始化内部的密钥
   * @param force  是否强制更新内部的密钥
   * @returns
   */
  private async initCryptKey(force = false) {
    if (this.#cryptoKeyPair && !force) return;
    return this.#cryptoKeyPair = await RSAOAEP.GenerateKeyPair();
  }
  /**
   * 导出内部的密钥
   * @returns 导出格式为arraybuffer的公钥
   */
  public async exportPublicKey(): Promise<ArrayBuffer> {
    await this.initCryptKey();

    return crypto.subtle.exportKey(
      "spki",
      this.#cryptoKeyPair!.publicKey,
    );
  }
  /**
   * 给出原始的公钥对象
   * @returns
   */
  public async publicKey(): Promise<CryptoKey> {
    await this.initCryptKey();

    return this.#cryptoKeyPair!.publicKey;
  }
  /**
   * 加密功能
   * @param publickKey
   * @param plaintext
   * @returns
   */
  static async encrypt(
    publickKey: ArrayBuffer | Uint8Array | CryptoKey,
    plaintext: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    if ((publickKey instanceof ArrayBuffer)) {
      publickKey = await RSAOAEP.parsePublicKey(publickKey);
    }
    return crypto.subtle.encrypt(
      {
        name: "RSA-OAEP",
      },
      publickKey as CryptoKey,
      plaintext,
    );
  }
  /**
   * 实例化的加密功能
   * @param plaintext
   * @returns
   */
  public async encrypt(plaintext: ArrayBuffer): Promise<ArrayBuffer> {
    await this.initCryptKey();

    return RSAOAEP.encrypt(this.#cryptoKeyPair!.publicKey, plaintext);
  }
  /**
   * 解密功能
   * @param privateKey 私钥解密
   * @param data 原始数据buffer
   * @returns
   */
  static decrypt(
    privateKey: CryptoKey,
    ciphertext: ArrayBuffer,
  ): Promise<ArrayBuffer> {
    return crypto.subtle.decrypt(
      {
        name: "RSA-OAEP",
      },
      privateKey,
      ciphertext,
    );
  }
  /**
   * 实例化的解密方法
   * @param ciphertext
   * @returns
   */
  public async decrypt(ciphertext: ArrayBuffer): Promise<ArrayBuffer> {
    if (!this.#cryptoKeyPair) {
      await this.initCryptKey();
    }
    return RSAOAEP.decrypt(this.#cryptoKeyPair!.privateKey, ciphertext);
  }
}
/**
 * RSA-PSS sha-256
 * modulusLength: 2048
 * 用于签名和验证签名
 */
export class RSAPSS {
  #cryptoKeyPair?: CryptoKeyPair;
  static GenerateKey(): Promise<CryptoKeyPair> {
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
  public async exportPublicKey(): Promise<ArrayBuffer> {
    await this.initCryptoPair();

    return crypto.subtle.exportKey(
      "spki",
      this.#cryptoKeyPair!.publicKey,
    );
  }
  /**
   * 解析公钥
   */
  static parsePublickKey(
    publicKey: ArrayBuffer | Uint8Array,
  ): Promise<CryptoKey> {
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
  static async sign(
    privateKey: CryptoKey,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer> {
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
  public async sign(data: ArrayBuffer): Promise<ArrayBuffer> {
    await this.initCryptoPair();

    return RSAPSS.sign(this.#cryptoKeyPair!.privateKey, data);
  }
  static async verify(
    publicKey: CryptoKey | ArrayBuffer | Uint8Array,
    signature: ArrayBuffer,
    data: ArrayBuffer,
  ): Promise<boolean> {
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
  public async verify(
    signature: ArrayBuffer,
    data: ArrayBuffer,
  ): Promise<boolean> {
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
  public async exportPublicKey(): Promise<ArrayBuffer> {
    await this.initCryptoPair();
    return crypto.subtle.exportKey(
      "spki",
      this.#cryptoKeyPair!.publicKey,
    );
  }
  static GenerateKey(): Promise<CryptoKeyPair> {
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
  static parsePublickKey(
    publicKey: ArrayBuffer | Uint8Array,
  ): Promise<CryptoKey> {
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
  static sign(privateKey: CryptoKey, data: ArrayBuffer): Promise<ArrayBuffer> {
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
  ): Promise<boolean> {
    return crypto.subtle.verify(
      {
        name: "RSASSA-PKCS1-v1_5",
      },
      publicKey,
      signature,
      data,
    );
  }
  public async sign(data: ArrayBuffer): Promise<ArrayBuffer> {
    await this.initCryptoPair();

    return RSASSA_PKCS_1v1$5.sign(this.#cryptoKeyPair!.privateKey, data);
  }
  public async verify(
    signature: ArrayBuffer,
    data: ArrayBuffer,
  ): Promise<boolean> {
    await this.initCryptoPair();
    return RSASSA_PKCS_1v1$5.verify(
      this.#cryptoKeyPair!.publicKey,
      signature,
      data,
    );
  }
}
