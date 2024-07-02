import { assertEquals } from "jsr:@std/assert";


import { AESCBC } from "../src/aes.ts";
import { HMAC } from "../src/hmac.ts";
import { RSAOAEP, RSAPSS, RSASSA_PKCS_1v1$5 } from "../src/rsa.ts";
const encoder = new TextEncoder(), decoder = new TextDecoder();
Deno.test("crypto", async (t) => {
  await t.step("AES", async (t) => {
    await t.step("AESCBC", async (t) => {
      const key = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(16));
      const aes = new AESCBC(key);

      await t.step("encrypt", async () => {
        const plaintext = encoder.encode("hello world");
        await aes.encrypt(plaintext, iv);
      });
      await t.step("decrypt", async () => {
        const ciphertext = await aes.encrypt(
          encoder.encode("hello world"),
          iv,
        );
        assertEquals(
          decoder.decode(await aes.decrypt(ciphertext, iv)),
          "hello world",
        );
      });
    });
  });

  await t.step("RSA", async (t) => {
    await t.step("RSAOAEP", async (t) => {
      const rsa = new RSAOAEP();
      await t.step("encrypt", async () => {
        const plaintext = encoder.encode("hello world");
        await rsa.encrypt(plaintext);
      });
      await t.step("decrypt", async () => {
        const ciphertext = await rsa.encrypt(
          encoder.encode("hello world"),
        );
        assertEquals(
          decoder.decode(await rsa.decrypt(ciphertext)),
          "hello world",
        );
      });
    });
    await t.step("RSASSA", async (t) => {
      const rsa = new RSAPSS();
      await t.step("sign", async () => {
        const plaintext = encoder.encode("hello world");
        await rsa.sign(plaintext);
      });
      await t.step("verify", async () => {
        const signature = await rsa.sign(
          encoder.encode("hello world"),
        );
        assertEquals(
          await rsa.verify(signature, encoder.encode("hello world")),
          true,
        );
      });
    });
  });
  await t.step("HMAC", async (t) => {
    const hmac = new HMAC(crypto.getRandomValues(new Uint8Array(16)));
    await t.step("GenerateKey", async () => {
      await HMAC.GenerateKey();
    });
    await t.step("parseKey", async () => {
      const key = crypto.getRandomValues(new Uint8Array(16));
      await HMAC.parseKey(key);
    });
    await t.step("exportKey", async () => {
      await hmac.exportKey(await HMAC.GenerateKey());
    });
    await t.step("import key sign", async () => {
      const plaintext = encoder.encode("hello world");
      await hmac.sign(plaintext);
    });
    await t.step("import key verify", async () => {
      const plaintext = encoder.encode("hello world");
      const sign = await hmac.sign(plaintext);
      assertEquals(await hmac.verify(sign, plaintext), true);
    });
    await t.step("GenerateKey sign", async () => {
      const key = await HMAC.GenerateKey();
      await HMAC.sign(key, encoder.encode("hello world"));
    });
    await t.step("GenerateKey verify", async () => {
      const key = await HMAC.GenerateKey();
      const sign = await HMAC.sign(key, encoder.encode("hello world"));
      assertEquals(
        await HMAC.verify(key, sign, encoder.encode("hello world")),
        true,
      );
    });
  });
  await t.step("rs256", async (t) => {
    const rsa = new RSASSA_PKCS_1v1$5();
    await t.step("GenerateKey", async () => {
      await RSASSA_PKCS_1v1$5.GenerateKey();
    });
    await t.step("parseKey", async () => {
      const publicKey = await rsa.exportPublicKey();
      await RSASSA_PKCS_1v1$5.parsePublickKey(publicKey);
    });
    await t.step("exportKey", async () => {
      await rsa.exportPublicKey();
    });
    await t.step("generate key sign", async () => {
      const plaintext = encoder.encode("hello world");
      await rsa.sign(plaintext);
    });
    await t.step("generate key verify", async () => {
      const plaintext = encoder.encode("hello world");
      const sign = await rsa.sign(plaintext);
      assertEquals(await rsa.verify(sign, plaintext), true);
    });
    await t.step("parse public key verify", async () => {
      const plaintext = encoder.encode("hello world");
      const sign = await rsa.sign(plaintext);
      const publicKey = await rsa.exportPublicKey();
      RSASSA_PKCS_1v1$5.verify(
        await RSASSA_PKCS_1v1$5.parsePublickKey(publicKey),
        sign,
        plaintext,
      );
    });
  });
});
