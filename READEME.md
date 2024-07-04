# web端和deno的原生加解密工具

## AESCBC

对称密钥算法.用于加解密,解析arraybuffer为密钥对象

## HMAC

对称密钥签名和验证,解析密钥为密钥对象,导出密钥为arraybuffer

## RSAOAEP

非对称密钥算法,用于加解密数据,解析arraybuffer公钥为密钥对象,导出公钥为arraybuffer,生成密钥对

## RSAPASS

非对称密钥算法,用于签名和验证,解析arraybuffer公钥为密钥对象,导出公钥为arraybuffer,生成密钥对

## RSAOAEP-PKCS1-v1_5

非对称密钥算法,用于验证和签名,解析arraybuffer公钥为密钥对象,导出公钥为arraybuffer,生成密钥对
