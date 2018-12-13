# X.509 证书解析

## X.509 证书结构描述

X.509证书有多种常用的文件扩展名，代表着不同形式的数据编码以及内容

其中常见的有（来自Wikipedia）：

- `.pem` – ([隐私增强型电子邮件](https://zh.wikipedia.org/w/index.php?title=%E9%9A%90%E7%A7%81%E5%A2%9E%E5%BC%BA%E5%9E%8B%E7%94%B5%E5%AD%90%E9%82%AE%E4%BB%B6&action=edit&redlink=1)) [DER](https://zh.wikipedia.org/w/index.php?title=DER&action=edit&redlink=1)编码的证书再进行[Base64](https://zh.wikipedia.org/wiki/Base64)编码的数据存放在"-----BEGIN CERTIFICATE-----"和"-----END CERTIFICATE-----"之中
- `.cer`, `.crt`, `.der` – 通常是[DER](https://zh.wikipedia.org/w/index.php?title=DER&action=edit&redlink=1)二进制格式的，但Base64编码后也很常见。
- `.p7b`, `.p7c` – [PKCS#7](https://zh.wikipedia.org/wiki/%E5%85%AC%E9%92%A5%E5%AF%86%E7%A0%81%E5%AD%A6%E6%A0%87%E5%87%86) SignedData structure without data, just certificate(s) or [CRL](https://zh.wikipedia.org/wiki/%E8%AF%81%E4%B9%A6%E5%90%8A%E9%94%80%E5%88%97%E8%A1%A8)(s)
- `.p12` – [PKCS#12](https://zh.wikipedia.org/wiki/%E5%85%AC%E9%92%A5%E5%AF%86%E7%A0%81%E5%AD%A6%E6%A0%87%E5%87%86)格式，包含证书的同时可能还有带密码保护的私钥
- `.pfx` – PFX，PKCS#12之前的格式（通常用PKCS#12格式，比如那些由[IIS](https://zh.wikipedia.org/wiki/IIS)产生的PFX文件）

这里我主要解析的是`DER`二进制格式经过Base64编码后的数据

其中证书的组成结构标准用`ASN.1`来进行描述，有着不同的版本，其中`V3`版本的基本结构如下（Wikipedia）：

- 证书 
  - 版本号
  - 序列号
  - 签名算法
  - 颁发者
  - 证书有效期 
    - 此日期前无效
    - 此日期后无效
  - 主题
  - 主题公钥信息 
    - 公钥算法
    - 主题公钥
  - 颁发者唯一身份信息（可选项）
  - 主题唯一身份信息（可选项）
  - 扩展信息（可选项） 
    - ...
- 证书签名算法
- 数字签名

也可以表示为以下的形式(RFC 5280)：

```
Certificate  ::=  SEQUENCE  {
  tbsCertificate       TBSCertificate,
  signatureAlgorithm   AlgorithmIdentifier,
  signatureValue       BIT STRING  }

TBSCertificate  ::=  SEQUENCE  {
  version         [0]  EXPLICIT Version DEFAULT v1,
  serialNumber         CertificateSerialNumber,
  signature            AlgorithmIdentifier,
  issuer               Name,
  validity             Validity,
  subject              Name,
  subjectPublicKeyInfo SubjectPublicKeyInfo,
  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
												-- If present, version MUST be v2 or v3
	subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
												-- If present, version MUST be v2 or v3
	extensions      [3]  EXPLICIT Extensions OPTIONAL
												-- If present, version MUST be v3
}

Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }

CertificateSerialNumber  ::=  INTEGER

Validity ::= SEQUENCE {
  notBefore      Time,
  notAfter       Time }

Time ::= CHOICE {
  utcTime        UTCTime,
  generalTime    GeneralizedTime }

UniqueIdentifier  ::=  BIT STRING

SubjectPublicKeyInfo  ::=  SEQUENCE  {
  algorithm            AlgorithmIdentifier,
  subjectPublicKey     BIT STRING  }

Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension

Extension  ::=  SEQUENCE  {
  extnID      OBJECT IDENTIFIER,
  critical    BOOLEAN DEFAULT FALSE,
  extnValue   OCTET STRING
              -- contains the DER encoding of an ASN.1 value
              -- corresponding to the extension type identified
              -- by extnID
}
```







数据结构；

C 语言(可选其它命令式语言) 源代码；

编译运行输出结果。 