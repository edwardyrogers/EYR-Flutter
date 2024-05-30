import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:asn1lib/asn1lib.dart';
import 'package:pointycastle/export.dart';

class CryptoService {
  AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> genRSAKeyPair(
    SecureRandom secureRandom, {
    int bitLength = 2048,
  }) {
    final keyGen = RSAKeyGenerator()
      ..init(
        ParametersWithRandom(
          RSAKeyGeneratorParameters(
            BigInt.parse('65537'),
            bitLength,
            64,
          ),
          secureRandom,
        ),
      );

    final pair = keyGen.generateKeyPair();

    final public = pair.publicKey as RSAPublicKey;
    final private = pair.privateKey as RSAPrivateKey;

    return AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey>(
      public,
      private,
    );
  }

  RSAPublicKey loadRSAPublicKey(String pubKey) {
    final bytes = base64.decode(pubKey);
    final asn1Parser = ASN1Parser(bytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    final publicKeyBitString = topLevelSeq.elements[1];

    final publicKeyAsn = ASN1Parser(publicKeyBitString.contentBytes());
    final publicKeySeq = publicKeyAsn.nextObject() as ASN1Sequence;
    final modulus = publicKeySeq.elements[0] as ASN1Integer;
    final exponent = publicKeySeq.elements[1] as ASN1Integer;

    final rsaPublicKey = RSAPublicKey(
      modulus.valueAsBigInteger,
      exponent.valueAsBigInteger,
    );

    return rsaPublicKey;
  }

  Uint8List doRSAEncryption(String data, PublicKey key) {
    final engine = PKCS1Encoding(RSAEngine())
      ..init(
        true,
        PublicKeyParameter<RSAPublicKey>(key),
      );

    return engine.process(utf8.encode(data));
  }

  SecureRandom simpleSecureRandom() {
    final random = Random.secure();
    final seed = List<int>.generate(32, (_) => random.nextInt(256));
    final secureRandom = SecureRandom('Fortuna')
      ..seed(
        KeyParameter(
          Uint8List.fromList(seed),
        ),
      );
    return secureRandom;
  }

  Uint8List sign(RSAPrivateKey privateKey, Uint8List dataToSign) {
    final signer = RSASigner(SHA256Digest(), '0609608648016503040201')
      ..init(
        true,
        PrivateKeyParameter<RSAPrivateKey>(privateKey),
      );

    final sig = signer.generateSignature(dataToSign);

    return sig.bytes;
  }

  bool verify(
    RSAPublicKey publicKey,
    Uint8List signedData,
    Uint8List signature,
  ) {
    //final signer = Signer('SHA-256/RSA'); // Get using registry
    final sig = RSASignature(signature);

    // initialize with false, which means verify
    final verifier = RSASigner(SHA256Digest(), '0609608648016503040201')
      ..init(
        false,
        PublicKeyParameter<RSAPublicKey>(publicKey),
      );

    return verifier.verifySignature(signedData, sig);
  }

  Uint8List decrypt(RSAPrivateKey privateKey, Uint8List cipherText) {
    final decryptor = OAEPEncoding(RSAEngine())
      ..init(
        false,
        PrivateKeyParameter<RSAPrivateKey>(privateKey),
      ); // false=decrypt

    return _processInBlocks(decryptor, cipherText);
  }

  Uint8List _processInBlocks(AsymmetricBlockCipher engine, Uint8List input) {
    final numBlocks = input.length ~/ engine.inputBlockSize +
        ((input.length % engine.inputBlockSize != 0) ? 1 : 0);

    final output = Uint8List(numBlocks * engine.outputBlockSize);

    var inputOffset = 0;
    var outputOffset = 0;
    while (inputOffset < input.length) {
      final chunkSize = (inputOffset + engine.inputBlockSize <= input.length)
          ? engine.inputBlockSize
          : input.length - inputOffset;

      outputOffset += engine.processBlock(
        input,
        inputOffset,
        chunkSize,
        output,
        outputOffset,
      );

      inputOffset += chunkSize;
    }

    return output.length == outputOffset
        ? output
        : output.sublist(0, outputOffset);
  }

  String encodePublicKeyToPem(RSAPublicKey publicKey) {
    final algorithmAsn1Obj = ASN1Object.fromBytes(
      Uint8List.fromList(
        [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1],
      ),
    );
    final paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));

    final algorithmSeq = ASN1Sequence()
      ..add(algorithmAsn1Obj)
      ..add(paramsAsn1Obj);

    final publicKeySeq = ASN1Sequence()
      ..add(ASN1Integer(publicKey.modulus!))
      ..add(ASN1Integer(publicKey.exponent!));

    final publicKeySeqBitString = ASN1BitString(
      Uint8List.fromList(publicKeySeq.encodedBytes),
    );

    final topLevelSeq = ASN1Sequence()
      ..add(algorithmSeq)
      ..add(publicKeySeqBitString);

    final dataBase64 = base64.encode(topLevelSeq.encodedBytes);

    return '''-----BEGIN PUBLIC KEY-----\r\n$dataBase64\r\n-----END PUBLIC KEY-----''';
  }

  String encodePrivateKeyToPem(RSAPrivateKey privateKey) {
    final version = ASN1Integer(BigInt.from(0));

    final algorithmAsn1Obj = ASN1Object.fromBytes(
      Uint8List.fromList(
        [0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1],
      ),
    );
    final paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));

    final algorithmSeq = ASN1Sequence()
      ..add(algorithmAsn1Obj)
      ..add(paramsAsn1Obj);

    final privateKeySeq = ASN1Sequence();
    final modulus = ASN1Integer(privateKey.n!);
    final publicExponent = ASN1Integer(BigInt.parse('65537'));
    final privateExponent = ASN1Integer(privateKey.privateExponent!);
    final p = ASN1Integer(privateKey.p!);
    final q = ASN1Integer(privateKey.q!);
    final dP = privateKey.privateExponent! % (privateKey.p! - BigInt.from(1));
    final exp1 = ASN1Integer(dP);
    final dQ = privateKey.privateExponent! % (privateKey.q! - BigInt.from(1));
    final exp2 = ASN1Integer(dQ);
    final iQ = privateKey.q!.modInverse(privateKey.p!);
    final co = ASN1Integer(iQ);

    privateKeySeq
      ..add(version)
      ..add(modulus)
      ..add(publicExponent)
      ..add(privateExponent)
      ..add(p)
      ..add(q)
      ..add(exp1)
      ..add(exp2)
      ..add(co);

    final publicKeySeqOctetString =
        ASN1OctetString(Uint8List.fromList(privateKeySeq.encodedBytes));

    final topLevelSeq = ASN1Sequence()
      ..add(version)
      ..add(algorithmSeq)
      ..add(publicKeySeqOctetString);

    final dataBase64 = base64.encode(topLevelSeq.encodedBytes);

    return '''-----BEGIN PRIVATE KEY-----\r\n$dataBase64\r\n-----END PRIVATE KEY-----''';
  }

  RSAPrivateKey parsePrivateKeyFromPem(Uint8List bytes) {
    // final privateKeyDER = decodePEM(pemString);
    var asn1Parser = ASN1Parser(bytes);
    final topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    final privateKey = topLevelSeq.elements[2];

    asn1Parser = ASN1Parser(privateKey.contentBytes());
    final pkSeq = asn1Parser.nextObject() as ASN1Sequence;

    final modulus = pkSeq.elements[1] as ASN1Integer;
    final privateExponent = pkSeq.elements[3] as ASN1Integer;
    final p = pkSeq.elements[4] as ASN1Integer;
    final q = pkSeq.elements[5] as ASN1Integer;

    final rsaPrivateKey = RSAPrivateKey(
      modulus.valueAsBigInteger,
      privateExponent.valueAsBigInteger,
      p.valueAsBigInteger,
      q.valueAsBigInteger,
    );

    return rsaPrivateKey;
  }

  Uint8List decodePEM(String pemToDecode) {
    var pem = pemToDecode;

    final startsWith = [
      '-----BEGIN PUBLIC KEY-----',
      '-----BEGIN PRIVATE KEY-----',
      '-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nVersion: React-Native-OpenPGP.js 0.1\r\nComment: http://openpgpjs.org\r\n\r\n',
      '-----BEGIN PGP PRIVATE KEY BLOCK-----\r\nVersion: React-Native-OpenPGP.js 0.1\r\nComment: http://openpgpjs.org\r\n\r\n',
    ];
    final endsWith = [
      '-----END PUBLIC KEY-----',
      '-----END PRIVATE KEY-----',
      '-----END PGP PUBLIC KEY BLOCK-----',
      '-----END PGP PRIVATE KEY BLOCK-----',
    ];
    final isOpenPgp = pem.contains('BEGIN PGP');

    for (final s in startsWith) {
      if (pem.startsWith(s)) {
        pem = pem.substring(s.length);
      }
    }

    for (final s in endsWith) {
      if (pem.endsWith(s)) {
        pem = pem.substring(0, pem.length - s.length);
      }
    }

    if (isOpenPgp) {
      final index = pem.indexOf('\r\n');
      pem = pem.substring(0, index);
    }

    pem = pem.replaceAll('\n', '');
    pem = pem.replaceAll('\r', '');

    return base64.decode(pem);
  }
}


// class CryptoService {
//   static EnvCubit get envCubit => GetIt.I<EnvCubit>();

//   static String encrypt(String text) {
//     final key = Key.fromBase64(envCubit.state.hsbcApiKY);
//     final iv = IV.fromBase64(envCubit.state.hsbcApiIV);
//     final encrypter = Encrypter(AES(key, mode: AESMode.cbc));
//     return encrypter.encrypt(text, iv: iv).base64;
//   }

//   static String encryptAsReq(String text) {
//     if (!envCubit.state.cryptoEnabled) return text;
//     final req = CryptoData(payload: encrypt(text));
//     return jsonEncode(req.toJson());
//   }

//   static String decrypt(String encryptedText) {
//     final key = Key.fromBase64(envCubit.state.hsbcApiKY);
//     final iv = IV.fromBase64(envCubit.state.hsbcApiIV);
//     final decrypt = Encrypter(AES(key, mode: AESMode.cbc));
//     return decrypt.decrypt64(encryptedText, iv: iv);
//   }

//   static String decryptAsRes(String encryptedRes) {
//     if (!envCubit.state.cryptoEnabled) return encryptedRes;
//     final res = CryptoData.fromJson(jsonDecode(encryptedRes));
//     return decrypt(res.payload);
//   }
// }
