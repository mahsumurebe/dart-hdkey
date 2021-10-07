import 'dart:typed_data';

import 'package:elliptic/elliptic.dart' as elliptic;
import 'package:hex/hex.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/export.dart';
import 'package:bip32/src/utils/ecurve.dart' as ecc;

final _ripemd160digest = RIPEMD160Digest();
final _sha256digest = SHA256Digest();
final _sha512digest = SHA512Digest();
final _ec = elliptic.getSecp256k1();

Uint8List hash160(Uint8List data) {
  return _ripemd160digest.process(sha256(data));
}

Uint8List sha256(Uint8List data, [Uint8List? secret]) {
  if (secret != null) {
    final _sha256digestHMAC = HMac(_sha256digest, 64);
    _sha256digestHMAC.init(KeyParameter(secret));
    return _sha256digestHMAC.process(data);
  }
  return _sha256digest.process(data);
}

Uint8List sha512(Uint8List data, [Uint8List? secret]) {
  if (secret != null) {
    final _sha512digestHMAC = HMac(_sha512digest, 128);
    _sha512digestHMAC.init(KeyParameter(secret));
    return _sha512digestHMAC.process(data);
  }
  return _sha512digest.process(data);
}

bool privateKeyVerify(Uint8List privateKey) {
  final bn = BigInt.parse(HEX.encode(privateKey), radix: 16);
  return bn.compareTo(_ec.n) < 0 && bn != BigInt.zero;
}

Uint8List publicKeyCreate(Uint8List privateKey, [bool compressed = false]) {
  final priv = elliptic.PrivateKey.fromBytes(_ec, privateKey);
  final pub = priv.publicKey;
  return Uint8List.fromList(
      HEX.decode(compressed ? pub.toCompressedHex() : pub.toHex()));
}

bool publicKeyVerify(Uint8List publicKey) {
  try {
    final convertedPublicKey =
        publicKeyConvert(publicKey, publicKey.length == 33);
    return HEX.encode(convertedPublicKey) == HEX.encode(publicKey);
  } catch (e) {
    return false;
  }
}

Uint8List publicKeyConvert(Uint8List publicKey, [bool compressed = false]) {
  final c = elliptic.PublicKey.fromHex(_ec, HEX.encode(publicKey));
  return Uint8List.fromList(
      HEX.decode(compressed ? c.toCompressedHex() : c.toHex()));
}

Uint8List privateKeyTweakAdd(Uint8List seckey, Uint8List tweak) {
  BigInt bn = BigInt.parse(HEX.encode(tweak), radix: 16);
  if (bn.compareTo(_ec.n) >= 0) {
    // return 1
    return seckey;
  }

  bn += BigInt.parse(HEX.encode(seckey), radix: 16);
  if (bn.compareTo(_ec.n) >= 0) bn -= _ec.n;
  if (bn == BigInt.zero) {
    //return 1;
    return seckey;
  }
  String bnHex = bn.toRadixString(16);
  if (bnHex.length < 64) bnHex = bnHex.padLeft(64, '0');
  List<int> tweaked = HEX.decode(bnHex);
  List<int> tmpSecret = seckey.toList(growable: true);
  tmpSecret.setAll(0, tweaked);
  //return 0;
  return Uint8List.fromList(tmpSecret);
}

Uint8List publicKeyTweakAdd(Uint8List publicKey, Uint8List tweak,
    [bool compress = false]) {
  if (!publicKeyVerify(publicKey)) {
    return publicKey;
  }

  BigInt bn = BigInt.parse(HEX.encode(tweak), radix: 16);

  if (bn.compareTo(_ec.n) >= 0) {
    //return 2;
    return publicKey;
  }

  final point = _ec.add(
      elliptic.PublicKey.fromHex(_ec, HEX.encode(publicKey.toList())),
      _ec.scalarMul(_ec.G, tweak.toList()));

  final pk = elliptic.PublicKey.fromPoint(_ec, point);

  return Uint8List.fromList(
      HEX.decode(compress ? pk.toCompressedHex() : pk.toHex()));
}

Uint8List eccSign(Uint8List privateKey, Uint8List hash) {
  return ecc.sign(hash, privateKey);
}

bool eccSignedHashVerify(Uint8List publicKey, Uint8List hash, Uint8List signature) {
  return ecc.verify(hash, publicKey, signature);
}
