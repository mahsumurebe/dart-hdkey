import 'dart:convert';
import 'dart:typed_data';

import 'package:bip32/bip32.dart';
import 'package:bip39/bip39.dart' as bip39;
import 'package:bs58check/bs58check.dart';
import 'package:bs58check/bs58check.dart' as bs58check;
import 'package:hex/hex.dart';

import './helpers/common_helper.dart';
import './helpers/crypto_helper.dart';
import './types.dart';

final BITCOIN_VERSION = new Bip32Type(public: 0x0488B21E, private: 0x0488ADE4);
final MASTER_SECRET = Uint8List.fromList(utf8.encode('Bitcoin seed'));
const LEN = 78;

class HDKey {
  static const HARDENED_OFFSET = 0x80000000;

  Bip32Type get versions {
    return this._versions ?? BITCOIN_VERSION;
  }

  Bip32Type? _versions;
  int depth = 0;
  int index = 0;

  Uint8List? _privateKey;
  Uint8List? _publicKey;
  Uint8List? chainCode;
  int _fingerprint = 0;
  int parentFingerprint = 0;
  Uint8List? _identifier;

  //region Getters
  int get fingerprint => _fingerprint;

  Uint8List? get identifier => _identifier;

  Uint8List? get pubKeyHash => _identifier;

  Uint8List? get privateKey => _privateKey;

  Uint8List? get publicKey => _publicKey;

  String? get privateExtendedKey {
    if (this._privateKey != null) {
      List<int> key = [];
      key.add(0);
      key.addAll(this.privateKey!.toList());
      return bs58check
          .encode(_serialize(this.versions.private, Uint8List.fromList(key)));
    }
    return null;
  }

  String get publicExtendedKey {
    return bs58check.encode(_serialize(this.versions.public, this.publicKey!));
  }

  ExtendedKeys get extendedKeys {
    return ExtendedKeys(this.publicExtendedKey, this.privateExtendedKey);
  }

  //endregion

  //region Setters

  void set privateKey(Uint8List? value) {
    trueOrThrow(
        value != null, FormatException('Private key must be defined.', value));
    trueOrThrow(value?.length == 32,
        FormatException('Private key must be 32 bytes.', value));
    trueOrThrow(privateKeyVerify(value!) == true,
        FormatException('Invalid private key', value));

    this._privateKey = value;
    this._publicKey = publicKeyCreate(value, true);
    this._identifier = hash160(this.publicKey!);
    this._fingerprint =
        this._identifier?.sublist(0, 4).buffer.asByteData().getUint32(0) ?? 0;
  }

  void set publicKey(Uint8List? value) {
    trueOrThrow(
        value != null, FormatException('Public key must be defined.', value));
    trueOrThrow(value?.length == 33 || value?.length == 65,
        FormatException('Public key must be 33 or 65 bytes.', value));
    trueOrThrow(publicKeyVerify(value!) == true,
        FormatException('Invalid public key', value));

    this._publicKey = publicKeyConvert(value, true); // force compressed point
    this._identifier = hash160(this.publicKey!);
    this._fingerprint =
        this._identifier!.sublist(0, 4).buffer.asByteData().getUint32(0);
    this._privateKey = null;
  }

  //endregion

  //region Constructors
  HDKey([Bip32Type? this._versions]);

  HDKey.fromMnemonic(String mnemonic, [Bip32Type? this._versions]) {
    Uint8List seedBuffer = bip39.mnemonicToSeed(mnemonic);
    final I = sha512(seedBuffer, MASTER_SECRET);
    final IL = I.sublist(0, 32);
    final IR = I.sublist(32);
    this.chainCode = IR;
    this.privateKey = IL;
  }

  HDKey.fromMasterSeed(Uint8List seed, [Bip32Type? this._versions]) {
    final I = sha512(seed, MASTER_SECRET);
    HEX.encode(I);
    final IL = I.sublist(0, 32);
    final IR = I.sublist(32);

    this.chainCode = IR;
    this.privateKey = IL;
  }

  HDKey.fromExtendedKey(String base58key, [Bip32Type? this._versions]) {
    // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    final decodedKeyBuffer = bs58check.decode(base58key);
    final keyBuffer = ByteData.view(decodedKeyBuffer.buffer);
    final version = keyBuffer.getUint32(0);

    trueOrThrow(
        version == versions.private || version == versions.public,
        FormatException(
            'Version mismatch: does not match private or public', base58key));

    this.depth = keyBuffer.getUint8(4);
    this.parentFingerprint = keyBuffer.getUint32(5);
    this.index = keyBuffer.getUint32(9);
    this.chainCode = decodedKeyBuffer.sublist(13, 45);

    var key = ByteData.view(decodedKeyBuffer.sublist(45).buffer);
    if (key.getUint8(0) == 0) {
      // private
      trueOrThrow(
          version == versions.private,
          FormatException(
              'Version mismatch: version does not match private', base58key));
      this.privateKey =
          Uint8List.view(key.buffer).sublist(1); // cut off first 0x0 byte
    } else {
      trueOrThrow(
          version == versions.public,
          FormatException(
              'Version mismatch: version does not match public', base58key));
      this.publicKey = Uint8List.view(key.buffer);
    }
  }

  //endregion

  //region Deriving Methods
  HDKey derive(String path) {
    if (path == 'm' || path == 'M' || path == "m'" || path == "M'") {
      return this;
    }

    List<String> entries = path.split('/');
    HDKey hdKey = this;

    for (int i = 0; i < entries.length; i++) {
      String c = entries[i];
      if (i == 0) {
        trueOrThrow(c.toLowerCase() == 'm',
            FormatException('Path must start with "m" or "M"', path));
        continue;
      }

      var hardened = (c.length > 1) && (c[c.length - 1] == "'");
      var childIndex = int.parse(c.replaceAll("'", ''),
          radix: 10); // & (HARDENED_OFFSET - 1)
      trueOrThrow(
          childIndex < HARDENED_OFFSET, FormatException('Invalid index', path));
      if (hardened) childIndex += HARDENED_OFFSET;

      hdKey = hdKey.deriveChild(childIndex);
    }

    return hdKey;
  }

  HDKey deriveChild(int index) {
    bool isHardened = index >= HARDENED_OFFSET;
    ByteData indexByteData = ByteData(4);
    indexByteData.setUint32(0, index);

    ByteData data;

    if (isHardened) {
      // Hardened child
      trueOrThrow(
          this.privateKey != null,
          FormatException(
              'Could not derive hardened child key', this.privateKey));

      ByteData zb = ByteData(1);
      List<int> tmpPk = Uint8List.view(zb.buffer).toList();
      tmpPk.addAll(this.privateKey!.toList());

      List<int> tmpData = [];
      tmpData.addAll(tmpPk); // or we can use tmpData.addAll(pk);
      tmpData.addAll(Uint8List.view(indexByteData.buffer).toList());
      data = ByteData.view(Uint8List.fromList(tmpData).buffer);
    } else {
      // Normal child
      // data = serP(point(kpar)) || ser32(index)
      //      = serP(Kpar) || ser32(index)
      List<int> pk = this.publicKey!.toList(growable: true);
      pk.addAll(Uint8List.view(indexByteData.buffer));
      data = ByteData.view(Uint8List.fromList(pk).buffer);
    }

    Uint8List I = sha512(Uint8List.view(data.buffer), this.chainCode);
    Uint8List IL = I.sublist(0, 32);
    Uint8List IR = I.sublist(32);

    HDKey hd = new HDKey(this.versions);

    // Private parent key -> private child key
    if (this.privateKey != null) {
      // ki = parse256(IL) + kpar (mod n)
      try {
        hd.privateKey = privateKeyTweakAdd(this.privateKey!, IL);
        // throw if IL >= n || (privateKey + IL) === 0
      } catch (err) {
        print("privateKeyTweakAdd error: ${err.toString()}");
        // In case parse256(IL) >= n or ki == 0, one should proceed with the next value for i
        return this.deriveChild(index + 1);
      }
      // Public parent key -> public child key
    } else {
      // Ki = point(parse256(IL)) + Kpar
      //    = G*IL + Kpar
      try {
        hd.publicKey = publicKeyTweakAdd(this.publicKey!, IL, true);
        // throw if IL >= n || (g**IL + publicKey) is infinity
      } catch (err) {
        print("publicKeyTweakAdd error: ${err.toString()}");
        // In case parse256(IL) >= n or Ki is the point at infinity, one should proceed with the next value for i
        return this.deriveChild(index + 1);
      }
    }

    hd.chainCode = IR;
    hd.depth = this.depth + 1;
    hd.parentFingerprint = this.fingerprint;
    hd.index = index;

    return hd;
  }

  //endregion

  //region Crypto Methods
  Uint8List sign(Uint8List hash) {
    trueOrThrow(this.privateKey != null,
        FormatException('Private key is null.', this.privateKey));
    return eccSign(this.privateKey!, hash);
  }

  bool verify(Uint8List hash, Uint8List signature) {
    if (this.publicKey == null) throw ('Public key not found.');
    return eccSignedHashVerify(this.publicKey!, hash, signature);
  }

  //endregion

  HDKey wipePrivateData() {
    if (this._privateKey != null) {
      this._privateKey?.setAll(0, Uint8List(this._privateKey!.length));
    }
    this._privateKey = null;
    return this;
  }

  Uint8List _serialize(int version, Uint8List key) {
    // => version(4) || depth(1) || fingerprint(4) || index(4) || chain(32) || key(33)
    ByteData byteData = ByteData(LEN);
    byteData.setUint32(0, version);
    byteData.setUint8(4, this.depth);

    int fingerprint = this.depth > 0 ? this.parentFingerprint : 0x00000000;
    byteData.setUint32(5, fingerprint);
    byteData.setUint32(9, this.index);

    List<int> buffer = [];
    buffer.addAll(Uint8List.view(byteData.buffer).toList());
    buffer.setAll(13, this.chainCode!.toList());
    buffer.setAll(45, key.toList());

    return Uint8List.fromList(buffer);
  }

  @override
  bool operator ==(covariant HDKey other) {
    return this.extendedKeys == other.extendedKeys;
  }
}
