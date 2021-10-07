hdkey
=====

A Dart library for [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki) (hierarchical deterministic keys).

Installation
------------

    dart pub add hdkey

Usage
-----

**example:**

```dart
import 'dart:typed_data';
import 'package:hdkey/hdkey.dart';
import 'package:hex/hex.dart';

void main() {
  const seed = 'a0c42a9c3ac6abf2ba6a9946ae83af18f51bf1c9fa7dacc4c92513cc4dd015834341c775dcd4c0fac73547c5662d81a9e9361a0aac604a73a321bd9103bce8af';
  final HDKey hdkey = HDKey.fromMasterSeed(Uint8List.fromList(HEX.decode(seed)));
  print(hdkey.privateExtendedKey);
  // output => 'xprv9s21ZrQH143K2SKJK9EYRW3Vsg8tWVHRS54hAJasj1eGsQXeWDHLeuu5hpLHRbeKedDJM4Wj9wHHMmuhPF8dQ3bzyup6R7qmMQ1i1FtzNEW'
  print(hdkey.publicExtendedKey);
  // output => 'xpub661MyMwAqRbcEvPmRAmYndzERhyNux1GoHzHxgzVHMBFkCro3kbbCiDZZ5XabZDyXPj5mH3hktvkjhhUdCQxie5e1g4t2GuAWNbPmsSfDp2'
}
```

### `HDKey.fromMnemonic(String mnemonic, [Bip32Type? this._versions])`

Creates an `HDKey` object from a mnemonic string. Accepts an optional `versions` object.

```dart
const mnemonic = 'chapter eager old retreat wire drift deal later ignore magic veteran liberty crime rice describe';
final HDKey hdkey = HDKey.fromMasterSeed(mnemonic);
```

### `HDKey.fromMasterSeed(Uint8List seed, [Bip32Type? this._versions])`

Creates an `HDKey` object from a master seed. Accepts an optional `versions` object.

```dart
const seed = 'a0c42a9c3ac6abf2ba6a9946ae83af18f51bf1c9fa7dacc4c92513cc4dd015834341c775dcd4c0fac73547c5662d81a9e9361a0aac604a73a321bd9103bce8af';
final HDKey hdkey = HDKey.fromMasterSeed(Uint8List.fromList(HEX.decode(seed)));
```

### `HDKey.fromExtendedKey(String base58key, [Bip32Type? this._versions])`

Creates an `HDKey` object from a `xprv` or `xpub` extended key string. Accepts an optional `versions` object.

```dart
const key = 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j';
final HDKey hdkey = HDKey.fromExtendedKey(key);
```

**or**

```dart
const key = 'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt';
final HDKey hdkey = HDKey.fromExtendedKey(key);
```

### `HDKey derive(String path)`

Derives the `HDKey` at `path` from the current `HDKey`.

```dart
var seed =
    'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542';
final HDKey hdkey = HDKey.fromMasterSeed(Uint8List.fromList(HEX.decode(seed)));

HDKey childkey = hdkey.derive("m/0/2147483647'/1");

print(childkey.privateExtendedKey);
// -> "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
print(childkey.publicExtendedKey);
// -> "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
```
### `Uint8List sign(Uint8List hash)`

Signs the Uint8List `hash` with the private key using `secp256k1` and returns the signature as a Uint8List.

### `bool verify(Uint8List hash, Uint8List signature)`

Verifies that the `signature` is valid for `hash` and the `HDKey`'s public key using `secp256k1`. Returns `true` for
valid, `false` for invalid. Throws if the `hash` or `signature` is the wrong length.

### `HDKey wipePrivateData()`

Wipes all record of the private key from the `HDKey` instance. After calling this method, the instance will behave as if
it was created via `HDKey.fromExtendedKey(xpub)`.

### `Uint8List? get privateKey`

Getter/Setter of the `HDKey`'s private key, stored as a Uint8List.

### `Uint8List? get publicKey`

Getter/Setter of the `HDKey`'s public key, stored as a Uint8List.

### `String? get privateExtendedKey`

Getter/Setter of the `HDKey`'s `xprv`, stored as a string.

### `String? get publicExtendedKey`

Getter/Setter of the `HDKey`'s `xpub`, stored as a string.

### `ExtendedKeys get extendedKeys`

Getter/Setter of the `HDKey`'s `xpub` and `xprv`, stored as a `ExtendedKeys`.

References
----------
This library is the development of the [hdkey](https://github.com/cryptocoinjs/hdkey) library developed for Javascript for Dart.

License
-------

MIT