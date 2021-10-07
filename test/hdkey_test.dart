import 'dart:typed_data';

import 'package:bs58check/bs58check.dart' as bs58check;
import 'package:hdkey/hdkey.dart';
import 'package:hdkey/src/types.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

import 'fixtures/hdkey.dart';

void main() {
  group('HDKey', () {
    group('+ fromMasterSeed', () {
      fixtures[FixtureKeys.valid]?.forEach((f) {
        test('should properly derive the chain path: $f.path', () {
          HDKey hdKey = HDKey.fromMasterSeed(f.seed);
          HDKey child = hdKey.derive(f.path);

          expect(
              bs58check.decode(child.privateExtendedKey!), equals(f.private));
          expect(bs58check.decode(child.publicExtendedKey), equals(f.public));
        });

        group('> ' + f.path + ' extendedKey / fromExtendedKey', () {
          test('should return an ExtendedKeys read for HDKey serialization',
              () {
            HDKey hdKey = HDKey.fromMasterSeed(f.seed);
            HDKey child = hdKey.derive(f.path);
            ExtendedKeys extendedKeys = ExtendedKeys(
                bs58check.encode(f.public), bs58check.encode(f.private));
            expect(child.extendedKeys, extendedKeys);

            HDKey newKey = HDKey.fromExtendedKey(extendedKeys.private!);
            expect(newKey.privateExtendedKey, bs58check.encode(f.private));
            expect(newKey.publicExtendedKey, bs58check.encode(f.public));
          });
        });
      });
    });
    group('- privateKey', () {
      test('should throw an error if is null', () {
        HDKey hdkey = new HDKey();
        expect(() => hdkey.privateKey = null, throwsFormatException);
      });
      test('should throw an error if incorrect key size', () {
        HDKey hdkey = new HDKey();
        expect(() => hdkey.privateKey = Uint8List.fromList([1, 2, 3, 4]),
            throwsFormatException);
      });
    });
    group('- publicKey', () {
      test('should throw an error if is null', () {
        HDKey hdkey = new HDKey();
        expect(() => hdkey.publicKey = null, throwsFormatException);
      });
      test('should throw an error if incorrect key size', () {
        HDKey hdkey = new HDKey();
        expect(() => hdkey.publicKey = Uint8List.fromList([1, 2, 3, 4]),
            throwsFormatException);
      });
      test('should not throw if key is 33 bytes (compressed)', () {
        HDKey hdkey = new HDKey();

        final publicKey = Uint8List.fromList(HEX.decode(
            '039b50417d0a067207194dd4239fdfcd70bdcd609e46880df52e64107ec0fed4b7'));
        try {
          hdkey.publicKey = publicKey;
          expect(hdkey.publicKey, equals(publicKey));
        } catch (e) {
          fail(e.toString());
        }
      });
      test('should not throw if key is 65 bytes (not compressed)', () {
        HDKey hdkey = new HDKey();

        final publicKeyNotCompressed = Uint8List.fromList(HEX.decode(
            '04a3b011a2ef2994e3957009313cce00f8463e843b83fb95996a63d6c0bae728865579e878d43e06807cfca494c0b618ef5cd37f3a2bd5611dc3037e44f28de166'));
        final publicKey = Uint8List.fromList(HEX.decode(
            '02a3b011a2ef2994e3957009313cce00f8463e843b83fb95996a63d6c0bae72886'));
        try {
          hdkey.publicKey = publicKeyNotCompressed;
          expect(hdkey.publicKey, equals(publicKey));
        } catch (e) {
          fail(e.toString());
        }
      });
    });

    group('+ fromExtendedKey()', () {
      group('> when private', () {
        test('should parse it', () {
          // m/0/2147483647'/1/2147483646'/2;
          const String key =
              'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j';
          HDKey hdkey = HDKey.fromExtendedKey(key);
          expect(hdkey.versions.private, equals(0x0488ade4));
          expect(hdkey.versions.public, equals(0x0488b21e));
          expect(hdkey.depth, equals(5));
          expect(hdkey.parentFingerprint, equals(0x31a507b8));
          expect(hdkey.index, equals(2));
          expect(
              HEX.encode(hdkey.chainCode!.toList()),
              equals(
                  '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271'));
          expect(
              HEX.encode(hdkey.privateKey!.toList()),
              equals(
                  'bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23'));
          expect(
              HEX.encode(hdkey.publicKey!.toList()),
              equals(
                  '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c'));
          expect(HEX.encode(hdkey.identifier!.toList()),
              equals('26132fdbe7bf89cbc64cf8dafa3f9f88b8666220'));
        });
      });
      group('> when public', () {
        test('should parse it', () {
          // m/0/2147483647'/1/2147483646'/2;
          const String key =
              'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt';
          HDKey hdkey = HDKey.fromExtendedKey(key);
          expect(hdkey.versions.private, equals(0x0488ade4));
          expect(hdkey.versions.public, equals(0x0488b21e));
          expect(hdkey.depth, equals(5));
          expect(hdkey.parentFingerprint, equals(0x31a507b8));
          expect(hdkey.index, equals(2));
          expect(
              HEX.encode(hdkey.chainCode!.toList()),
              equals(
                  '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271'));
          expect(hdkey.privateKey, isNull);
          expect(
              HEX.encode(hdkey.publicKey!.toList()),
              equals(
                  '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c'));
          expect(HEX.encode(hdkey.identifier!.toList()),
              equals('26132fdbe7bf89cbc64cf8dafa3f9f88b8666220'));
        });
      });
    });
    final validFixtures = fixtures[FixtureKeys.valid]!;
    group('> when signing', () {
      test('should work', () {
        const String key =
            'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j';
        String aHex =
            '6ba4e554457ce5c1f1d7dbd10459465e39219eb9084ee23270688cbe0d49b52b7905d5beb28492be439a3250e9359e0390f844321b65f1a88ce07960dd85da06';
        String bHex =
            'dfae85d39b73c9d143403ce472f7c4c8a5032c13d9546030044050e7d39355e47a532e5c0ae2a25392d97f5e55ab1288ef1e08d5c034bad3b0956fbbab73b381';

        HDKey hdkey = HDKey.fromExtendedKey(key);
        Uint8List ma = Uint8List.fromList(List.filled(32, 0));
        Uint8List mb = Uint8List.fromList(List.filled(32, 8));
        Uint8List a = hdkey.sign(ma);
        Uint8List b = hdkey.sign(mb);
        expect(HEX.encode(a), equals(aHex));
        expect(HEX.encode(b), equals(bHex));
        expect(hdkey.verify(ma, a), equals(true));
        expect(hdkey.verify(mb, b), equals(true));
        expect(hdkey.verify(Uint8List(32), Uint8List(64)), equals(false));
        expect(hdkey.verify(ma, b), equals(false));
        expect(hdkey.verify(mb, a), equals(false));

        expect(() => hdkey.verify(Uint8List(99), a), throwsArgumentError);
        expect(() => hdkey.verify(ma, Uint8List(99)), throwsArgumentError);
      });
      group('> when deriving public key', () {
        test('should work', () {
          const String key =
              'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';
          HDKey hdkey = HDKey.fromExtendedKey(key);
          const String path = 'm/3353535/2223/0/99424/4/33';
          HDKey derivedHDKey = hdkey.derive(path);
          const String expected =
              'xpub6JdKdVJtdx6sC3nh87pDvnGhotXuU5Kz6Qy7Piy84vUAwWSYShsUGULE8u6gCivTHgz7cCKJHiXaaMeieB4YnoFVAsNgHHKXJ2mN6jCMbH1';
          expect(derivedHDKey.publicExtendedKey, equals(expected));
        });
      });
      group('> when private key integer is less than 32 bytes', () {
        test('should work', () {
          const String seed = '000102030405060708090a0b0c0d0e0f';
          HDKey masterKey =
              HDKey.fromMasterSeed(Uint8List.fromList(HEX.decode(seed)));
          HDKey newKey = masterKey.derive("m/44'/6'/4'");
          const String expected =
              'xprv9ymoag6W7cR6KBcJzhCM6qqTrb3rRVVwXKzwNqp1tDWcwierEv3BA9if3ARHMhMPh9u2jNoutcgpUBLMfq3kADDo7LzfoCnhhXMRGX3PXDx';
          expect(newKey.privateExtendedKey, equals(expected));
        });
      });
      group('HARDENED_OFFSET', () {
        test('should be set', () {
          expect(HDKey.HARDENED_OFFSET, equals(0x80000000));
        });
      });
      group('> when private key has leading zeros', () {
        test('will include leading zeros when hashing to derive child', () {
          const String key =
              'xprv9s21ZrQH143K3ckY9DgU79uMTJkQRLdbCCVDh81SnxTgPzLLGax6uHeBULTtaEtcAvKjXfT7ZWtHzKjTpujMkUd9dDb8msDeAfnJxrgAYhr';
          HDKey hdkey = HDKey.fromExtendedKey(key);
          expect(
              HEX.encode(hdkey.privateKey!),
              equals(
                  '00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd'));
          HDKey derived = hdkey.derive("m/44'/0'/0'/0/0'");
          expect(
              HEX.encode(derived.privateKey!),
              equals(
                  '3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb'));
        });
      });
      group('> when private key is null', () {
        test('privateExtendedKey should return null and not throw', () {
          const String seed = '000102030405060708090a0b0c0d0e0f';
          HDKey masterKey =
              HDKey.fromMasterSeed(Uint8List.fromList(HEX.decode(seed)));
          expect(masterKey.privateExtendedKey, isNotNull);
          masterKey.wipePrivateData();
          try {
            masterKey.privateExtendedKey;
          } catch (e) {
            fail(e.toString());
          }
          expect(masterKey.privateExtendedKey, isNull);
        });
      });
      group(
          ' - when the path given to derive contains only the master extended key',
          () {
        HDKey hdKeyInstance = HDKey.fromMasterSeed(validFixtures[0].seed);
        test('should return the same hdkey instance', () {
          expect(hdKeyInstance.derive('m'), equals(hdKeyInstance));
          expect(hdKeyInstance.derive('M'), equals(hdKeyInstance));
          expect(hdKeyInstance.derive("m'"), equals(hdKeyInstance));
          expect(hdKeyInstance.derive("M'"), equals(hdKeyInstance));
        });
      });
      group(
          ' - when the path given to derive does not begin with master extended key',
          () {
        test('should throw an error', () {
          expect(() => HDKey().derive('123'), throwsFormatException);
        });
      });
      group('- after wipePrivateData()', () {
        test('should not have private data', () {
          HDKey hdkey =
              HDKey.fromMasterSeed(validFixtures[6].seed).wipePrivateData();
          expect(hdkey.privateKey, isNull);
          expect(hdkey.privateExtendedKey, isNull);
          expect(() => hdkey.sign(Uint8List(32)), throwsException);
          final HDKey childKey = hdkey.derive('m/0');
          expect(childKey.publicExtendedKey, equals(bs58check.encode(validFixtures[7].public)));
          expect(childKey.privateKey, isNull);
          expect(childKey.privateExtendedKey, isNull);
        });
        test('should have correct data', () {
          // m/0/2147483647'/1/2147483646'/2;
          const String key =
              'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j';
          HDKey hdkey = HDKey.fromExtendedKey(key).wipePrivateData();
          expect(hdkey.versions.private, equals(0x0488ade4));
          expect(hdkey.versions.public, equals(0x0488b21e));
          expect(hdkey.depth, equals(5));
          expect(hdkey.parentFingerprint, equals(0x31a507b8));
          expect(hdkey.index, equals(2));
          expect(
              HEX.encode(hdkey.chainCode!),
              equals(
                  '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271'));
          expect(
              HEX.encode(hdkey.publicKey!),
              equals(
                  '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c'));
          expect(HEX.encode(hdkey.identifier!),
              equals('26132fdbe7bf89cbc64cf8dafa3f9f88b8666220'));
        });
        test('should be able to verify signatures', () {
          final HDKey fullKey = HDKey.fromMasterSeed(validFixtures[0].seed);
          // using JSON methods to clone before mutating;
          final HDKey wipedKey =
              HDKey.fromExtendedKey(fullKey.privateExtendedKey!)
                  .wipePrivateData();
          final Uint8List hash = Uint8List.fromList(List.filled(32, 8));
          expect(wipedKey.verify(hash, fullKey.sign(hash)), isTrue);
        });
        test('should not throw if called on hdkey without private data', () {
          HDKey hdkey =
              HDKey.fromExtendedKey(bs58check.encode(validFixtures[0].public));
          try {
            hdkey.wipePrivateData();
          } catch (e) {
            fail(e.toString());
          }
          expect(hdkey.publicExtendedKey,
              bs58check.encode(validFixtures[0].public));
        });
      });
      group('Deriving a child key does not mutate the internal state', () {
        test('should not mutate it when deriving with a private key', () {
          HDKey hdkey =
              HDKey.fromExtendedKey(bs58check.encode(validFixtures[0].private));
          const String path = 'm/123';
          final String privateKeyBefore = HEX.encode(hdkey.privateKey!);
          HDKey child = hdkey.derive(path);
          expect(HEX.encode(hdkey.privateKey!), equals(privateKeyBefore));
          HDKey child2 = hdkey.derive(path);
          expect(HEX.encode(hdkey.privateKey!), equals(privateKeyBefore));
          HDKey child3 = hdkey.derive(path);
          expect(HEX.encode(hdkey.privateKey!), equals(privateKeyBefore));
          expect(child.privateKey, equals(child2.privateKey));
          expect(child2.privateKey, equals(child3.privateKey));
        });
        test('should not mutate it when deriving without a private key', () {
          HDKey hdkey =
              HDKey.fromExtendedKey(bs58check.encode(validFixtures[0].private));
          const String path = 'm/123/123/123';
          hdkey.wipePrivateData();
          String publicKeyBefore = HEX.encode(hdkey.publicKey!);
          HDKey child = hdkey.derive(path);
          expect(HEX.encode(hdkey.publicKey!), equals(publicKeyBefore));
          HDKey child2 = hdkey.derive(path);
          expect(HEX.encode(hdkey.publicKey!), equals(publicKeyBefore));
          HDKey child3 = hdkey.derive(path);
          expect(HEX.encode(hdkey.publicKey!), equals(publicKeyBefore));
          expect(HEX.encode(child.publicKey!),
              equals(HEX.encode(child2.publicKey!)));
          expect(HEX.encode(child2.publicKey!),
              equals(HEX.encode(child3.publicKey!)));
        });
      });
    });
  });
}
