import 'dart:typed_data';

import 'package:hdkey/src/helpers/crypto_helper.dart';
import 'package:hex/hex.dart';
import 'package:test/test.dart';

void main() {
  final publicKey = Uint8List.fromList(HEX.decode(
      '039514b095f105039a913e0d85db0f213281406d3786730b5c128aad8fda0f1d0b'));
  final publicKeyNotCompressed = Uint8List.fromList(HEX.decode(
      '049514b095f105039a913e0d85db0f213281406d3786730b5c128aad8fda0f1d0bf2fabc5473f84f49c09a3680ade586b26aa17c9fb5e306f1a67f23677f946ed7'));
  final privateKey = Uint8List.fromList(HEX
      .decode('0dcc9375efba74c8f817f963ca0d217e17384d34c02f31ab07608a904b4e0bdf'));

  group('Testing helpers', () {
    test('.hash160() processing data to riplemd160 digest.', () {
      String data = 'AABBCCDDEEFF';
      String convertedData =
          HEX.encode(hash160(Uint8List.fromList(HEX.decode(data))));
      expect(convertedData, equals('6cd7818c2ed773a1b19348feaca92ad664b45cd0'));
    });
    test('.sha256() processing data to sha256 digest.', () {
      String data = 'AABBCCDDEEFF';
      String convertedData =
          HEX.encode(sha256(Uint8List.fromList(HEX.decode(data))));
      expect(
          convertedData,
          equals(
              '17226b1f68aebacdef0746450f642874638b295707ef73fb2c6bb7f88e89929f'));
    });
    test('.sha512() processing data to sha512 digest.', () {
      String data = 'AABBCCDDEEFF';
      String convertedData =
          HEX.encode(sha512(Uint8List.fromList(HEX.decode(data))));
      expect(
          convertedData,
          equals(
              '4978894c6f45bf44d3ea25b626e2852c33287fa0a87f57ee36ee0c6c64afc78e04d150b484dbd4f70c5a94034489af6280905ef968d583048727cda8d924bf10'));
    });

    test('privateKeyVerify function', () {
      expect(privateKeyVerify(privateKey),
          equals(true));
    });
    test('publicKeyCreate function', () {
      expect(publicKeyCreate(privateKey, true), equals(publicKey));
    });
    test('publicKeyVerify function', () {
      expect(publicKeyVerify(publicKey),
          equals(true));
    });
    test('publicKeyConvert function', () {
      expect(publicKeyConvert(publicKey, false),
          equals(publicKeyNotCompressed));
      expect(publicKeyConvert(publicKey, true),
          equals(publicKey));
    });
    test('privateKeyTweakAdd function', () {
      //TODO
      expect(true, equals(true));
    });
    test('publicKeyTweakAdd function', () {
      //TODO
      expect(true, equals(true));
    });
  });
}
