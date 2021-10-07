import 'package:hdkey/src/helpers/common_helper.dart';
import 'package:test/test.dart';

void main() {
  group('Common Functions', () {
    group('trueOrThrow', () {
      test('Should be thrown', () {
        expect(() => trueOrThrow(false, Exception()), throwsException);
      });
      test('Should not be thrown', () {
        try {
          trueOrThrow(true, Exception());
          expect(true, isTrue);
        } catch (e) {
          fail('Should not be thrown');
        }
      });
    });
  });
}
