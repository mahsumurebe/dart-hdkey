import 'dart:typed_data';

import 'package:hdkey/hdkey.dart';
import 'package:hex/hex.dart';

void main() {

  var seed =
      'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542';

  final HDKey hdkey = HDKey.fromMasterSeed(Uint8List.fromList(HEX.decode(seed)));

  HDKey childkey = hdkey.derive("m/0/2147483647'/1");

  print(childkey.privateExtendedKey);
// -> "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef"
  print(childkey.publicExtendedKey);
// -> "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"
}
