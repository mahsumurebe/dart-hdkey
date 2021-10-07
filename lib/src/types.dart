import './helpers/common_helper.dart';

class ExtendedKeys {
  String? public;
  String? private;

  ExtendedKeys(this.public, this.private) {
    trueOrThrow(this.public != null && this.private != null,
        FormatException('At least one param must be defined.', this));
  }

  @override
  bool operator ==(covariant ExtendedKeys other) =>
      other.private == this.private && other.public == this.public;

  @override
  String toString() {
    List<String> out = [];
    if (this.public != null) out.add("PublicKey: $public!");
    if (this.private != null) out.add("PrivateKey: $private!");
    return "ExtendedKeys\n${out.join("\n")}";
  }
}
