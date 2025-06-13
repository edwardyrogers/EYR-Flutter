import 'package:equatable/equatable.dart';
import 'package:eyr/api/api_service.dart';
import 'package:eyr/api/eyr_spring_boot/eyr_spring_boot_service.dart';
import 'package:json_annotation/json_annotation.dart';

part 'api000004.g.dart';

@JsonSerializable()
class Api000004Req extends EYRSpringBootReq {
  @JsonKey(name: 'data')
  @JsonApi000004CryptoKey()
  final String data;

  Api000004Req({
    required this.data,
    super.method = ApiMethod.post,
    super.uri = 'API000004',
  });

  @override
  List<Object?> get props => [data];

  factory Api000004Req.fromJson(Map<String, dynamic> json) =>
      _$Api000004ReqFromJson(json);

  @override
  Map<String, dynamic> toJson() => _$Api000004ReqToJson(this);
}

@JsonSerializable()
class Api000004Res with EquatableMixin {
  @JsonKey(name: 'encryptedData')
  @JsonApi000004CryptoKey()
  final String encryptedData;

  @JsonKey(name: 'decryptedData')
  final String decryptedData;

  Api000004Res({
    required this.encryptedData,
    required this.decryptedData,
  });

  @override
  List<Object?> get props => [encryptedData, decryptedData];

  factory Api000004Res.fromJson(Map<String, dynamic> json) =>
      _$Api000004ResFromJson(json);

  Map<String, dynamic> toJson() => _$Api000004ResToJson(this);
}

class JsonApi000004CryptoKey extends JsonEYRCryptoKey {
  const JsonApi000004CryptoKey();
}
