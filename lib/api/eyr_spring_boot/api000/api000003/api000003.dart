import 'package:equatable/equatable.dart';
import 'package:eyr/api/api_service.dart';
import 'package:eyr/api/eyr_spring_boot/eyr_spring_boot_service.dart';
import 'package:json_annotation/json_annotation.dart';

part 'api000003.g.dart';

@JsonSerializable()
class Api000003Req extends EYRSpringBootReq {
  Api000003Req({
    super.method = ApiMethod.post,
    super.uri = 'API000003',
  });

  @override
  List<Object?> get props => [];

  factory Api000003Req.fromJson(Map<String, dynamic> json) =>
      _$Api000003ReqFromJson(json);

  @override
  Map<String, dynamic> toJson() => _$Api000003ReqToJson(this);
}

@JsonSerializable()
class Api000003Res with EquatableMixin {
  @JsonKey(name: 'pk')
  final String pubKey;

  Api000003Res({
    required this.pubKey,
  });

  @override
  List<Object?> get props => [pubKey];

  factory Api000003Res.fromJson(Map<String, dynamic> json) =>
      _$Api000003ResFromJson(json);

  Map<String, dynamic> toJson() => _$Api000003ResToJson(this);
}
