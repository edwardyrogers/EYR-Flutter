import 'package:flutter_proj/core/app.service.dart';
import 'package:flutter_proj/api/models/mbm081018/mbm081018.model.dart';
import 'package:flutter_proj/api/requests/mbm081018.request.dart';
import 'package:flutter_proj/shared/services/api.service.dart';
import 'package:get_it/get_it.dart';

class MBM081018Service extends AppService {
  final apiService = GetIt.instance.get<ApiService>();

  Future<MBM081018Model> getFxRate(String ccyName) async {
    var req = MBM081018Request(
      reqBody: MBM081018RequestBody(
        ccyName: ccyName,
      ),
    );

    var response = await apiService.request(req);

    return response.serialise<MBM081018Model>((res) => _serialiseFxRate(res));
  }

  MBM081018Model _serialiseFxRate(Map<String, dynamic> res) {
    var body = res['BODY'];
    var model = MBM081018Model.fromJson(body);

    return model;
  }
}
