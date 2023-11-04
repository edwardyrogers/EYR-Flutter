part of 'network.page.dart';

class NetworkCubit extends Cubit<NetworkState> with Alpha {
  TodosApiService get _todosService => injector.get<TodosApiService>();

  final _subscription = CompositeSubscription();

  NetworkCubit()
      : super(
          NetworkState.initialState(),
        );

  void requestTodos() {
    _subscription.add(
      _todosService.requestTodos().listen((res) {
        emit(NetworkState.create(res));
      }),
    );
  }

  @override
  Future<void> close() async {
    await _subscription.dispose();
    await super.close();
  }
}
