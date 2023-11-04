import 'package:auto_route/auto_route.dart';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_proj/api/api.service.dart';
import 'package:flutter_proj/api/todos/todos.service.dart';
import 'package:flutter_proj/app/app.widget.dart';
import 'package:flutter_proj/core/alpha.mixin.dart';
import 'package:flutter_proj/shares/widgets/header.widget.dart';
import 'package:rxdart/utils.dart';

part 'network.cubit.dart';
part 'network.state.dart';

@RoutePage<NetworkPage>()
class NetworkPage extends StatefulWidget implements AutoRouteWrapper {
  NetworkPage({super.key});

  @override
  State<NetworkPage> createState() => _NetworkPageState();

  @override
  Widget wrappedRoute(BuildContext context) => MultiBlocProvider(
        providers: [
          BlocProvider.value(value: NetworkCubit()),
        ],
        child: this,
      );
}

class _NetworkPageState extends State<NetworkPage> {
  late NetworkCubit _networkCubit;

  @override
  void didChangeDependencies() {
    _networkCubit = BlocProvider.of<NetworkCubit>(context);
    _networkCubit.requestTodos();

    super.didChangeDependencies();
  }

  @override
  void dispose() {
    _networkCubit.close();

    super.dispose();
  }

  PreferredSize header() {
    return PreferredSize(
      preferredSize: const Size.fromHeight(80),
      child: HeaderBarWidget(title: AppConfig.appTitle),
    );
  }

  Widget body(BuildContext context) {
    return SafeArea(
      child: Center(
        child: BlocBuilder<NetworkCubit, NetworkState>(
          builder: (context, state) {
            final todosModel = state.todos;

            if (todosModel is ApiLoading) {
              return const SizedBox.shrink();
            } else if (todosModel is ApiFail) {
              return const Text('Error');
            } else {
              return ListView.builder(
                key: UniqueKey(),
                padding: const EdgeInsets.symmetric(
                  vertical: 30,
                  horizontal: 20,
                ),
                itemCount: todosModel.value.length,
                itemBuilder: (context, index) {
                  return Card(
                    child: ListTile(
                      key: UniqueKey(),
                      title: Text(todosModel.value[index].title),
                    ),
                  );
                },
              );
            }
          },
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: header(),
      body: body(context),
    );
  }
}
