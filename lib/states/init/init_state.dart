part of 'init_cubit.dart';

sealed class InitState with EquatableMixin {
  const InitState();

  factory InitState.init() => InitInstance();

  factory InitState.copyWith() => InitInstance();

  @override
  List<Object> get props => [];
}

final class InitInstance extends InitState {}
