// ignore_for_file: implementation_imports, depend_on_referenced_packages

import 'package:analyzer/dart/element/element.dart';
import 'package:build/src/builder/build_step.dart';
import 'package:page_route_annotation/page_route.annotation.dart';
import 'package:page_route_generator/src/page_class.visitor.dart';
import 'package:source_gen/source_gen.dart';

class RouteParamGenerator extends GeneratorForAnnotation<RouteParamGenerable> {
  @override
  String generateForAnnotatedElement(
    Element element,
    ConstantReader annotation,
    BuildStep buildStep,
  ) {
    final visitor = PageClassVisitor();
    element.visitChildren(visitor);

    final buffer = StringBuffer();
    final className = '${visitor.className}RouteParam';

    buffer.writeln('class $className {');

    for (int i = 0; i < visitor.fields.length; i++) {
      buffer.writeln(
        'final ${visitor.fields.values.elementAt(i)} ${visitor.fields.keys.elementAt(i)};',
      );
    }

    // Constructor
    if (visitor.fields.isNotEmpty) {
      buffer.writeln('const $className({');

      for (int i = 0; i < visitor.fields.length; i++) {
        final type = visitor.fields.values.elementAt(i);

        if (type.toString().contains('?')) {
          buffer.writeln(
            'this.${visitor.fields.keys.elementAt(i)},',
          );
        } else {
          buffer.writeln(
            'required this.${visitor.fields.keys.elementAt(i)},',
          );
        }
      }

      buffer.writeln('});');
    } else {
      buffer.writeln('const $className();');
    }

    buffer.writeln('}');

    return buffer.toString();
  }
}
