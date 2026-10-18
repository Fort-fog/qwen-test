/// Shared fakes for identity-storage tests (extracted from
/// secure_identity_store_test.dart so multiple test files reuse them).
import 'package:boltun_client/state/secure_identity_store.dart';

class FakeBackend implements SecureBackend {
  /// [sharedData] lets several backend instances observe the same map,
  /// simulating a process restart over one persistent keystore.
  FakeBackend({
    required this.isProtected,
    this.unavailableReason,
    Map<String, String>? seed,
    Map<String, String>? sharedData,
  }) : data = sharedData ?? {...?seed};
  final Map<String, String> data;
  @override
  final bool isProtected;
  @override
  final String? unavailableReason;
  int writes = 0;
  @override
  Future<String?> read(String key) async => data[key];
  @override
  Future<void> write(String key, String value) async {
    writes++;
    data[key] = value;
  }

  @override
  Future<void> delete(String key) async => data.remove(key);
}

class ThrowingReadBackend implements SecureBackend {
  final Map<String, String> data;
  ThrowingReadBackend(this.data);
  @override
  bool get isProtected => true;
  @override
  String? get unavailableReason => null;
  @override
  Future<String?> read(String key) async => throw StateError('keystore down');
  @override
  Future<void> write(String key, String value) async => data[key] = value;
  @override
  Future<void> delete(String key) async => data.remove(key);
}

class ThrowingWriteBackend implements SecureBackend {
  final Map<String, String> data = {};
  int deletes = 0;
  @override
  bool get isProtected => true;
  @override
  String? get unavailableReason => null;
  @override
  Future<String?> read(String key) async => data[key];
  @override
  Future<void> write(String key, String value) async =>
      throw StateError('write denied');
  @override
  Future<void> delete(String key) async {
    deletes++;
    data.remove(key);
  }
}
