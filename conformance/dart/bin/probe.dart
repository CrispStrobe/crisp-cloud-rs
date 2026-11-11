import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as hashes;
import 'package:filen_client/crypto.dart';
import 'package:filen_client/aes_gcm_backend.dart';
import 'package:internxt_client/crypto.dart' as internxt;

class FixedNonceRandom implements Random {
  @override int nextInt(int max) => 26; // 'a' in the SDK's metadata alphabet.
  @override bool nextBool() => false;
  @override double nextDouble() => 0.5;
}
Uint8List unhex(String value) {
  if (value.length.isOdd || !RegExp(r'^[0-9a-fA-F]*$').hasMatch(value)) throw const FormatException();
  return Uint8List.fromList([for (var i=0;i<value.length;i+=2) int.parse(value.substring(i,i+2),radix:16)]);
}
String hex(List<int> value) => value.map((b)=>b.toRadixString(16).padLeft(2,'0')).join();
Uint8List pattern(int n)=>Uint8List.fromList(List.generate(n,(i)=>(i*17+23)%251));
Map<String,Object> summary(List<int> value)=>{'length':value.length,'sha256':hashes.sha256.convert(value).toString()};
Uint8List encrypted(Map c,String root)=>c['encrypted_file'] is String
  ? File('$root/${c['encrypted_file']}').readAsBytesSync() : base64.decode(c['encrypted'] as String);

Future<Object?> run(Map c,String root,FilenCrypto filen,List<Map<String,dynamic>> exports) async {
  final op=c['op'] as String;
  switch(op) {
    case 'filen.login': return filen.deriveKeys(c['password'] as String,c['version'] as int,c['salt'] as String);
    case 'filen.metadata.encrypt': return filen.encryptMetadata002(c['text'] as String,c['key'] as String);
    case 'filen.metadata.decrypt': return filen.decryptMetadata002(c['encrypted'] as String,c['key'] as String);
    case 'filen.chunk':
    case 'filen.chunk.decrypt':
      final key=unhex(c['key'] as String);
      final plain=await filen.decryptData(encrypted(c,root),key);
      if(c['export']==true) {
        final sealed=await filen.encryptData(pattern(c['size'] as int),key);
        exports.add({'id':c['id'],'op':'filen.chunk.decrypt','encrypted':base64.encode(sealed),'key':c['key'],'expected':c['expected']});
      }
      return summary(plain);
    case 'internxt.password': return internxt.passToHash(c['password'] as String,c['salt'] as String)['hash'];
    case 'internxt.text.decrypt': return internxt.decryptTextWithKey(c['encrypted'] as String,c['key'] as String);
    case 'internxt.text.roundtrip':
      final sealed=internxt.encryptTextWithKey(c['text'] as String,c['key'] as String);
      final plain=internxt.decryptTextWithKey(sealed,c['key'] as String);
      exports.add({'id':c['id'],'op':'internxt.text.decrypt','encrypted':sealed,'key':c['key'],'expected':c['expected']});
      return plain;
    case 'internxt.key': return hex(internxt.generateFileKey(c['mnemonic'] as String,c['bucket'] as String,unhex(c['index'] as String)));
    case 'internxt.ctr':
    case 'internxt.range':
    case 'internxt.ctr.decrypt':
      final plain=internxt.decryptStreamAt(encrypted(c,root),c['mnemonic'] as String,c['bucket'] as String,c['index'] as String,(c['offset'] as int?)??0);
      if(c['export']==true) {
        final sealed=internxt.encryptStream(pattern(c['size'] as int),c['mnemonic'] as String,c['bucket'] as String);
        exports.add({'id':c['id'],'op':'internxt.ctr.decrypt','encrypted':base64.encode(sealed['data'] as Uint8List),
          'index':sealed['index'],'bucket':c['bucket'],'mnemonic':c['mnemonic'],'expected':c['expected']});
      }
      return summary(plain);
    default: throw UnsupportedError(op);
  }
}
Future<void> main(List<String> args) async {
  if(args.length!=2) throw ArgumentError('probe <fixtures.json> <output.json>');
  final input=jsonDecode(File(args[0]).readAsStringSync()) as Map;
  final backend=Platform.environment['FILEN_TEST_BACKEND']??'cryptography';
  final crypto=FilenCrypto(random:FixedNonceRandom(),aesGcm:backend=='pointycastle'?PointycastleBackend():CryptographyBackend());
  final results=<String,Object?>{}, exports=<Map<String,dynamic>>[];
  for(final raw in input['cases'] as List) {
    final c=raw as Map;
    try { results[c['id'] as String]={'status':'ok','value':await run(c,File(args[0]).parent.path,crypto,exports)}; }
    catch(error) { results[c['id'] as String]={'status':'rejected'}; }
  }
  File(args[1]).writeAsStringSync(jsonEncode({'schema':1,'engine':'dart','backend':backend,'results':results,'exports':exports}));
  stdout.writeln('Dart probe: ${results.length} cases, ${exports.length} exports ($backend)');
}
