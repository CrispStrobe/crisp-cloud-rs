import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';
import 'package:crypto/crypto.dart' as hashes;
import 'package:filen_client/crypto.dart';
import 'package:filen_client/aes_gcm_backend.dart';
import 'package:internxt_client/crypto.dart' as internxt;
import 'package:filen_client/api.dart' as filen_api;
import 'package:filen_client/cache.dart' as filen_cache;
import 'package:internxt_client/drive.dart' as drive;
import 'package:internxt_client/cache.dart' as internxt_cache;
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';

// The only mocked component is transport routing. Production SDKs construct
// and parse every request/response; a real loopback HTTP server verifies them.
class LoopbackClient extends http.BaseClient {
  final Uri base;
  final http.Client inner = IOClient(HttpClient()..connectionTimeout=const Duration(seconds:5));
  LoopbackClient(String value):base=Uri.parse(value) {
    if(base.host!='127.0.0.1'||base.scheme!='http') throw ArgumentError('Loopback only');
  }
  @override Future<http.StreamedResponse> send(http.BaseRequest request) async {
    final url=request.url.host=='gateway.filen.io'
      ? base.replace(path:base.path+request.url.path,query:request.url.query) : request.url;
    if(url.host!='127.0.0.1'||url.port!=base.port||!url.path.startsWith('${base.path}/')) throw StateError('Non-fixture HTTP request');
    final copy=http.Request(request.method,url)
      ..headers.addAll(request.headers)
      ..followRedirects=false
      ..bodyBytes=await request.finalize().toBytes();
    return inner.send(copy).timeout(const Duration(seconds:10));
  }
  @override void close()=>inner.close();
}

Future<Object?> mock(Map c,FilenCrypto crypto) async {
  final base=c['base_url'] as String, client=LoopbackClient(c['base_url'] as String);
  try {
    if(c['op']=='filen.mock.list') {
      final cache=filen_cache.FilenCache(),api=filen_api.FilenApi(client:client)..apiKey='synthetic-test-token';
      List<Map<String,dynamic>> items=[];
      for(var i=0;i<((c['repeat'] as int?)??1);i++) {
        items=[...await cache.listFoldersAsync('root',api:api,crypto:crypto,masterKeys:['conformance-only-master-key']),
          ...await cache.listFolderFiles('root',api:api,crypto:crypto,masterKeys:['conformance-only-master-key'])];
      }
      final normalized=items.map((i)=><String,Object?>{'uuid':i['uuid'],'name':i['name'],'is_dir':i['type']=='folder','size':i['size']}).toList();
      normalized.sort((a,b)=>(a['uuid'] as String).compareTo(b['uuid'] as String));
      return normalized;
    }
    final folders=<String,internxt_cache.CacheEntry>{},files=<String,internxt_cache.CacheEntry>{};
    return await http.runWithClient(() async {
      if(c['op']=='internxt.mock.list') {
        List<Map<String,dynamic>> items=[];
        for(var i=0;i<((c['repeat'] as int?)??1);i++) {
          items=[...await drive.listFolders(base,'synthetic-test-token',folders,'root',client:client),
            ...await drive.listFolderFiles(base,'synthetic-test-token',files,'root',client:client)];
        }
        final normalized=items.map((i)=><String,Object?>{'uuid':i['uuid'],
          'name':'${i['name']}${i['type']=='file'&&(i['fileType'] as String).isNotEmpty?'.${i['fileType']}':''}',
          'is_dir':i['type']=='folder','size':i['size']}).toList();
        normalized.sort((a,b)=>(a['uuid'] as String).compareTo(b['uuid'] as String));
        return normalized;
      }
      switch(c['action']) {
        case 'create': return (await drive.createFolder(base,'synthetic-test-token',folders,files,'新規 Grüße','root'))['uuid'];
        case 'rename': await drive.renameFile(base,'synthetic-test-token',folders,files,'file','新規 Grüße','txt',client:client); return true;
        case 'move': await drive.moveFile(base,'synthetic-test-token',folders,files,'file','destination',client:client); return true;
        case 'trash': await drive.trashItems(base,'synthetic-test-token',folders,files,'file','file',client:client); return true;
        default: throw UnsupportedError('mutation');
      }
    },()=>client);
  } finally {client.close();}
}

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
  if(op.contains('.mock.')) return mock(c,filen);
  switch(op) {
    case 'filen.login': return filen.deriveKeys(c['password'] as String,c['version'] as int,c['salt'] as String);
    case 'filen.metadata.encrypt': return filen.encryptMetadata002(c['text'] as String,c['key'] as String);
    case 'filen.metadata.decrypt': return filen.decryptMetadata002(c['encrypted'] as String,c['key'] as String);
    case 'filen.chunk.encrypt.reject': return base64.encode(await filen.encryptData(Uint8List.fromList([1,2,3]),unhex(c['key'] as String)));
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
    case 'internxt.stream':
      final raw=encrypted(c,root), output=BytesBuilder();
      final cipher=internxt.downloadDecryptor(c['mnemonic'] as String,c['bucket'] as String,c['index'] as String);
      var cursor=0;
      for(final length in c['chunks'] as List) {
        final end=cursor+(length as int);
        output.add(cipher.process(Uint8List.sublistView(raw,cursor,end)));
        cursor=end;
      }
      if(cursor!=raw.length) throw StateError('incomplete streaming fixture');
      return summary(output.takeBytes());
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
  final aes=backend=='pointycastle' ? PointycastleBackend((n)=>Uint8List.fromList(List.generate(n,(i)=>i)))
    : backend=='native' ? chooseAesGcmBackend() : CryptographyBackend();
  final crypto=FilenCrypto(random:FixedNonceRandom(),aesGcm:aes);
  final results=<String,Object?>{}, exports=<Map<String,dynamic>>[];
  for(final raw in input['cases'] as List) {
    final c=raw as Map;
    try { results[c['id'] as String]={'status':'ok','value':await run(c,File(args[0]).parent.path,crypto,exports)}; }
    catch(error) { results[c['id'] as String]={'status':'rejected'}; }
  }
  File(args[1]).writeAsStringSync(jsonEncode({'schema':1,'engine':'dart','backend':backend,'actual_backend':aes.name,'results':results,'exports':exports}));
  stdout.writeln('Dart probe: ${results.length} cases, ${exports.length} exports ($backend)');
}
