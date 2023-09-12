import 'dart:convert';
import 'dart:io';
// import 'dart:async';

import 'package:async/async.dart';
import 'package:path/path.dart';
import 'package:http/http.dart';

import 'package:amazon_cognito_identity_dart_2/sig_v4.dart';
import 'package:built_value/serializer.dart';
import 'package:xml2json/xml2json.dart';

// upload용
import 'package:amazon_cognito_identity_dart_2/cognito.dart' as cog;

import 'package:flutter_aws_s3_client/src/client/exceptions.dart';

import '../model/list_bucket_result.dart';
import '../model/list_bucket_result_parker.dart';

class Policy {
  String expiration;
  String region;
  String bucket;
  String key;
  String credential;
  String datetime;
  String sessionToken;
  int maxFileSize;

  Policy(this.key, this.bucket, this.datetime, this.expiration, this.credential, this.maxFileSize, this.sessionToken,
      {this.region = 'us-east-1'});

  factory Policy.fromS3PresignedPost(
      String key, String bucket, int expiryMinutes, String accessKeyId, int maxFileSize, String sessionToken,
      {String region = 'us-east-1'}) {
    final datetime = SigV4.generateDatetime();
    final expiration = (DateTime.now()).add(Duration(minutes: expiryMinutes)).toUtc().toString().split(' ').join('T');
    final cred = '$accessKeyId/${SigV4.buildCredentialScope(datetime, region, 's3')}';
    final p = Policy(key, bucket, datetime, expiration, cred, maxFileSize, sessionToken, region: region);
    return p;
  }

  String encode() {
    final bytes = utf8.encode(toString());
    return base64.encode(bytes);
  }

  @override
  String toString() {
    // Safe to remove the "acl" line if your bucket has no ACL permissions
    // {"acl": "public-read"},
    return '''
    { "expiration": "${this.expiration}",
      "conditions": [
        {"bucket": "${this.bucket}"},
        ["starts-with", "\$key", "${this.key}"],
        ["content-length-range", 1, ${this.maxFileSize}],
        {"x-amz-credential": "${this.credential}"},
        {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
        {"x-amz-date": "${this.datetime}" },
        {"x-amz-security-token": "${this.sessionToken}" }
      ]
    }
    ''';
  }
}

final _dd = (X509Certificate cert, String host, int port) => true;

class MyHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (X509Certificate cert, String host, int port) => true;
  }
}

class AwsS3Client {
  final String _secretKey;
  final String _accessKey;
  final String _host;
  final String _region;
  final String _bucketId;
  final String? _sessionToken;
  final Client _client;

  static const _service = "s3";

  /// Creates a new AwsS3Client instance.
  ///
  /// @param secretKey The secret key. Required. see https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html
  /// @param accessKey The access key. Required. see https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html
  /// @param bucketId The bucket. Required. See https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingBucket.html#access-bucket-intro
  /// @param host The host, in path-style. Defaults to "s3.$region.amazonaws.com". See https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingBucket.html#access-bucket-intro
  /// @param region The region of the bucket. Required.
  /// @param sessionToken The session token. Optional.
  /// @param client The http client. Optional. Useful for debugging.
  AwsS3Client(
      {required String secretKey,
      required String accessKey,
      required String bucketId,
      String? host,
      required String region,
      String? sessionToken,
      Client? client})
      : _accessKey = accessKey,
        _secretKey = secretKey,
        _host = host ?? "s3.$region.amazonaws.com",
        _bucketId = bucketId,
        _region = region,
        _sessionToken = sessionToken,
        _client = client ?? Client() {
    // HttpOverrides.global = new MyHttpOverrides();
  }

  Future<ListBucketResult?> listObjects({String? prefix, String? delimiter, int? maxKeys, String? startAfterId}) async {
    final response = await _doSignedGetRequest(key: '', queryParams: {
      "list-type": "2",
      if (prefix != null) "prefix": prefix,
      if (delimiter != null) "delimiter": delimiter,
      // if (maxKeys != null) "maxKeys": maxKeys.toString(),
      if (maxKeys != null) "max-keys": maxKeys.toString(),
      if (startAfterId != null) "start-after": startAfterId,
    });
    _checkResponseError(response);
    return _parseListObjectResponse(response.body);
  }

  Future<Response> getObject(String key) {
    return _doSignedGetRequest(key: key);
  }

  Future<Response> putObject(String key, File fp) {
    // return _doSignedGetRequest(key: key);
    final buf = fp.readAsBytesSync();
    final SignedRequestParams params = buildSignedGetParamsPut(buf, key: key);
    // print('uri - ${params.uri}, ${params.headers}');
    return _client.put(params.uri, headers: params.headers, body: buf);
  }

  Future<Response> headObject(String key) {
    return _doSignedHeadRequest(key: key);
  }

  String keytoPath(String key) => "${'/$key'.split('/').map(Uri.encodeQueryComponent).join('/')}";

  // s3는 되는데 b2는 이거 지원 안하다 - 그것도 HttpOverrides.global = new MyHttpOverrides() 해야만 된다
  // 안하면 아래 오류남
  // HandshakeException: Handshake error in client (OS Error:
  // CERTIFICATE_VERIFY_FAILED: application verification failure(handshake.cc:393))
  // https://stackoverflow.com/questions/54285172/how-to-solve-flutter-certificate-verify-failed-error-while-performing-a-post-req
  // 여기보면 letsencrypt 인증서 문제인듯

  // 이거는 browser-based uploads using post인듯
  // https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html
  // https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
  // https://www.matano.dev/blog-archive/2022/02/14/s3-post-policy
  Future postUpload(String key, File file) async {
    // https://github.com/furaiev/amazon-cognito-identity-dart-2/#for-s3-uploads
    final stream = ByteStream(DelegatingStream.typed(file.openRead()));
    final length = await file.length();

    // final uri = Uri.parse(_s3Endpoint);
    final uri = Uri.parse('https://$_bucketId.$_host');
    final req = MultipartRequest("POST", uri);
    final multipartFile = MultipartFile('file', stream, length, filename: basename(file.path));

    // final String fileName = 'square-cinnamon.jpg';
    // final String usrIdentityId = _credentials.userIdentityId;
    // final String bucketKey = 'test/$usrIdentityId/$fileName';

    final policy = Policy.fromS3PresignedPost(
        key,
        // 'my-s3-bucket',
        _bucketId,
        15,
        // _credentials.accessKeyId,
        _accessKey,
        length,
        // _credentials.sessionToken,
        _sessionToken ?? '',
        region: _region);

    final signKey = SigV4.calculateSigningKey(
        // _credentials.secretAccessKey, policy.datetime, _region, 's3');
        _secretKey,
        policy.datetime,
        _region,
        's3');
    final signature = SigV4.calculateSignature(signKey, policy.encode());

    req.files.add(multipartFile);

    req.fields['key'] = policy.key;
    req.fields['Policy'] = policy.encode();
    // req.fields['acl'] = 'public-read'; // Safe to remove this if your bucket has no ACL permissions
    req.fields['X-Amz-Credential'] = policy.credential;
    req.fields['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256';
    req.fields['X-Amz-Date'] = policy.datetime;
    req.fields['X-Amz-Signature'] = signature;
    // req.fields['x-amz-security-token'] = _credentials.sessionToken;
    req.fields['x-amz-security-token'] = _sessionToken ?? '';
    try {
      final res = await req.send();
      await for (final value in res.stream.transform(utf8.decoder)) {
        print('upload: $value');
      }
    } catch (e) {
      print('s3client exception $e');
    }
  }

  ///Returns a [SignedRequestParams] object containing the uri and the HTTP headers
  ///needed to do a signed GET request to AWS S3. Does not actually execute a request.
  ///You can use this method to integrate this client with an HTTP client of your choice.
  SignedRequestParams buildSignedGetParamsPut(List<int> buf, {required String key, Map<String, String>? queryParams}) {
    final unencodedPath = key;
    // Uri.https에 +문자를 넣으면 space가 되버린다
    // final uri = Uri.https(_host, unencodedPath, queryParams);
    final host = '$_bucketId.$_host';
    final uri = Uri(
      scheme: 'https',
      host: host,
      path: unencodedPath.split('/').map(Uri.encodeComponent).join('/'),
      queryParameters: queryParams,
    );
    // final payload = SigV4.hashCanonicalRequest('');
    final payload = SigV4.hexEncode(SigV4.hash(buf));
    final datetime = SigV4.generateDatetime();
    final credentialScope = SigV4.buildCredentialScope(datetime, _region, _service);

    final canonicalQuery = SigV4.buildCanonicalQueryString(queryParams);
    final canonicalRequest = '''PUT
${'/$unencodedPath'.split('/').map(Uri.encodeComponent).join('/')}
$canonicalQuery
host:$host
x-amz-content-sha256:$payload
x-amz-date:$datetime

host;x-amz-content-sha256;x-amz-date
$payload''';

    final stringToSign =
        SigV4.buildStringToSign(datetime, credentialScope, SigV4.hashCanonicalRequest(canonicalRequest));
    final signingKey = SigV4.calculateSigningKey(_secretKey, datetime, _region, _service);
    final signature = SigV4.calculateSignature(signingKey, stringToSign);

    final authorization = [
      'AWS4-HMAC-SHA256 Credential=$_accessKey/$credentialScope',
      'SignedHeaders=host;x-amz-content-sha256;x-amz-date',
      'Signature=$signature',
    ].join(',');

    return SignedRequestParams(uri, {
      'Authorization': authorization,
      'x-amz-content-sha256': payload,
      'x-amz-date': datetime,
      'Content-Length': '${buf.length}',
      // 'Expect': '100-continue',
    });
  }

  ///Returns a [SignedRequestParams] object containing the uri and the HTTP headers
  ///needed to do a signed GET request to AWS S3. Does not actually execute a request.
  ///You can use this method to integrate this client with an HTTP client of your choice.
  SignedRequestParams buildSignedGetParams({required String key, Map<String, String>? queryParams}) {
    final unencodedPath = "$_bucketId/$key";
    // Uri.https에 +문자를 넣으면 space가 되버린다
    // final uri = Uri.https(_host, unencodedPath, queryParams);
    final uri = Uri(
      scheme: 'https',
      host: _host,
      path: unencodedPath.split('/').map(Uri.encodeComponent).join('/'),
      queryParameters: queryParams,
    );
    final payload = SigV4.hashCanonicalRequest('');
    final datetime = SigV4.generateDatetime();
    final credentialScope = SigV4.buildCredentialScope(datetime, _region, _service);

    final canonicalQuery = SigV4.buildCanonicalQueryString(queryParams);
    final canonicalRequest = '''GET
${'/$unencodedPath'.split('/').map(Uri.encodeComponent).join('/')}
$canonicalQuery
host:$_host
x-amz-content-sha256:$payload
x-amz-date:$datetime
x-amz-security-token:${_sessionToken ?? ""}

host;x-amz-content-sha256;x-amz-date;x-amz-security-token
$payload''';

    final stringToSign =
        SigV4.buildStringToSign(datetime, credentialScope, SigV4.hashCanonicalRequest(canonicalRequest));
    final signingKey = SigV4.calculateSigningKey(_secretKey, datetime, _region, _service);
    final signature = SigV4.calculateSignature(signingKey, stringToSign);

    final authorization = [
      'AWS4-HMAC-SHA256 Credential=$_accessKey/$credentialScope',
      'SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token',
      'Signature=$signature',
    ].join(',');

    return SignedRequestParams(uri, {
      'Authorization': authorization,
      'x-amz-content-sha256': payload,
      'x-amz-date': datetime,
    });
  }

  Future<Response> _doSignedGetRequest({
    required String key,
    Map<String, String>? queryParams,
  }) async {
    final SignedRequestParams params = buildSignedGetParams(key: key, queryParams: queryParams);
    return _client.get(params.uri, headers: params.headers);
  }

  Future<Response> _doSignedHeadRequest({
    required String key,
    Map<String, String>? queryParams,
  }) async {
    final SignedRequestParams params = buildSignedGetParams(key: key, queryParams: queryParams);
    return _client.head(params.uri, headers: params.headers);
  }

  void _checkResponseError(Response response) {
    if (response.statusCode >= 200 && response.statusCode <= 300) {
      return;
    }
    switch (response.statusCode) {
      case 403:
        throw NoPermissionsException(response);
      default:
        throw S3Exception(response);
    }
  }
}

class SignedRequestParams {
  final Uri uri;
  final Map<String, String> headers;

  const SignedRequestParams(this.uri, this.headers);
}

/// aws s3 list bucket response string -> [ListBucketResult] object,
/// this function should be called via [compute]
ListBucketResult? _parseListObjectResponse(String responseXml) {
  //parse xml
  final Xml2Json myTransformer = Xml2Json();
  myTransformer.parse(responseXml);
  //convert xml to json
  String jsonString = myTransformer.toParker();
  //parse json to src.model objects
  try {
    ListBucketResult? parsedObj = ListBucketResultParker.fromJson(jsonString).result;

    return parsedObj;
  } on DeserializationError {
    //fix for https://github.com/diagnosia/flutter_aws_s3_client/issues/6
    //issue due to json/xml transform: Lists with 1 element are transformed to json objects instead of lists
    final fixedJson = json.decode(jsonString);

    fixedJson["ListBucketResult"]["Contents"] = [fixedJson["ListBucketResult"]["Contents"]];

    return ListBucketResultParker.fromJsonMap(fixedJson).result;
  }
}
