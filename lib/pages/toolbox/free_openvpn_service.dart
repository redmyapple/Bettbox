// Free OpenVPN server discovery for Bettbox.
//
// Pure Dart (dart:io/convert/async/math) so it can be validated headlessly with
// `dart run` before the Flutter page is wired up, and reused on any desktop
// platform Bettbox targets.
//
// Ported from the verified reference implementation in
// D:/net-tools/purvpn-port/serverhub.py (1.2.0). Three facts are load-bearing:
//   * vpngate.net and softether.org are unreachable from many networks — race
//     the official API plus five GitHub mirrors and take the first good reply.
//   * socket/DNS stalls are real; every request runs under a hard timeout.
//   * TCP 443 connectivity is NOT proof of OpenVPN — send a control-channel
//     hard-reset (opcode 7) and require a server hard-reset (opcode 8) back.
//
// This module does not install anything, does not touch routes and does not
// change the system proxy. It produces server data and a mihomo proxy profile.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

/// Official API first, then mirrors that serve the same VPN Gate CSV.
const List<String> vpnGateSources = <String>[
  'https://www.vpngate.net/api/iphone/',
  'https://raw.githubusercontent.com/rainsstory/vpngate-mirror/main/api/iphone/index.html',
  'https://raw.githubusercontent.com/ezedin63/vpngate-mirror/main/data/vpngate.csv',
  'https://raw.githubusercontent.com/Ahriman117/vpngate-cache/main/servers.csv',
  'https://raw.githubusercontent.com/sinspired/VpngateAPI/main/servers.csv',
  'https://raw.githubusercontent.com/GeorgeXie2333/vpngate-list-mirror/main/data/vpngate.csv',
];

const String geoBatchUrl =
    'http://ip-api.com/batch?fields=status,country,countryCode,regionName,city,isp,query';

const String localProxy = 'http://127.0.0.1:7890';

// OpenVPN control opcodes (openvpn ssl_pkt.h).
const int pControlHardResetClientV2 = 7;
const int pControlHardResetServerV2 = 8;

const Map<String, String> cnNames = <String, String>{
  'JP': '日本', 'KR': '韩国', 'TH': '泰国', 'VN': '越南', 'TW': '中国台湾',
  'HK': '中国香港', 'SG': '新加坡', 'MY': '马来西亚', 'ID': '印尼', 'PH': '菲律宾',
  'IN': '印度', 'US': '美国', 'CA': '加拿大', 'MX': '墨西哥', 'BR': '巴西',
  'AR': '阿根廷', 'CL': '智利', 'GB': '英国', 'IE': '爱尔兰', 'FR': '法国',
  'DE': '德国', 'NL': '荷兰', 'BE': '比利时', 'CH': '瑞士', 'AT': '奥地利',
  'SE': '瑞典', 'NO': '挪威', 'DK': '丹麦', 'FI': '芬兰', 'PL': '波兰',
  'CZ': '捷克', 'SK': '斯洛伐克', 'HU': '匈牙利', 'RO': '罗马尼亚', 'BG': '保加利亚',
  'RS': '塞尔维亚', 'HR': '克罗地亚', 'SI': '斯洛文尼亚', 'GR': '希腊', 'TR': '土耳其',
  'UA': '乌克兰', 'RU': '俄罗斯', 'BY': '白俄罗斯', 'KZ': '哈萨克斯坦', 'LT': '立陶宛',
  'LV': '拉脱维亚', 'EE': '爱沙尼亚', 'MD': '摩尔多瓦', 'AL': '阿尔巴尼亚',
  'IS': '冰岛', 'PT': '葡萄牙', 'ES': '西班牙', 'IT': '意大利', 'AU': '澳大利亚',
  'NZ': '新西兰', 'ZA': '南非', 'NG': '尼日利亚', 'EG': '埃及', 'AE': '阿联酋',
  'IR': '伊朗', 'IL': '以色列', 'SA': '沙特', 'PK': '巴基斯坦', 'BD': '孟加拉',
  'CN': '中国大陆', 'MO': '中国澳门', 'KH': '柬埔寨', 'MM': '缅甸', 'LK': '斯里兰卡',
};

String flagEmoji(String cc) {
  final code = cc.trim().toUpperCase();
  if (code.length != 2) return '\u{1F3F3}';
  final units = <int>[];
  for (final c in code.codeUnits) {
    if (c < 65 || c > 90) return '\u{1F3F3}';
    units.add(0x1F1E6 + c - 65);
  }
  return String.fromCharCodes(units);
}

String locationLabel(String cc, [String countryLong = '']) {
  final code = cc.trim().toUpperCase();
  final name = cnNames[code] ?? countryLong.trim();
  if (code.isEmpty) return '${flagEmoji(code)} $name';
  return '${flagEmoji(code)} $name ($code)';
}

/// One discovered OpenVPN server. Immutable so the page can hold a plain list.
class FreeOpenVpnServer {
  final String server; // IPv4
  final int port;
  final String cc; // ISO2, corrected by real GeoIP
  final String location; // flag + Chinese/English name + ISO2
  final String detail; // city · ISP
  final int score;
  final int ping;
  final double speedMbps;
  final String proto;
  final String cipher;
  final String auth;
  final String ca;
  final String cert;
  final String key;
  final bool alive;
  final int? handshakeMs;
  final String reason;
  final bool geoMismatch;

  const FreeOpenVpnServer({
    required this.server,
    required this.port,
    required this.cc,
    required this.location,
    this.detail = '',
    required this.score,
    this.ping = 0,
    this.speedMbps = 0,
    this.proto = 'tcp',
    required this.cipher,
    required this.auth,
    required this.ca,
    required this.cert,
    required this.key,
    this.alive = false,
    this.handshakeMs,
    this.reason = '',
    this.geoMismatch = false,
  });

  FreeOpenVpnServer copyWith({
    String? cc,
    String? location,
    String? detail,
    bool? geoMismatch,
    bool? alive,
    int? handshakeMs,
    String? reason,
  }) {
    return FreeOpenVpnServer(
      server: server,
      port: port,
      cc: cc ?? this.cc,
      location: location ?? this.location,
      detail: detail ?? this.detail,
      score: score,
      ping: ping,
      speedMbps: speedMbps,
      proto: proto,
      cipher: cipher,
      auth: auth,
      ca: ca,
      cert: cert,
      key: key,
      alive: alive ?? this.alive,
      handshakeMs: handshakeMs ?? this.handshakeMs,
      reason: reason ?? this.reason,
      geoMismatch: geoMismatch ?? this.geoMismatch,
    );
  }

  /// Stable, unique node name for the generated mihomo profile.
  String get nodeName => 'FreeOVPN $location $server';
}

/// Result of one fetch attempt, carrying the route/mirror that won.
class FetchResult {
  final String text;
  final String source;
  final String route;
  const FetchResult(this.text, this.source, this.route);
}

/// TCP framing reader over a single [Socket] subscription.
class _SocketReader {
  final List<int> _buf = <int>[];
  late final StreamSubscription<List<int>> _sub;
  Completer<void>? _waiting;
  int _need = 0;
  Object? _error;

  _SocketReader(Socket socket) {
    _sub = socket.listen(
      _onData,
      onDone: _onDone,
      onError: _onError,
      cancelOnError: true,
    );
  }

  void _onData(List<int> data) {
    _buf.addAll(data);
    _wake();
  }

  void _onDone() {
    _error ??= const SocketException('EOF');
    _wake();
  }

  void _onError(Object e) {
    _error = e;
    _wake();
  }

  void _wake() {
    final w = _waiting;
    if (w != null && !w.isCompleted && (_buf.length >= _need || _error != null)) {
      w.complete();
    }
  }

  Future<List<int>> read(int n, Duration timeout) async {
    _need = n;
    _error = null;
    final c = Completer<void>();
    _waiting = c;
    _wake();
    await c.future.timeout(timeout);
    _waiting = null;
    if (_buf.length < n) throw _error ?? const SocketException('EOF');
    final out = List<int>.from(_buf.take(n));
    _buf.removeRange(0, n);
    return out;
  }

  Future<void> close() async {
    await _sub.cancel();
  }
}

class FreeOpenVpnService {
  FreeOpenVpnService({this.timeout = const Duration(seconds: 8)});

  /// Hard timeout applied to every HTTP hop (covers connect + DNS stall).
  final Duration timeout;

  String _lastGoodSource = '';

  /// Fetch, parse, geo-correct and probe. [log] receives progress lines.
  Future<List<FreeOpenVpnServer>> discover({
    bool probe = true,
    Duration probeTimeout = const Duration(seconds: 4),
    int concurrency = 32,
    void Function(String)? log,
  }) async {
    final fetched = await fetchCsv(log: log);
    var servers = parseCsv(fetched.text);
    log?.call('解析到 ${servers.length} 条 VPN Gate 记录（来源 ${fetched.source}·${fetched.route}）');

    await enrichGeo(servers, log: log);
    if (probe) await probeAll(servers, timeout: probeTimeout, concurrency: concurrency, log: log);
    return servers;
  }

  /// Race official API + mirrors over both direct and the local proxy.
  /// First response larger than 20 KB wins.
  Future<FetchResult> fetchCsv({void Function(String)? log}) async {
    final sources = <String>[
      if (_lastGoodSource.isNotEmpty) _lastGoodSource,
      ...vpnGateSources.where((s) => s != _lastGoodSource),
    ];
    final tries = <Future<FetchResult>>[];
    for (final url in sources) {
      final who = url == vpnGateSources.first
          ? '官方'
          : Uri.tryParse(url)?.pathSegments.firstWhere(
                (s) => s.isNotEmpty,
                orElse: () => 'mirror',
              ) ??
              'mirror';
      tries.add(_tryFetch(url, useProxy: false).then(
          (bytes) => _accept(bytes, who, '直连'),
        ));
      tries.add(_tryFetch(url, useProxy: true).then(
          (bytes) => _accept(bytes, who, '本机代理'),
        ));
    }

    final completer = Completer<FetchResult>();
    for (final t in tries) {
      t.then(
        (r) {
          if (!completer.isCompleted) completer.complete(r);
        },
        onError: (_) {}, // other routes are allowed to fail
      );
    }
    try {
      final result = await completer.future.timeout(timeout + const Duration(seconds: 2));
      _lastGoodSource = sources.firstWhere(
        (s) => result.source != '官方' ? s.contains(result.source) : s == vpnGateSources.first,
        orElse: () => _lastGoodSource,
      );
      log?.call('数据源：${result.source}（${(result.text.length / 1024).round()} KB，${result.route}）');
      return result;
    } on TimeoutException {
      throw const SocketException('全部 VPN Gate 数据源超时');
    }
  }

  FetchResult _accept(String text, String who, String route) {
    if (text.length < 20000) throw const SocketException('内容过短');
    return FetchResult(text, who, route);
  }

  Future<String> _tryFetch(String url, {required bool useProxy}) async {
    final client = HttpClient();
    client.connectionTimeout = timeout;
    client.findProxy = (_) => useProxy ? 'PROXY 127.0.0.1:7890' : 'DIRECT';
    try {
      final req = await client.getUrl(Uri.parse(url)).timeout(timeout);
      req.headers.set('User-Agent', 'Mozilla/5.0 Bettbox-FreeOpenVPN/1.0');
      req.headers.set('Accept', '*/*');
      final resp = await req.close().timeout(timeout);
      final bytes = await resp.toList().timeout(timeout);
      return utf8.decode(
        bytes.expand((b) => b).toList(),
        allowMalformed: true,
      );
    } finally {
      client.close(force: true);
    }
  }

  /// Parse the 15-column VPN Gate CSV into typed servers, deduped by IP.
  List<FreeOpenVpnServer> parseCsv(String text) {
    final lines = text
        .split(RegExp(r'\r?\n'))
        .where((l) => l.isNotEmpty && !l.startsWith('*'))
        .toList();
    if (lines.isEmpty) return const <FreeOpenVpnServer>[];
    if (lines.first.startsWith('#')) lines[0] = lines.first.substring(1);

    final byIp = <String, FreeOpenVpnServer>{};
    for (final line in lines) {
      final row = _parseCsvLine(line);
      if (row.length < 15 || !row[1].contains('.')) continue;
      final ip = row[1].trim();
      final b64 = row[14].trim();
      if (b64.isEmpty) continue;
      String ovpn;
      try {
        ovpn = utf8.decode(base64.decode(b64), allowMalformed: true);
      } catch (_) {
        continue;
      }
      final ca = _inlineBlock(ovpn, 'ca');
      final cert = _inlineBlock(ovpn, 'cert');
      final key = _inlineBlock(ovpn, 'key');
      if (ca.isEmpty || cert.isEmpty || key.isEmpty) continue;
      final remote = _directive(ovpn, 'remote') ?? '443';
      final parts = remote.split(RegExp(r'\s+'));
      final port = int.tryParse(parts.length > 1 ? parts[1] : parts.first) ?? 443;
      final score = int.tryParse(row[2].trim()) ?? 0;
      final prev = byIp[ip];
      if (prev != null && prev.score >= score) continue;
      byIp[ip] = FreeOpenVpnServer(
        server: ip,
        port: port,
        cc: row[6].trim().toUpperCase(),
        location: locationLabel(row[6], row[5]),
        score: score,
        ping: int.tryParse(row[3].trim()) ?? 0,
        speedMbps: (int.tryParse(row[4].trim()) ?? 0) / 1e6,
        proto: _directive(ovpn, 'proto') ?? 'tcp',
        cipher: _directive(ovpn, 'cipher') ?? 'AES-128-CBC',
        auth: _directive(ovpn, 'auth') ?? 'SHA1',
        ca: ca,
        cert: cert,
        key: key,
      );
    }
    final out = byIp.values.toList()
      ..sort((a, b) => b.score.compareTo(a.score));
    return out;
  }

  /// Correct CSV country codes with real GeoIP (CSV can be badly wrong:
  /// 104.28.246.125 was labelled US but is a RU Cloudflare WARP exit).
  Future<void> enrichGeo(List<FreeOpenVpnServer> servers,
      {void Function(String)? log}) async {
    for (var start = 0; start < servers.length; start += 100) {
      final chunk = servers.skip(start).take(100).toList();
      final body = jsonEncode(
        chunk.map((s) => <String, String>{'query': s.server}).toList(),
      );
      try {
        final res = await _post(geoBatchUrl, body);
        final data = jsonDecode(res) as List<dynamic>;
        for (var i = 0; i < chunk.length && i < data.length; i++) {
          final g = data[i];
          if (g is! Map<String, dynamic> || g['status'] != 'success') continue;
          final realCc = (g['countryCode'] as String? ?? '').toUpperCase();
          if (realCc.isEmpty) continue;
          final city = (g['city'] as String? ?? '').trim();
          final isp = (g['isp'] as String? ?? '').trim();
          final detail = <String>[if (city.isNotEmpty) city, if (isp.isNotEmpty) isp].join(' · ');
          servers[start + i] = chunk[i].copyWith(
            cc: realCc,
            location: locationLabel(realCc, g['country'] as String? ?? ''),
            detail: detail,
            geoMismatch: realCc != chunk[i].cc,
          );
        }
      } catch (_) {
        // GeoIP is best-effort; keep CSV locations when it fails.
      }
    }
    final mismatches = servers.where((s) => s.geoMismatch).length;
    log?.call('GeoIP 校正 ${servers.length} 条，$mismatches 条国家与 CSV 不符');
  }

  Future<String> _post(String url, String body) async {
    final client = HttpClient()
      ..connectionTimeout = timeout
      ..findProxy = (_) => 'PROXY 127.0.0.1:7890';
    try {
      final req = await client.postUrl(Uri.parse(url)).timeout(timeout);
      req.headers.contentType = ContentType('application', 'json', charset: 'utf-8');
      req.headers.set('User-Agent', 'Bettbox-FreeOpenVPN/1.0');
      req.write(body);
      final resp = await req.close().timeout(timeout);
      final bytes = await resp.toList().timeout(timeout);
      return utf8.decode(bytes.expand((b) => b).toList(), allowMalformed: true);
    } finally {
      client.close(force: true);
    }
  }

  /// OpenVPN control-channel handshake. TCP open alone is not enough.
  Future<void> probeAll(
    List<FreeOpenVpnServer> servers, {
    Duration timeout = const Duration(seconds: 4),
    int concurrency = 32,
    void Function(String)? log,
  }) async {
    var cursor = 0;
    Future<void> worker() async {
      while (true) {
        final i = cursor++;
        if (i >= servers.length) return;
        servers[i] = await _probeOne(servers[i], timeout);
      }
    }

    final workers = List.generate(
      min(concurrency, max(1, servers.length)),
      (_) => worker(),
    );
    await Future.wait(workers);
    final alive = servers.where((s) => s.alive).length;
    log?.call('握手实测 $alive/${servers.length} 台真可用');
  }

  Future<FreeOpenVpnServer> _probeOne(
    FreeOpenVpnServer s,
    Duration timeout,
  ) async {
    Socket? socket;
    _SocketReader? reader;
    final sw = Stopwatch()..start();
    try {
      socket = await Socket.connect(s.server, s.port, timeout: timeout);
      reader = _SocketReader(socket);
      final rnd = Random.secure();
      final session = List<int>.generate(8, (_) => rnd.nextInt(256));
      final pkt = <int>[
        pControlHardResetClientV2 << 3,
        ...session,
        0,
        0, 0, 0, 0, // packet-id length 0 + packet-id 4 bytes
      ];
      final frame = <int>[(pkt.length >> 8) & 0xff, pkt.length & 0xff, ...pkt];
      socket.add(frame);
      await socket.flush();
      final header = await reader.read(2, timeout);
      final n = (header[0] << 8) | header[1];
      if (n == 0) return s.copyWith(reason: 'EMPTY_BODY');
      final body = await reader.read(n, timeout);
      final opcode = body[0] >> 3;
      final ms = sw.elapsedMilliseconds;
      return s.copyWith(
        alive: opcode == pControlHardResetServerV2,
        handshakeMs: ms,
        reason: opcode == pControlHardResetServerV2 ? '' : 'opcode_$opcode',
      );
    } on TimeoutException {
      return s.copyWith(reason: 'TIMEOUT');
    } catch (e) {
      return s.copyWith(reason: e.runtimeType.toString());
    } finally {
      await reader?.close();
      socket?.destroy();
    }
  }

  /// Build a mihomo proxy profile from the selected servers. The PEM blocks
  /// are emitted as YAML literal scalars without the `<ca>`/`<cert>`/`<key>`
  /// tags — exactly the form mihomo's OpenVPN adapter expects
  /// (core/Clash.Meta/docs/config.yaml:1462).
  String buildProfileYaml(List<FreeOpenVpnServer> selected) {
    final buf = StringBuffer()
      ..writeln('# Generated by Bettbox Free OpenVPN')
      ..writeln('proxies:');
    for (final s in selected) {
      buf
        ..writeln('  - name: "${s.nodeName}"')
        ..writeln('    type: openvpn')
        ..writeln('    server: ${s.server}')
        ..writeln('    port: ${s.port}')
        ..writeln('    proto: ${s.proto}')
        ..writeln('    dev: tun')
        ..writeln('    cipher: ${s.cipher}')
        ..writeln('    auth: ${s.auth}')
        ..writeln('    ca: |');
      _writePem(buf, s.ca);
      buf.writeln('    cert: |');
      _writePem(buf, s.cert);
      buf.writeln('    key: |');
      _writePem(buf, s.key);
    }
    buf
      ..writeln('proxy-groups:')
      ..writeln('  - name: "FreeOVPN"')
      ..writeln('    type: select')
      ..writeln('    proxies:');
    for (final s in selected) {
      buf.writeln('      - "${s.nodeName}"');
    }
    buf
      ..writeln('rules:')
      ..writeln('  - MATCH,FreeOVPN');
    return buf.toString();
  }

  void _writePem(StringBuffer buf, String pem) {
    for (final line in pem.split(RegExp(r'\r?\n'))) {
      if (line.trim().isEmpty) continue;
      buf.writeln('      ${line.trimRight()}');
    }
  }

  // ---- helpers -----------------------------------------------------------

  static List<String> _parseCsvLine(String line) {
    final out = <String>[];
    final cur = StringBuffer();
    var quoted = false;
    for (var i = 0; i < line.length; i++) {
      final c = line[i];
      if (c == '"') {
        if (quoted && i + 1 < line.length && line[i + 1] == '"') {
          cur.write('"');
          i++;
        } else {
          quoted = !quoted;
        }
      } else if (c == ',' && !quoted) {
        out.add(cur.toString());
        cur.clear();
      } else {
        cur.write(c);
      }
    }
    out.add(cur.toString());
    return out;
  }

  static String _inlineBlock(String ovpn, String tag) {
    final m = RegExp('<$tag>(.*?)</$tag>', dotAll: true).firstMatch(ovpn);
    return m?.group(1)?.trim() ?? '';
  }

  static String? _directive(String ovpn, String key) {
    for (final line in ovpn.split(RegExp(r'\r?\n'))) {
      final t = line.trim();
      if (t.startsWith('$key ')) {
        final parts = t.split(RegExp(r'\s+'));
        return parts.length > 1 ? parts.sublist(1).join(' ') : parts.first;
      }
    }
    return null;
  }
}

/// Standalone smoke test:
///   dart run lib/pages/toolbox/free_openvpn_service.dart --limit 5 --yaml out.yaml
Future<void> main(List<String> args) async {
  String? yamlPath;
  var limit = 5;
  var doProbe = true;
  for (var i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--limit':
        limit = int.tryParse(args[++i]) ?? limit;
      case '--yaml':
        yamlPath = args[++i];
      case '--no-probe':
        doProbe = false;
    }
  }
  final service = FreeOpenVpnService();
  try {
    final all = await service.discover(
      probe: doProbe,
      log: (l) => stderr.writeln(l),
    );
    final alive = all.where((s) => s.alive).toList();
    final shown = (doProbe ? alive : all).take(limit).toList();
    stdout.writeln('RESULT total=${all.length} alive=${alive.length} shown=${shown.length}');
    for (final s in shown) {
      stdout.writeln(
        '${s.location}|${s.server}:${s.port}|score=${s.score}|ping=${s.ping}|'
        '${s.handshakeMs ?? '-'}ms|${s.geoMismatch ? 'MISMATCH' : ''}',
      );
    }
    if (yamlPath != null) {
      final yaml = service.buildProfileYaml(shown);
      await File(yamlPath).writeAsString(yaml);
      stdout.writeln('YAML $yamlPath (${yaml.length} bytes)');
    }
  } catch (e) {
    stderr.writeln('ERROR ${e.runtimeType}: $e');
    exitCode = 1;
  }
}
