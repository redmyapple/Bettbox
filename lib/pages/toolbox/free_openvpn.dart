// Toolbox page: discover free OpenVPN servers without a tunnel and add the
// selected ones to Bettbox as mihomo OpenVPN proxy nodes.
//
// Backed by FreeOpenVpnService (pure Dart, headlessly testable). Network work
// runs off the UI isolate; stale results are guarded by a serial counter, the
// same pattern used by ip_lookup.dart.

import 'package:bett_box/common/common.dart';
import 'package:bett_box/models/models.dart';
import 'package:bett_box/pages/pages.dart';
import 'package:bett_box/state.dart';
import 'package:bett_box/widgets/widgets.dart';
import 'package:flutter/material.dart';

import 'common.dart';
import 'free_openvpn_service.dart';

enum _AliveFilter { all, alive }

class FreeOpenVpnPage extends StatefulWidget {
  const FreeOpenVpnPage({super.key});

  @override
  State<FreeOpenVpnPage> createState() => _FreeOpenVpnPageState();
}

class _FreeOpenVpnPageState extends State<FreeOpenVpnPage> {
  final _service = FreeOpenVpnService();
  final Set<FreeOpenVpnServer> _selected = <FreeOpenVpnServer>{};

  List<FreeOpenVpnServer> _servers = const <FreeOpenVpnServer>[];
  bool _loading = false;
  bool _importing = false;
  String _error = '';
  String _status = '';
  _AliveFilter _filter = _AliveFilter.alive;
  int _serial = 0;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _refresh());
  }

  Future<void> _refresh() async {
    final serial = ++_serial;
    setState(() {
      _loading = true;
      _error = '';
      _status = 'Fetching VPN Gate servers (racing mirrors, direct + proxy)…';
      _selected.clear();
    });
    try {
      final servers = await _service.discover(
        probe: true,
        log: (line) {
          if (!mounted || serial != _serial) return;
          setState(() => _status = line);
        },
      );
      if (!mounted || serial != _serial) return;
      setState(() {
        _servers = servers;
        _status = 'Done. ${servers.where((s) => s.alive).length}/${servers.length} responded to the OpenVPN handshake.';
      });
    } catch (e) {
      if (!mounted || serial != _serial) return;
      setState(() {
        _error = 'Failed to fetch servers: $e';
        _status = '';
      });
    } finally {
      if (mounted && serial == _serial) setState(() => _loading = false);
    }
  }

  List<FreeOpenVpnServer> get _visible => _filter == _AliveFilter.alive
      ? _servers.where((s) => s.alive).toList()
      : _servers;

  void _toggle(FreeOpenVpnServer s) {
    setState(() {
      if (_selected.contains(s)) {
        _selected.remove(s);
      } else {
        _selected.add(s);
      }
    });
  }

  Future<void> _importSelected() async {
    if (_selected.isEmpty || _importing) return;
    setState(() => _importing = true);
    final messenger = ScaffoldMessenger.of(context);
    try {
      final yaml = _service.buildProfileYaml(_selected.toList());
      final profile = await Profile.normal(label: 'Free OpenVPN')
          .saveFileWithString(yaml);
      await globalState.appController.addProfile(profile);
      if (!mounted) return;
      messenger.showSnackBar(
        SnackBar(content: Text('Added ${_selected.length} OpenVPN node(s) to Bettbox.')),
      );
    } catch (e) {
      if (!mounted) return;
      messenger.showSnackBar(
        SnackBar(content: Text('Import failed: $e')),
      );
    } finally {
      if (mounted) setState(() => _importing = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = context.colorScheme;
    final visible = _visible;
    return CommonScaffold(
      title: 'Free OpenVPN',
      actions: [
        IconButton(
          tooltip: 'Refresh',
          onPressed: _loading ? null : _refresh,
          icon: const Icon(Icons.refresh_rounded),
        ),
      ],
      body: ToolPageBody(
        bottom: Padding(
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
          child: Row(
            children: [
              Expanded(
                child: Text(
                  _selected.isEmpty
                      ? 'Select servers to add them as mihomo OpenVPN nodes.'
                      : '${_selected.length} selected',
                  style: context.textTheme.bodySmall?.copyWith(
                    color: colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
              const SizedBox(width: 12),
              FilledButton.icon(
                onPressed: _selected.isEmpty || _importing ? null : _importSelected,
                icon: _importing
                    ? const SizedBox(
                        width: 16,
                        height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.add_rounded),
                label: const Text('Add to Bettbox'),
              ),
            ],
          ),
        ),
        children: [
          ToolNote(
            icon: Icons.info_outline_rounded,
            text: 'Fetches the public VPN Gate list directly (no tunnel needed), '
                'corrects locations with real GeoIP, then verifies each server '
                'with an OpenVPN handshake — TCP connectivity alone is not enough.',
          ),
          const SizedBox(height: 12),
          ToolSectionHeader(
            'Servers',
            trailing: ToolSegmented<_AliveFilter>(
              values: _AliveFilter.values,
              value: _filter,
              labelOf: (v) => v == _AliveFilter.alive ? 'Alive' : 'All',
              onChanged: (v) => setState(() => _filter = v),
            ),
          ),
          if (_error.isNotEmpty) ...[
            const SizedBox(height: 12),
            ToolNote(
              icon: Icons.error_outline_rounded,
              text: _error,
              color: colorScheme.error,
            ),
          ] else if (_status.isNotEmpty) ...[
            const SizedBox(height: 8),
            Text(
              _status,
              style: context.textTheme.bodySmall?.copyWith(
                color: colorScheme.onSurfaceVariant,
              ),
            ),
          ],
          const SizedBox(height: 12),
          ToolLoadingSwitcher(
            loading: _loading,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                for (final s in visible) ...[
                  _ServerTile(
                    server: s,
                    selected: _selected.contains(s),
                    onTap: () => _toggle(s),
                  ),
                  const SizedBox(height: 8),
                ],
                if (!_loading && visible.isEmpty)
                  ToolNote(
                    icon: Icons.inbox_rounded,
                    text: 'No servers to show. Try the "All" filter or refresh.',
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _ServerTile extends StatelessWidget {
  final FreeOpenVpnServer server;
  final bool selected;
  final VoidCallback onTap;

  const _ServerTile({
    required this.server,
    required this.selected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = context.colorScheme;
    final aliveColor = server.alive
        ? const Color(0xFF22A06B)
        : colorScheme.onSurfaceVariant;
    return ToolSurface(
      onTap: onTap,
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
      child: Row(
        children: [
          Icon(
            selected
                ? Icons.check_circle_rounded
                : Icons.radio_button_unchecked_rounded,
            color: selected ? colorScheme.primary : colorScheme.outline,
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Flexible(
                      child: Text(
                        '${server.location}  ${server.server}:${server.port}',
                        style: context.textTheme.bodyMedium?.copyWith(
                          fontWeight: FontWeight.w600,
                        ),
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                    if (server.geoMismatch) ...[
                      const SizedBox(width: 6),
                      Icon(Icons.warning_amber_rounded,
                          size: 14, color: const Color(0xFFE59A1A)),
                    ],
                  ],
                ),
                const SizedBox(height: 4),
                Text(
                  [
                    if (server.detail.isNotEmpty) server.detail,
                    'score ${server.score}',
                    'ping ${server.ping}ms',
                    '${server.speedMbps.toStringAsFixed(1)} Mbps',
                  ].join(' · '),
                  style: context.textTheme.bodySmall?.copyWith(
                    color: colorScheme.onSurfaceVariant,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          const SizedBox(width: 12),
          Column(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Text(
                server.alive ? '✓ ${server.handshakeMs}ms' : '✗ ${server.reason}',
                style: context.textTheme.labelMedium?.copyWith(color: aliveColor),
              ),
              Text(
                server.proto.toUpperCase(),
                style: context.textTheme.labelSmall?.copyWith(
                  color: colorScheme.onSurfaceVariant,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}
