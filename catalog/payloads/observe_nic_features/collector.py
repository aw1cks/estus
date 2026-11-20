import datetime
import json
import os
import re
import sys

import estus_runtime

INTERFACE_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}')
FEATURE_LABELS = {
    'rx_checksumming': 'rx-checksumming',
    'tx_checksumming': 'tx-checksumming',
    'scatter_gather': 'scatter-gather',
    'tcp_segmentation_offload': 'tcp-segmentation-offload',
    'generic_segmentation_offload': 'generic-segmentation-offload',
    'generic_receive_offload': 'generic-receive-offload',
    'large_receive_offload': 'large-receive-offload',
    'rx_vlan_offload': 'rx-vlan-offload',
    'tx_vlan_offload': 'tx-vlan-offload',
    'receive_hashing': 'receive-hashing',
}
PROJECTION_BOUND = 4096
MAX_NODES = 256


def node_count(value):
    if isinstance(value, dict):
        return 1 + sum(node_count(item) for item in value.values())
    if isinstance(value, list):
        return 1 + sum(node_count(item) for item in value)
    return 1


def main():
    request = json.loads(sys.argv[1])
    interface = request.get('interface')
    if not isinstance(interface, str) or INTERFACE_PATTERN.fullmatch(interface) is None:
        raise ValueError('invalid interface selector')
    if not os.path.isdir('/sys/class/net/' + interface):
        print(json.dumps({'estus_error': {'code': 'target_not_found'}}))
        sys.exit(1)

    executable = os.environ.get('ESTUS_EXEC_ETHTOOL')
    if not executable:
        print(json.dumps({'estus_error': {'code': 'dependency_unavailable'}}))
        sys.exit(1)
    observed = estus_runtime.run_bounded([executable, '-k', interface], timeout=20, max_bytes=262144)
    if observed['timed_out']:
        print(json.dumps({'estus_error': {'code': 'timeout'}}))
        sys.exit(1)
    if observed['returncode'] != 0:
        print(json.dumps({'estus_error': {'code': 'unsupported_platform'}}))
        sys.exit(1)

    available = {}
    for line in observed['stdout'].splitlines():
        label, separator, value = line.partition(':')
        if not separator:
            continue
        available[label.strip()] = estus_runtime.check_text(value.strip(), maximum=4096)

    unavailable = []
    features = {}
    for name, label in FEATURE_LABELS.items():
        if label in available:
            features[name] = available[label]
        else:
            unavailable.append(name)

    result = {
        'source': 'ethtool -k',
        'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
        'unavailable': unavailable,
        'interface': interface,
        'features': features,
        'truncated': False,
        'omitted_records': 0,
    }
    encoded = json.dumps(result, separators=(',', ':'), allow_nan=False)
    if len(encoded.encode('utf-8')) > PROJECTION_BOUND or node_count(result) > MAX_NODES:
        raise ValueError('projection output bound exceeded')
    print(encoded)


if __name__ == '__main__':
    main()
