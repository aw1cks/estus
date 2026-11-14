import datetime, json, os, re, sys

def parse_attribute(raw):
    if len(raw) > 256:
        raise ValueError('MD attribute exceeds bound')
    value = raw.decode('ascii').strip()
    if not value or len(value) > 128:
        raise ValueError('invalid MD attribute')
    return value


def parse_md_snapshot(snapshot):
    def selected(key):
        value = snapshot[key]
        if not isinstance(value, str) or not value or len(value) > 128:
            raise ValueError('invalid MD attribute')
        return value
    def integer(key, maximum):
        value = selected(key)
        if not re.fullmatch(r'[0-9]+', value) or int(value) > maximum:
            raise ValueError('MD count outside bound')
        return int(value)
    level = selected('level')
    if level != 'raid1':
        raise ValueError('only reviewed Linux MD RAID1 is supported')
    count = integer('raid_disks', 2)
    if count != 2:
        raise ValueError('expected reviewed two-member array')
    degraded = integer('degraded', count)
    members = []
    for member in snapshot['members']:
        if len(members) >= 2 or member['device'] not in ('vdb', 'vdc'):
            raise ValueError('member outside reviewed device scope')
        if member['device'] in [m['device'][5:] for m in members]:
            raise ValueError('duplicate MD member')
        member_state = member['state'].split(',')
        if len(member_state) > 12 or any(not re.fullmatch(r'[a-z_]{1,128}', s) for s in member_state):
            raise ValueError('invalid MD member state')
        if member['slot'] not in ('none', '0', '1'):
            raise ValueError('invalid MD member slot')
        if not re.fullmatch(r'[0-9]{1,16}', member['errors']) or int(member['errors']) > 9007199254740991:
            raise ValueError('MD error count outside bound')
        members.append({'device': '/dev/' + member['device'], 'states': member_state,
                        'slot': member['slot'], 'read_errors': int(member['errors'])})
    return {'device': '/dev/md0', 'scope': 'linux_md_raid1_reported',
            'source': 'linux_sysfs_md', 'level': level, 'array_state': selected('array_state'),
            'raid_disks': count, 'degraded_members': degraded,
            'sync_action': selected('sync_action'),
            'members': sorted(members, key=lambda m: m['device'])}


def main():
    if sys.argv[1] != '/dev/md0':
        raise ValueError('device outside reviewed MD scope')
    base = '/sys/class/block/md0/md'
    def text(path):
        with open(path, 'rb') as stream:
            raw = stream.read(257)
        return parse_attribute(raw)
    snapshot = {key: text(base + '/' + key)
                for key in ('level', 'raid_disks', 'degraded', 'array_state', 'sync_action')}
    snapshot['members'] = []
    with os.scandir(base) as entries:
        for entry in entries:
            if not entry.name.startswith('dev-'):
                continue
            if len(snapshot['members']) >= 2 or entry.name not in ('dev-vdb', 'dev-vdc'):
                raise ValueError('member outside reviewed device scope')
            snapshot['members'].append(dict(device=entry.name[4:],
                **{key: text(entry.path + '/' + key) for key in ('state', 'slot', 'errors')}))
    result = parse_md_snapshot(snapshot)
    result['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    # These are kernel observations across files, not atomic or physical-media health proof.
    print(json.dumps(result, separators=(',', ':'), allow_nan=False))


if __name__ == "__main__":
    main()
