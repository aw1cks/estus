def main():
    import decimal
    import json
    import re
    import uuid

    def read_proc(path):
        try:
            with open(path, 'rb', buffering=0) as stream:
                data = stream.read(128)
                if len(data) == 128:
                    raise ValueError('proc observation exceeds read bound')
                return data
        except OSError:
            return None

    boot = read_proc('/proc/sys/kernel/random/boot_id')
    boot_id = None
    if boot is not None:
        text = boot.decode('ascii').strip()
        boot_id = str(uuid.UUID(text))
        if text != boot_id:
            raise ValueError('noncanonical boot identifier')

    uptime = read_proc('/proc/uptime')
    uptime_seconds = None
    if uptime is not None:
        if re.fullmatch(rb'[0-9]+(?:\.[0-9]+)?[ \t]+[0-9]+(?:\.[0-9]+)?\n?', uptime) is None:
            raise ValueError('malformed proc uptime')
        seconds = decimal.Decimal(uptime.split()[0].decode('ascii'))
        if not seconds.is_finite() or seconds < 0 or seconds > 9007199254740991:
            raise ValueError('proc uptime outside supported range')
        uptime_seconds = int(seconds)

    print(json.dumps({'boot_id': boot_id, 'uptime_seconds': uptime_seconds},
                     separators=(',', ':'), allow_nan=False))


if __name__ == "__main__":
    main()
