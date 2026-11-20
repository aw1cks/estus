def main():
    import datetime, json, os, platform, resource, uuid
    if platform.system() != 'Linux':
        raise ValueError('requires Linux')
    def read(path, maximum=4096, optional=False):
        try:
            with open(path, 'rb') as f:
                b = f.read(maximum + 1)
        except (FileNotFoundError, PermissionError):
            if optional:
                return None
            raise
        if len(b) > maximum:
            raise ValueError('source read exceeds bound')
        return b

    def boot_id():
        v = read('/proc/sys/kernel/random/boot_id', 128).decode('ascii').strip()
        if str(uuid.UUID(v)) != v:
            raise ValueError('invalid boot ID')
        return v

    def child_limits():
        os.setsid()
        resource.setrlimit(resource.RLIMIT_FSIZE, (262144, 262144))

    def run(argv):
        return estus_runtime.run_bounded(
            argv, timeout=12, max_bytes=262144, accepted=None,
            env={'SYSTEMD_COLORS': '0', 'SYSTEMD_PAGER': 'cat'})

    result = {'boot_id':boot_id(), 'source':'Linux procfs/sysfs; installed target utilities', 'unavailable':[]}

    mutation = run([os.environ['ESTUS_EXEC_SYSTEMD_RUN'],'--unit=estus-catalog-reboot','--on-active=5s','--timer-property=AccuracySec=1s',os.environ['ESTUS_EXEC_SYSTEMCTL'],'reboot'])
    result.update({'outcome':'uncertain' if mutation['timed_out'] else ('scheduled' if mutation['returncode'] == 0 else 'rejected'),
        'command_returncode':mutation['returncode'],'reboot_confirmed':False,
        'reconciliation_required':'independent reconnect and changed boot_id; disconnection is not proof; never automatically replay',
        'schedule_unit':'estus-catalog-reboot.timer'})

    result['observed_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds').replace('+00:00','Z')
    encoded = json.dumps(result,separators=(',',':'),allow_nan=False)
    if len(encoded.encode('utf-8')) > 4096:
        raise ValueError('result exceeds bound')
    print(encoded)


if __name__ == "__main__":
    main()
