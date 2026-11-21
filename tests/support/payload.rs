use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write, read_to_string};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};

// One long-lived bridge per test thread. Each request line carries the collector
// source path; the bridge re-executes every collector in a fresh module namespace
// so cases stay isolated, and reuses bootstrap's COLLECTOR_RUNTIME exactly as the
// shipped collector harness does, so parser behaviour is identical to production.
const BRIDGE: &str = r#"import importlib.util, json, sys, types
sys.dont_write_bytecode = True
bootstrap = types.ModuleType('estus_bootstrap')
exec(compile(sys.argv[1], 'bootstrap.py', 'exec'), bootstrap.__dict__)
def decode(value):
    if isinstance(value, dict):
        if set(value) == {'$bytes'}: return bytes(value['$bytes'])
        return {key: decode(item) for key, item in value.items()}
    if isinstance(value, list): return [decode(item) for item in value]
    return value
while True:
    line = sys.stdin.buffer.readline(2097153)
    if not line or not line.endswith(b'\n'):
        break
    request = json.loads(line[:-1])
    source_spec = importlib.util.spec_from_file_location('catalog_payload', request['source'])
    module = importlib.util.module_from_spec(source_spec)
    try:
        namespace = {'types': types}
        exec(compile(bootstrap.COLLECTOR_RUNTIME, '<estus_runtime>', 'exec'), namespace)
        sys.modules['estus_runtime'] = namespace['_make_runtime'](request.get('request', []))
        source_spec.loader.exec_module(module)
    except Exception as error:
        print(json.dumps({'error': type(error).__name__}, allow_nan=False, separators=(',', ':')))
        continue
    try:
        result = {'ok': getattr(module, request['function'])(*decode(request['args']))}
    except Exception as error:
        result = {'error': type(error).__name__}
    encoded = json.dumps(result, allow_nan=False, separators=(',', ':'))
    if len(encoded.encode()) > 65536: raise ValueError('bridge result bound')
    print(encoded, flush=True)
"#;

pub fn bytes(value: &[u8]) -> Value {
    json!({"$bytes": value})
}

pub fn call(role: &str, function: &str, args: Value) -> Result<Value> {
    call_with_request(role, function, args, Vec::new())
}

/// Parser tests reach pure functions directly; collectors read the request through the
/// same `estus_runtime.request()` seam the harness injects, so tests never touch argv.
pub fn call_with_request(
    role: &str,
    function: &str,
    args: Value,
    request: Vec<&str>,
) -> Result<Value> {
    let assets = std::env::var_os("ESTUS_TEST_CATALOG_ASSETS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog"));
    let manifest: Value = serde_json::from_slice(&std::fs::read(assets.join("catalog.json"))?)?;
    let executor = &manifest["tools"][role]["executor"];
    let bundle = assets.join(
        executor["path"]
            .as_str()
            .context("catalog payload assets")?,
    );
    let source = match executor["kind"].as_str() {
        Some("native_payload") => bundle.join("collector.py"),
        _ => anyhow::bail!("executor has no standalone collector"),
    };
    let line = serde_json::to_vec(&json!({
        "source": source.to_string_lossy(),
        "function": function,
        "args": args,
        "request": request,
    }))?;
    ensure!(line.len() <= 2097152, "payload request bound");
    let mut request_line = line;
    request_line.push(b'\n');
    BRIDGE_SLOT
        .with_borrow_mut(|slot| {
            if slot.is_none() {
                *slot = Some(Bridge::spawn()?);
            }
            let bridge = slot.as_mut().context("payload bridge slot")?;
            match bridge.transact(&request_line) {
                Transact::Answer(response) => {
                    ensure!(response.len() <= 65536, "payload response bound");
                    let result: Value =
                        serde_json::from_slice(&response).context("payload bridge response")?;
                    ensure!(
                        result.as_object().is_some_and(|fields| {
                            fields.len() == 1
                                && (fields.contains_key("ok") || fields.contains_key("error"))
                        }),
                        "{role}.{function}: {result}"
                    );
                    Ok(result)
                }
                Transact::Dead(stderr) => {
                    *slot = None;
                    Err(anyhow::anyhow!("payload bridge exited: {stderr}"))
                }
            }
        })
        .context("payload bridge slot")
}

/// One exchange with the bridge: a request line, then exactly one answer line.
enum Transact {
    Answer(Vec<u8>),
    Dead(String),
}

struct Bridge {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    stderr: Option<ChildStderr>,
}

thread_local! {
    static BRIDGE_SLOT: std::cell::RefCell<Option<Bridge>> = const { std::cell::RefCell::new(None) };
}

impl Bridge {
    fn spawn() -> Result<Bridge> {
        let mut child =
            Command::new(std::env::var_os("ESTUS_TEST_PYTHON").unwrap_or_else(|| "python3".into()))
                .args(["-I", "-B", "-c", BRIDGE])
                // Embedded at build time: installed acceptance executables run
                // where the source tree no longer exists.
                .arg(include_str!("../../src/native_payload/bootstrap.py"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .context("spawning payload bridge")?;
        let stdin = child.stdin.take().context("bridge stdin")?;
        let stdout = child
            .stdout
            .take()
            .map(BufReader::new)
            .context("bridge stdout")?;
        let stderr = child.stderr.take().context("bridge stderr")?;
        Ok(Bridge {
            child,
            stdin,
            stdout,
            stderr: Some(stderr),
        })
    }

    fn transact(&mut self, line: &[u8]) -> Transact {
        for attempt in 0..2 {
            if self.stdin.write_all(line).is_err() {
                // The bridge died between calls; respawn once and retry the request.
                if attempt == 0 {
                    if self.respawn().is_err() {
                        return Transact::Dead("cannot respawn payload bridge".into());
                    }
                    continue;
                }
                return Transact::Dead("writing to payload bridge failed".into());
            }
            let mut response = String::new();
            match self.stdout.read_line(&mut response) {
                Ok(0) => return Transact::Dead(self.drain_stderr()),
                Ok(_) => return Transact::Answer(response.into_bytes()),
                Err(_) => return Transact::Dead("reading from payload bridge failed".into()),
            }
        }
        Transact::Dead("payload bridge write retry exhausted".into())
    }

    fn respawn(&mut self) -> Result<()> {
        self.drain_stderr();
        let _ = self.child.kill();
        let fresh = Bridge::spawn()?;
        *self = fresh;
        Ok(())
    }

    /// The bridge has exited (or its pipe broke); its stderr holds the reason.
    fn drain_stderr(&mut self) -> String {
        let stderr = self
            .stderr
            .take()
            .and_then(|mut stream| read_to_string(&mut stream).ok())
            .unwrap_or_default();
        let _ = self.child.wait();
        stderr.trim().to_owned()
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.try_wait();
    }
}
