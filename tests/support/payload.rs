use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::io::Write;
use std::process::{Command, Stdio};

// This bridge only imports and calls the shipped module. Cases and assertions belong to Rust.
const BRIDGE: &str = r#"import importlib.util, json, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('catalog_payload', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
def decode(value):
    if isinstance(value, dict):
        if set(value) == {'$bytes'}: return bytes(value['$bytes'])
        return {key: decode(item) for key, item in value.items()}
    if isinstance(value, list): return [decode(item) for item in value]
    return value
request = json.loads(sys.stdin.buffer.read(2097153))
try:
    result = {'ok': getattr(module, request['function'])(*decode(request['args']))}
except Exception as error:
    result = {'error': type(error).__name__}
encoded = json.dumps(result, allow_nan=False, separators=(',', ':'))
if len(encoded.encode()) > 65536: raise ValueError('bridge result bound')
print(encoded)
"#;

pub fn bytes(value: &[u8]) -> Value {
    json!({"$bytes": value})
}

pub fn call(role: &str, function: &str, args: Value) -> Result<Value> {
    let assets = std::env::var_os("ESTUS_TEST_CATALOG_ASSETS")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog"));
    let manifest: Value = serde_json::from_slice(&std::fs::read(assets.join("catalog.json"))?)?;
    let executor = &manifest["tools"][role]["executor"];
    let bundle = assets.join(executor["path"].as_str().context("catalog payload assets")?);
    let source = match executor["kind"].as_str() {
        Some("native_payload") => bundle.join("collector.py"),
        Some("ansible_role") => bundle.join("files/collector.py"),
        _ => anyhow::bail!("executor has no standalone collector"),
    };
    let request = serde_json::to_vec(&json!({"function": function, "args": args}))?;
    ensure!(request.len() <= 2097152, "payload request bound");
    let mut child =
        Command::new(std::env::var_os("ESTUS_TEST_PYTHON").unwrap_or_else(|| "python3".into()))
            .args(["-I", "-c", BRIDGE])
            .arg(source)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
    child
        .stdin
        .take()
        .context("bridge stdin")?
        .write_all(&request)?;
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success(),
        "{role}.{function}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    ensure!(output.stdout.len() <= 65536, "payload response bound");
    serde_json::from_slice(&output.stdout).context("payload bridge response")
}
