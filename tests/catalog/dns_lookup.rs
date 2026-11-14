use crate::catalog;
use anyhow::{Result, ensure};
use serde_json::json;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ESTUS_TEST_CATALOG_VM and pinned Runner runtime"]
async fn dns_lookup() -> Result<()> {
    let guest = catalog::Guest::start().await?;
    let result: Result<()> = async {
        let prepared = guest.shell(r#"systemd-run --unit=catalog-dns /usr/bin/python3 -c 'import socket,struct; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("127.0.0.1",15353));
while True:
 d,a=s.recvfrom(512); qtype=struct.unpack("!H",d[-4:-2])[0]; address=socket.inet_pton(socket.AF_INET if qtype==1 else socket.AF_INET6,"192.0.2.42" if qtype==1 else "2001:db8::42"); answer=b"\xc0\x0c"+struct.pack("!HHIH",qtype,1,30,len(address))+address; s.sendto(d[:2]+struct.pack("!HHHHH",0x8180,1,1,0,0)+d[12:]+answer,a)'
for n in 1 2 3 4 5; do /usr/bin/ss -H -lun | grep -q :15353 && exit 0; sleep 1; done; exit 1"#).await?;
        ensure!(prepared.status.success(), "independent fixture preparation failed: {:?}", prepared);
        let binding = guest.binding("dns_lookup", json!({})).await?;
        binding.reject(json!({"name": "example.com", "type": "A"})).await?;
        binding.reject(json!({"operator_policy":{"interfaces":["eth0"]}})).await?;
        let oracle = guest.shell(r#"/usr/bin/ss -H -lun"#).await?;
        ensure!(oracle.status.success(), "independent network oracle failed");
        let reply = binding.call(json!({"name": "catalog.test", "type": "A", "resolver": "127.0.0.1"})).await?;
        let value = catalog::projection(&reply)?;
        ensure!(value["rcode"] == 0 && value["addresses"][0] == "192.0.2.42", "real fixture DNS answer missing");
        let second = binding.call(json!({"name":"catalog.test","type":"AAAA"})).await?;
        ensure!(catalog::projection(&second)?["addresses"][0] == "2001:db8::42", "real AAAA answer missing");
        Ok(())
    }.await;
    let cleanup = guest.stop().await;
    result?;
    cleanup
}
