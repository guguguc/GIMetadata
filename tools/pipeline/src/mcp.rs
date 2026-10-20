//! Minimal JSON-RPC-over-HTTP client for the local IDA MCP server.
//!
//! The Python tools use only plain HTTP POSTs with JSON-RPC `tools/call`
//! requests.  Keeping this small avoids pulling a full HTTP/TLS stack into
//! the single-file executable.

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

fn http_post(url: &str, body: &str, timeout: Duration) -> Result<String> {
    let rest = url.strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("only http:// MCP URLs are supported: {url}"))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().context("invalid MCP port")?),
        None => (hostport, 80),
    };
    let mut addrs = (host, port).to_socket_addrs()
        .with_context(|| format!("resolve {host}:{port}"))?;
    let addr = addrs.next().context("MCP address not found")?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("connect MCP {addr}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.as_bytes().len()
    );
    stream.write_all(req.as_bytes())?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n")
        .context("malformed MCP HTTP response")?;
    let headers = String::from_utf8_lossy(&buf[..split]).to_ascii_lowercase();
    if !headers.starts_with("http/1.1 200") && !headers.starts_with("http/1.0 200") {
        bail!("MCP HTTP error: {}", headers.lines().next().unwrap_or(""));
    }
    let mut body_bytes = buf[split + 4..].to_vec();
    if headers.contains("transfer-encoding: chunked") {
        body_bytes = decode_chunked(&body_bytes)?;
    } else if let Some(line) = headers.lines().find(|x| x.starts_with("content-length:")) {
        let n: usize = line.split(':').nth(1).unwrap_or("").trim().parse()
            .context("invalid MCP content-length")?;
        body_bytes.truncate(n);
    }
    String::from_utf8(body_bytes).context("MCP response is not UTF-8")
}

fn decode_chunked(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let line_end = data[i..].windows(2).position(|w| w == b"\r\n")
            .context("bad chunk header")? + i;
        let size_s = String::from_utf8_lossy(&data[i..line_end]);
        let size = usize::from_str_radix(size_s.split(';').next().unwrap_or("").trim(), 16)
            .context("bad chunk size")?;
        i = line_end + 2;
        if size == 0 { break; }
        if i + size > data.len() { bail!("truncated MCP chunk"); }
        out.extend_from_slice(&data[i..i + size]);
        i += size + 2;
    }
    Ok(out)
}

/// Run one MCP `tools/call` and return the JSON value decoded from its text
/// content block.
pub fn call(name: &str, arguments: Value, url: &str, timeout: Duration) -> Result<Value> {
    let body = serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments}
    }))?;
    let text = http_post(url, &body, timeout)?;
    let v: Value = serde_json::from_str(&text).context("MCP response JSON")?;
    let content = v.pointer("/result/content/0/text")
        .and_then(|x| x.as_str())
        .ok_or_else(|| anyhow::anyhow!("MCP response has no content text: {}", &text[..text.len().min(500)]))?;
    serde_json::from_str(content).context("MCP content JSON")
}

/// Return {addr: [{from, norm}]} using IDA's code xrefs.
pub fn target_xrefs(addrs: &[String], url: &str) -> Result<Value> {
    if addrs.is_empty() { return Ok(json!({})); }
    let list = serde_json::to_string(addrs)?;
    let code = format!(r#"
import idautils, ida_funcs, ida_xref, json
addrs={list}
out={{}}
for a in addrs:
    ea=int(a,16); xs=[]
    for x in idautils.XrefsTo(ea, ida_xref.XREF_CODE):
        cf=ida_funcs.get_func(x.frm)
        xs.append({{'from':x.frm,
                   'start':cf.start_ea if cf else None,
                   'end':cf.end_ea if cf else None,
                   'norm':(x.frm-cf.start_ea)/max(1,cf.end_ea-cf.start_ea) if cf else None}})
    out[a]=xs
print(json.dumps(out))
"#);
    let v = call("py_eval", json!({"code": code}), url, Duration::from_secs(120))?;
    let stdout = v.get("stdout").and_then(|x| x.as_str())
        .ok_or_else(|| anyhow::anyhow!("py_eval returned no stdout"))?;
    serde_json::from_str(stdout).context("IDA xref stdout JSON")
}

/// Ask IDA for a complete function export (same shape as ida export_funcs).
pub fn export_funcs(addrs: &[String], url: &str) -> Result<Value> {
    call("export_funcs", json!({"addrs": addrs, "format": "json"}),
         url, Duration::from_secs(600))
}
