//! `limen mcp` over its real stdin and stdout, with no login.
//!
//! Guards the invariant that stdout carries protocol messages only.

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::Value;

fn session(input: &str) -> (Vec<Value>, std::process::ExitStatus) {
    let home = tempfile::tempdir().expect("temp home");
    let mut child = Command::new(env!("CARGO_BIN_EXE_limen"))
        .arg("mcp")
        // An empty home: no profile, so nothing can be reached or logged in.
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("XDG_DATA_HOME", home.path())
        .env_remove("LIMEN_SERVER")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn limen mcp");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write");
    // Dropping stdin above closed it: the server must exit on EOF.
    let out = child.wait_with_output().expect("wait");
    let replies = String::from_utf8(out.stdout)
        .expect("utf-8")
        .lines()
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("stdout line is not JSON ({e}): {l}"))
        })
        .collect();
    (replies, out.status)
}

#[test]
fn speaks_json_rpc_and_nothing_else_on_stdout() {
    let (replies, status) = session(concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"limen_status","arguments":{}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"limen_show","arguments":{"resource":"--help"}}}"#,
        "\n",
        "not json\n",
    ));
    assert!(status.success());
    // The notification gets no reply: initialize, tools/list, two calls, one parse error.
    assert_eq!(replies.len(), 5);
    assert_eq!(replies[0]["result"]["serverInfo"]["name"], "limen");
    let names: Vec<_> = replies[1]["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|t| t["name"].as_str().expect("name"))
        .collect();
    assert_eq!(
        names,
        [
            "limen_status",
            "limen_ls",
            "limen_show",
            "limen_explain",
            "limen_requests"
        ]
    );
    // Logged out: a tool error the model can read, not a protocol error.
    assert_eq!(replies[2]["result"]["isError"], true);
    // `--help` is passed as a name after `--`, so it is not the CLI's help text.
    assert_eq!(replies[3]["result"]["isError"], true);
    assert!(
        !replies[3]["result"]["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("Usage:")
    );
    assert_eq!(replies[4]["error"]["code"], -32700);
}

#[test]
fn exits_cleanly_on_eof_with_no_input() {
    let (replies, status) = session("");
    assert_eq!(replies.len(), 0);
    assert!(status.success());
}
