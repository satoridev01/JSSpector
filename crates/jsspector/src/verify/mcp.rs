//! MCP (Model Context Protocol) tool calls as a verification transport. Pure: the sandbox
//! ([`super::sandbox`]) runs the server and its driver, and this module only works out what to call
//! and how to tell the reader to reproduce it, so it can be unit-tested on its own.
//!
//! A finding in an MCP server names a tool (`MCP run`), but rarely which of the tool's arguments
//! carries the tainted value: the arguments object is passed whole to helpers, often across files,
//! so the sink names a local, not a field. The server itself says what it accepts, through
//! `tools/list`: each tool's JSON Schema. The verifier reads it back and works from it, rather than
//! guessing statically — every free-text argument of the tool is a candidate for the payload, and the
//! other required arguments are filled with values that satisfy the schema, because a server
//! validates arguments before its handler runs and rejects what does not fit.

use jss_core::VulnClass;
use serde_json::Value;

use super::plan::{Entry, Probe};

/// What the planner learned about an MCP finding that the probe's own fields cannot carry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct McpHints {
    /// URL paths the server's source mounts an MCP endpoint at, likeliest first.
    pub endpoints: Vec<String>,
    /// Names the source reads off the tool's arguments or builds the sink's value from, used to
    /// rank which argument of a tool is the tainted one.
    pub fields: Vec<String>,
}

/// One tool a server lists: its name and the JSON Schema of its `arguments`.
#[derive(Debug, Clone)]
pub struct McpTool {
    pub name: String,
    pub schema: Value,
}

/// Where a server was found and what it offers.
#[derive(Debug, Clone)]
pub struct McpDiscovery {
    /// `streamable` (one POST endpoint) or `sse` (the legacy GET event stream plus POST endpoint).
    pub transport: String,
    pub path: String,
    pub tools: Vec<McpTool>,
}

/// What a discovery that found no HTTP endpoint says first: the verifier then tries the server as a
/// stdio one (see [`super::stdio`]).
pub const NO_ENDPOINT: &str = "no MCP endpoint answered";

/// The most candidate (tool, argument) pairs tried for one finding.
pub const MAX_CANDIDATES: usize = 24;
/// The most requests spent on one candidate before moving to the next one.
pub const ATTEMPTS_PER_CANDIDATE: usize = 160;

/// Paths a server is commonly mounted at, tried after those the source names.
const DEFAULT_PATHS: [&str; 8] = [
    "/mcp",
    "/",
    "/sse",
    "/api/mcp",
    "/mcp/",
    "/message",
    "/messages",
    "/stream",
];

/// The endpoint paths to try, the ones mined from the source first, then the conventional ones,
/// each once.
pub fn endpoint_paths(mined: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for path in mined
        .iter()
        .map(String::as_str)
        .chain(DEFAULT_PATHS.iter().copied())
    {
        if !out.iter().any(|seen| seen == path) {
            out.push(path.to_owned());
        }
    }
    out
}

/// Reads what the driver's `discover` mode printed, with the status it reported.
pub fn parse_discovery(stdout: &str, status: Option<u16>) -> Result<McpDiscovery, String> {
    let value: Value = serde_json::from_str(stdout.trim())
        .map_err(|_| "the MCP driver returned nothing readable".to_owned())?;
    let Some(endpoint) = value.get("endpoint").filter(|endpoint| !endpoint.is_null()) else {
        return Err(match status {
            Some(code @ (401 | 403)) => format!(
                "the MCP endpoint requires authentication (HTTP {code}), which verification does not perform"
            ),
            _ => format!("{NO_ENDPOINT} at the paths the source or convention suggest"),
        });
    };
    let text = |key: &str| endpoint.get(key).and_then(Value::as_str).map(str::to_owned);
    let (Some(transport), Some(path)) = (text("transport"), text("path")) else {
        return Err("the MCP driver reported an endpoint without a transport".to_owned());
    };
    let tools = value
        .get("tools")
        .and_then(Value::as_array)
        .map(|tools| {
            tools
                .iter()
                .filter_map(|tool| {
                    Some(McpTool {
                        name: tool.get("name")?.as_str()?.to_owned(),
                        schema: tool.get("inputSchema").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(McpDiscovery {
        transport,
        path,
        tools,
    })
}

/// A value valid for `schema`, as JSON.
fn fill_json(schema: &Value, depth: usize) -> Value {
    let filler = || Value::String("jsspector".to_owned());
    let Some(object) = schema.as_object() else {
        return filler();
    };
    if depth > 4 {
        return filler();
    }
    if let Some(constant) = object.get("const") {
        return constant.clone();
    }
    if let Some(first) = object
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|values| values.first())
    {
        return first.clone();
    }
    for key in ["anyOf", "oneOf", "allOf"] {
        if let Some(first) = object
            .get(key)
            .and_then(Value::as_array)
            .and_then(|branches| branches.first())
        {
            return fill_json(first, depth + 1);
        }
    }
    let declared = match object.get("type") {
        Some(Value::String(kind)) => Some(kind.as_str()),
        Some(Value::Array(kinds)) => kinds
            .iter()
            .filter_map(Value::as_str)
            .find(|kind| *kind != "null"),
        _ => None,
    };
    let kind = declared.unwrap_or(if object.contains_key("properties") {
        "object"
    } else if object.contains_key("items") {
        "array"
    } else {
        "string"
    });
    match kind {
        "integer" | "number" => {
            let bound = |key: &str| object.get(key).and_then(Value::as_f64);
            let mut n = 1.0_f64;
            if let Some(minimum) = bound("minimum") {
                n = n.max(minimum);
            }
            if let Some(exclusive) = bound("exclusiveMinimum") {
                n = n.max(exclusive + 1.0);
            }
            if let Some(maximum) = bound("maximum") {
                n = n.min(maximum);
            }
            if kind == "integer" || n.fract() == 0.0 {
                Value::from(n as i64)
            } else {
                Value::from(n)
            }
        }
        "boolean" => Value::Bool(true),
        "null" => Value::Null,
        "array" => {
            let wanted = object
                .get("minItems")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .min(8) as usize;
            let item = object
                .get("items")
                .map_or_else(filler, |items| fill_json(items, depth + 1));
            Value::Array(vec![item; wanted])
        }
        "object" => Value::Object(
            required_members(schema, None, depth + 1)
                .into_iter()
                .collect(),
        ),
        _ => {
            let mut text = match object.get("format").and_then(Value::as_str) {
                Some("uri" | "url" | "uri-reference") => "http://example.com".to_owned(),
                Some("email") => "jss@example.com".to_owned(),
                Some("uuid") => "00000000-0000-4000-8000-000000000000".to_owned(),
                Some("date-time") => "2026-01-01T00:00:00Z".to_owned(),
                Some("date") => "2026-01-01".to_owned(),
                _ => "jsspector".to_owned(),
            };
            if let Some(minimum) = object.get("minLength").and_then(Value::as_u64) {
                while (text.len() as u64) < minimum.min(256) {
                    text.push('a');
                }
            }
            Value::String(text)
        }
    }
}

/// The required members of an object schema, each filled, in declaration order, except `skip`.
fn required_members(schema: &Value, skip: Option<&str>, depth: usize) -> Vec<(String, Value)> {
    let properties = schema.get("properties").and_then(Value::as_object);
    schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|name| Some(*name) != skip)
        .map(|name| {
            let member = properties.and_then(|properties| properties.get(name));
            (
                name.to_owned(),
                member.map_or_else(
                    || Value::String("jsspector".to_owned()),
                    |member| fill_json(member, depth),
                ),
            )
        })
        .collect()
}

/// The required arguments other than `tainted`, each with a value its schema accepts, in the
/// text form [`Probe::siblings`] carries: a string as itself, anything else as its JSON.
pub fn fill_siblings(schema: &Value, tainted: &str) -> Vec<(String, String)> {
    required_members(schema, Some(tainted), 0)
        .into_iter()
        .map(|(name, value)| match value {
            Value::String(text) => (name, text),
            other => (name, other.to_string()),
        })
        .collect()
}

/// Whether the schema allows free text (a string, or no type to say otherwise): the only kind of
/// argument a payload can ride in.
fn takes_text(schema: &Value) -> bool {
    let Some(object) = schema.as_object() else {
        return true;
    };
    if object.contains_key("enum") || object.contains_key("const") {
        return false;
    }
    match object.get("type") {
        Some(Value::String(kind)) => kind == "string",
        Some(Value::Array(kinds)) => kinds.iter().any(|kind| kind == "string"),
        _ => {
            ["anyOf", "oneOf"].iter().any(|key| {
                object
                    .get(*key)
                    .and_then(Value::as_array)
                    .is_some_and(|branches| branches.iter().any(takes_text))
            }) || !(object.contains_key("properties")
                || object.contains_key("items")
                || object.contains_key("anyOf")
                || object.contains_key("oneOf"))
        }
    }
}

/// Argument names that usually carry a payload of the class, likeliest first.
fn class_names(class: VulnClass) -> &'static [&'static str] {
    match class {
        VulnClass::PathTraversal => &[
            "path",
            "file",
            "filepath",
            "filename",
            "file_path",
            "dir",
            "directory",
            "folder",
            "name",
            "id",
            "key",
            "uri",
            "cwd",
            "root",
            "base",
        ],
        VulnClass::CommandInjection => &[
            "command", "cmd", "script", "args", "host", "input", "query", "pattern", "name",
        ],
        VulnClass::CodeInjection => &[
            "code",
            "expression",
            "expr",
            "script",
            "eval",
            "formula",
            "input",
            "query",
        ],
        VulnClass::Ssrf => &[
            "url", "uri", "endpoint", "host", "target", "link", "href", "address", "callback",
        ],
        _ => &[],
    }
}

/// The tool's text arguments, the likeliest carrier of the payload first: those the source's own
/// names point at, then the conventional names of the class, then the rest in declaration order.
fn ranked_text_fields(
    properties: &serde_json::Map<String, Value>,
    class: VulnClass,
    hints: &[String],
) -> Vec<(usize, String)> {
    let lower = |name: &str| name.to_ascii_lowercase();
    let mut ranked: Vec<(usize, usize, String)> = properties
        .iter()
        .enumerate()
        .filter(|(_, (_, schema))| takes_text(schema))
        .map(|(order, (name, _))| {
            let key = lower(name);
            let hinted = hints.iter().position(|hint| lower(hint) == key);
            let conventional = class_names(class).iter().position(|known| *known == key);
            let rank = match (hinted, conventional) {
                (Some(position), _) => position,
                (None, Some(position)) => 100 + position,
                (None, None) => 1000 + order,
            };
            (rank, order, name.clone())
        })
        .collect();
    ranked.sort();
    ranked
        .into_iter()
        .map(|(rank, _, name)| (rank, name))
        .collect()
}

/// The concrete probes to try for `probe` against the tools a server lists: one per (tool, argument)
/// pair that can carry the payload, the likeliest first, each with the other required arguments
/// filled from the schema. A probe that already names its tool and argument keeps them.
pub fn candidates(probe: &Probe, tools: &[McpTool]) -> Result<Vec<Probe>, String> {
    let hints = probe.mcp.clone().unwrap_or_default();
    let named = !probe.path.is_empty();
    let selected: Vec<&McpTool> = tools
        .iter()
        .filter(|tool| !named || tool.name == probe.path)
        .collect();
    if tools.is_empty() {
        return Err("the server lists no tools".to_owned());
    }
    if selected.is_empty() {
        let offered: Vec<&str> = tools
            .iter()
            .map(|tool| tool.name.as_str())
            .take(8)
            .collect();
        return Err(format!(
            "the server has no tool named `{}` (it lists {})",
            probe.path,
            offered.join(", ")
        ));
    }
    let known = match &probe.entry {
        Entry::Body(Some(field)) => Some(field.as_str()),
        _ => None,
    };
    // (rank, tool order, argument order, probe): ranked across every tool, so the likeliest pair is
    // tried first whichever tool it belongs to.
    let mut out: Vec<(usize, usize, usize, Probe)> = Vec::new();
    for (tool_order, tool) in selected.into_iter().enumerate() {
        let Some(properties) = tool.schema.get("properties").and_then(Value::as_object) else {
            continue;
        };
        let fields: Vec<(usize, String)> = match known {
            Some(field) if properties.contains_key(field) => vec![(0, field.to_owned())],
            Some(_) => Vec::new(),
            None => ranked_text_fields(properties, probe.class, &hints.fields),
        };
        for (field_order, (rank, field)) in fields.into_iter().enumerate() {
            if properties
                .get(&field)
                .is_some_and(|schema| !takes_text(schema))
            {
                continue;
            }
            let mut candidate = probe.clone();
            candidate.path = tool.name.clone();
            candidate.entry = Entry::Body(Some(field.clone()));
            candidate.siblings = fill_siblings(&tool.schema, &field);
            out.push((rank, tool_order, field_order, candidate));
        }
    }
    out.sort_by_key(|(rank, tool, field, _)| (*rank, *tool, *field));
    let mut out: Vec<Probe> = out.into_iter().map(|(_, _, _, probe)| probe).collect();
    if out.is_empty() {
        return Err(match known {
            Some(field) => format!(
                "the tool has no free-text argument named `{field}` for the payload to ride in"
            ),
            None => "no tool the finding could be about takes a free-text argument".to_owned(),
        });
    }
    out.truncate(MAX_CANDIDATES);
    Ok(out)
}

/// A shell command that reproduces one tool call against `endpoint`, to carry in a report. For the
/// Streamable HTTP transport it is plain `curl`: initialize (keeping the session id a stateful server
/// issues), announce initialized, call. The legacy event-stream transport cannot be driven by `curl`
/// alone, so it is the official client instead.
pub fn poc_command(transport: &str, path: &str, tool: &str, arguments: &str, port: u16) -> String {
    let arguments: Value = serde_json::from_str(arguments).unwrap_or(Value::Null);
    let url = format!("http://TARGET_HOST:{port}{path}");
    if transport == "sse" {
        let script = format!(
            "const {{ Client }} = require('@modelcontextprotocol/sdk/client/index.js');\n\
             const {{ SSEClientTransport }} = require('@modelcontextprotocol/sdk/client/sse.js');\n\
             (async () => {{\n\
               const client = new Client({{ name: 'poc', version: '1' }});\n\
               await client.connect(new SSEClientTransport(new URL({})));\n\
               console.log(JSON.stringify(await client.callTool({{ name: {}, arguments: {} }})));\n\
               process.exit(0);\n\
             }})();",
            Value::String(url),
            Value::String(tool.to_owned()),
            arguments,
        );
        return format!(
            "# npm i @modelcontextprotocol/sdk\nnode -e {}",
            super::sandbox::shell_quote(&script)
        );
    }
    let rpc = |id: Option<u32>, method: &str, params: Value| {
        let mut message = serde_json::Map::new();
        message.insert("jsonrpc".to_owned(), Value::from("2.0"));
        message.insert("method".to_owned(), Value::from(method));
        if let Some(id) = id {
            message.insert("id".to_owned(), Value::from(id));
        }
        if !params.is_null() {
            message.insert("params".to_owned(), params);
        }
        super::sandbox::shell_quote(&Value::Object(message).to_string())
    };
    let initialize = rpc(
        Some(0),
        "initialize",
        serde_json::json!({
            "protocolVersion": "2025-03-26", "capabilities": {},
            "clientInfo": { "name": "poc", "version": "1" },
        }),
    );
    let initialized = rpc(None, "notifications/initialized", Value::Null);
    let call = rpc(
        Some(1),
        "tools/call",
        serde_json::json!({ "name": tool, "arguments": arguments }),
    );
    let headers =
        "-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream'";
    let session = "${sid:+-H \"Mcp-Session-Id: $sid\"}";
    format!(
        "url={url}\n\
         sid=$(curl -sS -D - -o /dev/null \"$url\" {headers} -d {initialize} | \
         awk -F': ' 'tolower($1)==\"mcp-session-id\"{{print $2}}' | tr -d '\\r')\n\
         curl -sS \"$url\" {headers} {session} -d {initialized}\n\
         curl -sS \"$url\" {headers} {session} -d {call}",
        url = super::sandbox::shell_quote(&url),
    )
}

/// What the stdio bridge reported about starting the server: the command that did, or why none did.
pub fn parse_bridge(stdout: &str) -> Result<Vec<String>, String> {
    let value: Value = serde_json::from_str(stdout.trim())
        .map_err(|_| "the stdio bridge returned nothing readable".to_owned())?;
    let state = value.get("state").and_then(Value::as_str).unwrap_or("");
    if state == "ready" {
        let command: Vec<String> = value
            .get("command")
            .and_then(Value::as_array)
            .map(|words| {
                words
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        if !command.is_empty() {
            return Ok(command);
        }
    }
    if state != "failed" {
        return Err(format!(
            "the stdio bridge was still `{state}` when the wait for it ended"
        ));
    }
    // Every trial and how it ended, with the last words of the one that said anything: a missing
    // module on stderr is what tells a build that did not run from a command that was wrong.
    let trials = value.get("trials").and_then(Value::as_array);
    let tried: Vec<String> = trials
        .into_iter()
        .flatten()
        .take(6)
        .map(|trial| {
            let command = trial
                .get("command")
                .and_then(Value::as_array)
                .map(|words| {
                    words
                        .iter()
                        .filter_map(Value::as_str)
                        .skip(1)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
                .unwrap_or_default();
            let outcome = trial.get("outcome").and_then(Value::as_str).unwrap_or("");
            format!("`{command}` {outcome}")
        })
        .collect();
    let said = trials
        .into_iter()
        .flatten()
        .filter_map(|trial| trial.get("stderr").and_then(Value::as_str))
        .map(str::trim)
        .find(|text| !text.is_empty())
        .map(|text| {
            let last: Vec<&str> = text.lines().rev().take(2).collect();
            let joined: String = last.into_iter().rev().collect::<Vec<_>>().join(" / ");
            format!(
                " — it said: {}",
                joined.chars().take(240).collect::<String>()
            )
        })
        .unwrap_or_default();
    Err(format!(
        "no command started an MCP server over stdio ({}){said}",
        if tried.is_empty() {
            "none was tried".to_owned()
        } else {
            tried.join("; ")
        }
    ))
}

/// A script that reproduces one tool call against a stdio server: the official client starts the
/// server the way a real client would and calls the tool.
pub fn stdio_poc_command(command: &[String], tool: &str, arguments: &str) -> String {
    let arguments: Value = serde_json::from_str(arguments).unwrap_or(Value::Null);
    let (program, rest) = command
        .split_first()
        .map_or(("node", &[][..]), |(program, rest)| {
            (program.as_str(), rest)
        });
    let script = format!(
        "const {{ Client }} = require('@modelcontextprotocol/sdk/client/index.js');\n\
         const {{ StdioClientTransport }} = require('@modelcontextprotocol/sdk/client/stdio.js');\n\
         (async () => {{\n\
           const client = new Client({{ name: 'poc', version: '1' }});\n\
           await client.connect(new StdioClientTransport({{ command: {}, args: {} }}));\n\
           console.log(JSON.stringify(await client.callTool({{ name: {}, arguments: {} }})));\n\
           process.exit(0);\n\
         }})();",
        Value::String(program.to_owned()),
        Value::from(rest.to_vec()),
        Value::String(tool.to_owned()),
        arguments,
    );
    format!(
        "# from the package directory, after installing it and running its build\n\
         # npm i @modelcontextprotocol/sdk\n\
         node -e {}",
        super::sandbox::shell_quote(&script)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::plan::{Method, Probe};

    fn tool(name: &str, schema: Value) -> McpTool {
        McpTool {
            name: name.to_owned(),
            schema,
        }
    }

    fn probe(path: &str, entry: Entry, class: VulnClass) -> Probe {
        Probe::call(Method::Mcp, path.to_owned(), entry, class)
    }

    #[test]
    fn endpoint_paths_puts_the_mined_ones_first_without_repeats() {
        let paths = endpoint_paths(&["/api/v2/mcp".to_owned(), "/mcp".to_owned()]);
        assert_eq!(&paths[..2], ["/api/v2/mcp", "/mcp"]);
        assert_eq!(paths.iter().filter(|path| *path == "/mcp").count(), 1);
        assert!(paths.contains(&"/sse".to_owned()));
    }

    #[test]
    fn parse_discovery_reads_the_endpoint_and_the_tools() {
        let found = parse_discovery(
            r#"{"endpoint":{"transport":"streamable","path":"/mcp"},"tools":[
                {"name":"run","inputSchema":{"type":"object","properties":{"cmd":{"type":"string"}}}},
                {"name":"bare"}]}"#,
            Some(200),
        )
        .unwrap();
        assert_eq!(
            (found.transport.as_str(), found.path.as_str()),
            ("streamable", "/mcp")
        );
        assert_eq!(found.tools.len(), 2);
        assert_eq!(found.tools[1].schema, Value::Null);
    }

    #[test]
    fn parse_discovery_explains_a_missing_endpoint() {
        let auth = parse_discovery(r#"{"endpoint":null}"#, Some(401)).unwrap_err();
        assert!(
            auth.contains("authentication") && auth.contains("401"),
            "{auth}"
        );
        let none = parse_discovery(r#"{"endpoint":null}"#, Some(404)).unwrap_err();
        assert!(none.contains("no MCP endpoint"), "{none}");
        assert!(parse_discovery("not json", None).is_err());
    }

    #[test]
    fn fillers_satisfy_the_schema_they_come_from() {
        let schema: Value = serde_json::from_str(
            r#"{"type":"object","required":["mode","limit","url","tags","opts","flag","when","name"],
                "properties":{
                  "mode":{"enum":["fast","slow"]},
                  "limit":{"type":"integer","minimum":5,"maximum":9},
                  "url":{"type":"string","format":"uri"},
                  "tags":{"type":"array","minItems":2,"items":{"type":"string"}},
                  "opts":{"type":"object","required":["depth"],"properties":{"depth":{"type":"number","exclusiveMinimum":2}}},
                  "flag":{"type":"boolean"},
                  "when":{"anyOf":[{"type":"string","format":"date"},{"type":"null"}]},
                  "name":{"type":"string","minLength":12},
                  "unused":{"type":"string"}}}"#,
        )
        .unwrap();
        let got = fill_siblings(&schema, "name");
        let get = |key: &str| got.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
        assert_eq!(get("mode"), Some("fast"));
        assert_eq!(get("limit"), Some("5"));
        assert_eq!(get("url"), Some("http://example.com"));
        assert_eq!(get("tags"), Some(r#"["jsspector","jsspector"]"#));
        assert_eq!(get("opts"), Some(r#"{"depth":3}"#));
        assert_eq!(get("flag"), Some("true"));
        assert_eq!(get("when"), Some("2026-01-01"));
        // The tainted argument is left to the payload, and an optional one is not invented.
        assert_eq!(get("name"), None);
        assert_eq!(get("unused"), None);
    }

    #[test]
    fn a_named_tool_and_argument_are_kept_and_the_others_filled() {
        let tools = [tool(
            "run",
            serde_json::json!({"properties":{"cmd":{"type":"string"},"n":{"type":"integer"}},"required":["cmd","n"]}),
        )];
        let found = candidates(
            &probe(
                "run",
                Entry::Body(Some("cmd".to_owned())),
                VulnClass::CommandInjection,
            ),
            &tools,
        )
        .unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].entry, Entry::Body(Some("cmd".to_owned())));
        assert_eq!(found[0].siblings, [("n".to_owned(), "1".to_owned())]);
    }

    #[test]
    fn an_undiscovered_argument_tries_each_text_property_likeliest_first() {
        let tools = [tool(
            "read_note",
            serde_json::json!({"properties":{
                "limit":{"type":"integer"},
                "title":{"type":"string"},
                "path":{"type":"string"},
                "mode":{"enum":["a","b"]},
                "dir":{"type":"string"}},"required":["limit"]}),
        )];
        let mut base = probe("read_note", Entry::Body(None), VulnClass::PathTraversal);
        base.mcp = Some(McpHints {
            endpoints: Vec::new(),
            fields: vec!["dir".to_owned()],
        });
        let order: Vec<String> = candidates(&base, &tools)
            .unwrap()
            .into_iter()
            .map(|c| match c.entry {
                Entry::Body(Some(field)) => field,
                other => panic!("{other:?}"),
            })
            .collect();
        // The source's own name first, then the class's conventional one, then the rest; the
        // integer and the enum can carry no payload.
        assert_eq!(order, ["dir", "path", "title"]);
    }

    #[test]
    fn an_unnamed_tool_is_tried_across_every_tool_the_server_lists() {
        let tools = [
            tool(
                "a",
                serde_json::json!({"properties":{"q":{"type":"string"}}}),
            ),
            tool(
                "b",
                serde_json::json!({"properties":{"n":{"type":"integer"}}}),
            ),
            tool(
                "c",
                serde_json::json!({"properties":{"url":{"type":"string"}}}),
            ),
        ];
        let found = candidates(&probe("", Entry::Body(None), VulnClass::Ssrf), &tools).unwrap();
        let names: Vec<&str> = found.iter().map(|c| c.path.as_str()).collect();
        // The `url` of `c` is the conventional carrier of an SSRF payload, so it comes before the
        // unremarkable `q` of `a`; `b` takes no text and is left out.
        assert_eq!(names, ["c", "a"]);
    }

    #[test]
    fn candidates_explain_why_there_is_nothing_to_try() {
        let tools = [tool(
            "a",
            serde_json::json!({"properties":{"n":{"type":"integer"}}}),
        )];
        let missing =
            candidates(&probe("zzz", Entry::Body(None), VulnClass::Ssrf), &tools).unwrap_err();
        assert!(
            missing.contains("no tool named `zzz`") && missing.contains('a'),
            "{missing}"
        );
        let wrong = candidates(
            &probe("a", Entry::Body(Some("cmd".to_owned())), VulnClass::Ssrf),
            &tools,
        )
        .unwrap_err();
        assert!(wrong.contains("`cmd`"), "{wrong}");
        let none = candidates(&probe("a", Entry::Body(None), VulnClass::Ssrf), &tools).unwrap_err();
        assert!(none.contains("free-text"), "{none}");
        assert!(
            candidates(&probe("a", Entry::Body(None), VulnClass::Ssrf), &[])
                .unwrap_err()
                .contains("no tools")
        );
    }

    #[test]
    fn the_streamable_poc_is_a_replayable_curl_sequence() {
        let command = poc_command("streamable", "/mcp", "run", r#"{"cmd":"id"}"#, 3000);
        assert!(command.contains("http://TARGET_HOST:3000/mcp"), "{command}");
        assert!(command.contains("initialize") && command.contains("notifications/initialized"));
        assert!(command.contains(r#""name":"run""#) && command.contains(r#""cmd":"id""#));
        assert!(command.contains("Mcp-Session-Id"), "{command}");
    }

    #[test]
    fn the_sse_poc_uses_the_official_client() {
        let command = poc_command("sse", "/sse", "run", r#"{"cmd":"id"}"#, 3000);
        assert!(command.contains("SSEClientTransport") && command.contains("callTool"));
        assert!(command.contains("http://TARGET_HOST:3000/sse"), "{command}");
    }

    #[test]
    fn the_bridge_that_started_a_server_reports_its_command() {
        let command = parse_bridge(
            r#"{"state":"ready","command":["node","dist/cli/index.js","server","start"],"trials":[]}"#,
        )
        .unwrap();
        assert_eq!(command, ["node", "dist/cli/index.js", "server", "start"]);
    }

    #[test]
    fn a_bridge_that_started_nothing_says_what_each_command_did_and_what_the_last_one_said() {
        let reason = parse_bridge(
            r#"{"state":"failed","command":null,"trials":[
                {"command":["node","dist/index.js"],"outcome":"exited (1) before answering initialize",
                 "stderr":"Error: Cannot find module '/app/dist/index.js'\n    at Module._resolveFilename"},
                {"command":["node","dist/cli.js","serve"],"outcome":"did not answer initialize within 20000 ms","stderr":""}]}"#,
        )
        .unwrap_err();
        assert!(reason.contains("`dist/index.js` exited (1)"), "{reason}");
        assert!(
            reason.contains("`dist/cli.js serve` did not answer"),
            "{reason}"
        );
        assert!(reason.contains("Cannot find module"), "{reason}");
        // A bridge still trying when the wait ended is not a verdict about the server.
        assert!(
            parse_bridge(r#"{"state":"starting","trials":[]}"#)
                .unwrap_err()
                .contains("still `starting`")
        );
    }

    #[test]
    fn a_stdio_reproduction_starts_the_server_with_the_official_client() {
        let command = stdio_poc_command(
            &[
                "node".to_owned(),
                "dist/index.js".to_owned(),
                "serve".to_owned(),
            ],
            "read_note",
            r#"{"name":"../../etc/passwd"}"#,
        );
        assert!(command.contains("StdioClientTransport"), "{command}");
        assert!(command.contains(r#"command: "node""#), "{command}");
        assert!(
            command.contains(r#"args: ["dist/index.js","serve"]"#),
            "{command}"
        );
        assert!(command.contains(r#"name: "read_note""#), "{command}");
        assert!(command.contains("../../etc/passwd"), "{command}");
    }
}
