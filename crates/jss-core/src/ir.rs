//! JSSpector's owned intermediate representation: what each module says, lifetime-free and
//! independent of the parser.
//!
//! `jss-frontend` lowers every parsed file to a [`Module`]: its imports (resolved to files of the
//! scan root), exports, functions (parameters, calls with classified arguments, and the flows its
//! summaries found: parameter to sink, parameter to return value), entry points and router mounts.
//! Everything after lowering works on this IR: the cross-file linker ([`link`]) builds the call
//! graph from it, and the entry-point inventory is computed from it.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::finding::{Auth, Severity, VulnClass};

/// One source file, lowered.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Module {
    /// Root-relative path.
    pub file: String,
    pub imports: Vec<Import>,
    /// Export name (`default` for `module.exports =` / `export default`) to local name.
    pub exports: BTreeMap<String, String>,
    pub functions: Vec<Function>,
    /// Entry points registered here, before mount prefixes.
    pub entries: Vec<Entry>,
    /// Routers mounted under a prefix here.
    pub mounts: Vec<Mount>,
    /// Files re-exported from here (`export * from './x'`).
    pub reexports: Vec<String>,
    /// Classes declared here with the classes and interfaces they extend or implement.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub classes: Vec<ClassDecl>,
    /// Properties assigned an instance of one of our classes here (`config.database = new
    /// DatabaseController(..)`): (property, (defining file, class)).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub properties: Vec<(String, (String, String))>,
}

/// A class and its bases (`extends`, `implements`), each as (defining file, name there).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ClassDecl {
    pub name: String,
    pub bases: Vec<(String, String)>,
}

/// `import x from './y'` / `const x = require('./y')`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Import {
    pub local: String,
    pub specifier: String,
    /// The export bound (`None`: the whole module).
    pub export: Option<String>,
    /// The file of the scan root it resolves to.
    pub resolved: Option<String>,
}

/// A named function (or method, `Class.method`; or route handler, `GET /path`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Function {
    pub name: String,
    pub line: u32,
    pub params: Vec<String>,
    pub calls: Vec<Call>,
    pub flows: Vec<Flow>,
    /// The local variable the function returns, when it returns one (`return router`).
    pub returns_local: Option<String>,
}

/// A call made by a function.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Call {
    /// The callee as written: `db.query`, `svc.find`, `exec`.
    pub callee: String,
    pub line: u32,
    pub args: Vec<Value>,
}

/// What a call argument is, as far as one file tells.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum Value {
    Literal(String),
    /// The calling function's parameter at this index.
    Param(usize),
    /// Attacker-controlled data of this source kind.
    Source(String),
    Other,
}

/// What a parameter reaches: a sink, or the function's return value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Flow {
    pub param: usize,
    /// The parameter's field, when the function destructures it.
    pub field: Option<String>,
    pub to: FlowTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum FlowTarget {
    Sink {
        class: VulnClass,
        severity: Severity,
        api: String,
        /// File and line of the sink (it may be in another module).
        file: String,
        line: u32,
    },
    Return,
}

/// An entry point as registered (mount prefixes are applied by the inventory).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Entry {
    pub receiver: Option<String>,
    /// The file that declares `receiver`, when it is another file's router.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver_file: Option<String>,
    pub method: String,
    pub path: String,
    pub handler: String,
    pub line: u32,
    pub auth: Auth,
    pub kind: String,
    pub inputs: Vec<(String, String)>,
}

/// `router.use('/prefix', child)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Mount {
    pub receiver: Option<String>,
    pub prefix: String,
    pub target: Option<String>,
    pub target_file: Option<String>,
    /// The export of `target_file` that is mounted (`require('./api').router`); its default
    /// export when `None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_export: Option<String>,
    /// Authentication middleware applied at the mount.
    pub auth: Auth,
}

/// A function, by module and name.
pub type FunctionId = (String, String);

/// The call graph across modules: caller -> callees, resolved through imports.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CallGraph {
    pub edges: BTreeMap<String, BTreeSet<String>>,
    /// Calls that resolved to a function of another module.
    pub cross_module: usize,
    /// Calls to a relative import whose target function was not found.
    pub unresolved: usize,
}

/// Links modules: resolves each call to a function of the same module or, through a resolved
/// import, of another one.
pub fn link(modules: &[Module]) -> CallGraph {
    let by_file: BTreeMap<&str, &Module> = modules.iter().map(|m| (m.file.as_str(), m)).collect();
    let mut graph = CallGraph::default();
    for module in modules {
        let local: BTreeSet<&str> = module.functions.iter().map(|f| f.name.as_str()).collect();
        let imports: BTreeMap<&str, &Import> = module
            .imports
            .iter()
            .map(|i| (i.local.as_str(), i))
            .collect();
        for function in &module.functions {
            for call in &function.calls {
                let target = resolve_call(&call.callee, &local, &imports, &by_file, &module.file);
                let caller = format!("{}#{}", module.file, function.name);
                match target {
                    Some((file, name)) => {
                        if file != module.file {
                            graph.cross_module += 1;
                        }
                        graph
                            .edges
                            .entry(caller)
                            .or_default()
                            .insert(format!("{file}#{name}"));
                    }
                    None => {
                        let head = call.callee.split('.').next().unwrap_or("");
                        if imports.get(head).is_some_and(|i| i.resolved.is_some()) {
                            graph.unresolved += 1;
                        }
                    }
                }
            }
        }
    }
    graph
}

/// The function `reference` (as written in `file`: `list`, `ctrl.list`, `Users.find`) names,
/// in that module or, through its imports, another.
pub fn resolve_reference(
    modules: &BTreeMap<&str, &Module>,
    file: &str,
    reference: &str,
) -> Option<FunctionId> {
    let module = modules.get(file)?;
    let local: BTreeSet<&str> = module.functions.iter().map(|f| f.name.as_str()).collect();
    let imports: BTreeMap<&str, &Import> = module
        .imports
        .iter()
        .map(|i| (i.local.as_str(), i))
        .collect();
    resolve_call(reference, &local, &imports, modules, file)
}

/// Functions reachable from `roots` through the call graph, each with the index of the first
/// root, in the order given, that reaches it: pass the roots in order of preference (the
/// weakest authentication first, so a helper reached from any public route counts as public).
pub fn reachable(graph: &CallGraph, roots: &[FunctionId]) -> BTreeMap<FunctionId, usize> {
    let mut seen: BTreeMap<FunctionId, usize> = BTreeMap::new();
    for (index, root) in roots.iter().enumerate() {
        let mut stack: Vec<FunctionId> = vec![root.clone()];
        while let Some(id) = stack.pop() {
            if seen.contains_key(&id) || seen.len() > 200_000 {
                continue;
            }
            seen.insert(id.clone(), index);
            if let Some(callees) = graph.edges.get(&format!("{}#{}", id.0, id.1)) {
                for callee in callees {
                    if let Some((file, name)) = callee.split_once('#') {
                        stack.push((file.to_owned(), name.to_owned()));
                    }
                }
            }
        }
    }
    seen
}

fn resolve_call(
    callee: &str,
    local: &BTreeSet<&str>,
    imports: &BTreeMap<&str, &Import>,
    by_file: &BTreeMap<&str, &Module>,
    file: &str,
) -> Option<FunctionId> {
    resolve_in(callee, local, imports, by_file, file, 0)
}

/// Resolves `callee` in one module, following imports, export names, namespace re-exports
/// (`import * as watch from './watch'; export { watch }`) and barrels (`export * from`).
fn resolve_in(
    callee: &str,
    local: &BTreeSet<&str>,
    imports: &BTreeMap<&str, &Import>,
    by_file: &BTreeMap<&str, &Module>,
    file: &str,
    depth: usize,
) -> Option<FunctionId> {
    if local.contains(callee) {
        return Some((file.to_owned(), callee.to_owned()));
    }
    if depth > 6 {
        return None;
    }
    let (head, rest) = match callee.split_once('.') {
        Some((head, rest)) => (head, Some(rest)),
        None => (callee, None),
    };
    let Some(import) = imports.get(head) else {
        // Neither defined nor imported here: a barrel's `export * from './x'` may re-export it
        // (followed through every level of barrels).
        return by_file.get(file)?.reexports.iter().find_map(|barrel| {
            let module = by_file.get(barrel.as_str())?;
            let names: BTreeSet<&str> = module.functions.iter().map(|f| f.name.as_str()).collect();
            let imports: BTreeMap<&str, &Import> = module
                .imports
                .iter()
                .map(|i| (i.local.as_str(), i))
                .collect();
            resolve_in(callee, &names, &imports, by_file, barrel, depth + 1)
        });
    };
    let target_file = import.resolved.as_deref()?;
    let target = by_file.get(target_file)?;
    let exported = |name: &str| {
        target
            .exports
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_owned())
    };
    // `import { find } ...; find()`, `import svc ...; svc.find()`, `import { Users } ...; Users.find()`.
    let candidates: Vec<String> = match (import.export.as_deref(), rest) {
        (Some(export), None) => vec![exported(export)],
        (Some(export), Some(method)) => vec![
            format!("{export}.{method}"),
            format!("{}.{method}", exported(export)),
        ],
        (None, Some(method)) => {
            let mut names = vec![method.to_owned()];
            if let Some(default) = target.exports.get("default") {
                names.push(format!("{default}.{method}"));
            }
            if let Some(name) = target.exports.get(method) {
                names.push(name.clone());
            }
            names
        }
        (None, None) => target.exports.get("default").cloned().into_iter().collect(),
    };
    if let Some(name) = candidates
        .iter()
        .find(|name| target.functions.iter().any(|f| f.name == **name))
    {
        return Some((target_file.to_owned(), name.clone()));
    }
    // Not defined there: follow what the target itself imports or re-exports.
    let target_local: BTreeSet<&str> = target.functions.iter().map(|f| f.name.as_str()).collect();
    let target_imports: BTreeMap<&str, &Import> = target
        .imports
        .iter()
        .map(|i| (i.local.as_str(), i))
        .collect();
    let follow = match (import.export.as_deref(), rest) {
        (Some(export), None) => Some(exported(export)),
        (Some(export), Some(more)) => Some(format!("{}.{more}", exported(export))),
        (None, Some(more)) => {
            let (segment, remaining) = match more.split_once('.') {
                Some((segment, remaining)) => (segment, Some(remaining)),
                None => (more, None),
            };
            Some(match remaining {
                Some(remaining) => format!("{}.{remaining}", exported(segment)),
                None => exported(segment),
            })
        }
        (None, None) => None,
    };
    if let Some(next) = &follow
        && let Some(found) = resolve_in(
            next,
            &target_local,
            &target_imports,
            by_file,
            target_file,
            depth + 1,
        )
    {
        return Some(found);
    }
    // Barrels: `export * from './x'`.
    let wanted = follow.or_else(|| candidates.first().cloned())?;
    target.reexports.iter().find_map(|barrel| {
        let module = by_file.get(barrel.as_str())?;
        let names: BTreeSet<&str> = module.functions.iter().map(|f| f.name.as_str()).collect();
        let imports: BTreeMap<&str, &Import> = module
            .imports
            .iter()
            .map(|i| (i.local.as_str(), i))
            .collect();
        resolve_in(&wanted, &names, &imports, by_file, barrel, depth + 1)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn function(name: &str, calls: &[&str]) -> Function {
        Function {
            name: name.to_owned(),
            calls: calls
                .iter()
                .map(|c| Call {
                    callee: (*c).to_owned(),
                    line: 1,
                    args: vec![Value::Source("http".to_owned())],
                })
                .collect(),
            ..Function::default()
        }
    }

    #[test]
    fn calls_link_through_imports_and_exports() {
        let routes = Module {
            file: "routes.js".to_owned(),
            imports: vec![Import {
                local: "svc".to_owned(),
                specifier: "./svc".to_owned(),
                export: None,
                resolved: Some("svc.js".to_owned()),
            }],
            functions: vec![
                function("GET /x", &["svc.find", "helper", "svc.missing"]),
                function("helper", &[]),
            ],
            ..Module::default()
        };
        let svc = Module {
            file: "svc.js".to_owned(),
            exports: BTreeMap::from([("find".to_owned(), "find".to_owned())]),
            functions: vec![function("find", &[])],
            ..Module::default()
        };
        let graph = link(&[routes, svc]);
        let callees = graph.edges.get("routes.js#GET /x").unwrap();
        assert!(callees.contains("svc.js#find"));
        assert!(callees.contains("routes.js#helper"));
        assert_eq!(graph.cross_module, 1);
        assert_eq!(graph.unresolved, 1);
    }

    #[test]
    fn references_follow_namespace_re_exports() {
        let app = Module {
            file: "app.js".to_owned(),
            imports: vec![Import {
                local: "api".to_owned(),
                specifier: "./api".to_owned(),
                export: None,
                resolved: Some("api/index.js".to_owned()),
            }],
            ..Module::default()
        };
        let index = Module {
            file: "api/index.js".to_owned(),
            imports: vec![Import {
                local: "watch".to_owned(),
                specifier: "./api.watch".to_owned(),
                export: None,
                resolved: Some("api/api.watch.js".to_owned()),
            }],
            exports: BTreeMap::from([("watch".to_owned(), "watch".to_owned())]),
            ..Module::default()
        };
        let watch = Module {
            file: "api/api.watch.js".to_owned(),
            exports: BTreeMap::from([("readFile".to_owned(), "readFile".to_owned())]),
            functions: vec![function("readFile", &[])],
            ..Module::default()
        };
        let modules = [app, index, watch];
        let by_file: BTreeMap<&str, &Module> =
            modules.iter().map(|m| (m.file.as_str(), m)).collect();
        assert_eq!(
            resolve_reference(&by_file, "app.js", "api.watch.readFile"),
            Some(("api/api.watch.js".to_owned(), "readFile".to_owned()))
        );
    }
}
