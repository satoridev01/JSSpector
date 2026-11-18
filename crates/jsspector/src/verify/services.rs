//! The backing databases an app needs before it listens, and how it reaches them.
//!
//! Many apps exit at startup when their SQL database is missing (a connection pool that throws, an
//! ORM `sync()` that rejects). The verifier reproduces that precondition honestly instead of skipping
//! the app: it starts a throwaway database container on the sandbox network and tells the app where it
//! is. What to start comes, in order, from:
//!
//! 1. the repository's own Compose file: the database services the app's service depends on, with
//!    the image tag, environment and init scripts the project ships, reachable under the service
//!    name the app's configuration already uses (`db`, `mysql-db`, `dvws-mysql`);
//! 2. the app's declared drivers (`pg`, `mysql2`), when no Compose file names a database.
//!
//! Only official database images are ever started (never arbitrary services a Compose file lists),
//! only files inside the repository are mounted (read-only), and the app's environment is completed
//! from its own `process.env` reads of database settings, by naming convention. Nothing names a
//! specific application.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_norway::Value;

/// A SQL engine the sandbox can provide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlKind {
    Postgres,
    Mysql,
}

impl SqlKind {
    fn port(self) -> u16 {
        match self {
            Self::Postgres => 5432,
            Self::Mysql => 3306,
        }
    }

    fn scheme(self) -> &'static str {
        match self {
            Self::Postgres => "postgres",
            Self::Mysql => "mysql",
        }
    }
}

/// One SQL database container to start before the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlSidecar {
    pub kind: SqlKind,
    /// The image, as the project pins it (`postgres:14-alpine`), or a current default.
    pub image: String,
    /// Network aliases the app reaches it by; the first is its canonical host.
    pub aliases: Vec<String>,
    /// The database container's own environment (credentials, database name).
    pub container_env: Vec<(String, String)>,
    /// Repository files mounted read-only into the container (init scripts).
    pub mounts: Vec<(PathBuf, String)>,
    pub user: String,
    pub password: String,
    pub database: String,
}

impl SqlSidecar {
    /// The host the app connects to.
    pub fn host(&self) -> &str {
        self.aliases.first().map_or("db", String::as_str)
    }

    pub fn port(&self) -> u16 {
        self.kind.port()
    }

    /// A connection URL for this database.
    pub fn url(&self) -> String {
        format!(
            "{}://{}:{}@{}:{}/{}",
            self.kind.scheme(),
            self.user,
            self.password,
            self.host(),
            self.port(),
            self.database
        )
    }
}

/// What to start besides the app, and the environment the app gets for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServicePlan {
    pub sql: Vec<SqlSidecar>,
    /// Extra aliases for the MongoDB sidecar (Compose service names the app connects to).
    pub mongo_aliases: Vec<String>,
    /// Environment for the app, applied after the generic database variables.
    pub app_env: Vec<(String, String)>,
    /// The MongoDB image the repository pins (its Compose file or CI), when it pins one.
    pub mongo_image: Option<String>,
}

/// Database images a repository names outside a Compose file the app uses: its CI services
/// (GitHub Actions `jobs.*.services.*.image`, GitLab CI `services`). The first of each engine wins.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RepoImages {
    postgres: Option<String>,
    mysql: Option<String>,
    mongo: Option<String>,
}

impl RepoImages {
    fn note(&mut self, image: &str) {
        let slot = match image_engine(image) {
            Some(Engine::Sql(SqlKind::Postgres)) => &mut self.postgres,
            Some(Engine::Sql(SqlKind::Mysql)) => &mut self.mysql,
            Some(Engine::Mongo) => &mut self.mongo,
            None => return,
        };
        if slot.is_none() {
            *slot = Some(image.to_owned());
        }
    }
}

/// The images the repository's CI runs its databases as.
fn ci_images(root: &Path) -> RepoImages {
    let mut images = RepoImages::default();
    let mut files: Vec<PathBuf> = std::fs::read_dir(root.join(".github/workflows"))
        .map(|entries| {
            entries
                .flatten()
                .map(|entry| entry.path())
                .filter(|path| {
                    path.extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| matches!(ext, "yml" | "yaml"))
                })
                .collect()
        })
        .unwrap_or_default();
    files.sort();
    for file in &files {
        let Some(workflow) = read_yaml(file) else {
            continue;
        };
        let Some(jobs) = workflow.get("jobs").and_then(Value::as_mapping) else {
            continue;
        };
        for job in jobs.values() {
            let Some(services) = job.get("services").and_then(Value::as_mapping) else {
                continue;
            };
            for service in services.values() {
                if let Some(image) = service.as_str().or_else(|| service.get("image")?.as_str()) {
                    images.note(image);
                }
            }
        }
    }
    if let Some(gitlab) = read_yaml(&root.join(".gitlab-ci.yml")) {
        let mut lists: Vec<&Value> = gitlab.get("services").into_iter().collect();
        if let Some(map) = gitlab.as_mapping() {
            lists.extend(map.values().filter_map(|job| job.get("services")));
        }
        for list in lists.into_iter().filter_map(Value::as_sequence) {
            for service in list {
                if let Some(image) = service.as_str().or_else(|| service.get("name")?.as_str()) {
                    images.note(image);
                }
            }
        }
    }
    images
}

fn read_yaml(path: &Path) -> Option<Value> {
    serde_norway::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

const COMPOSE_NAMES: [&str; 4] = [
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
];
/// Variables the sandbox controls itself: the port it asks the app to listen on, the interface,
/// and the environment mode the operator chose for the run.
const SANDBOX_OWNED: [&str; 3] = ["PORT", "HOST", "NODE_ENV"];
const SANDBOX_PASSWORD: &str = "jsspector";
/// Words naming stores that are not a SQL server the sandbox runs.
const NOT_SQL_SERVER: [&str; 14] = [
    "REDIS",
    "CACHE",
    "SQLITE",
    "SQLITE3",
    "ELASTIC",
    "ELASTICSEARCH",
    "INFLUX",
    "INFLUXDB",
    "CLICKHOUSE",
    "NEO4J",
    "COUCH",
    "COUCHDB",
    "DYNAMO",
    "DYNAMODB",
];
const SANDBOX_DATABASE: &str = "jssverifydb";

/// Plans the databases for the app at `app_root` inside the repository at `root`. `mongo` says
/// whether the MongoDB sidecar runs (its URL fills Mongo settings the app reads by other names).
pub fn plan(root: &Path, app_root: &Path, mongo: bool) -> ServicePlan {
    let mut plan = ServicePlan::default();
    // The first Compose file (nearest first; the main file before its variants) that defines a
    // database; failing that, the first one, for the app's own environment.
    let composes = compose_files(root, app_root);
    let mut chosen = None;
    for (index, (dir, compose)) in composes.iter().enumerate() {
        let mut candidate = ServicePlan::default();
        plan_from_compose(root, app_root, dir, compose, mongo, &mut candidate);
        let defines_db = !candidate.sql.is_empty() || candidate.mongo_image.is_some();
        if defines_db {
            chosen = Some(candidate);
            break;
        }
        if index == 0 {
            chosen = Some(candidate);
        }
    }
    if let Some(candidate) = chosen {
        plan = candidate;
    }
    let repo = ci_images(root);
    if plan.sql.is_empty() {
        plan.sql = sidecars_from_dependencies(app_root, mongo, &repo);
    }
    if mongo && plan.mongo_image.is_none() {
        plan.mongo_image = repo.mongo.clone();
    }
    let sources = env_reads(app_root);
    complete_env(&mut plan, &sources, mongo);
    plan
}

/// Compose files from `app_root` up to `root`, nearest directory first: in each, the main file
/// (`docker-compose.yml`, `compose.yaml`), then its variants (`docker-compose.dev.yml`), then a
/// dev container's (`.devcontainer/docker-compose.yml`). Each with the directory paths resolve from.
fn compose_files(root: &Path, app_root: &Path) -> Vec<(PathBuf, Value)> {
    let mut out = Vec::new();
    let mut dir = Some(app_root);
    while let Some(current) = dir {
        let mut variants: Vec<PathBuf> = std::fs::read_dir(current)
            .map(|entries| {
                entries
                    .flatten()
                    .map(|entry| entry.path())
                    .filter(|path| {
                        let name = path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or_default();
                        (name.starts_with("docker-compose.") || name.starts_with("compose."))
                            && (name.ends_with(".yml") || name.ends_with(".yaml"))
                            && !COMPOSE_NAMES.contains(&name)
                    })
                    .collect()
            })
            .unwrap_or_default();
        variants.sort();
        let files = COMPOSE_NAMES
            .iter()
            .map(|name| current.join(name))
            .chain(variants)
            .chain(
                COMPOSE_NAMES
                    .iter()
                    .map(|name| current.join(".devcontainer").join(name)),
            );
        for file in files {
            if let Some(value) = read_yaml(&file)
                && value.get("services").is_some_and(Value::is_mapping)
            {
                let base = file
                    .parent()
                    .map_or_else(|| current.to_path_buf(), Path::to_path_buf);
                out.push((base, value));
            }
        }
        if current == root {
            break;
        }
        dir = current.parent().filter(|parent| parent.starts_with(root));
    }
    out
}

fn plan_from_compose(
    root: &Path,
    app_root: &Path,
    compose_dir: &Path,
    compose: &Value,
    mongo: bool,
    plan: &mut ServicePlan,
) {
    let Some(services) = compose.get("services").and_then(Value::as_mapping) else {
        return;
    };
    let dotenv = read_env_file(&compose_dir.join(".env")).unwrap_or_default();
    let app_canonical = app_root.canonicalize().ok();
    // The app's own service: the one whose build context is the app directory.
    let app_service = services.iter().find_map(|(name, service)| {
        let context = match service.get("build")? {
            Value::String(context) => context.clone(),
            build => build.get("context")?.as_str()?.to_owned(),
        };
        let resolved = compose_dir.join(context).canonicalize().ok()?;
        let name = name.as_str()?.to_owned();
        (Some(&resolved) == app_canonical.as_ref()).then_some((name, service))
    });
    // The databases it depends on, or every database the file defines when no service builds the app.
    let depends: Option<Vec<String>> =
        app_service
            .as_ref()
            .map(|(_, service)| match service.get("depends_on") {
                Some(Value::Sequence(list)) => list
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect(),
                Some(Value::Mapping(map)) => map
                    .keys()
                    .filter_map(|k| k.as_str().map(str::to_owned))
                    .collect(),
                _ => Vec::new(),
            });
    for (name, service) in services {
        let Some(name) = name.as_str() else {
            continue;
        };
        if let Some(depends) = &depends
            && !depends.is_empty()
            && !depends.iter().any(|d| d == name)
        {
            continue;
        }
        let Some(image) = service.get("image").and_then(Value::as_str) else {
            continue;
        };
        let image = interpolate(image, &dotenv);
        match image_engine(&image) {
            Some(Engine::Sql(kind)) => {
                let env = service_env(root, compose_dir, service, &dotenv);
                let mounts = init_mounts(root, compose_dir, service);
                plan.sql
                    .push(sql_sidecar(kind, image, vec![name.to_owned()], env, mounts));
            }
            Some(Engine::Mongo) if mongo => {
                plan.mongo_aliases.push(name.to_owned());
                plan.mongo_image.get_or_insert(image);
            }
            _ => {}
        }
    }
    if let Some((_, service)) = app_service {
        for (key, value) in service_env(root, compose_dir, service, &dotenv) {
            if !SANDBOX_OWNED.contains(&key.as_str()) {
                set(&mut plan.app_env, &key, value);
            }
        }
    }
}

enum Engine {
    Sql(SqlKind),
    Mongo,
}

/// The engine an official database image runs: `postgres:14-alpine`, `library/mysql:8`,
/// `mariadb`, `mongo:7`. Anything else is not started.
fn image_engine(image: &str) -> Option<Engine> {
    let repository = image.split(['@', ':']).next().unwrap_or(image);
    let repository = repository.strip_prefix("docker.io/").unwrap_or(repository);
    let repository = repository.strip_prefix("library/").unwrap_or(repository);
    match repository {
        "postgres" | "postgis/postgis" => Some(Engine::Sql(SqlKind::Postgres)),
        "mysql" | "mariadb" => Some(Engine::Sql(SqlKind::Mysql)),
        "mongo" => Some(Engine::Mongo),
        _ => None,
    }
}

/// A service's environment: its `env_file`s, then its `environment`, interpolated with the
/// Compose directory's `.env`. A missing env file falls back to the template the project commits
/// next to it (`vars.env.example`), never to anything outside the repository.
fn service_env(
    root: &Path,
    compose_dir: &Path,
    service: &Value,
    dotenv: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    let mut env = Vec::new();
    let files: Vec<String> = match service.get("env_file") {
        Some(Value::String(file)) => vec![file.clone()],
        Some(Value::Sequence(list)) => list
            .iter()
            .filter_map(|v| match v {
                Value::String(s) => Some(s.clone()),
                other => other.get("path")?.as_str().map(str::to_owned),
            })
            .collect(),
        _ => Vec::new(),
    };
    for file in files {
        let path = compose_dir.join(&file);
        let candidates = [
            path.clone(),
            PathBuf::from(format!("{}.example", path.display())),
            PathBuf::from(format!("{}.sample", path.display())),
        ];
        if let Some(values) = candidates
            .iter()
            .filter(|candidate| inside(root, candidate))
            .find_map(|candidate| read_env_file(candidate))
        {
            for (key, value) in values {
                set(&mut env, &key, interpolate(&value, dotenv));
            }
        }
    }
    match service.get("environment") {
        Some(Value::Mapping(map)) => {
            for (key, value) in map {
                let Some(key) = key.as_str() else { continue };
                let value = match value {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    _ => continue,
                };
                set(&mut env, key, interpolate(&value, dotenv));
            }
        }
        Some(Value::Sequence(list)) => {
            for item in list.iter().filter_map(Value::as_str) {
                if let Some((key, value)) = item.split_once('=') {
                    set(&mut env, key.trim(), interpolate(value, dotenv));
                }
            }
        }
        _ => {}
    }
    env.retain(|(_, value)| !value.is_empty());
    env
}

/// Init scripts a database service mounts from the repository (`./database/init.sql:/docker-
/// entrypoint-initdb.d/init.sql`): relative bind mounts that resolve inside the repository.
/// Named volumes and host paths are not mounted.
fn init_mounts(root: &Path, compose_dir: &Path, service: &Value) -> Vec<(PathBuf, String)> {
    let Some(volumes) = service.get("volumes").and_then(Value::as_sequence) else {
        return Vec::new();
    };
    let mut mounts = Vec::new();
    for volume in volumes {
        let (source, target) = match volume {
            Value::String(spec) => {
                let mut parts = spec.splitn(3, ':');
                let (Some(source), Some(target)) = (parts.next(), parts.next()) else {
                    continue;
                };
                (source.to_owned(), target.to_owned())
            }
            Value::Mapping(_) => {
                let (Some(source), Some(target)) = (
                    volume.get("source").and_then(Value::as_str),
                    volume.get("target").and_then(Value::as_str),
                ) else {
                    continue;
                };
                (source.to_owned(), target.to_owned())
            }
            _ => continue,
        };
        if !(source.starts_with("./") || source.starts_with("../")) {
            continue;
        }
        if !target.starts_with("/docker-entrypoint-initdb.d") {
            continue;
        }
        let Ok(resolved) = compose_dir.join(&source).canonicalize() else {
            continue;
        };
        if inside(root, &resolved) {
            mounts.push((resolved, target));
        }
    }
    mounts
}

fn inside(root: &Path, path: &Path) -> bool {
    match (root.canonicalize(), path.canonicalize()) {
        (Ok(root), Ok(path)) => path.starts_with(root),
        _ => false,
    }
}

/// A database container for `kind`, with credentials taken from (or added to) its environment so
/// that the container initializes and the app can log in.
fn sql_sidecar(
    kind: SqlKind,
    image: String,
    aliases: Vec<String>,
    mut env: Vec<(String, String)>,
    mounts: Vec<(PathBuf, String)>,
) -> SqlSidecar {
    let get = |env: &[(String, String)], key: &str| {
        env.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    };
    let (user, password, database) = match kind {
        SqlKind::Postgres => {
            let user = get(&env, "POSTGRES_USER").unwrap_or_else(|| "postgres".to_owned());
            let password = match get(&env, "POSTGRES_PASSWORD") {
                Some(password) => password,
                None => {
                    set(&mut env, "POSTGRES_PASSWORD", SANDBOX_PASSWORD.to_owned());
                    SANDBOX_PASSWORD.to_owned()
                }
            };
            let database = get(&env, "POSTGRES_DB").unwrap_or_else(|| user.clone());
            (user, password, database)
        }
        SqlKind::Mysql => {
            let pick = |env: &[(String, String)], suffix: &str| {
                get(env, &format!("MYSQL_{suffix}"))
                    .or_else(|| get(env, &format!("MARIADB_{suffix}")))
            };
            let database = match pick(&env, "DATABASE") {
                Some(database) => database,
                None => {
                    set(&mut env, "MYSQL_DATABASE", SANDBOX_DATABASE.to_owned());
                    SANDBOX_DATABASE.to_owned()
                }
            };
            let root_password = match pick(&env, "ROOT_PASSWORD") {
                Some(password) => Some(password),
                None if pick(&env, "ALLOW_EMPTY_PASSWORD").is_some()
                    || pick(&env, "RANDOM_ROOT_PASSWORD").is_some() =>
                {
                    None
                }
                None => {
                    set(&mut env, "MYSQL_ROOT_PASSWORD", SANDBOX_PASSWORD.to_owned());
                    Some(SANDBOX_PASSWORD.to_owned())
                }
            };
            match (pick(&env, "USER"), pick(&env, "PASSWORD")) {
                (Some(user), Some(password)) => (user, password, database),
                _ => match root_password {
                    Some(password) => ("root".to_owned(), password, database),
                    None => ("root".to_owned(), String::new(), database),
                },
            }
        }
    };
    SqlSidecar {
        kind,
        image,
        aliases,
        container_env: env,
        mounts,
        user,
        password,
        database,
    }
}

/// Databases implied by the drivers the app declares, when no Compose file names one.
fn sidecars_from_dependencies(app_root: &Path, mongo: bool, repo: &RepoImages) -> Vec<SqlSidecar> {
    let Ok(manifest) = std::fs::read_to_string(app_root.join("package.json")) else {
        return Vec::new();
    };
    let Ok(json) = serde_json::from_str::<serde_json::Value>(&manifest) else {
        return Vec::new();
    };
    let declares = |names: &[&str]| {
        ["dependencies", "optionalDependencies"]
            .iter()
            .filter_map(|section| json.get(section).and_then(serde_json::Value::as_object))
            .any(|deps| names.iter().any(|name| deps.contains_key(*name)))
    };
    // Generic hostnames apps default to; the MongoDB sidecar keeps `db`/`database` when it runs.
    let generic: &[&str] = if mongo { &[] } else { &["db", "database"] };
    let mut out = Vec::new();
    if declares(&["pg", "pg-promise", "postgres", "pg-pool"]) {
        let mut aliases = vec!["postgres".to_owned(), "postgresql".to_owned()];
        aliases.extend(generic.iter().map(|a| (*a).to_owned()));
        out.push(sql_sidecar(
            SqlKind::Postgres,
            repo.postgres
                .clone()
                .unwrap_or_else(|| default_image("POSTGRES", "postgres:16-alpine")),
            aliases,
            vec![("POSTGRES_DB".to_owned(), SANDBOX_DATABASE.to_owned())],
            Vec::new(),
        ));
    }
    if declares(&["mysql", "mysql2", "mariadb"]) {
        let mut aliases = vec!["mysql".to_owned(), "mariadb".to_owned()];
        if out.is_empty() {
            aliases.extend(generic.iter().map(|a| (*a).to_owned()));
        }
        out.push(sql_sidecar(
            SqlKind::Mysql,
            repo.mysql
                .clone()
                .unwrap_or_else(|| default_image("MYSQL", "mysql:8")),
            aliases,
            Vec::new(),
            Vec::new(),
        ));
    }
    out
}

/// Fills database settings the app reads from `process.env` but nothing set yet, by the naming
/// convention of the variable: the engine from its words (`PG`, `POSTGRES`, `MYSQL`, `MONGO`, or a
/// generic `DB`/`SQL` when one SQL database runs), the part from its last word (`_URL`, `_HOST`,
/// `_PORT`, `_USER`, `_PASSWORD`, `_NAME`). Also the standard libpq variables (`PGHOST`, ...) the
/// `pg` driver reads by itself, and a `DATABASE_URL` when the only database is SQL.
fn complete_env(plan: &mut ServicePlan, reads: &[String], mongo: bool) {
    let mongo_host = plan
        .mongo_aliases
        .first()
        .cloned()
        .unwrap_or_else(|| "mongo".to_owned());
    let mongo_url = format!("mongodb://{mongo_host}:27017/{SANDBOX_DATABASE}");
    let postgres = plan
        .sql
        .iter()
        .find(|s| s.kind == SqlKind::Postgres)
        .cloned();
    let mysql = plan.sql.iter().find(|s| s.kind == SqlKind::Mysql).cloned();
    let single_sql = match plan.sql.as_slice() {
        [only] => Some(only.clone()),
        _ => None,
    };
    if let Some(pg) = &postgres {
        for (key, value) in [
            ("PGHOST", pg.host().to_owned()),
            ("PGPORT", pg.port().to_string()),
            ("PGUSER", pg.user.clone()),
            ("PGPASSWORD", pg.password.clone()),
            ("PGDATABASE", pg.database.clone()),
        ] {
            set_default(&mut plan.app_env, key, value);
        }
    }
    if !mongo && let Some(sql) = &single_sql {
        set_default(&mut plan.app_env, "DATABASE_URL", sql.url());
    }
    for name in reads {
        if plan.app_env.iter().any(|(k, _)| k == name) || SANDBOX_OWNED.contains(&name.as_str()) {
            continue;
        }
        let words: Vec<&str> = name.split('_').filter(|w| !w.is_empty()).collect();
        let has = |w: &str| words.contains(&w);
        // Other stores whose settings share the vocabulary (`REDIS_DB`, `SQLITE_DB`).
        if NOT_SQL_SERVER.iter().any(|w| has(w)) {
            continue;
        }
        let target = if has("MONGO") || has("MONGODB") {
            mongo.then_some(None)
        } else if has("PG") || has("POSTGRES") || has("POSTGRESQL") || name.starts_with("PG") {
            postgres.clone().map(Some)
        } else if has("MYSQL") || has("MARIADB") {
            mysql.clone().map(Some)
        } else if has("DB") || has("DATABASE") || has("SQL") {
            single_sql.clone().map(Some)
        } else {
            None
        };
        let Some(target) = target else { continue };
        let Some(last) = words.last() else { continue };
        // A bare `DB`/`DATABASE` is too ambiguous to fill.
        if words.len() == 1 && !name.starts_with("PG") {
            continue;
        }
        let value = match (*last, &target) {
            ("URL" | "URI" | "CONN" | "CONNECTION" | "DSN" | "STRING", None) => mongo_url.clone(),
            ("URL" | "URI" | "CONN" | "CONNECTION" | "DSN" | "STRING", Some(sql)) => sql.url(),
            ("HOST" | "HOSTNAME" | "SERVER" | "ADDR" | "ADDRESS", None) => mongo_host.clone(),
            ("HOST" | "HOSTNAME" | "SERVER" | "ADDR" | "ADDRESS", Some(sql)) => {
                sql.host().to_owned()
            }
            ("PORT", None) => "27017".to_owned(),
            ("PORT", Some(sql)) => sql.port().to_string(),
            ("USER" | "USERNAME" | "LOGIN", Some(sql)) => sql.user.clone(),
            ("PASS" | "PASSWORD" | "PWD", Some(sql)) => sql.password.clone(),
            ("NAME" | "DB" | "DATABASE" | "SCHEMA", None) => SANDBOX_DATABASE.to_owned(),
            ("NAME" | "DB" | "DATABASE" | "SCHEMA", Some(sql)) => sql.database.clone(),
            _ => continue,
        };
        set(&mut plan.app_env, name, value);
    }
}

/// The environment variable names the app's own sources read (`process.env.DB_HOST`,
/// `process.env['DB_HOST']`), skipping dependencies and build output.
fn env_reads(app_root: &Path) -> Vec<String> {
    const MAX_BYTES: usize = 4 * 1024 * 1024;
    let mut names: Vec<String> = Vec::new();
    let mut seen = 0usize;
    let mut stack = vec![app_root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut entries: Vec<_> = entries.flatten().collect();
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if !matches!(
                    name.as_ref(),
                    "node_modules" | ".git" | "dist" | "build" | "coverage" | "vendor" | ".next"
                ) {
                    stack.push(path);
                }
                continue;
            }
            let script = path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| matches!(ext, "js" | "mjs" | "cjs" | "ts" | "mts" | "cts"));
            if !script || name.ends_with(".min.js") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            seen += text.len();
            for name in process_env_names(&text) {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
            if seen > MAX_BYTES {
                return names;
            }
        }
    }
    names
}

fn process_env_names(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(pos) = text[from..].find("process.env") {
        let after = &text[from + pos + "process.env".len()..];
        from += pos + "process.env".len();
        let name: String = if let Some(rest) = after.strip_prefix('.') {
            rest.chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect()
        } else if let Some(rest) = after.strip_prefix('[') {
            let rest = rest.trim_start();
            match rest.chars().next() {
                Some(quote @ ('\'' | '"' | '`')) => {
                    rest[1..].chars().take_while(|c| *c != quote).collect()
                }
                _ => String::new(),
            }
        } else {
            String::new()
        };
        if !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            && !out.contains(&name)
        {
            out.push(name);
        }
    }
    out
}

/// `KEY=VALUE` lines of an env file (comments, blank lines and surrounding quotes dropped).
fn read_env_file(path: &Path) -> Option<BTreeMap<String, String>> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
            .unwrap_or(value);
        out.insert(key.trim().to_owned(), value.to_owned());
    }
    Some(out)
}

/// Compose variable interpolation: `${VAR}`, `${VAR:-default}`, `${VAR-default}`, `$VAR`, `$$`.
/// Values come from the Compose directory's `.env` only (never the verifier's own environment).
fn interpolate(text: &str, vars: &BTreeMap<String, String>) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(tail) = after.strip_prefix('$') {
            out.push('$');
            rest = tail;
        } else if let Some(body) = after.strip_prefix('{')
            && let Some(end) = body.find('}')
        {
            let inner = &body[..end];
            let (name, default, empty_counts) = if let Some((n, d)) = inner.split_once(":-") {
                (n, Some(d), true)
            } else if let Some((n, d)) = inner.split_once('-') {
                (n, Some(d), false)
            } else {
                (inner, None, false)
            };
            let value = vars.get(name.trim());
            let resolved = match (value, default) {
                (Some(v), Some(d)) if v.is_empty() && empty_counts => d.to_owned(),
                (Some(v), _) => v.clone(),
                (None, Some(d)) => d.to_owned(),
                (None, None) => String::new(),
            };
            out.push_str(&resolved);
            rest = &body[end + 1..];
        } else {
            let name: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                out.push('$');
                rest = after;
            } else {
                out.push_str(vars.get(&name).map_or("", String::as_str));
                rest = &after[name.len()..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The image for an engine the repository does not pin anywhere: the operator's choice
/// (`JSS_VERIFY_POSTGRES_IMAGE`, `JSS_VERIFY_MYSQL_IMAGE`) when it names an official image of that
/// engine, else `fallback`.
fn default_image(engine: &str, fallback: &str) -> String {
    std::env::var(format!("JSS_VERIFY_{engine}_IMAGE"))
        .ok()
        .filter(|image| {
            !image.is_empty()
                && image.len() <= 128
                && image.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':' | b'/')
                })
                && matches!(
                    (image_engine(image), engine),
                    (Some(Engine::Sql(SqlKind::Postgres)), "POSTGRES")
                        | (Some(Engine::Sql(SqlKind::Mysql)), "MYSQL")
                )
        })
        .unwrap_or_else(|| fallback.to_owned())
}

fn set(env: &mut Vec<(String, String)>, key: &str, value: String) {
    match env.iter_mut().find(|(k, _)| k == key) {
        Some(slot) => slot.1 = value,
        None => env.push((key.to_owned(), value)),
    }
}

fn set_default(env: &mut Vec<(String, String)>, key: &str, value: String) {
    if env.iter().all(|(k, _)| k != key) {
        env.push((key.to_owned(), value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, text: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn env<'a>(plan: &'a ServicePlan, key: &str) -> Option<&'a str> {
        plan.app_env
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn compose_databases_the_app_depends_on_are_planned_under_their_service_names() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "docker-compose.yml",
            "services:\n  db:\n    image: postgres:14-alpine\n    environment:\n      POSTGRES_USER: ${POSTGRES_USER:-postgres}\n      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-pw}\n      POSTGRES_DB: shop\n    volumes:\n      - pgdata:/var/lib/postgresql/data\n      - ./database/init.sql:/docker-entrypoint-initdb.d/init.sql\n      - /etc/passwd:/docker-entrypoint-initdb.d/x.sql\n  ollama:\n    image: ollama/ollama:latest\n  attacker:\n    image: evil/thing\n  server:\n    build: .\n    environment:\n      - POSTGRES_HOST=${POSTGRES_HOST:-db}\n      - PORT=5000\n      - NODE_ENV=production\n    depends_on:\n      db:\n        condition: service_healthy\n",
        );
        write(root, "database/init.sql", "create table t(id int);");
        write(root, "package.json", r#"{"dependencies":{"pg":"8"}}"#);
        write(
            root,
            "server.js",
            "const host = process.env.POSTGRES_HOST || 'db';",
        );
        let plan = plan(root, root, false);
        assert_eq!(plan.sql.len(), 1, "{plan:?}");
        let db = &plan.sql[0];
        assert_eq!(db.kind, SqlKind::Postgres);
        assert_eq!(db.image, "postgres:14-alpine");
        assert_eq!(db.aliases, vec!["db"]);
        assert_eq!(
            (db.user.as_str(), db.password.as_str(), db.database.as_str()),
            ("postgres", "pw", "shop")
        );
        // Only the repository's own init script, never a host path or a named volume.
        assert_eq!(db.mounts.len(), 1, "{:?}", db.mounts);
        assert!(db.mounts[0].0.ends_with("database/init.sql"));
        // The app's Compose environment, minus what the sandbox controls.
        assert_eq!(env(&plan, "POSTGRES_HOST"), Some("db"));
        assert_eq!(env(&plan, "PORT"), None);
        assert_eq!(env(&plan, "NODE_ENV"), None);
        assert_eq!(env(&plan, "PGHOST"), Some("db"));
        assert_eq!(
            env(&plan, "DATABASE_URL"),
            Some("postgres://postgres:pw@db:5432/shop")
        );
    }

    #[test]
    fn a_missing_env_file_and_unset_reads_are_completed_by_convention() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "docker-compose.yml",
            "services:\n  app:\n    build:\n      context: ./\n    depends_on:\n      - mysql-db\n    env_file:\n      - ./vars.env\n  mysql-db:\n    image: mysql:5.7\n    env_file:\n      - ./vars.env\n",
        );
        write(
            root,
            "config/db.js",
            "module.exports = { username: process.env.MYSQL_USER, password: process.env.MYSQL_PASSWORD, database: process.env['MYSQL_DATABASE'], host: process.env.MYSQL_HOST || 'mysql-db', port: process.env.MYSQL_PORT };",
        );
        let plan = plan(root, root, false);
        let db = &plan.sql[0];
        assert_eq!(db.kind, SqlKind::Mysql);
        assert_eq!(db.image, "mysql:5.7");
        assert_eq!(db.aliases, vec!["mysql-db"]);
        // No env file: the container gets credentials, and the app reads them back.
        assert!(
            db.container_env
                .iter()
                .any(|(k, v)| k == "MYSQL_ROOT_PASSWORD" && v == "jsspector")
        );
        assert_eq!(env(&plan, "MYSQL_USER"), Some("root"));
        assert_eq!(env(&plan, "MYSQL_PASSWORD"), Some("jsspector"));
        assert_eq!(env(&plan, "MYSQL_DATABASE"), Some("jssverifydb"));
        assert_eq!(env(&plan, "MYSQL_HOST"), Some("mysql-db"));
        assert_eq!(env(&plan, "MYSQL_PORT"), Some("3306"));
    }

    #[test]
    fn mongo_and_sql_services_share_the_network_without_sharing_names() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "docker-compose.yml",
            "services:\n  dvws-mongo:\n    image: mongo:4.0.4\n  dvws-mysql:\n    image: mysql:8\n    environment:\n      MYSQL_ROOT_PASSWORD: secret\n      MYSQL_DATABASE: app_db\n  web:\n    build: .\n    environment:\n      SQL_LOCAL_CONN_URL: dvws-mysql\n      MONGO_LOCAL_CONN_URL: mongodb://dvws-mongo:27017/app\n    depends_on:\n      dvws-mongo:\n        condition: service_healthy\n      dvws-mysql:\n        condition: service_healthy\n",
        );
        write(
            root,
            "src/db.js",
            "mysql.createConnection({ host: process.env.SQL_LOCAL_CONN_URL, user: process.env.SQL_USERNAME, password: process.env.SQL_PASSWORD });",
        );
        let plan = plan(root, root, true);
        assert_eq!(plan.mongo_aliases, vec!["dvws-mongo"]);
        assert_eq!(plan.sql.len(), 1);
        assert_eq!(plan.sql[0].aliases, vec!["dvws-mysql"]);
        assert_eq!(
            env(&plan, "MONGO_LOCAL_CONN_URL"),
            Some("mongodb://dvws-mongo:27017/app")
        );
        assert_eq!(env(&plan, "SQL_LOCAL_CONN_URL"), Some("dvws-mysql"));
        assert_eq!(env(&plan, "SQL_USERNAME"), Some("root"));
        assert_eq!(env(&plan, "SQL_PASSWORD"), Some("secret"));
        // With MongoDB running, `DATABASE_URL` stays the MongoDB sidecar's.
        assert_eq!(env(&plan, "DATABASE_URL"), None);
    }

    #[test]
    fn drivers_imply_a_database_when_no_compose_file_names_one() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "package.json",
            r#"{"dependencies":{"express":"4","pg":"8"}}"#,
        );
        write(
            root,
            "db.js",
            "new Pool({ connectionString: process.env.DATABASE_URL, host: process.env.DB_HOST }); redis(process.env.REDIS_DB); open(process.env.SQLITE_DB);",
        );
        let plan = plan(root, root, false);
        assert_eq!(plan.sql.len(), 1);
        assert_eq!(plan.sql[0].image, "postgres:16-alpine");
        assert_eq!(plan.sql[0].host(), "postgres");
        assert!(plan.sql[0].aliases.contains(&"db".to_owned()));
        assert_eq!(env(&plan, "DB_HOST"), Some("postgres"));
        assert_eq!(env(&plan, "REDIS_DB"), None);
        assert_eq!(env(&plan, "SQLITE_DB"), None);
        assert!(
            env(&plan, "DATABASE_URL")
                .is_some_and(|u| u.starts_with("postgres://postgres:jsspector@postgres:5432/"))
        );
        // No driver, nothing to start.
        let other = tempfile::tempdir().unwrap();
        write(
            other.path(),
            "package.json",
            r#"{"dependencies":{"express":"4"}}"#,
        );
        assert!(plan_for(other.path()).sql.is_empty());
    }

    #[test]
    fn without_a_compose_file_the_repository_ci_pins_the_versions() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "package.json",
            r#"{"dependencies":{"pg":"8","mongoose":"6"}}"#,
        );
        write(
            root,
            ".github/workflows/test.yml",
            "jobs:\n  test:\n    services:\n      postgres:\n        image: postgres:13\n      mongo:\n        image: mongo:4.4\n",
        );
        let plan = plan(root, root, true);
        assert_eq!(plan.sql[0].image, "postgres:13");
        assert_eq!(plan.mongo_image.as_deref(), Some("mongo:4.4"));
        // GitLab CI lists them too.
        let other = tempfile::tempdir().unwrap();
        write(
            other.path(),
            "package.json",
            r#"{"dependencies":{"mysql2":"3"}}"#,
        );
        write(
            other.path(),
            ".gitlab-ci.yml",
            "test:\n  services:\n    - mysql:5.7\n",
        );
        assert_eq!(plan_for(other.path()).sql[0].image, "mysql:5.7");
    }

    #[test]
    fn a_compose_variant_or_dev_container_names_the_database_when_the_main_file_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "docker-compose.yml",
            "services:\n  web:\n    build: .\n",
        );
        write(
            root,
            "docker-compose.dev.yml",
            "services:\n  db:\n    image: postgres:15\n  mongo:\n    image: mongo:5\n  web:\n    build: .\n",
        );
        let plan = plan(root, root, true);
        assert_eq!(plan.sql[0].image, "postgres:15");
        assert_eq!(plan.sql[0].aliases, vec!["db"]);
        assert_eq!(plan.mongo_image.as_deref(), Some("mongo:5"));
        assert_eq!(plan.mongo_aliases, vec!["mongo"]);
        let devc = tempfile::tempdir().unwrap();
        write(
            devc.path(),
            "package.json",
            r#"{"dependencies":{"mysql2":"3"}}"#,
        );
        write(
            devc.path(),
            ".devcontainer/docker-compose.yml",
            "services:\n  mysql:\n    image: mariadb:10.6\n",
        );
        assert_eq!(plan_for(devc.path()).sql[0].image, "mariadb:10.6");
    }

    fn plan_for(root: &Path) -> ServicePlan {
        plan(root, root, false)
    }

    #[test]
    fn interpolation_follows_compose_rules() {
        let mut vars = BTreeMap::new();
        vars.insert("SET".to_owned(), "v".to_owned());
        vars.insert("EMPTY".to_owned(), String::new());
        assert_eq!(interpolate("${SET:-d}", &vars), "v");
        assert_eq!(interpolate("${MISSING:-d}", &vars), "d");
        assert_eq!(interpolate("${EMPTY:-d}", &vars), "d");
        assert_eq!(interpolate("${EMPTY-d}", &vars), "");
        assert_eq!(interpolate("a$SET-b$$c", &vars), "av-b$c");
        assert_eq!(interpolate("${MISSING}", &vars), "");
    }

    #[test]
    fn process_env_reads_in_both_spellings() {
        assert_eq!(
            process_env_names(
                "a(process.env.DB_HOST); b(process.env['DB_USER']); c(process.env[\"X\"]); d(process.env[name])"
            ),
            vec!["DB_HOST", "DB_USER", "X"]
        );
    }
}
