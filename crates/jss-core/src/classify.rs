//! Path classification: the ONE place that decides whether a file is source, test, docs,
//! example, generated or vendored code. (PySpector duplicated this logic in five places.)
//!
//! The rules are a data table ([`RULES`]) matched on the `/`-separated segments of a
//! root-relative path. When several rules match, the class with the highest precedence wins:
//! Vendor > Generated > Test > Example > Docs > Source. Besides the path, a file is Generated
//! when its first [`GENERATED_SCAN_BYTES`] contain [`GENERATED_MARKER`].
//!
//! - Directory names match exactly, case included: the conventional names are lowercase, while
//!   capitalized segments are usually real code (n8n's `nodes/Google/Docs/`,
//!   `descriptions/Vendor/`). File name patterns (`.min.js`, `.test.`) ignore case.
//! - Names that often mean real code inside a source tree ([`Pattern::DirOutsideSrc`]: `build`,
//!   `spec`, `examples`, `docs`, ...) only apply above the first `src` segment: `build/src/a.js`
//!   is build output, `src/build/controller.ts` is a feature.
//! - Hidden paths (any segment starting with `.`, such as `.next/` or `.yarn/`) are never walked
//!   (see [`crate::discover()`]), so the table has no rules for them.

use std::fmt;

use serde::{Serialize, Serializer};

/// What kind of code a file holds. Only [`ClassSet`]-selected classes are analyzed.
///
/// Variants are declared in ascending precedence, so `Ord` (and `max`) picks the class that wins
/// when several rules match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum FileClass {
    /// Application code: everything no other rule claims.
    Source,
    /// Documentation sites and snippets.
    Docs,
    /// Examples, demos, samples and fixtures.
    Example,
    /// Tests, mocks, end-to-end suites and stories.
    Test,
    /// Build output, bundles and files marked `@generated`.
    Generated,
    /// Third-party code checked into the tree.
    Vendor,
}

impl FileClass {
    /// Every class, in ascending precedence.
    pub const ALL: [FileClass; 6] = [
        FileClass::Source,
        FileClass::Docs,
        FileClass::Example,
        FileClass::Test,
        FileClass::Generated,
        FileClass::Vendor,
    ];

    /// The stable output name, e.g. `source` or `test`.
    pub const fn as_str(self) -> &'static str {
        match self {
            FileClass::Source => "source",
            FileClass::Docs => "docs",
            FileClass::Example => "example",
            FileClass::Test => "test",
            FileClass::Generated => "generated",
            FileClass::Vendor => "vendor",
        }
    }

    /// Parses a class name as a user would type it: singular or plural, any case
    /// (`test`/`tests`, `example`/`examples`, `doc`/`docs`, `source`/`src`, ...).
    pub fn from_name(name: &str) -> Option<FileClass> {
        let class = match name.trim().to_ascii_lowercase().as_str() {
            "source" | "sources" | "src" => FileClass::Source,
            "doc" | "docs" => FileClass::Docs,
            "example" | "examples" => FileClass::Example,
            "test" | "tests" => FileClass::Test,
            "generated" => FileClass::Generated,
            "vendor" | "vendored" => FileClass::Vendor,
            _ => return None,
        };
        Some(class)
    }

    const fn bit(self) -> u8 {
        match self {
            FileClass::Source => 1,
            FileClass::Docs => 1 << 1,
            FileClass::Example => 1 << 2,
            FileClass::Test => 1 << 3,
            FileClass::Generated => 1 << 4,
            FileClass::Vendor => 1 << 5,
        }
    }
}

impl fmt::Display for FileClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for FileClass {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// The set of classes selected for analysis. The default is Source only; Vendor and Generated
/// code is never analyzed unless explicitly added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClassSet(u8);

impl ClassSet {
    /// No classes.
    pub const EMPTY: ClassSet = ClassSet(0);

    /// Every class.
    pub const ALL: ClassSet = ClassSet(0b11_1111);

    /// A set holding only `class`.
    pub const fn only(class: FileClass) -> Self {
        ClassSet(class.bit())
    }

    /// This set plus `class`.
    #[must_use]
    pub const fn with(self, class: FileClass) -> Self {
        ClassSet(self.0 | class.bit())
    }

    /// Adds `class` to the set.
    pub fn insert(&mut self, class: FileClass) {
        self.0 |= class.bit();
    }

    /// Whether `class` is in the set.
    pub const fn contains(self, class: FileClass) -> bool {
        self.0 & class.bit() != 0
    }

    /// The classes in the set, in ascending precedence.
    pub fn iter(self) -> impl Iterator<Item = FileClass> {
        FileClass::ALL
            .into_iter()
            .filter(move |class| self.contains(*class))
    }
}

impl Default for ClassSet {
    fn default() -> Self {
        ClassSet::only(FileClass::Source)
    }
}

impl FromIterator<FileClass> for ClassSet {
    fn from_iter<I: IntoIterator<Item = FileClass>>(iter: I) -> Self {
        let mut set = ClassSet::EMPTY;
        for class in iter {
            set.insert(class);
        }
        set
    }
}

/// What a classification [`Rule`] matches. All names are lowercase ASCII. Directory names are
/// compared exactly; file name patterns with the lowercased file name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
    /// A directory segment (any segment but the file name) equal to one of these names.
    Dir(&'static [&'static str]),
    /// Like [`Pattern::Dir`], but only for segments before the first [`SOURCE_DIR`] segment:
    /// inside a source tree these names usually name real code.
    DirOutsideSrc(&'static [&'static str]),
    /// A file name ending with one of these suffixes, e.g. `.min.js`.
    Suffix(&'static [&'static str]),
    /// A file name containing one of these infixes, e.g. `.test.` for `*.test.*`.
    Infix(&'static [&'static str]),
    /// A file name starting with one of these prefixes, e.g. `jest.config.`.
    Prefix(&'static [&'static str]),
}

/// The directory name that starts a source tree (see [`Pattern::DirOutsideSrc`]).
pub const SOURCE_DIR: &str = "src";

/// One row of the classification table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub class: FileClass,
    pub pattern: Pattern,
}

/// The classification table. Order does not matter: precedence comes from [`FileClass`].
pub const RULES: &[Rule] = &[
    Rule {
        class: FileClass::Vendor,
        // Not `vendors`: n8n's `nodes/vendors/` holds its AI vendor integrations (real code).
        pattern: Pattern::Dir(&[
            "node_modules",
            "vendor",
            "bower_components",
            "third_party",
            "third-party",
            "thirdparty",
            "3rdparty",
            "jspm_packages",
        ]),
    },
    Rule {
        class: FileClass::Generated,
        pattern: Pattern::Dir(&["storybook-static"]),
    },
    Rule {
        class: FileClass::Generated,
        pattern: Pattern::DirOutsideSrc(&["dist", "build", "out", "coverage"]),
    },
    Rule {
        class: FileClass::Generated,
        pattern: Pattern::Suffix(&[".min.js", ".min.mjs", ".bundle.js"]),
    },
    Rule {
        class: FileClass::Test,
        pattern: Pattern::Dir(&[
            "test",
            "tests",
            "__test__",
            "__tests__",
            "__mocks__",
            "test-utils",
            "test_utils",
            "test-fixtures",
            "test_fixtures",
            "e2e",
            "cypress",
            "playwright",
        ]),
    },
    Rule {
        class: FileClass::Test,
        pattern: Pattern::DirOutsideSrc(&["spec"]),
    },
    Rule {
        class: FileClass::Test,
        pattern: Pattern::Infix(&[".test.", ".spec.", ".e2e.", ".stories."]),
    },
    Rule {
        // Test-runner configuration: never application code.
        class: FileClass::Test,
        pattern: Pattern::Prefix(&[
            "jest.config.",
            "jest.setup.",
            "vitest.config.",
            "vitest.setup.",
            "vitest.workspace.",
            "playwright.config.",
            "cypress.config.",
            "karma.conf.",
        ]),
    },
    Rule {
        class: FileClass::Docs,
        pattern: Pattern::DirOutsideSrc(&["docs", "doc", "documentation", "website"]),
    },
    Rule {
        class: FileClass::Example,
        pattern: Pattern::DirOutsideSrc(&[
            "examples", "example", "demo", "demos", "samples", "sample",
        ]),
    },
    Rule {
        class: FileClass::Example,
        pattern: Pattern::Dir(&["fixtures", "__fixtures__"]),
    },
];

/// The marker that makes a file Generated when it appears near the top (case-sensitive, so
/// TypeORM's `@Generated()` decorator does not match).
pub const GENERATED_MARKER: &[u8] = b"@generated";

/// How many leading bytes of a file are searched for [`GENERATED_MARKER`].
pub const GENERATED_SCAN_BYTES: usize = 2048;

/// Classifies a root-relative, `/`-separated path using [`RULES`] alone.
pub fn classify_path(rel_path: &str) -> FileClass {
    let (dirs, name) = match rel_path.rsplit_once('/') {
        Some((dirs, name)) => (dirs, name),
        None => ("", rel_path),
    };
    let name = name.to_ascii_lowercase();
    let mut class = FileClass::Source;
    for rule in RULES {
        if rule.class > class && rule_matches(rule.pattern, dirs, &name) {
            class = rule.class;
        }
    }
    class
}

fn rule_matches(pattern: Pattern, dirs: &str, name: &str) -> bool {
    let mut segments = dirs.split('/').filter(|segment| !segment.is_empty());
    match pattern {
        Pattern::Dir(names) => segments.any(|segment| names.contains(&segment)),
        Pattern::DirOutsideSrc(names) => segments
            .take_while(|&segment| segment != SOURCE_DIR)
            .any(|segment| names.contains(&segment)),
        Pattern::Suffix(suffixes) => suffixes.iter().any(|suffix| name.ends_with(suffix)),
        Pattern::Infix(infixes) => infixes.iter().any(|infix| name.contains(infix)),
        Pattern::Prefix(prefixes) => prefixes.iter().any(|prefix| name.starts_with(prefix)),
    }
}

/// Whether the file's leading bytes can still change a path class (only classes below
/// Generated can become Generated). Callers use it to avoid reading headers needlessly.
pub fn header_can_change(path_class: FileClass) -> bool {
    path_class < FileClass::Generated
}

/// Whether the first [`GENERATED_SCAN_BYTES`] of `head` contain [`GENERATED_MARKER`].
pub fn has_generated_marker(head: &[u8]) -> bool {
    let head = head.get(..GENERATED_SCAN_BYTES).unwrap_or(head);
    head.windows(GENERATED_MARKER.len())
        .any(|window| window == GENERATED_MARKER)
}

/// The final class of a file whose path class is `path_class`, given its leading bytes.
pub fn with_header(path_class: FileClass, head: &[u8]) -> FileClass {
    if header_can_change(path_class) && has_generated_marker(head) {
        FileClass::Generated
    } else {
        path_class
    }
}

/// Classifies a file from its root-relative path and, when available, its leading bytes.
pub fn classify(rel_path: &str, head: Option<&[u8]>) -> FileClass {
    let class = classify_path(rel_path);
    match head {
        Some(head) => with_header(class, head),
        None => class,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(path: &str) -> FileClass {
        classify_path(path)
    }

    #[test]
    fn plain_files_are_source() {
        assert_eq!(c("index.js"), FileClass::Source);
        assert_eq!(c("src/routes/users.ts"), FileClass::Source);
        // File names are not directory segments.
        assert_eq!(c("src/test.js"), FileClass::Source);
        assert_eq!(c("build.js"), FileClass::Source);
        assert_eq!(c("scripts/vendor.js"), FileClass::Source);
        // Segment matching is exact, not substring.
        assert_eq!(c("src/testing/a.js"), FileClass::Source);
        assert_eq!(c("src/latest/a.js"), FileClass::Source);
        assert_eq!(c("src/distribution/a.js"), FileClass::Source);
        assert_eq!(c("src/contest.js"), FileClass::Source);
    }

    #[test]
    fn every_vendor_directory_is_vendor() {
        for dir in [
            "node_modules",
            "vendor",
            "bower_components",
            "third_party",
            "third-party",
            "thirdparty",
            "3rdparty",
            "jspm_packages",
        ] {
            assert_eq!(c(&format!("{dir}/lib/a.js")), FileClass::Vendor, "{dir}");
            assert_eq!(
                c(&format!("public/{dir}/a.js")),
                FileClass::Vendor,
                "nested {dir}"
            );
            assert_eq!(
                c(&format!("src/static/js/{dir}/jquery.ts")),
                FileClass::Vendor,
                "inside src: {dir}"
            );
        }
    }

    #[test]
    fn every_generated_rule_is_generated() {
        for dir in ["dist", "build", "out", "coverage", "storybook-static"] {
            assert_eq!(c(&format!("{dir}/a.js")), FileClass::Generated, "{dir}");
            assert_eq!(
                c(&format!("packages/x/{dir}/src/a.js")),
                FileClass::Generated,
                "{dir}"
            );
        }
        for name in ["app.min.js", "app.min.mjs", "app.bundle.js"] {
            assert_eq!(c(&format!("public/{name}")), FileClass::Generated, "{name}");
        }
        assert_eq!(c("app.min.ts"), FileClass::Source);
    }

    #[test]
    fn every_test_rule_is_test() {
        for dir in [
            "test",
            "tests",
            "__test__",
            "__tests__",
            "__mocks__",
            "test-utils",
            "test_utils",
            "test-fixtures",
            "test_fixtures",
            "spec",
            "e2e",
            "cypress",
            "playwright",
        ] {
            assert_eq!(c(&format!("{dir}/a.js")), FileClass::Test, "{dir}");
        }
        for name in [
            "jest.config.js",
            "jest.setup.ts",
            "vitest.config.ts",
            "vitest.config.mts",
            "vitest.setup.ts",
            "vitest.workspace.ts",
            "playwright.config.ts",
            "cypress.config.js",
            "karma.conf.js",
            "Vitest.Config.TS",
        ] {
            assert_eq!(c(&format!("packages/x/{name}")), FileClass::Test, "{name}");
        }
        // Build tooling is not test code, and there is no generic `test-*` rule.
        assert_eq!(c("vite.config.ts"), FileClass::Source);
        assert_eq!(c("webpack.config.js"), FileClass::Source);
        assert_eq!(
            c("packages/cli/src/evaluation.ee/test-runner/runner.ts"),
            FileClass::Source
        );
        for name in [
            "a.test.js",
            "a.spec.ts",
            "a.e2e.tsx",
            "Button.stories.tsx",
            "a.test.helper.js",
        ] {
            assert_eq!(c(&format!("src/{name}")), FileClass::Test, "{name}");
        }
    }

    #[test]
    fn every_docs_and_example_rule_matches() {
        for dir in ["docs", "doc", "documentation", "website"] {
            assert_eq!(c(&format!("{dir}/a.js")), FileClass::Docs, "{dir}");
        }
        for dir in [
            "examples",
            "example",
            "demo",
            "demos",
            "samples",
            "sample",
            "fixtures",
            "__fixtures__",
        ] {
            assert_eq!(c(&format!("{dir}/a.js")), FileClass::Example, "{dir}");
        }
    }

    #[test]
    fn vendors_is_not_a_vendor_directory() {
        // n8n's AI vendor integration nodes are real code.
        assert_eq!(
            c("packages/@n8n/nodes-langchain/nodes/vendors/OpenAi/OpenAi.node.ts"),
            FileClass::Source
        );
    }

    #[test]
    fn directory_names_match_case_sensitively_and_file_names_do_not() {
        // Capitalized segments are real code (n8n integration nodes).
        assert_eq!(
            c("packages/nodes-base/nodes/Google/Docs/GoogleDocs.node.ts"),
            FileClass::Source
        );
        assert_eq!(
            c("packages/nodes-base/nodes/QuickBooks/descriptions/Vendor/VendorDescription.ts"),
            FileClass::Source
        );
        assert_eq!(c("Node_Modules/x/a.js"), FileClass::Source);
        assert_eq!(c("DIST/a.js"), FileClass::Source);
        assert_eq!(c("Tests/a.js"), FileClass::Source);
        assert_eq!(c("Examples/a.js"), FileClass::Source);
        assert_eq!(c("Src/build/a.js"), FileClass::Generated);
        // File name patterns ignore case.
        assert_eq!(c("src/App.MIN.JS"), FileClass::Generated);
        assert_eq!(c("src/a.Test.JS"), FileClass::Test);
        assert_eq!(c("src/Button.Stories.tsx"), FileClass::Test);
    }

    #[test]
    fn ambiguous_directory_names_do_not_apply_inside_a_source_tree() {
        // Real server code in corpus repos (n8n) that these names used to hide.
        for path in [
            "packages/modules/apps/backend/src/build/app-build.controller.ts",
            "packages/cli/src/modules/n8n-packages/spec/requirements.schema.ts",
            "packages/x/src/prompts/chains/parameter-updater/examples/registry-entry.ts",
            "src/docs/swagger.ts",
            "src/out/writer.ts",
            "src/coverage/report.service.ts",
            "src/demo/seed.ts",
        ] {
            assert_eq!(c(path), FileClass::Source, "{path}");
        }
        // Above the first `src`, they still apply.
        assert_eq!(c("build/src/a.js"), FileClass::Generated);
        assert_eq!(c("examples/basic/src/index.js"), FileClass::Example);
        assert_eq!(c("docs/src/components/a.js"), FileClass::Docs);
        assert_eq!(c("spec/src/a.js"), FileClass::Test);
        // Unambiguous names apply everywhere.
        assert_eq!(c("src/__tests__/a.js"), FileClass::Test);
        assert_eq!(c("src/test/a.js"), FileClass::Test);
        assert_eq!(c("src/fixtures/a.js"), FileClass::Example);
        assert_eq!(c("src/node_modules/x/a.js"), FileClass::Vendor);
        assert_eq!(c("src/storybook-static/a.js"), FileClass::Generated);
        // File name patterns too.
        assert_eq!(c("src/spec/a.spec.ts"), FileClass::Test);
        assert_eq!(c("src/build/app.min.js"), FileClass::Generated);
    }

    #[test]
    fn precedence_is_vendor_generated_test_example_docs_source() {
        // Vendor beats everything.
        assert_eq!(c("examples/node_modules/x/a.test.js"), FileClass::Vendor);
        assert_eq!(c("dist/vendor/a.js"), FileClass::Vendor);
        // Generated beats Test, Example and Docs.
        assert_eq!(c("test/dist/a.js"), FileClass::Generated);
        assert_eq!(c("src/a.test.min.js"), FileClass::Generated);
        assert_eq!(c("docs/build/a.js"), FileClass::Generated);
        // Test beats Example and Docs.
        assert_eq!(c("test/fixtures/a.js"), FileClass::Test);
        assert_eq!(c("examples/a.spec.js"), FileClass::Test);
        assert_eq!(c("docs/tests/a.js"), FileClass::Test);
        // Example beats Docs.
        assert_eq!(c("docs/examples/a.js"), FileClass::Example);
        assert_eq!(c("examples/docs/a.js"), FileClass::Example);
    }

    #[test]
    fn generated_marker_is_case_sensitive_and_limited_to_the_header() {
        assert!(has_generated_marker(b"/**\n * @generated by protoc\n */"));
        assert!(!has_generated_marker(
            b"@Entity() class A { @Generated('uuid') id }"
        ));
        let mut late = vec![b' '; GENERATED_SCAN_BYTES];
        late.extend_from_slice(b"// @generated");
        assert!(!has_generated_marker(&late), "past the first 2 KiB");
        let mut edge = vec![b' '; GENERATED_SCAN_BYTES - GENERATED_MARKER.len()];
        edge.extend_from_slice(GENERATED_MARKER);
        assert!(has_generated_marker(&edge), "ends exactly at 2 KiB");
    }

    #[test]
    fn header_marker_upgrades_lower_classes_only() {
        let head: &[u8] = b"// @generated\nexport {}";
        assert_eq!(classify("src/schema.ts", Some(head)), FileClass::Generated);
        assert_eq!(classify("test/a.js", Some(head)), FileClass::Generated);
        assert_eq!(classify("node_modules/a.js", Some(head)), FileClass::Vendor);
        assert_eq!(classify("src/schema.ts", None), FileClass::Source);
        assert_eq!(
            classify("src/schema.ts", Some(b"export {}")),
            FileClass::Source
        );
        assert_eq!(with_header(FileClass::Docs, head), FileClass::Generated);
        assert_eq!(with_header(FileClass::Vendor, head), FileClass::Vendor);
        assert_eq!(with_header(FileClass::Source, b"x"), FileClass::Source);
        assert!(header_can_change(FileClass::Test));
        assert!(!header_can_change(FileClass::Generated));
        assert!(!header_can_change(FileClass::Vendor));
    }

    #[test]
    fn class_names_parse_singular_and_plural() {
        assert_eq!(FileClass::from_name("tests"), Some(FileClass::Test));
        assert_eq!(FileClass::from_name("Examples"), Some(FileClass::Example));
        assert_eq!(FileClass::from_name("doc"), Some(FileClass::Docs));
        assert_eq!(FileClass::from_name("vendor"), Some(FileClass::Vendor));
        assert_eq!(
            FileClass::from_name("generated"),
            Some(FileClass::Generated)
        );
        assert_eq!(FileClass::from_name("source"), Some(FileClass::Source));
        assert_eq!(FileClass::from_name("nope"), None);
        for class in FileClass::ALL {
            assert_eq!(FileClass::from_name(class.as_str()), Some(class));
        }
    }

    #[test]
    fn class_set_defaults_to_source_only() {
        let default = ClassSet::default();
        assert!(default.contains(FileClass::Source));
        for class in [
            FileClass::Test,
            FileClass::Docs,
            FileClass::Example,
            FileClass::Generated,
            FileClass::Vendor,
        ] {
            assert!(!default.contains(class), "{class}");
        }
        let more = default.with(FileClass::Test).with(FileClass::Docs);
        assert_eq!(
            more.iter().collect::<Vec<_>>(),
            [FileClass::Source, FileClass::Docs, FileClass::Test]
        );
        assert_eq!(
            FileClass::ALL.into_iter().collect::<ClassSet>(),
            ClassSet::ALL
        );
        assert_eq!(ClassSet::EMPTY.iter().count(), 0);
    }
}
