//! Structured diagnostics.
//!
//! Nothing is dropped silently: every file that is skipped, cannot be read or fails to parse
//! produces exactly one [`Diagnostic`] with a stable [`DiagCode`]. Diagnostics are always output
//! sorted (see [`sort`]) so reports are deterministic.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use serde::{Serialize, Serializer};

/// A stable diagnostic code. Its kebab-case string ([`DiagCode::as_str`]) is part of the output
/// format and must never change once released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiagCode {
    /// `skip/too-large`: the file is over [`crate::content::MAX_FILE_BYTES`].
    SkipTooLarge,
    /// `skip/minified`: the file looks minified (very long lines).
    SkipMinified,
    /// `skip/not-utf8`: the file is not valid UTF-8.
    SkipNotUtf8,
    /// `skip/too-deep`: bracket nesting is deep enough to risk a parser stack overflow.
    SkipTooDeep,
    /// `skip/symlink-outside-root`: a symlink resolves outside the scan root and is not followed.
    SkipSymlinkOutsideRoot,
    /// `skip/io-error`: the file or directory could not be read.
    SkipIoError,
    /// `parse/fatal`: the parser gave up; the file has no AST.
    ParseFatal,
    /// `parse/recovered`: the parser reported syntax errors but recovered an AST.
    ParseRecovered,
    /// `parse/panicked`: the parser panicked; the panic was contained to this file.
    ParsePanicked,
    /// `skip/template`: the file is a server-side template with a JS extension (EJS-style
    /// `<%` delimiters), not JavaScript.
    SkipTemplate,
}

impl DiagCode {
    /// Every code, in declaration order.
    pub const ALL: [DiagCode; 10] = [
        DiagCode::SkipTooLarge,
        DiagCode::SkipMinified,
        DiagCode::SkipNotUtf8,
        DiagCode::SkipTooDeep,
        DiagCode::SkipSymlinkOutsideRoot,
        DiagCode::SkipIoError,
        DiagCode::ParseFatal,
        DiagCode::ParseRecovered,
        DiagCode::ParsePanicked,
        DiagCode::SkipTemplate,
    ];

    /// The stable string form, e.g. `skip/too-large`.
    pub const fn as_str(self) -> &'static str {
        match self {
            DiagCode::SkipTooLarge => "skip/too-large",
            DiagCode::SkipMinified => "skip/minified",
            DiagCode::SkipNotUtf8 => "skip/not-utf8",
            DiagCode::SkipTooDeep => "skip/too-deep",
            DiagCode::SkipSymlinkOutsideRoot => "skip/symlink-outside-root",
            DiagCode::SkipIoError => "skip/io-error",
            DiagCode::ParseFatal => "parse/fatal",
            DiagCode::ParseRecovered => "parse/recovered",
            DiagCode::ParsePanicked => "parse/panicked",
            DiagCode::SkipTemplate => "skip/template",
        }
    }

    /// The skip reason for `skip/*` codes, `None` for the others.
    pub const fn skip_reason(self) -> Option<SkipReason> {
        match self {
            DiagCode::SkipTooLarge => Some(SkipReason::TooLarge),
            DiagCode::SkipMinified => Some(SkipReason::Minified),
            DiagCode::SkipNotUtf8 => Some(SkipReason::NotUtf8),
            DiagCode::SkipTooDeep => Some(SkipReason::TooDeep),
            DiagCode::SkipSymlinkOutsideRoot => Some(SkipReason::SymlinkOutsideRoot),
            DiagCode::SkipIoError => Some(SkipReason::IoError),
            DiagCode::SkipTemplate => Some(SkipReason::Template),
            DiagCode::ParseFatal | DiagCode::ParseRecovered | DiagCode::ParsePanicked => None,
        }
    }
}

/// Codes order by their string form, so "sorted by code" means the same thing in Rust and in
/// any tool that reads the JSON.
impl Ord for DiagCode {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for DiagCode {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for DiagCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for DiagCode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Error returned when parsing an unknown diagnostic code string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownDiagCode(pub String);

impl fmt::Display for UnknownDiagCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown diagnostic code `{}`", self.0)
    }
}

impl std::error::Error for UnknownDiagCode {}

impl FromStr for DiagCode {
    type Err = UnknownDiagCode;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DiagCode::ALL
            .into_iter()
            .find(|code| code.as_str() == s)
            .ok_or_else(|| UnknownDiagCode(s.to_owned()))
    }
}

/// Why a file was not parsed. Each reason corresponds to one `skip/*` [`DiagCode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SkipReason {
    TooLarge,
    Minified,
    NotUtf8,
    TooDeep,
    SymlinkOutsideRoot,
    IoError,
    Template,
}

impl SkipReason {
    /// Every reason, in declaration order.
    pub const ALL: [SkipReason; 7] = [
        SkipReason::TooLarge,
        SkipReason::Minified,
        SkipReason::NotUtf8,
        SkipReason::TooDeep,
        SkipReason::SymlinkOutsideRoot,
        SkipReason::IoError,
        SkipReason::Template,
    ];

    /// The diagnostic code reported for this reason.
    pub const fn code(self) -> DiagCode {
        match self {
            SkipReason::TooLarge => DiagCode::SkipTooLarge,
            SkipReason::Minified => DiagCode::SkipMinified,
            SkipReason::NotUtf8 => DiagCode::SkipNotUtf8,
            SkipReason::TooDeep => DiagCode::SkipTooDeep,
            SkipReason::SymlinkOutsideRoot => DiagCode::SkipSymlinkOutsideRoot,
            SkipReason::IoError => DiagCode::SkipIoError,
            SkipReason::Template => DiagCode::SkipTemplate,
        }
    }

    /// The reason part of the code, e.g. `too-large` for `skip/too-large`.
    pub const fn as_str(self) -> &'static str {
        match self {
            SkipReason::TooLarge => "too-large",
            SkipReason::Minified => "minified",
            SkipReason::NotUtf8 => "not-utf8",
            SkipReason::TooDeep => "too-deep",
            SkipReason::SymlinkOutsideRoot => "symlink-outside-root",
            SkipReason::IoError => "io-error",
            SkipReason::Template => "template",
        }
    }
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for SkipReason {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// One diagnostic. `path` is repo-relative and `/`-separated (lossy for non-UTF-8 names, but
/// stable), or `None` when the problem is not tied to a file.
///
/// `Ord` sorts by path, then code, then message: the order in which reports print them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Diagnostic {
    pub code: DiagCode,
    pub path: Option<String>,
    pub message: String,
}

impl Diagnostic {
    /// A diagnostic, optionally tied to a path.
    pub fn new(code: DiagCode, path: Option<String>, message: impl Into<String>) -> Self {
        Self {
            code,
            path,
            message: message.into(),
        }
    }

    /// A diagnostic about one file or directory, given by its relative path.
    pub fn at(code: DiagCode, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(code, Some(path.into()), message)
    }
}

impl Ord for Diagnostic {
    fn cmp(&self, other: &Self) -> Ordering {
        self.path
            .cmp(&other.path)
            .then_with(|| self.code.cmp(&other.code))
            .then_with(|| self.message.cmp(&other.message))
    }
}

impl PartialOrd for Diagnostic {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Sorts diagnostics into output order: path, then code, then message. Duplicates are kept, so
/// nothing is lost even when two files share a lossy path.
pub fn sort(diagnostics: &mut [Diagnostic]) {
    diagnostics.sort();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_have_stable_kebab_case_strings() {
        let strings: Vec<&str> = DiagCode::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(
            strings,
            [
                "skip/too-large",
                "skip/minified",
                "skip/not-utf8",
                "skip/too-deep",
                "skip/symlink-outside-root",
                "skip/io-error",
                "parse/fatal",
                "parse/recovered",
                "parse/panicked",
                "skip/template",
            ]
        );
        for code in DiagCode::ALL {
            assert_eq!(code.as_str().parse::<DiagCode>(), Ok(code));
            assert_eq!(
                serde_json::to_string(&code).unwrap(),
                format!("\"{}\"", code.as_str())
            );
        }
        assert!("skip/whatever".parse::<DiagCode>().is_err());
    }

    #[test]
    fn skip_reasons_round_trip_through_codes() {
        for reason in SkipReason::ALL {
            assert_eq!(reason.code().skip_reason(), Some(reason));
            assert_eq!(reason.code().as_str(), format!("skip/{}", reason.as_str()));
        }
        assert_eq!(DiagCode::ParseFatal.skip_reason(), None);
    }

    #[test]
    fn diagnostics_sort_by_path_then_code_then_message() {
        let mut diags = vec![
            Diagnostic::at(DiagCode::SkipTooLarge, "b.js", "x"),
            Diagnostic::at(DiagCode::ParseRecovered, "a.js", "z"),
            Diagnostic::at(DiagCode::ParseRecovered, "a.js", "y"),
            Diagnostic::at(DiagCode::ParseFatal, "a.js", "q"),
            Diagnostic::new(DiagCode::SkipIoError, None, "root"),
        ];
        sort(&mut diags);
        let keys: Vec<(Option<&str>, &str, &str)> = diags
            .iter()
            .map(|d| (d.path.as_deref(), d.code.as_str(), d.message.as_str()))
            .collect();
        assert_eq!(
            keys,
            [
                (None, "skip/io-error", "root"),
                (Some("a.js"), "parse/fatal", "q"),
                (Some("a.js"), "parse/recovered", "y"),
                (Some("a.js"), "parse/recovered", "z"),
                (Some("b.js"), "skip/too-large", "x"),
            ]
        );
    }

    #[test]
    fn diagnostics_serialize_with_string_codes() {
        let diag = Diagnostic::at(DiagCode::SkipMinified, "dist/app.js", "long line");
        assert_eq!(
            serde_json::to_string(&diag).unwrap(),
            r#"{"code":"skip/minified","path":"dist/app.js","message":"long line"}"#
        );
    }
}
