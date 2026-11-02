//! `scan --verify`: confirm a finding by running the scanned app in a throwaway container and
//! sending the request the finding implies. Opt-in; nothing here runs without `--verify`.
//!
//! The work splits in two: [`plan`] and [`payload`] decide what to send and how to recognize a
//! hit, with no I/O (unit-tested directly); [`sandbox`] builds the image, starts the app with no
//! network reach beyond a marker service, sends the requests and tears everything down. A
//! finding the planner cannot drive is reported `skipped` with the reason, never a false
//! "clean".

mod payload;
mod plan;
mod sandbox;

use jss_core::Finding;
use serde::Serialize;

/// What verification concluded about one finding.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum Outcome {
    /// The app reproduced the finding; `how` names the request that did it.
    Verified { how: String },
    /// Every derived request was sent and none tripped the marker.
    NotReproduced { tried: usize },
    /// The finding was not driven; `reason` says why.
    Skipped { reason: String },
}

impl Outcome {
    /// A short, stable label for a report property: `verified`, `not-reproduced` or `skipped`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Verified { .. } => "verified",
            Self::NotReproduced { .. } => "not-reproduced",
            Self::Skipped { .. } => "skipped",
        }
    }
}

/// A finding's verdict, for the report.
#[derive(Debug, Clone, Serialize)]
pub struct Verdict {
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry: Option<String>,
    pub class: String,
    #[serde(flatten)]
    pub outcome: Outcome,
}

/// How a run should behave when Docker is not reachable.
pub enum Missing {
    /// Mark every finding skipped (the default: `--verify` is best-effort).
    Skip,
    /// Fail the command (`--verify=strict`): the user asked to verify and means it.
    Fail,
}

/// Verifies `findings` against the app rooted at `root`. Returns one verdict per finding, in the
/// same order. Builds the image once and reuses it for every finding.
pub fn run(
    root: &std::path::Path,
    findings: &[Finding],
    missing: Missing,
) -> Result<Vec<Verdict>, String> {
    let plans: Vec<Result<plan::Probe, plan::Skip>> =
        findings.iter().map(plan::Probe::from_finding).collect();

    // Nothing drivable, or no Docker: answer without building anything.
    let any_drivable = plans.iter().any(Result::is_ok);
    if !any_drivable {
        return Ok(findings
            .iter()
            .zip(&plans)
            .map(|(f, p)| verdict(f, skip_outcome(p)))
            .collect());
    }
    if !sandbox::available() {
        return match missing {
            Missing::Fail => Err(
                "--verify needs a running Docker daemon; none is reachable (start Docker, or drop --verify)"
                    .to_owned(),
            ),
            Missing::Skip => Ok(findings
                .iter()
                .map(|f| verdict(f, Outcome::Skipped {
                    reason: "no Docker daemon reachable".to_owned(),
                }))
                .collect()),
        };
    }

    let mut session = sandbox::Session::start(root)?;
    let verdicts = findings
        .iter()
        .zip(&plans)
        .map(|(finding, plan)| {
            let outcome = match plan {
                Err(skip) => Outcome::Skipped {
                    reason: skip.0.clone(),
                },
                Ok(probe) => session.exercise(probe),
            };
            verdict(finding, outcome)
        })
        .collect();
    session.teardown();
    Ok(verdicts)
}

fn verdict(finding: &Finding, outcome: Outcome) -> Verdict {
    Verdict {
        fingerprint: finding.fingerprint.clone(),
        entry: finding.entry.clone(),
        class: finding.class.name().to_owned(),
        outcome,
    }
}

fn skip_outcome(plan: &Result<plan::Probe, plan::Skip>) -> Outcome {
    match plan {
        Err(skip) => Outcome::Skipped {
            reason: skip.0.clone(),
        },
        // Reached only when nothing is drivable, so this arm is for completeness.
        Ok(_) => Outcome::Skipped {
            reason: "not attempted".to_owned(),
        },
    }
}

/// Renders the verification section of the text report: a line per finding that was driven, then
/// a count. Nothing when no finding was driven.
pub fn write_text(
    out: &mut dyn std::io::Write,
    verdicts: &[Verdict],
    color: bool,
) -> std::io::Result<()> {
    if verdicts.is_empty() {
        return Ok(());
    }
    let (bold, green, yellow, dim, reset) = if color {
        ("\x1b[1m", "\x1b[32m", "\x1b[33m", "\x1b[2m", "\x1b[0m")
    } else {
        ("", "", "", "", "")
    };
    let (mut verified, mut not_reproduced, mut skipped) = (0, 0, 0);
    writeln!(out, "\n  {bold}Verification{reset}")?;
    for v in verdicts {
        let entry = v.entry.as_deref().unwrap_or(&v.class);
        match &v.outcome {
            Outcome::Verified { how } => {
                verified += 1;
                writeln!(
                    out,
                    "  {green}✔ verified{reset} {entry} {dim}{}{reset}  ({how})",
                    v.fingerprint
                )?;
            }
            Outcome::NotReproduced { tried } => {
                not_reproduced += 1;
                writeln!(
                    out,
                    "  {yellow}• not reproduced{reset} {entry} {dim}{}{reset}  ({tried} request(s) sent)",
                    v.fingerprint
                )?;
            }
            Outcome::Skipped { .. } => skipped += 1,
        }
    }
    writeln!(
        out,
        "  {dim}verified {verified}, not reproduced {not_reproduced}, skipped {skipped}{reset}"
    )?;
    Ok(())
}
