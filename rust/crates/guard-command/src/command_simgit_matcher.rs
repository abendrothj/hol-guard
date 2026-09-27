//! The two destructive simgit flags and shell arguments that can supply them.

use std::collections::BTreeSet;
use std::sync::LazyLock;
use std::time::Instant;

use serde::Deserialize;

use crate::command_ascii_comparison::executable_matches;
use crate::command_option_parsing::{
    flags_present_in_all_option_parses_with_deadline, known_option_advance,
    long_flag_assignment_is_enabled, subcommand_parse_tails_with_deadline, MAX_OPTION_PARSE_STATES,
};
use crate::command_structured_matchers::check_deadline;
use crate::{shell_tokens, CommandSegmentV1};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SimgitFlagConfig {
    required_flag: String,
    #[serde(default)]
    quiet_flag: Option<String>,
    #[serde(skip)]
    quiet_flags: BTreeSet<String>,
}

impl SimgitFlagConfig {
    pub(super) fn validate(mut self) -> Result<Self, &'static str> {
        if !matches!(
            self.required_flag.as_str(),
            "--discard-dirty" | "--delete-unmerged"
        ) || self
            .quiet_flag
            .as_deref()
            .is_some_and(|flag| !matches!(flag, "--help" | "--dry-run"))
        {
            return Err("invalid_specialized_matcher_config");
        }
        if let Some(flag) = &self.quiet_flag {
            self.quiet_flags.insert(flag.clone());
        }
        Ok(self)
    }

    pub(super) fn matches(
        &self,
        segment: &CommandSegmentV1,
        deadline: Option<Instant>,
    ) -> Result<bool, &'static str> {
        if !executable_matches(segment, &EXECUTABLES) {
            return Ok(false);
        }
        let expansion_kinds = if segment.arguments.iter().any(|arg| has_marker(arg)) {
            expansion_kinds(segment)
        } else {
            Vec::new()
        };
        let arguments = &segment.arguments;
        for grammar in GRAMMARS.iter() {
            if self.quiet_flag.as_deref() == Some("--dry-run") && grammar.name == "remove" {
                continue;
            }
            let tails = subcommand_parse_tails_with_deadline(
                arguments,
                &grammar.subcommands,
                &grammar.options_with_values,
                &grammar.known_flags,
                deadline,
            );
            let quiet = self.quiet_flag.is_none()
                || (arguments.iter().any(|arg| {
                    self.quiet_flags.iter().any(|flag| {
                        arg == flag
                            || arg.strip_prefix(flag.as_str()).is_some_and(|suffix| {
                                suffix.starts_with('=')
                                    && !has_marker(suffix)
                                    && long_flag_assignment_is_enabled(arg)
                            })
                    })
                }) && !arguments.iter().any(|arg| {
                    self.quiet_flags.iter().any(|flag| {
                        arg.strip_prefix(flag.as_str())
                            .is_some_and(|suffix| suffix.starts_with('=') && has_marker(suffix))
                    })
                }) && flags_present_in_all_option_parses_with_deadline(
                    arguments,
                    &self.quiet_flags,
                    &grammar.options_with_values,
                    &grammar.known_flags,
                    deadline,
                ));
            if !quiet {
                continue;
            }
            let Some(tails) = tails else {
                // Exhausting the bounded subcommand parser cannot prove the flag absent.
                return Ok(self.quiet_flag.is_none());
            };
            for start in tails {
                check_deadline(deadline)?;
                if segment.wrapper_chain.iter().any(|name| name == "xargs")
                    || flag_slot_candidate(
                        arguments,
                        start,
                        grammar,
                        self.required_flag.as_str(),
                        &expansion_kinds,
                        deadline,
                    )?
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

static EXECUTABLES: LazyLock<BTreeSet<String>> = LazyLock::new(|| {
    set(&[
        "simgit",
        "sg",
        "simgit.exe",
        "sg.exe",
        "simgit.cmd",
        "sg.cmd",
    ])
});
static GRAMMARS: LazyLock<[SimgitGrammar; 2]> = LazyLock::new(|| {
    [
        SimgitGrammar::new(
            "remove",
            1,
            &["-m", "--message"],
            &[
                "--json",
                "--commit",
                "--delete-branch",
                "--discard-dirty",
                "--delete-unmerged",
                "--help",
            ],
        ),
        SimgitGrammar::new(
            "gc",
            0,
            &["--older-than", "--prefix"],
            &[
                "--json",
                "--include-persistent",
                "--delete-branches",
                "--discard-dirty",
                "--delete-unmerged",
                "--dry-run",
                "--help",
            ],
        ),
    ]
});

struct SimgitGrammar {
    name: &'static str,
    arity: usize,
    subcommands: Vec<String>,
    options_with_values: BTreeSet<String>,
    known_flags: BTreeSet<String>,
}

impl SimgitGrammar {
    fn new(name: &'static str, arity: usize, values: &[&str], flags: &[&str]) -> Self {
        Self {
            name,
            arity,
            subcommands: vec![name.to_owned()],
            options_with_values: set(values),
            known_flags: set(flags),
        }
    }
}

fn set(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Expansion {
    None,
    OneWord,
    ManyWords,
}

// Recover quote context from raw command text rather than shell_tokens' quote-stripped
// argv. An unaligned token remains unbounded, never a proof that it was quoted.
fn expansion_kinds(segment: &CommandSegmentV1) -> Vec<Expansion> {
    let mut result = vec![Expansion::ManyWords; segment.arguments.len()];
    let Ok(raw_tokens) = shell_tokens(&segment.text, false) else {
        return result;
    };
    let context = raw_expansion_kinds(&segment.text);
    if raw_tokens.len() != context.len() {
        return result;
    }
    for index in 0..raw_tokens.len() {
        if raw_tokens[index..].starts_with(&segment.arguments)
            && index > 0
            && segment.executable.as_deref() == Some(raw_tokens[index - 1].as_str())
        {
            let len = result.len();
            result.copy_from_slice(&context[index..index + len]);
            return result;
        }
    }
    result
}

fn raw_expansion_kinds(text: &str) -> Vec<Expansion> {
    let mut result = Vec::new();
    let mut kind = Expansion::None;
    let mut quote = None;
    let mut started = false;
    let mut chars = text.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if quote.is_none() && matches!(character, ' ' | '\t' | '\r' | '\n') {
            if started {
                result.push(kind);
                kind = Expansion::None;
                started = false;
            }
            continue;
        }
        started = true;
        if character == '\\' && quote != Some('\'') {
            chars.next();
            continue;
        }
        if character == '\'' && quote != Some('"') {
            quote = if quote.is_some() { None } else { Some('\'') };
            continue;
        }
        if character == '"' && quote != Some('\'') {
            quote = if quote.is_some() { None } else { Some('"') };
            continue;
        }
        if quote == Some('\'') || !matches!(character, '$' | '`') {
            continue;
        }
        let many =
            quote.is_none() || (character == '$' && expands_to_many_words(&text[index + 1..]));
        kind = if many {
            Expansion::ManyWords
        } else if kind == Expansion::None {
            Expansion::OneWord
        } else {
            kind
        };
    }
    if started {
        result.push(kind);
    }
    result
}

fn expands_to_many_words(after_dollar: &str) -> bool {
    if after_dollar.starts_with('@') {
        return true;
    }
    let Some(body) = after_dollar.strip_prefix('{') else {
        return false;
    };
    let body = body.split('}').next().unwrap_or(body);
    body.starts_with('@') || body.contains("[@]")
}

fn flag_slot_candidate(
    arguments: &[String],
    start: usize,
    grammar: &SimgitGrammar,
    required: &str,
    expansion_kinds: &[Expansion],
    deadline: Option<Instant>,
) -> Result<bool, &'static str> {
    let mut pending = vec![(start, 0usize, false)]; // index, positional count, -- ended options
    let mut visited = BTreeSet::new();
    while let Some(state) = pending.pop() {
        check_deadline(deadline)?;
        if !visited.insert(state) {
            continue;
        }
        if visited.len() > MAX_OPTION_PARSE_STATES {
            return Ok(true); // bounded uncertainty cannot establish absence
        }
        let (index, positionals, ended) = state;
        let Some(argument) = arguments.get(index) else {
            continue;
        };
        if !ended && argument == "--" {
            pending.push((index + 1, positionals, true));
        } else if !ended && argument.len() > 1 && argument.starts_with('-') {
            let name = argument
                .split_once('=')
                .map_or(argument.as_str(), |(name, _)| name);
            if name == required && long_flag_assignment_is_enabled(argument) {
                return Ok(true);
            }
            let expansion = expansion_kinds
                .get(index)
                .copied()
                .unwrap_or(Expansion::None);
            if expansion == Expansion::ManyWords && has_marker(argument) {
                return Ok(true);
            }
            if has_marker(name) && expansion != Expansion::None {
                return Ok(true);
            }
            let advance =
                known_option_advance(argument, &grammar.options_with_values, &grammar.known_flags);
            if let Some(advance) = advance {
                if advance == 2 && expansion_kinds.get(index + 1) == Some(&Expansion::ManyWords) {
                    return Ok(true); // the option consumes the first word, not the rest
                }
                pending.push((index + advance, positionals, ended));
            } else {
                pending.push((index + 1, positionals, ended));
                if !argument.contains('=') {
                    if expansion_kinds.get(index + 1) == Some(&Expansion::ManyWords) {
                        return Ok(true);
                    }
                    pending.push((index + 2, positionals, ended));
                }
            }
        } else {
            let expansion = expansion_kinds
                .get(index)
                .copied()
                .unwrap_or(Expansion::None);
            if !ended
                && has_marker(argument)
                && (expansion == Expansion::ManyWords
                    || (expansion == Expansion::OneWord && positionals >= grammar.arity))
            {
                return Ok(true);
            }
            pending.push((
                index + 1,
                positionals.saturating_add(1).min(grammar.arity + 1),
                ended,
            ));
        }
    }
    Ok(false)
}

fn has_marker(argument: &str) -> bool {
    argument.contains('$') || argument.contains('`')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_command, CommandModelRequestV1};

    fn matches(source: &str, required: &str, quiet: Option<&str>) -> bool {
        let command = parse_command(&CommandModelRequestV1 {
            command: source.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .unwrap();
        assert_eq!(
            command.confidence, "exact",
            "{source}: {:?}",
            command.uncertainty_reason
        );
        let config = SimgitFlagConfig {
            required_flag: required.to_owned(),
            quiet_flag: quiet.map(str::to_owned),
            quiet_flags: quiet.into_iter().map(str::to_owned).collect(),
        }
        .validate()
        .unwrap();
        command
            .segments
            .iter()
            .any(|segment| config.matches(segment, None).unwrap())
    }

    #[test]
    fn literal_flags_require_an_actual_option_slot() {
        for flag in ["--discard-dirty", "--delete-unmerged"] {
            for command in [
                format!("simgit remove work {flag}"),
                format!("sg.exe --json gc {flag}"),
                format!("/usr/local/bin/simgit.cmd gc --prefix dev {flag}"),
                format!("sg remove --delete-branch {flag}"),
                format!("simgit remove --unknown {flag}"),
                format!("simgit remove work {flag}=true"),
            ] {
                assert!(matches(&command, flag, None), "{command}");
            }
            for command in [
                format!("simgit remove work -m {flag}"),
                format!("sg remove --message={flag} work"),
                format!("sg gc --older-than {flag}"),
                format!("sg gc --prefix {flag}"),
                format!("sg remove -- work {flag}"),
                format!("sg gc -- {flag}"),
                format!("sg remove work {flag}=false"),
                format!("simgit run work -- echo {flag}"),
                format!("git remove work {flag}"),
            ] {
                assert!(!matches(&command, flag, None), "{command}");
            }
        }
        assert!(!matches(
            "simgit gc --discard-dirty",
            "--delete-unmerged",
            None
        ));
    }

    #[test]
    fn expansions_respect_quote_context_positional_arity_and_terminators() {
        for flag in ["--discard-dirty", "--delete-unmerged"] {
            for command in [
                "simgit remove $FLAGS",
                "simgit remove work \"$FLAGS\"",
                "simgit remove \"$@\"",
                "simgit remove \"${args[@]}\"",
                "simgit gc \"$FLAGS\"",
                "simgit gc \"$(printf -- --discard-dirty)\"",
                "simgit remove work --$FLAG",
                "simgit gc --prefix --dry-run $FLAGS",
                "simgit remove -m $FLAGS",
                "simgit gc --older-than=$FLAGS",
            ] {
                assert!(matches(command, flag, None), "{command}");
            }
            for command in [
                "simgit remove \"$TARGET\"",
                "simgit remove \"$(printf -- --discard-dirty)\"",
                "simgit remove '${FLAGS}'",
                "simgit remove \\$FLAGS",
                "simgit remove \"$*\"",
                "simgit gc --prefix \"$FLAGS\"",
                "simgit remove work -- \"$FLAGS\"",
                "simgit gc -- $FLAGS",
                "simgit remove -m \"$FLAGS\" work",
            ] {
                assert!(!matches(command, flag, None), "{command}");
            }
        }
    }

    #[test]
    fn quiet_variants_require_both_risk_and_a_parsed_quiet_flag() {
        for flag in ["--discard-dirty", "--delete-unmerged"] {
            assert!(matches(
                &format!("simgit remove -m msg --help {flag}"),
                flag,
                Some("--help")
            ));
            assert!(matches(
                &format!("sg gc --dry-run {flag}"),
                flag,
                Some("--dry-run")
            ));
            assert!(matches("sg gc --dry-run $FLAGS", flag, Some("--dry-run")));
            assert!(!matches("sg gc --dry-run", flag, Some("--dry-run")));
            assert!(!matches(
                &format!("sg remove --dry-run {flag}"),
                flag,
                Some("--dry-run")
            ));
            assert!(!matches(
                &format!("sg remove -m --help {flag}"),
                flag,
                Some("--help")
            ));
            assert!(!matches(
                "sg gc --prefix --dry-run $FLAGS",
                flag,
                Some("--dry-run")
            ));
            assert!(!matches(
                &format!("sg gc -- --dry-run {flag}"),
                flag,
                Some("--dry-run")
            ));
            assert!(!matches(
                &format!("sg gc --help=false {flag}"),
                flag,
                Some("--help")
            ));
            assert!(matches(&format!("sg gc --help {flag}"), flag, None));
        }
    }

    #[test]
    fn xargs_supplied_argv_is_unresolved_but_exec_is_not() {
        for flag in ["--discard-dirty", "--delete-unmerged"] {
            assert!(matches("xargs -a input.txt simgit remove work", flag, None));
            assert!(matches("xargs sg.cmd gc", flag, None));
            assert!(matches("xargs sg gc --help", flag, Some("--help")));
            assert!(matches("xargs sg gc --dry-run", flag, Some("--dry-run")));
            assert!(!matches("exec simgit remove work", flag, None));
        }
    }

    #[test]
    fn nested_shell_raw_quotes_control_expansion_arity() {
        for flag in ["--discard-dirty", "--delete-unmerged"] {
            assert!(!matches("bash -c 'simgit remove \"$TARGET\"'", flag, None));
            assert!(matches("sh -c 'sg gc \"$FLAGS\"'", flag, None));
            assert!(matches("bash -c 'sg remove $FLAGS'", flag, None));
            assert!(matches(
                "env MODE=test command simgit gc ${FLAGS}",
                flag,
                None
            ));
        }
    }

    #[test]
    fn operation_admits_both_configured_flags() {
        for flag in ["--discard-dirty", "--delete-unmerged"] {
            let matcher = super::super::SpecializedMatcher::from_config(
                "simgit-flag.v1",
                serde_json::json!({"required_flag":flag}),
            )
            .unwrap();
            let command = parse_command(&CommandModelRequestV1 {
                command: format!("simgit remove work {flag}"),
                dialect: "posix".to_owned(),
                transport: "shell_string".to_owned(),
                extraction_provenance: "guard-shell".to_owned(),
            })
            .unwrap();
            assert_eq!(matcher.match_segments(&command), Ok(vec![0]));
        }
    }

    #[test]
    fn config_rejects_unreviewed_flag_names() {
        for value in [
            serde_json::json!({"required_flag":"--force"}),
            serde_json::json!({"required_flag":"--discard-dirty","quiet_flag":"--json"}),
            serde_json::json!({"required_flag":"--delete-unmerged","extra":true}),
        ] {
            assert!(serde_json::from_value::<SimgitFlagConfig>(value)
                .map_or(true, |config| config.validate().is_err()));
        }
    }
}
