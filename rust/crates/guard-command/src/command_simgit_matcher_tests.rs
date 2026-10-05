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
            "simgit remove \"$FLAG\" work",
            "simgit remove \"$FLAG\" -- work",
            "simgit remove \"$(printf -- --discard-dirty)\" work",
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
            "simgit remove \"$*\"",
            "simgit gc --prefix \"$FLAGS\"",
            "simgit remove work -- \"$FLAGS\"",
            "simgit gc -- $FLAGS",
            "simgit remove -m \"$FLAGS\" work",
            "simgit remove -- \"$FLAG\" work",
        ] {
            assert!(!matches(command, flag, None), "{command}");
        }
        // Windows POSIX parsing keeps unquoted backslashes literal, so the expansion stays live.
        assert_eq!(matches("simgit remove \\$FLAGS", flag, None), cfg!(windows));
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
