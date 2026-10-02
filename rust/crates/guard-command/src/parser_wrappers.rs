//! Bounded executable extraction; unsupported execution modes remain uncertain.

use crate::{assignment_name, executable_basename, CommandSegmentV1, RawSegment};

pub(super) struct WrapperStep {
    pub next_index: usize,
    pub name: &'static str,
    pub environment_names: Vec<String>,
    pub script: Option<String>,
}

pub(super) fn unwrap_supported(
    tokens: &[String],
    index: usize,
) -> Result<Option<WrapperStep>, &'static str> {
    let Some(command) = tokens.get(index) else {
        return Ok(None);
    };
    let name = executable_basename(command);
    let mut next = index + 1;
    let mut environment_names = Vec::new();
    let mut script = None;
    let mut replacement = None;
    match name {
        "exec" => {
            while let Some(option) = tokens.get(next) {
                match option.as_str() {
                    "--" => {
                        next += 1;
                        break;
                    }
                    "-a" => {
                        if tokens.get(next + 1).is_none_or(String::is_empty) {
                            return Err("nested_command_executor_not_yet_supported");
                        }
                        next += 2;
                    }
                    value if value.starts_with('-') => {
                        return Err("nested_command_executor_not_yet_supported")
                    }
                    _ => break,
                }
            }
        }
        "xargs" => {
            while let Some(option) = tokens.get(next) {
                match option.as_str() {
                    "--" => {
                        next += 1;
                        break;
                    }
                    "-n" => {
                        if !tokens.get(next + 1).is_some_and(|value| {
                            value.len() <= 9
                                && value.bytes().all(|byte| byte.is_ascii_digit())
                                && value.bytes().any(|byte| byte != b'0')
                        }) {
                            return Err("nested_command_executor_not_yet_supported");
                        }
                        next += 2;
                    }
                    value if value.starts_with("-n") && value.len() > 2 => {
                        let count = &value[2..];
                        if count.len() > 9
                            || !count.bytes().all(|byte| byte.is_ascii_digit())
                            || !count.bytes().any(|byte| byte != b'0')
                        {
                            return Err("nested_command_executor_not_yet_supported");
                        }
                        next += 1;
                    }
                    "-a" | "-I" => {
                        let Some(value) = tokens.get(next + 1).filter(|value| !value.is_empty())
                        else {
                            return Err("nested_command_executor_not_yet_supported");
                        };
                        if option == "-I" {
                            replacement = Some(value.as_str());
                        }
                        next += 2;
                    }
                    value
                        if (value.starts_with("-a") || value.starts_with("-I"))
                            && value.len() > 2 =>
                    {
                        if let Some(value) = value.strip_prefix("-I") {
                            replacement = Some(value);
                        }
                        next += 1;
                    }
                    value if value.starts_with('-') => {
                        return Err("nested_command_executor_not_yet_supported")
                    }
                    _ => break,
                }
            }
        }
        "env" => {
            while let Some(option) = tokens.get(next) {
                match option.as_str() {
                    "--" => {
                        next += 1;
                        break;
                    }
                    "-i" | "--ignore-environment" => next += 1,
                    "-u" | "--unset" => {
                        if tokens.get(next + 1).is_none_or(String::is_empty) {
                            return Err("transparent_wrapper_not_yet_supported");
                        }
                        next += 2;
                    }
                    value if value.starts_with('-') => {
                        return Err("transparent_wrapper_not_yet_supported")
                    }
                    value => {
                        if let Some(assignment) = assignment_name(value) {
                            environment_names.push(assignment.to_owned());
                            next += 1;
                        } else {
                            break;
                        }
                    }
                }
            }
        }
        "command" => {
            while let Some(option) = tokens.get(next) {
                match option.as_str() {
                    "--" => {
                        next += 1;
                        break;
                    }
                    "-p" => next += 1,
                    value if value.starts_with('-') => {
                        return Err("transparent_wrapper_not_yet_supported")
                    }
                    _ => break,
                }
            }
        }
        "sh" | "bash" => {
            if tokens.get(next).map(String::as_str) != Some("-c") || tokens.len() != next + 2 {
                return Ok(None);
            }
            script = Some(tokens[next + 1].clone());
            next += 2;
        }
        _ => return Ok(None),
    }
    if script.is_none() && tokens.get(next).is_none_or(String::is_empty) {
        return Err(if matches!(name, "exec" | "xargs") {
            "nested_command_executor_not_yet_supported"
        } else {
            "transparent_wrapper_not_yet_supported"
        });
    }
    if let Some(replacement) = replacement {
        // Replacement may rewrite any argv word, including the executable,
        // subcommand or a safety option. Admit only standalone operands after
        // a fixed first argument; stdin may still supply further arguments.
        if tokens
            .get(next + 1)
            .is_none_or(|value| value.starts_with('-') || value.contains(replacement))
            || tokens[next..].iter().enumerate().any(|(offset, value)| {
                value.contains(replacement)
                    && (offset < 2 || value != replacement || value.starts_with('-'))
            })
        {
            return Err("nested_command_executor_not_yet_supported");
        }
    }
    Ok(Some(WrapperStep {
        next_index: next,
        name: match name {
            "exec" => "exec",
            "xargs" => "xargs",
            "env" => "env",
            "command" => "command",
            "sh" => "sh",
            "bash" => "bash",
            _ => unreachable!(),
        },
        environment_names,
        script,
    }))
}

pub(super) fn unwrap_sudo(
    tokens: &[String],
    mut index: usize,
) -> Result<(usize, Vec<String>), &'static str> {
    let mut wrappers = Vec::new();
    while tokens
        .get(index)
        .is_some_and(|token| matches!(executable_basename(token), "sudo" | "timeout"))
    {
        if wrappers.len() == 4 {
            return Err("command_wrapper_limit_exceeded");
        }
        let wrapper = executable_basename(&tokens[index]);
        wrappers.push(wrapper.to_owned());
        index += 1;
        if wrapper == "timeout" {
            if tokens.get(index).is_some_and(|value| value == "--") {
                index += 1;
            }
            if !tokens.get(index).is_some_and(|value| timeout(value)) {
                return Err("transparent_wrapper_not_yet_supported");
            }
            index += 1;
            let Some(command) = tokens.get(index) else {
                return Err("transparent_wrapper_not_yet_supported");
            };
            if command.is_empty() || command.starts_with('-') || assignment_name(command).is_some()
            {
                return Err("transparent_wrapper_not_yet_supported");
            }
            continue;
        }
        while let Some(option) = tokens.get(index) {
            match option.as_str() {
                "--" => {
                    index += 1;
                    break;
                }
                "-n" | "--non-interactive" => index += 1,
                "-T" | "--command-timeout" => {
                    if !tokens.get(index + 1).is_some_and(|value| timeout(value)) {
                        return Err("transparent_wrapper_not_yet_supported");
                    }
                    index += 2;
                }
                value if value.starts_with("--command-timeout=") => {
                    if !timeout(&value["--command-timeout=".len()..]) {
                        return Err("transparent_wrapper_not_yet_supported");
                    }
                    index += 1;
                }
                value if value.starts_with('-') => {
                    return Err("transparent_wrapper_not_yet_supported");
                }
                _ => break,
            }
        }
        let Some(command) = tokens.get(index) else {
            return Err("transparent_wrapper_not_yet_supported");
        };
        if command.is_empty() || assignment_name(command).is_some() {
            return Err("transparent_wrapper_not_yet_supported");
        }
    }
    Ok((index, wrappers))
}

fn timeout(value: &str) -> bool {
    !value.is_empty() && value.len() <= 10 && value.bytes().all(|byte| byte.is_ascii_digit())
}

pub(super) fn is_encoded_stdin_shell(
    executable: Option<&str>,
    arguments: &[String],
    raw: &RawSegment,
    previous: Option<&CommandSegmentV1>,
) -> bool {
    // Do not normalize arbitrary interpreters, script files, shell flags or
    // unknown stdin. This exact producer/consumer shape is observed by the
    // native encoded-execution matcher, with the full raw pipeline preserved.
    let Some(previous) = previous else {
        return false;
    };
    executable.is_some_and(|value| matches!(executable_basename(value), "sh" | "bash" | "zsh"))
        && arguments.is_empty()
        && raw.pipeline_index > 0
        && previous.pipeline_index + 1 == raw.pipeline_index
        && previous.execution_context == format!("top:{}", raw.group_index)
        && previous
            .executable
            .as_deref()
            .is_some_and(|value| matches!(executable_basename(value), "base64" | "gpg" | "openssl"))
        && previous.arguments.iter().any(|argument| argument == "-d")
}

#[cfg(test)]
mod tests {
    use crate::{parse_command, CommandModelRequestV1};

    fn parse(command: &str) -> crate::CanonicalCommandV1 {
        parse_command(&CommandModelRequestV1 {
            command: command.to_owned(),
            dialect: "posix".to_owned(),
            transport: "shell_string".to_owned(),
            extraction_provenance: "guard-shell".to_owned(),
        })
        .unwrap()
    }

    #[test]
    fn sudo_keeps_source_and_wrapper_evidence_for_destructive_arguments() {
        for command in [
            "sudo -n git push origin main --force",
            "sudo --command-timeout 10 git --config-env token=TOKEN push origin main --force",
            "sudo -T 10 -- git push origin main --force",
        ] {
            let model = parse(command);
            assert_eq!(model.confidence, "exact", "{command}");
            assert_eq!(model.wrapper_chain, ["sudo"]);
            assert_eq!(model.segments[0].wrapper_chain, ["sudo"]);
            assert_eq!(model.segments[0].text, command);
            assert_eq!(model.segments[0].tokens[0], "sudo");
            assert_eq!(model.segments[0].executable.as_deref(), Some("git"));
            assert_eq!(model.segments[0].arguments.last().unwrap(), "--force");
        }
    }

    #[test]
    fn unknown_wrapper_modes_cannot_hide_or_fabricate_executables() {
        for command in [
            "sudo -s git push --force",
            "sudo -i git status",
            "sudo -u user git status",
            "sudo --command-timeout git push --force",
            "sudo -n FOO=bar git status",
            "sudo sudo sudo sudo sudo git status",
            "sudo -n",
            "sudo -- sh -c 'rm -rf /tmp/x; echo done'",
        ] {
            let model = parse(command);
            assert_eq!(model.confidence, "uncertain", "{command}");
            assert!(model.segments.is_empty());
        }
    }

    #[test]
    fn only_observed_decoder_pipelines_accept_bare_shell_consumers() {
        let source = "echo 'cm0gLXJmIC4vYnVpbGQ=' | base64 -d | sh";
        let model = parse(source);
        assert_eq!(model.confidence, "exact");
        assert_eq!(model.segments.len(), 3);
        assert_eq!(model.segments[2].executable.as_deref(), Some("sh"));
        for source in [
            "echo arbitrary | sh",
            "base64 -d; sh",
            "base64 -d | sh -c 'payload; other'",
            "sh",
        ] {
            assert_eq!(parse(source).confidence, "uncertain", "{source}");
        }
    }

    #[test]
    fn normalizes_literal_nested_commands_and_keeps_wrapper_evidence() {
        for (command, wrappers, executable, arguments) in [
            (
                "exec -a alias simgit.exe remove --discard-dirty tree",
                vec!["exec"],
                "simgit.exe",
                vec!["remove", "--discard-dirty", "tree"],
            ),
            (
                "xargs -a input.txt -I ITEM sg.cmd gc --delete-unmerged ITEM",
                vec!["xargs"],
                "sg.cmd",
                vec!["gc", "--delete-unmerged", "ITEM"],
            ),
            (
                "xargs -n 1 sg remove agent/1234 --delete-branch --delete-unmerged",
                vec!["xargs"],
                "sg",
                vec![
                    "remove",
                    "agent/1234",
                    "--delete-branch",
                    "--delete-unmerged",
                ],
            ),
            (
                "env -i PATH=/custom command -p sg remove --discard-dirty tree",
                vec!["env", "command"],
                "sg",
                vec!["remove", "--discard-dirty", "tree"],
            ),
            (
                "sudo -n exec -- xargs -I '{}' simgit remove --discard-dirty '{}'",
                vec!["sudo", "exec", "xargs"],
                "simgit",
                vec!["remove", "--discard-dirty", "{}"],
            ),
        ] {
            let model = parse(command);
            assert_eq!(
                model.confidence, "exact",
                "{command}: {:?}",
                model.uncertainty_reason
            );
            assert_eq!(model.wrapper_chain, wrappers, "{command}");
            assert_eq!(
                model.segments[0].executable.as_deref(),
                Some(executable),
                "{command}"
            );
            assert_eq!(model.segments[0].arguments, arguments, "{command}");
            assert_eq!(model.segments[0].text, command, "{command}");
        }
        assert!(parse("env PATH=/custom simgit gc --delete-unmerged").path_overridden);
    }

    #[test]
    fn nested_shell_script_retains_effective_quote_context() {
        for (command, executable, arguments, text) in [
            (
                "sh -c 'sg remove \"$TARGET\"'",
                "sg",
                vec!["remove", "$TARGET"],
                "sg remove \"$TARGET\"",
            ),
            (
                "bash -c 'exec simgit gc $FLAGS'",
                "simgit",
                vec!["gc", "$FLAGS"],
                "exec simgit gc $FLAGS",
            ),
        ] {
            let model = parse(command);
            assert_eq!(
                model.confidence, "exact",
                "{command}: {:?}",
                model.uncertainty_reason
            );
            assert_eq!(model.segments[0].executable.as_deref(), Some(executable));
            assert_eq!(model.segments[0].arguments, arguments);
            assert_eq!(model.segments[0].text, text);
            assert_eq!(
                model.segments[0].tokens[0],
                if command.starts_with("sh") {
                    "sh"
                } else {
                    "bash"
                }
            );
        }
        assert_eq!(
            parse("bash -c 'exec simgit gc $FLAGS'").wrapper_chain,
            ["bash", "exec"]
        );
    }

    #[test]
    fn opaque_command_substitutions_keep_argument_and_raw_quote_context() {
        for (command, arguments) in [
            (
                "simgit --json gc $(printf -- --discard-dirty)",
                vec!["--json", "gc", "$(printf -- --discard-dirty)"],
            ),
            (
                "simgit gc --older-than 1h `cat /tmp/flags`",
                vec!["gc", "--older-than", "1h", "`cat /tmp/flags`"],
            ),
            (
                "simgit remove \"$(git branch --show-current)\"",
                vec!["remove", "$(git branch --show-current)"],
            ),
            (
                "bash -c 'sg remove \"$(git branch --show-current)\"'",
                vec!["remove", "$(git branch --show-current)"],
            ),
            ("simgit gc ${FLAGS}", vec!["gc", "${FLAGS}"]),
        ] {
            let model = parse(command);
            assert_eq!(
                model.confidence, "exact",
                "{command}: {:?}",
                model.uncertainty_reason
            );
            assert_eq!(model.segments[0].arguments, arguments, "{command}");
            let effective_text = &model.segments[0].text;
            assert!(
                effective_text.contains("$(git branch --show-current)")
                    || effective_text.contains("$(printf -- --discard-dirty)")
                    || effective_text.contains("`cat /tmp/flags`")
                    || effective_text.contains("${FLAGS}"),
                "{command}"
            );
        }
        for command in [
            "echo $(uname)",
            "echo `uname`",
            "$(echo simgit) gc --delete-unmerged",
            "echo ${FLAGS}",
            "simgit gc ${FLAGS:-unsafe}",
            "simgit remove \"$(rm -rf /tmp/data)\"",
            "simgit gc `rm -rf /tmp/data`",
            "bash -c 'simgit remove \"$(rm -rf /tmp/data)\"'",
            "simgit gc $(printf -- $(rm -rf /tmp/data))",
        ] {
            assert_eq!(parse(command).confidence, "uncertain", "{command}");
        }
    }

    #[test]
    fn unsupported_wrapper_modes_and_dynamic_executable_remain_uncertain() {
        for command in [
            "exec -c simgit gc --delete-unmerged",
            "exec -a simgit",
            "xargs -P 4 simgit gc --delete-unmerged",
            "xargs -n 0 simgit gc --delete-unmerged",
            "xargs -n nope simgit gc --delete-unmerged",
            "xargs -a input.txt",
            "env -S 'simgit gc --delete-unmerged'",
            "command -v simgit",
            "bash -lc 'simgit gc --delete-unmerged'",
            "sh -c 'simgit gc --delete-unmerged; echo done'",
            "sh -c 'simgit gc' extra-arg",
            "exec exec exec exec exec simgit gc",
            "simgit gc # --dry-run",
            "sh -c 'simgit remove # --help'",
            "xargs -I X Xsimgit gc --delete-unmerged",
        ] {
            let model = parse(command);
            assert_eq!(model.confidence, "uncertain", "{command}");
            assert!(model.segments.is_empty(), "{command}");
        }
    }

    #[test]
    fn posix_embedded_braces_are_arguments_but_brace_groups_are_unsupported() {
        let model = parse("aws s3api put-object-tagging --tagging TagSet=[{Key=env,Value=prod}]");
        assert_eq!(model.confidence, "exact");
        assert_eq!(
            model.segments[0].arguments.last().unwrap(),
            "TagSet=[{Key=env,Value=prod}]"
        );
        for source in [
            "{ rm -rf /tmp/x; }",
            "true;{ rm -rf /tmp/x;}",
            "true&&{ rm -rf /tmp/x;}",
            "printf x|{ rm -rf /tmp/x;}",
            "printf %s ${COMMAND}",
            "${COMMAND} --force",
            "sudo -n git ${ACTION}",
        ] {
            let model = parse(source);
            assert_eq!(model.confidence, "uncertain", "{source}");
            assert!(model.segments.is_empty(), "{source}");
        }
        assert_eq!(parse("printf %s '${COMMAND}'").confidence, "exact");
    }
}
