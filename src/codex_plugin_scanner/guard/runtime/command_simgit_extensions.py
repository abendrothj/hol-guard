"""Structured rules and metadata for the simgit command safety extension."""

from __future__ import annotations

from dataclasses import dataclass

from .command_extension_matchers import executable_matcher, executable_names, safe_flag_variant
from .command_extension_specs import CommandExtensionSpec
from .command_matcher_contracts import MatcherEvidence
from .command_model import CanonicalCommand
from .command_option_parsing import known_option_advance, long_flag_assignment_is_enabled
from .command_rules import (
    AnyMatcher,
    CommandSafetyRule,
    _after_leading_options,
    _segment_matches_executable,
    _without_options,
)

# Flag surface verified against simgit 0.3.0 (`sg/src/commands/worktree.rs`) and
# the project's published stability contract in AGENTS.md, "What approval gates
# depend on". Exactly two flags destroy work Git cannot return:
#
# - `--discard-dirty` removes a worktree that still holds uncommitted and
#   untracked files. A worktree lives outside the source repository, so those
#   files are not recoverable from the repository afterwards.
# - `--delete-unmerged` deletes a branch past Git's merged check. It only
#   relaxes an accompanying `--delete-branch` (remove) or `--delete-branches`
#   (gc).
#
# Both flags exist on `remove` and on `gc`, and simgit's contract requires any
# future destructive operation to sit behind one of them. Everything else
# refuses first: `remove` and `gc` will not touch a dirty worktree, `gc` reaps
# only ephemeral worktrees idle past `--older-than` and skips locked ones,
# branch deletion stops at the merged check, `prune` drops only caches that
# rematerialize, `repair` remounts, and `unlock` refuses while the recorded
# owner PID is alive and has no override flag. Plain `add`, `remove`, `gc`,
# `doctor`, `list`, `unlock`, `prune` and `repair` therefore stay unreviewed.
#
# `simgit run [BRANCH] -- <command>` executes a caller-supplied command inside a
# worktree. The risk there is that argv, which Guard's existing command handling
# already judges, so `run` is not matched here.
#
# Conservative matching covers:
# - Both launchers: `simgit` is canonical and `sg` is an equivalent alias built
#   from the same source, so both carry the same authority.
# - The global `--json` flag, which is accepted before or after the subcommand.
# - Shell wrappers: `exec simgit ...`, `xargs simgit ...`, including the
#   portable `.exe`/`.cmd` spellings of the nested launcher.
# - Value-taking options, so `-m --discard-dirty` (a commit message) and
#   `--prefix --discard-dirty` (a branch prefix) are read as values.
# - Fail-secure subcommand resolution, so an unknown option cannot hide a
#   destructive subcommand.
# - Unresolved shell expansions that can occupy a flag slot, because argv then
#   cannot prove either destructive flag absent.

_SIMGIT_EXECUTABLES: tuple[str, ...] = ("simgit", "sg")
_SIMGIT_WRAPPERS: tuple[str, ...] = ("exec", "xargs")
# A wrapper names its child in argv, so the portable `.exe`/`.cmd` spellings are
# enumerated here; the leading token is matched through `executable_names`.
_SIMGIT_LAUNCHERS: tuple[tuple[str, ...], ...] = (
    *((executable,) for executable in _SIMGIT_EXECUTABLES),
    *(
        (wrapper, nested)
        for wrapper in _SIMGIT_WRAPPERS
        for executable in _SIMGIT_EXECUTABLES
        for nested in sorted(executable_names(executable))
    ),
)
_WRAPPER_LEADING_OPTIONS_WITH_VALUES = frozenset({"-n", "-P", "-I", "-L", "-s"})
# `--json` is a global flag and may appear before or after the subcommand.
_SIMGIT_GLOBAL_FLAGS = frozenset({"--json"})
_REMOVE_OPTIONS_WITH_VALUES = frozenset({"-m", "--message"})
_GC_OPTIONS_WITH_VALUES = frozenset({"--older-than", "--prefix"})
# Every other boolean flag the subcommand accepts, so a companion flag is never
# read as an unknown option. `simgit gc --delete-unmerged` requires
# `--delete-branches`, so without this the `--dry-run` preview of exactly that
# command could not be recognised as its safe counterpart. `--dry-run` and
# `--help` are deliberately absent: the safe variants require them, and an
# interspersed flag is stripped before required flags are checked.
_REMOVE_COMPANION_FLAGS = frozenset({"--commit", "--delete-branch", "--discard-dirty", "--delete-unmerged"})
_GC_COMPANION_FLAGS = frozenset({"--include-persistent", "--delete-branches", "--discard-dirty", "--delete-unmerged"})
_COMMIT_ALTERNATIVE = (
    'Keep the work with `simgit remove --commit -m "<message>"`, which commits to the worktree branch first.'
)


def _flagged_subcommand(
    subcommand: str,
    flag: str,
    options_with_values: frozenset[str],
    companion_flags: frozenset[str],
) -> AnyMatcher:
    """Match one simgit subcommand carrying one destructive flag."""

    known_flags = _SIMGIT_GLOBAL_FLAGS | (companion_flags - {flag})
    return AnyMatcher(
        matchers=tuple(
            executable_matcher(
                *launcher,
                subcommand,
                required_flags=frozenset({flag}),
                global_flags=known_flags,
                options_with_values=options_with_values,
                allow_leading_options=launcher[0] in _SIMGIT_WRAPPERS,
                leading_options_with_values=(
                    _WRAPPER_LEADING_OPTIONS_WITH_VALUES if launcher[0] in _SIMGIT_WRAPPERS else frozenset()
                ),
                fail_secure_unknown_options=True,
            )
            for launcher in _SIMGIT_LAUNCHERS
        )
    )


_SIMGIT_REMOVE_DISCARD_DIRTY = _flagged_subcommand(
    "remove", "--discard-dirty", _REMOVE_OPTIONS_WITH_VALUES, _REMOVE_COMPANION_FLAGS
)
_SIMGIT_GC_DISCARD_DIRTY = _flagged_subcommand("gc", "--discard-dirty", _GC_OPTIONS_WITH_VALUES, _GC_COMPANION_FLAGS)
_SIMGIT_DISCARD_DIRTY = AnyMatcher(
    matchers=(*_SIMGIT_REMOVE_DISCARD_DIRTY.matchers, *_SIMGIT_GC_DISCARD_DIRTY.matchers),
)

_SIMGIT_REMOVE_DELETE_UNMERGED = _flagged_subcommand(
    "remove", "--delete-unmerged", _REMOVE_OPTIONS_WITH_VALUES, _REMOVE_COMPANION_FLAGS
)
_SIMGIT_GC_DELETE_UNMERGED = _flagged_subcommand(
    "gc", "--delete-unmerged", _GC_OPTIONS_WITH_VALUES, _GC_COMPANION_FLAGS
)
_SIMGIT_DELETE_UNMERGED = AnyMatcher(
    matchers=(*_SIMGIT_REMOVE_DELETE_UNMERGED.matchers, *_SIMGIT_GC_DELETE_UNMERGED.matchers),
)

# A `$VAR`, `${VAR}`, `$(...)` or backtick token is decided by the shell after
# Guard sees argv, so it can arrive as `--discard-dirty` or `--delete-unmerged`.
# Only the slots a flag can occupy count as uncertainty: `remove` accepts one
# positional target and `gc` accepts none, so an expansion inside that arity is
# the documented allocator pattern (`simgit remove "$CLEANUP_TOKEN"`) and stays
# quiet, while an expansion in an option slot, or one more argument than the
# subcommand can place, cannot be a positional value.
#
# Quoting decides token count before Guard sees argv, which is what makes that
# split hold: `simgit remove "$(git branch --show-current)"` arrives as one
# token and fills the one slot `remove` has, while the unquoted form arrives as
# several and overflows it.
#
# Residual, as simgit's own contract intends: a lone `simgit remove $FLAGS`
# whose variable word-splits into a flag is spelled exactly like the ordinary
# cleanup it imitates, and reviewing it would review every cleanup.
#
# `--dry-run` and `--help` only make a run quiet when option parsing puts them
# in a flag slot of their own. `simgit gc --prefix --dry-run $FLAGS` spends the
# token as the `--prefix` value, so the run previews nothing and `$FLAGS` is
# still an unproven flag slot; reading the token before parsing would hand any
# argv a two-token cloak for a destructive expansion.
_EXPANSION_MARKERS: frozenset[str] = frozenset({"$", "`"})


@dataclass(frozen=True, slots=True)
class SimgitFlagSlotExpansionMatcher:
    """Match simgit commands whose unresolved expansion can supply a destructive flag."""

    subcommand: str
    positional_arity: int
    options_with_values: frozenset[str]
    known_flags: frozenset[str]
    quiet_flags: frozenset[str]
    launchers: tuple[tuple[str, ...], ...] = _SIMGIT_LAUNCHERS
    leading_options_with_values: frozenset[str] = _WRAPPER_LEADING_OPTIONS_WITH_VALUES
    expansion_markers: frozenset[str] = _EXPANSION_MARKERS

    def match(self, command: CanonicalCommand) -> tuple[MatcherEvidence, ...]:
        evidence: list[MatcherEvidence] = []
        for index, segment in enumerate(command.segments):
            if segment.executable is None:
                continue
            lowered_arguments = tuple(argument.lower() for argument in segment.arguments)
            for launcher in self.launchers:
                if not _segment_matches_executable(segment, executable_names(launcher[0])):
                    continue
                candidate_arguments = _without_options(lowered_arguments, frozenset(), _SIMGIT_GLOBAL_FLAGS)
                if launcher[0] in _SIMGIT_WRAPPERS:
                    candidate_arguments = _after_leading_options(
                        candidate_arguments,
                        self.leading_options_with_values,
                        _SIMGIT_GLOBAL_FLAGS,
                    )
                prefix = (*launcher[1:], self.subcommand)
                if candidate_arguments[: len(prefix)] != prefix:
                    continue
                if self._flag_slot_is_unresolved(candidate_arguments[len(prefix) :]):
                    evidence.append(
                        MatcherEvidence(
                            segment_index=index,
                            executable=segment.executable,
                            detail="Matched a simgit argument slot that may expand to a destructive flag.",
                        )
                    )
                break
        return tuple(evidence)

    def _flag_slot_is_unresolved(self, arguments: tuple[str, ...]) -> bool:
        """Return whether an expansion sits where a flag, not a value, can land."""

        positionals = 0
        saw_expansion = False
        saw_quiet_flag = False
        unresolved_option_name = False
        options_ended = False
        index = 0
        while index < len(arguments):
            argument = arguments[index]
            if not options_ended and argument == "--":
                options_ended = True
                index += 1
                continue
            if not options_ended and len(argument) > 1 and argument.startswith("-"):
                advance = known_option_advance(
                    argument,
                    options_with_values=self.options_with_values,
                    known_flags=self.known_flags,
                )
                if advance is None:
                    if self._is_unresolved(argument.partition("=")[0]):
                        unresolved_option_name = True
                    advance = 1
                elif self._occupies_quiet_flag_slot(argument):
                    saw_quiet_flag = True
                saw_expansion = saw_expansion or any(
                    self._is_unresolved(token) for token in arguments[index : index + advance]
                )
                index += advance
                continue
            positionals += 1
            saw_expansion = saw_expansion or self._is_unresolved(argument)
            index += 1
        # The quiet verdict is the whole parse's, not one token's: a preview or
        # help run anywhere in argv acts on nothing, and an unresolved option
        # name earlier in the same argv does not change that.
        if saw_quiet_flag:
            return False
        return unresolved_option_name or (saw_expansion and positionals > self.positional_arity)

    def _occupies_quiet_flag_slot(self, argument: str) -> bool:
        """Return whether a parsed option is a quiet flag in its own flag slot."""

        name, _, _ = argument.partition("=")
        return name in self.quiet_flags and long_flag_assignment_is_enabled(argument)

    def _is_unresolved(self, argument: str) -> bool:
        """Return whether a token carries shell syntax argv cannot resolve."""

        return any(marker in argument for marker in self.expansion_markers)


_SIMGIT_FLAG_SLOT_EXPANSIONS: tuple[SimgitFlagSlotExpansionMatcher, ...] = (
    SimgitFlagSlotExpansionMatcher(
        subcommand="remove",
        positional_arity=1,
        options_with_values=_REMOVE_OPTIONS_WITH_VALUES,
        known_flags=_SIMGIT_GLOBAL_FLAGS | _REMOVE_COMPANION_FLAGS | frozenset({"--help"}),
        quiet_flags=frozenset({"--help"}),
    ),
    SimgitFlagSlotExpansionMatcher(
        subcommand="gc",
        positional_arity=0,
        options_with_values=_GC_OPTIONS_WITH_VALUES,
        known_flags=_SIMGIT_GLOBAL_FLAGS | _GC_COMPANION_FLAGS | frozenset({"--dry-run", "--help"}),
        quiet_flags=frozenset({"--dry-run", "--help"}),
    ),
)

# The literal-flag matchers stay free of custom children so the safe variants
# keep cloning pure executable matchers; each rule adds the flag-slot overlay on
# top. Both rules carry it because an unresolved flag slot proves neither flag
# absent, and the two permissions are enabled independently.
_SIMGIT_DISCARD_DIRTY_WITH_EXPANSIONS = AnyMatcher(
    matchers=(*_SIMGIT_DISCARD_DIRTY.matchers, *_SIMGIT_FLAG_SLOT_EXPANSIONS),
)
_SIMGIT_DELETE_UNMERGED_WITH_EXPANSIONS = AnyMatcher(
    matchers=(*_SIMGIT_DELETE_UNMERGED.matchers, *_SIMGIT_FLAG_SLOT_EXPANSIONS),
)

SIMGIT_COMMAND_RULES = (
    CommandSafetyRule(
        rule_id="command.simgit.discard-dirty",
        title="simgit uncommitted worktree discard",
        description=(
            "Identifies `--discard-dirty` on `simgit remove` and `simgit "
            "gc`, which delete a worktree still holding uncommitted and "
            "untracked files. A worktree lives outside the source "
            "repository, so those files are not recoverable there. Without "
            "the flag both commands refuse a dirty worktree. An invocation "
            "whose unresolved expansion can occupy a flag slot is reviewed "
            "too: argv cannot prove the flag absent."
        ),
        severity="critical",
        risk_classes=("destructive_shell",),
        action_classes=("simgit uncommitted worktree discard command",),
        safer_alternatives=(
            "Drop the flag: plain `simgit remove` refuses a dirty worktree and names the path it kept.",
            _COMMIT_ALTERNATIVE,
            "Preview the selection with `simgit gc --dry-run` before letting GC discard anything.",
            "Expand shell variables and command substitutions so argv shows which flags simgit receives.",
        ),
        matcher=_SIMGIT_DISCARD_DIRTY_WITH_EXPANSIONS,
        default_mode="review",
        example_command="simgit remove /path/to/worktree --discard-dirty",
        safe_variants=(
            safe_flag_variant(
                _SIMGIT_GC_DISCARD_DIRTY,
                variant_id="dry-run",
                title="simgit gc discard preview",
                flag="--dry-run",
            ),
            safe_flag_variant(
                _SIMGIT_DISCARD_DIRTY,
                variant_id="help",
                title="simgit command help",
                flag="--help",
            ),
        ),
    ),
    CommandSafetyRule(
        rule_id="command.simgit.delete-unmerged",
        title="simgit unmerged branch deletion",
        description=(
            "Identifies `--delete-unmerged` on `simgit remove` and `simgit "
            "gc`, which deletes a worktree's branch past Git's merged check "
            "and drops commits that were never integrated. Without it, branch "
            "deletion retains unmerged branches and reports them as retained. "
            "A `remove` or `gc` invocation whose unresolved shell expansion "
            "can occupy a flag slot is reviewed too, because argv cannot "
            "prove the flag absent."
        ),
        severity="high",
        risk_classes=("destructive_shell",),
        action_classes=("simgit unmerged branch deletion command",),
        safer_alternatives=(
            "Drop the flag: `--delete-branch` alone keeps an unmerged branch and reports it as retained.",
            "Merge or push the branch before deleting the worktree that produced it.",
            "Preview the selection with `simgit gc --dry-run` before deleting branches in bulk.",
            "Expand shell variables and command substitutions so argv shows which flags simgit receives.",
        ),
        matcher=_SIMGIT_DELETE_UNMERGED_WITH_EXPANSIONS,
        default_mode="review",
        example_command="simgit remove feature-branch --delete-branch --delete-unmerged",
        safe_variants=(
            safe_flag_variant(
                _SIMGIT_GC_DELETE_UNMERGED,
                variant_id="dry-run",
                title="simgit gc branch deletion preview",
                flag="--dry-run",
            ),
            safe_flag_variant(
                _SIMGIT_DELETE_UNMERGED,
                variant_id="help",
                title="simgit command help",
                flag="--help",
            ),
        ),
    ),
)

SIMGIT_COMMAND_EXTENSION_SPECS = (
    CommandExtensionSpec(
        extension_id="command.simgit",
        name="simgit command protection",
        description=(
            "Reviews the two simgit flags that destroy work Git cannot return: "
            "discarding a dirty worktree and deleting an unmerged branch."
        ),
        action_classes=(
            "simgit uncommitted worktree discard command",
            "simgit unmerged branch deletion command",
        ),
        risk_classes=("destructive_shell",),
        safer_alternatives=(
            "Run the command without --discard-dirty or --delete-unmerged and read what it refuses to touch.",
            "Commit the worktree's changes with `simgit remove --commit` instead of discarding them.",
        ),
        reference_urls=("https://github.com/abendrothj/simgit",),
        executables=("simgit", "sg"),
        ecosystem_ids=("simgit",),
    ),
)
