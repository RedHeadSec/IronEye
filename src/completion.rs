//! File completion support for Cerbero commands
//!
//! Provides tab completion for file paths in commands like `export` and `list`

use rustyline::completion::{Completer, FilenameCompleter, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Context, Helper};
use std::borrow::Cow;

/// Commands that support file path completion
const FILE_COMMANDS: &[&str] = &["export ", "list ", "convert -i ", "convert -o "];

/// Helper for Cerbero command line with file completion support
pub struct CerberoCompleter {
    file_completer: FilenameCompleter,
}

impl CerberoCompleter {
    pub fn new() -> Self {
        Self {
            file_completer: FilenameCompleter::new(),
        }
    }

    /// Find if we're in a position that should trigger file completion
    fn find_file_completion_start(&self, line: &str) -> Option<usize> {
        for cmd in FILE_COMMANDS {
            if line.starts_with(cmd) {
                return Some(cmd.len());
            }
        }

        // Also handle -i and -o flags anywhere in the line
        if let Some(pos) = line.rfind(" -i ") {
            return Some(pos + 4);
        }
        if let Some(pos) = line.rfind(" -o ") {
            return Some(pos + 4);
        }

        None
    }
}

impl Completer for CerberoCompleter {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        ctx: &Context<'_>,
    ) -> Result<(usize, Vec<Pair>), ReadlineError> {
        if let Some(file_start) = self.find_file_completion_start(line) {
            if pos >= file_start {
                // Extract the file path portion being typed
                let file_part = &line[file_start..pos];

                // Use FilenameCompleter on just the file portion
                match self
                    .file_completer
                    .complete(file_part, file_part.len(), ctx)
                {
                    Ok((start, completions)) => {
                        // Filter to show only relevant file types for ticket
                        // commands
                        let filtered: Vec<Pair> = completions
                            .into_iter()
                            .filter(|p| {
                                let path = &p.replacement;
                                // Show directories (end with /)
                                path.ends_with('/')
                                    // Show ticket files
                                    || path.ends_with(".ccache")
                                    || path.ends_with(".krb")
                                    || path.ends_with(".kirbi")
                                    // Show files without extension
                                    // (like krb5cc_1000)
                                    || !path.contains('.')
                                    // Show all if user started typing
                                    || !file_part.is_empty()
                            })
                            .collect();

                        // Adjust start position relative to full line
                        return Ok((file_start + start, filtered));
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        // No completion available
        Ok((0, vec![]))
    }
}

impl Hinter for CerberoCompleter {
    type Hint = String;

    fn hint(&self, _line: &str, _pos: usize, _ctx: &Context<'_>) -> Option<String> {
        None
    }
}

impl Highlighter for CerberoCompleter {
    fn highlight_hint<'h>(&self, hint: &'h str) -> Cow<'h, str> {
        Cow::Borrowed(hint)
    }
}

impl Validator for CerberoCompleter {}

impl Helper for CerberoCompleter {}

impl Default for CerberoCompleter {
    fn default() -> Self {
        Self::new()
    }
}
