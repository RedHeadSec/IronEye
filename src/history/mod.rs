use rusqlite::{Connection, Result};
use rustyline::completion::Completer;
use rustyline::highlight::Highlighter;
use rustyline::hint::Hinter;
use rustyline::validate::Validator;
use rustyline::{Editor, Helper};
use std::path::PathBuf;

pub struct HistoryManager {
    conn: Connection,
}

impl HistoryManager {
    pub fn new() -> Result<Self> {
        let db_path = Self::get_db_path();

        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        }

        let conn = Connection::open(db_path)?;
        Self::init_schema(&conn)?;

        Ok(Self { conn })
    }

    fn get_db_path() -> PathBuf {
        PathBuf::from("ironeye_history.db")
    }

    fn init_schema(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module TEXT NOT NULL,
                command TEXT NOT NULL,
                timestamp INTEGER NOT NULL
            )",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_module_time 
             ON history(module, timestamp DESC)",
            [],
        )?;

        Ok(())
    }

    pub fn add(&self, module: &str, command: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO history (module, command, timestamp) VALUES (?1, ?2, ?3)",
            (module, command, chrono::Utc::now().timestamp()),
        )?;
        Ok(())
    }

    pub fn get_recent(&self, module: &str, limit: usize) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT command FROM history 
             WHERE module = ?1 
             ORDER BY timestamp DESC 
             LIMIT ?2",
        )?;

        let commands = stmt
            .query_map((module, limit), |row| row.get(0))?
            .collect::<Result<Vec<String>>>()?;

        Ok(commands)
    }

    pub fn get_all_recent(&self, limit: usize) -> Result<Vec<(String, String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT module, command, timestamp FROM history 
             ORDER BY timestamp DESC 
             LIMIT ?1",
        )?;

        let results = stmt
            .query_map([limit], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<Result<Vec<_>>>()?;

        Ok(results)
    }

    pub fn search(&self, pattern: &str) -> Result<Vec<(String, String, i64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT module, command, timestamp FROM history 
             WHERE command LIKE ?1 
             ORDER BY timestamp DESC 
             LIMIT 100",
        )?;

        let results = stmt
            .query_map([format!("%{}%", pattern)], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?
            .collect::<Result<Vec<_>>>()?;

        Ok(results)
    }

    pub fn cleanup_old(&self, days: i64) -> Result<usize> {
        let cutoff = chrono::Utc::now().timestamp() - (days * 86400);
        self.conn
            .execute("DELETE FROM history WHERE timestamp < ?1", [cutoff])
    }

    pub fn clear_module(&self, module: &str) -> Result<usize> {
        self.conn
            .execute("DELETE FROM history WHERE module = ?1", [module])
    }

    pub fn clear_all(&self) -> Result<usize> {
        self.conn.execute("DELETE FROM history", [])
    }

    pub fn export_to_file(&self, filepath: &str) -> Result<usize> {
        use std::fs::File;
        use std::io::Write;

        let mut stmt = self
            .conn
            .prepare("SELECT module, command, timestamp FROM history ORDER BY timestamp DESC")?;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;

        let mut file = File::create(filepath)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        writeln!(file, "# IronEye Command History Export")
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        writeln!(
            file,
            "# Generated: {}\n",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
        )
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        let mut count = 0;
        for row_result in rows {
            let (module, command, timestamp) = row_result?;
            let dt = chrono::DateTime::from_timestamp(timestamp, 0)
                .unwrap_or_else(|| chrono::Utc::now());
            writeln!(
                file,
                "[{}] {} | {}",
                dt.format("%Y-%m-%d %H:%M:%S"),
                module,
                command
            )
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            count += 1;
        }

        Ok(count)
    }

    pub fn get_stats(&self) -> Result<Vec<(String, usize)>> {
        let mut stmt = self.conn.prepare(
            "SELECT module, COUNT(*) as count FROM history 
             GROUP BY module 
             ORDER BY count DESC",
        )?;

        let stats = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<Result<Vec<_>>>()?;

        Ok(stats)
    }
}

/// Bracketed paste (on by default in rustyline) inserts a clipboard's
/// embedded or trailing newline as a literal character in the line buffer -
/// rustyline normalizes CRLF to LF but never strips it. Since almost every
/// copy from a code block or terminal output carries a trailing newline,
/// pasting a command glues that newline directly onto the last token (e.g.
/// `-k` becomes `-k\n`), which then fails to match any flag during parsing
/// and gets written to the history DB verbatim, embedded newline and all.
/// Collapse newlines to spaces (not delete them outright) so pasted
/// multi-line input doesn't silently fuse adjacent tokens together, then
/// trim the ends.
fn sanitize_pasted_line(line: &str) -> String {
    line.replace(['\r', '\n'], " ").trim().to_string()
}

pub struct HistoryEditor {
    manager: HistoryManager,
    module: String,
    editor: rustyline::DefaultEditor,
}

impl HistoryEditor {
    pub fn new(module: &str) -> Result<Self> {
        let manager = HistoryManager::new()?;
        let mut editor = rustyline::DefaultEditor::new()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        for cmd in manager.get_recent(module, 100)?.into_iter().rev() {
            editor.add_history_entry(&cmd).ok();
        }

        Ok(Self {
            manager,
            module: module.to_string(),
            editor,
        })
    }

    pub fn readline(&mut self, prompt: &str) -> Result<String> {
        let line = self
            .editor
            .readline(prompt)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let line = sanitize_pasted_line(&line);

        self.manager.add(&self.module, &line)?;
        self.editor.add_history_entry(&line).ok();

        Ok(line)
    }
}

pub struct HistoryEditorWithCompleter<H: Helper> {
    manager: HistoryManager,
    module: String,
    editor: Editor<H, rustyline::history::DefaultHistory>,
}

impl<H> HistoryEditorWithCompleter<H>
where
    H: Helper + Completer + Hinter + Highlighter + Validator,
{
    pub fn new(module: &str, helper: H) -> Result<Self> {
        let manager = HistoryManager::new()?;
        let mut editor =
            Editor::new().map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

        editor.set_helper(Some(helper));

        for cmd in manager.get_recent(module, 100)?.into_iter().rev() {
            editor.add_history_entry(&cmd).ok();
        }

        Ok(Self {
            manager,
            module: module.to_string(),
            editor,
        })
    }

    pub fn readline(&mut self, prompt: &str) -> Result<String> {
        let line = self
            .editor
            .readline(prompt)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let line = sanitize_pasted_line(&line);

        self.manager.add(&self.module, &line)?;
        self.editor.add_history_entry(&line).ok();

        Ok(line)
    }
}

#[cfg(test)]
mod sanitize_tests {
    use super::*;

    #[test]
    fn strips_trailing_newline_from_pasted_clipboard() {
        let sanitized =
            sanitize_pasted_line("-u redheadsecadmin -i 10.3.50.2 -d redheadsec.dev -k\n");
        assert_eq!(
            sanitized,
            "-u redheadsecadmin -i 10.3.50.2 -d redheadsec.dev -k"
        );
    }

    #[test]
    fn collapses_embedded_newline_to_a_space_instead_of_fusing_tokens() {
        let sanitized = sanitize_pasted_line("-d redheadsec.dev\n-k");
        assert_eq!(sanitized, "-d redheadsec.dev -k");
    }

    #[test]
    fn handles_windows_style_crlf() {
        let sanitized = sanitize_pasted_line("-k -d redheadsec.dev\r\n");
        assert_eq!(sanitized, "-k -d redheadsec.dev");
    }
}
