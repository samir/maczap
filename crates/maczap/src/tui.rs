//! The selection screen of `uninstall` (DESIGN §7): items grouped by category,
//! coloured by confidence, with the match reason of the current item.
//!
//! `Selector` is a pure state machine (`handle_key`) plus a `render` function, so both
//! are tested without a terminal; `run` is the thin event loop around them.

use std::io;
use std::path::Path;

use maczap_core::candidate::Confidence;
use maczap_core::plan::Plan;
use ratatui::Frame;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

use crate::output::{category, confidence, size, tilde};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub group: &'static str,
    pub label: String,
    pub confidence: Confidence,
    pub size: u64,
    /// Why it matched, or why the guard keeps it.
    pub reason: String,
    pub selectable: bool,
    pub selected: bool,
    pub needs_root: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    PageUp,
    PageDown,
    Toggle,
    AllHigh,
    Nothing,
    Confirm,
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Continue,
    Confirm,
    Cancel,
}

#[derive(Debug, Clone)]
pub struct Selector {
    pub title: String,
    /// What Enter does, e.g. "move to quarantine".
    pub action: String,
    pub rows: Vec<Row>,
    pub notes: Vec<String>,
    cursor: usize,
    message: Option<String>,
}

const PAGE: usize = 10;

impl Selector {
    pub fn new(title: String, action: String, rows: Vec<Row>, notes: Vec<String>) -> Self {
        Selector {
            title,
            action,
            rows,
            notes,
            cursor: 0,
            message: None,
        }
    }

    pub fn from_plan(
        title: String,
        action: String,
        plan: &Plan,
        sizes: &[u64],
        home: &Path,
        notes: Vec<String>,
    ) -> Self {
        let rows = plan
            .items
            .iter()
            .zip(sizes)
            .map(|(item, bytes)| Row {
                group: category(item.candidate.category),
                label: tilde(&item.candidate.path, home),
                confidence: item.candidate.confidence,
                size: *bytes,
                reason: match &item.verdict {
                    Ok(_) => item.candidate.reason.clone(),
                    Err(rejection) => format!("kept: {rejection}"),
                },
                selectable: item.verdict.is_ok(),
                selected: item.selected,
                needs_root: item.needs_root,
            })
            .collect();
        Self::new(title, action, rows, notes)
    }

    #[cfg(test)]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    #[cfg(test)]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    pub fn selection(&self) -> Vec<bool> {
        self.rows.iter().map(|r| r.selected).collect()
    }

    fn selected_totals(&self) -> (usize, u64) {
        self.rows
            .iter()
            .filter(|r| r.selected)
            .fold((0, 0), |(n, b), r| (n + 1, b + r.size))
    }

    pub fn handle_key(&mut self, key: Key) -> Outcome {
        self.message = None;
        let last = self.rows.len().saturating_sub(1);
        match key {
            Key::Up => self.cursor = self.cursor.saturating_sub(1),
            Key::Down => self.cursor = (self.cursor + 1).min(last),
            Key::PageUp => self.cursor = self.cursor.saturating_sub(PAGE),
            Key::PageDown => self.cursor = (self.cursor + PAGE).min(last),
            Key::Toggle => {
                if let Some(row) = self.rows.get_mut(self.cursor) {
                    if row.selectable {
                        row.selected = !row.selected;
                    } else {
                        self.message =
                            Some(format!("{} cannot be selected ({})", row.label, row.reason));
                    }
                }
            }
            Key::AllHigh => {
                for row in self.rows.iter_mut().filter(|r| r.selectable) {
                    if matches!(row.confidence, Confidence::High | Confidence::Curated) {
                        row.selected = true;
                    }
                }
            }
            Key::Nothing => self.rows.iter_mut().for_each(|r| r.selected = false),
            Key::Confirm => {
                if self.selected_totals().0 == 0 {
                    self.message = Some("Nothing is selected.".into());
                } else {
                    return Outcome::Confirm;
                }
            }
            Key::Cancel => return Outcome::Cancel,
        }
        Outcome::Continue
    }

    pub fn render(&self, frame: &mut Frame) {
        let [header, list, details, footer] = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(5),
            Constraint::Length(4),
            Constraint::Length(2),
        ])
        .areas(frame.area());

        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    self.title.clone(),
                    Style::new().add_modifier(Modifier::BOLD),
                )),
                Line::from(format!(
                    "Select what to remove; Enter will {}.",
                    self.action
                )),
            ]),
            header,
        );

        // Group headers are interleaved with rows; remember where the cursor row is.
        let mut items = Vec::new();
        let mut cursor_line = 0;
        let mut last_group = None;
        for (index, row) in self.rows.iter().enumerate() {
            if last_group != Some(row.group) {
                items.push(ListItem::new(Line::from(Span::styled(
                    row.group,
                    Style::new().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                ))));
                last_group = Some(row.group);
            }
            if index == self.cursor {
                cursor_line = items.len();
            }
            let mark = match (row.selectable, row.selected) {
                (false, _) => " - ",
                (true, true) => "[x]",
                (true, false) => "[ ]",
            };
            let colour = match (row.selectable, row.confidence) {
                (false, _) => Color::DarkGray,
                (true, Confidence::High) => Color::Green,
                (true, Confidence::Curated) => Color::Cyan,
                (true, Confidence::Low) => Color::Yellow,
                (true, Confidence::Shared) => Color::DarkGray,
            };
            let admin = if row.needs_root { "  (admin)" } else { "" };
            items.push(ListItem::new(Line::from(vec![
                Span::raw(format!("  {mark} ")),
                Span::styled(
                    format!("{:<7}", confidence(row.confidence)),
                    Style::new().fg(colour),
                ),
                Span::raw(format!(" {:>9}  {}{admin}", size(row.size), row.label)),
            ])));
        }
        let mut state = ListState::default().with_selected(Some(cursor_line));
        frame.render_stateful_widget(
            List::new(items)
                .block(Block::new().borders(Borders::TOP | Borders::BOTTOM))
                .highlight_style(Style::new().add_modifier(Modifier::REVERSED)),
            list,
            &mut state,
        );

        let detail = match (&self.message, self.rows.get(self.cursor)) {
            (Some(message), _) => message.clone(),
            (None, Some(row)) => format!("{}\n{}", row.label, row.reason),
            (None, None) => String::new(),
        };
        frame.render_widget(Paragraph::new(detail).wrap(Wrap { trim: true }), details);

        let (count, bytes) = self.selected_totals();
        let mut lines = vec![Line::from(format!(
            "{count} selected, {}   space toggle · a all high · n none · enter confirm · q cancel",
            size(bytes)
        ))];
        if let Some(note) = self.notes.first() {
            lines.push(Line::from(Span::styled(
                format!(
                    "{note}{}",
                    if self.notes.len() > 1 {
                        format!(" (+{} more)", self.notes.len() - 1)
                    } else {
                        String::new()
                    }
                ),
                Style::new().fg(Color::DarkGray),
            )));
        }
        frame.render_widget(Paragraph::new(lines), footer);
    }
}

fn map_key(code: KeyCode, modifiers: KeyModifiers) -> Option<Key> {
    Some(match code {
        KeyCode::Up | KeyCode::Char('k') => Key::Up,
        KeyCode::Down | KeyCode::Char('j') => Key::Down,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        KeyCode::Char(' ') => Key::Toggle,
        KeyCode::Char('a') => Key::AllHigh,
        KeyCode::Char('n') => Key::Nothing,
        KeyCode::Enter => Key::Confirm,
        KeyCode::Esc | KeyCode::Char('q') => Key::Cancel,
        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => Key::Cancel,
        _ => return None,
    })
}

/// Runs the screen. Returns the final selection, or `None` when cancelled.
pub fn run(mut selector: Selector) -> io::Result<Option<Vec<bool>>> {
    let mut terminal = ratatui::try_init()?;
    let result = (|| loop {
        terminal.draw(|frame| selector.render(frame))?;
        if let Event::Key(key) = event::read()?
            && key.kind == KeyEventKind::Press
            && let Some(key) = map_key(key.code, key.modifiers)
        {
            match selector.handle_key(key) {
                Outcome::Continue => {}
                Outcome::Confirm => return Ok(Some(selector.selection())),
                Outcome::Cancel => return Ok(None),
            }
        }
    })();
    ratatui::restore();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn row(
        group: &'static str,
        label: &str,
        confidence: Confidence,
        selectable: bool,
        selected: bool,
    ) -> Row {
        Row {
            group,
            label: label.into(),
            confidence,
            size: 1000,
            reason: format!("reason for {label}"),
            selectable,
            selected,
            needs_root: false,
        }
    }

    fn selector() -> Selector {
        Selector::new(
            "Bar 1.0 (com.foo.Bar)".into(),
            "move to quarantine".into(),
            vec![
                row(
                    "Application",
                    "/Applications/Bar.app",
                    Confidence::High,
                    true,
                    true,
                ),
                row(
                    "Caches",
                    "~/Library/Caches/com.foo.Bar",
                    Confidence::High,
                    true,
                    false,
                ),
                row(
                    "Caches",
                    "~/Library/Caches/Bar",
                    Confidence::Low,
                    true,
                    false,
                ),
                row(
                    "Group Containers",
                    "~/Library/Group Containers/X.shared",
                    Confidence::Shared,
                    false,
                    false,
                ),
            ],
            vec!["not checked: ~/Library/Containers".into()],
        )
    }

    #[test]
    fn toggles_selectable_rows_but_never_rejected_ones() {
        let mut s = selector();
        s.handle_key(Key::Down);
        s.handle_key(Key::Down);
        assert_eq!(s.handle_key(Key::Toggle), Outcome::Continue);
        assert_eq!(s.selection(), vec![true, false, true, false]);
        s.handle_key(Key::Down);
        s.handle_key(Key::Toggle);
        assert_eq!(s.selection(), vec![true, false, true, false]);
        assert!(s.message().unwrap().contains("cannot be selected"));
    }

    #[test]
    fn all_high_selects_high_and_curated_only_and_none_clears() {
        let mut s = selector();
        s.handle_key(Key::AllHigh);
        assert_eq!(s.selection(), vec![true, true, false, false]);
        s.handle_key(Key::Nothing);
        assert_eq!(s.selection(), vec![false, false, false, false]);
    }

    #[test]
    fn confirm_needs_a_selection_and_cancel_always_works() {
        let mut s = selector();
        s.handle_key(Key::Nothing);
        assert_eq!(s.handle_key(Key::Confirm), Outcome::Continue);
        assert_eq!(s.message(), Some("Nothing is selected."));
        s.handle_key(Key::Toggle);
        assert_eq!(s.handle_key(Key::Confirm), Outcome::Confirm);
        assert_eq!(s.handle_key(Key::Cancel), Outcome::Cancel);
    }

    #[test]
    fn the_cursor_stays_within_the_rows() {
        let mut s = selector();
        s.handle_key(Key::Up);
        assert_eq!(s.cursor(), 0);
        s.handle_key(Key::PageDown);
        assert_eq!(s.cursor(), 3);
        s.handle_key(Key::Down);
        assert_eq!(s.cursor(), 3);
        s.handle_key(Key::PageUp);
        assert_eq!(s.cursor(), 0);
    }

    fn screen(s: &Selector) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 20)).unwrap();
        terminal.draw(|f| s.render(f)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn renders_groups_marks_details_and_totals() {
        let mut s = selector();
        s.handle_key(Key::Down);
        let text = screen(&s);
        for expected in [
            "Bar 1.0 (com.foo.Bar)",
            "Enter will move to quarantine",
            "Application",
            "Group Containers",
            "[x] high",
            "[ ] low",
            " -  shared",
            "reason for ~/Library/Caches/com.foo.Bar",
            "1 selected, 1.0 KB",
            "not checked: ~/Library/Containers",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in\n{text}");
        }
    }

    #[test]
    fn renders_the_message_instead_of_the_reason_after_a_refusal() {
        let mut s = selector();
        s.handle_key(Key::PageDown);
        s.handle_key(Key::Toggle);
        assert!(screen(&s).contains("cannot be selected"));
    }
}
