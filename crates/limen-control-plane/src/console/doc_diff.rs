//! A line diff of two documents, for the policy change page: what an approver is about to apply,
//! shown against what is active. Pure, bounded and tested. The documents are shown as pretty JSON,
//! which is what the control plane holds; the diff says nothing about formatting the YAML source had.

/// One line of a diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    /// `+` added, `-` removed, ` ` unchanged, `…` lines left out between changes.
    pub op: char,
    pub text: String,
}

/// Documents longer than this many lines on either side are shown as a whole replacement rather than
/// diffed: the table is quadratic and an approver can't read more anyway.
const MAX_LINES: usize = 600;

/// The line diff of `old` against `new`, by longest common subsequence, unchanged lines kept.
#[must_use]
pub fn line_diff(old: &str, new: &str) -> Vec<DiffLine> {
    let a: Vec<&str> = old.lines().collect();
    let b: Vec<&str> = new.lines().collect();
    let line = |op, t: &str| DiffLine {
        op,
        text: t.to_owned(),
    };
    if a.len() > MAX_LINES || b.len() > MAX_LINES {
        return a
            .iter()
            .map(|t| line('-', t))
            .chain(b.iter().map(|t| line('+', t)))
            .collect();
    }
    // lcs[i][j]: length of the common subsequence of a[i..] and b[j..].
    let mut lcs = vec![vec![0_u32; b.len() + 1]; a.len() + 1];
    for i in (0..a.len()).rev() {
        for j in (0..b.len()).rev() {
            lcs[i][j] = if a[i] == b[j] {
                lcs[i + 1][j + 1] + 1
            } else {
                lcs[i + 1][j].max(lcs[i][j + 1])
            };
        }
    }
    let (mut i, mut j) = (0, 0);
    let mut out = Vec::new();
    while i < a.len() && j < b.len() {
        if a[i] == b[j] {
            out.push(line(' ', a[i]));
            i += 1;
            j += 1;
        } else if lcs[i + 1][j] >= lcs[i][j + 1] {
            out.push(line('-', a[i]));
            i += 1;
        } else {
            out.push(line('+', b[j]));
            j += 1;
        }
    }
    out.extend(a[i..].iter().map(|t| line('-', t)));
    out.extend(b[j..].iter().map(|t| line('+', t)));
    out
}

/// Keep `context` unchanged lines around each change and replace longer unchanged runs with one
/// `…` line saying how many were left out.
#[must_use]
pub fn with_context(lines: Vec<DiffLine>, context: usize) -> Vec<DiffLine> {
    let keep: Vec<bool> = (0..lines.len())
        .map(|i| {
            let lo = i.saturating_sub(context);
            let hi = (i + context + 1).min(lines.len());
            lines[lo..hi].iter().any(|l| l.op != ' ')
        })
        .collect();
    let mut out = Vec::new();
    let mut skipped = 0;
    for (l, k) in lines.into_iter().zip(keep) {
        if k {
            if skipped > 0 {
                out.push(DiffLine {
                    op: '…',
                    text: format!("{skipped} unchanged lines"),
                });
                skipped = 0;
            }
            out.push(l);
        } else {
            skipped += 1;
        }
    }
    if skipped > 0 {
        out.push(DiffLine {
            op: '…',
            text: format!("{skipped} unchanged lines"),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ops(d: &[DiffLine]) -> String {
        d.iter().map(|l| l.op).collect()
    }

    #[test]
    fn identical_text_is_all_unchanged() {
        let d = line_diff("a\nb\nc", "a\nb\nc");
        assert_eq!(ops(&d), "   ");
    }

    #[test]
    fn an_edit_is_a_removal_and_an_addition_in_place() {
        let d = line_diff("a\nb\nc", "a\nB\nc");
        assert_eq!(ops(&d), " -+ ");
        assert_eq!(d[1].text, "b");
        assert_eq!(d[2].text, "B");
    }

    #[test]
    fn added_and_removed_tails_are_kept() {
        assert_eq!(ops(&line_diff("a", "a\nb\nc")), " ++");
        assert_eq!(ops(&line_diff("a\nb\nc", "a")), " --");
        assert_eq!(ops(&line_diff("", "x")), "+");
        assert_eq!(ops(&line_diff("x", "")), "-");
        assert_eq!(line_diff("", "").len(), 0);
    }

    #[test]
    fn replaying_the_diff_gives_both_sides_back() {
        let (old, new) = ("a\nb\nc\nd\ne", "a\nc\nX\nd\ne\nf");
        let d = line_diff(old, new);
        let back = |keep: &[char]| {
            d.iter()
                .filter(|l| keep.contains(&l.op))
                .map(|l| l.text.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert_eq!(back(&[' ', '-']), old);
        assert_eq!(back(&[' ', '+']), new);
    }

    #[test]
    fn very_long_documents_are_a_whole_replacement_not_a_quadratic_table() {
        let big = (0..=MAX_LINES)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let d = line_diff(&big, "x");
        assert!(d.iter().all(|l| l.op == '-' || l.op == '+'));
        assert_eq!(d.len(), MAX_LINES + 1 + 1);
    }

    #[test]
    fn context_keeps_a_few_lines_around_changes_and_counts_the_rest() {
        let old = (0..30)
            .map(|i| format!("l{i}"))
            .collect::<Vec<_>>()
            .join("\n");
        let new = old.replace("l15", "changed");
        let d = with_context(line_diff(&old, &new), 2);
        let shown: Vec<&str> = d.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(
            shown,
            [
                "13 unchanged lines",
                "l13",
                "l14",
                "l15",
                "changed",
                "l16",
                "l17",
                "12 unchanged lines"
            ]
        );
        assert_eq!(d[0].op, '…');
    }

    #[test]
    fn nothing_changed_leaves_one_note() {
        let d = with_context(line_diff("a\nb", "a\nb"), 3);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].op, '…');
    }
}
