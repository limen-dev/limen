//! A small XML reader for AWS query API responses (ADR-0027). It builds a
//! tree of elements with their text and ignores attributes, namespaces,
//! comments and processing instructions. It has hard limits on size, depth
//! and node count, so a hostile or broken endpoint can't use it to exhaust the
//! worker. It is not a general XML parser and does not try to be.

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 400_000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub text: String,
    pub children: Vec<Node>,
}

impl Node {
    /// The first child with this name.
    #[must_use]
    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Follow a path of child names.
    #[must_use]
    pub fn path(&self, path: &[&str]) -> Option<&Node> {
        path.iter().try_fold(self, |n, p| n.child(p))
    }

    /// All children with this name.
    pub fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// The text of a child, trimmed, if it has any.
    #[must_use]
    pub fn text_of(&self, name: &str) -> Option<&str> {
        self.child(name)
            .map(|c| c.text.trim())
            .filter(|t| !t.is_empty())
    }

    #[must_use]
    pub fn text_at(&self, path: &[&str]) -> Option<&str> {
        self.path(path)
            .map(|c| c.text.trim())
            .filter(|t| !t.is_empty())
    }
}

fn local(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn unescape(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let Some(end) = rest.find(';').filter(|e| *e <= 10) else {
            out.push('&');
            rest = &rest[1..];
            continue;
        };
        let entity = &rest[1..end];
        let ch = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            e => e
                .strip_prefix("#x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| e.strip_prefix('#').and_then(|d| d.parse().ok()))
                .and_then(char::from_u32),
        };
        match ch {
            Some(c) => {
                out.push(c);
                rest = &rest[end + 1..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Parse a document into its root element.
pub fn parse(input: &str) -> Result<Node, String> {
    if input.len() > MAX_BYTES {
        return Err("the response is too large".into());
    }
    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<Node> = None;
    let mut nodes = 0usize;
    let mut rest = input;
    while !rest.is_empty() {
        let Some(lt) = rest.find('<') else {
            if let Some(top) = stack.last_mut() {
                top.text.push_str(&unescape(rest));
            }
            break;
        };
        if lt > 0
            && let Some(top) = stack.last_mut()
        {
            top.text.push_str(&unescape(&rest[..lt]));
        }
        rest = &rest[lt..];
        if let Some(r) = rest.strip_prefix("<![CDATA[") {
            let end = r.find("]]>").ok_or("unterminated CDATA")?;
            if let Some(top) = stack.last_mut() {
                top.text.push_str(&r[..end]);
            }
            rest = &r[end + 3..];
        } else if let Some(r) = rest.strip_prefix("<!--") {
            rest = &r[r.find("-->").ok_or("unterminated comment")? + 3..];
        } else if rest.starts_with("<?") || rest.starts_with("<!") {
            rest = &rest[rest.find('>').ok_or("unterminated declaration")? + 1..];
        } else if let Some(r) = rest.strip_prefix("</") {
            let end = r.find('>').ok_or("unterminated end tag")?;
            let name = local(r[..end].trim());
            let node = stack.pop().ok_or("unbalanced end tag")?;
            if node.name != name {
                return Err(format!("expected </{}>, found </{name}>", node.name));
            }
            match stack.last_mut() {
                Some(parent) => parent.children.push(node),
                None => root = Some(node),
            }
            rest = &r[end + 1..];
        } else {
            let end = rest.find('>').ok_or("unterminated tag")?;
            let mut tag = &rest[1..end];
            let empty = tag.ends_with('/');
            if empty {
                tag = &tag[..tag.len() - 1];
            }
            let name = local(tag.split_whitespace().next().ok_or("empty tag")?).to_owned();
            nodes += 1;
            if nodes > MAX_NODES {
                return Err("too many elements".into());
            }
            let node = Node {
                name,
                ..Node::default()
            };
            if empty {
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => root = Some(node),
                }
            } else {
                if stack.len() >= MAX_DEPTH {
                    return Err("nested too deeply".into());
                }
                stack.push(node);
            }
            rest = &rest[end + 1..];
        }
    }
    if !stack.is_empty() {
        return Err("unclosed element".into());
    }
    root.ok_or_else(|| "no root element".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_tree_and_ignores_namespaces_and_attributes() {
        let n = parse(
            r#"<?xml version="1.0"?><r:Root xmlns:r="urn:x"><a id="1"><b>one &amp; two</b><c/></a><a><b><![CDATA[<raw>]]></b></a></r:Root>"#,
        )
        .expect("parse");
        assert_eq!(n.name, "Root");
        let bs: Vec<&str> = n.all("a").filter_map(|a| a.text_of("b")).collect();
        assert_eq!(bs, ["one & two", "<raw>"]);
        assert!(n.path(&["a", "c"]).is_some());
        assert_eq!(n.text_at(&["a", "b"]), Some("one & two"));
    }

    #[test]
    fn entities_numeric_and_broken() {
        assert_eq!(unescape("a&#65;&#x42;&lt;&bogus;&"), "aAB<&bogus;&");
    }

    #[test]
    fn refuses_what_could_hurt_the_worker() {
        assert!(parse("<a><b></a>").is_err());
        assert!(parse("<a>").is_err());
        assert!(parse("</a>").is_err());
        assert!(parse("").is_err());
        assert!(parse(&format!("{}{}", "<a>".repeat(100), "</a>".repeat(100))).is_err());
        let wide = format!("<r>{}</r>", "<i/>".repeat(MAX_NODES + 1));
        assert!(parse(&wide).is_err());
        assert!(parse(&"x".repeat(MAX_BYTES + 1)).is_err());
        // Garbage in the middle of text never panics.
        let _ = parse("<a>\u{0}&#xFFFFFFFF;<<</a>");
    }
}
