//! Classifying a Kubernetes API request the way the API server does
//! (`k8s.io/apiserver/pkg/endpoints/request.RequestInfoFactory`), so audit
//! events carry the same verb, resource, namespace, and name as the cluster's
//! own audit log.

/// What an API request is for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RequestInfo {
    /// `get`, `list`, `watch`, `create`, `update`, `patch`, `delete`,
    /// `deletecollection`; for non-resource URLs the lowercase HTTP method.
    pub verb: String,
    /// False for `/healthz`, `/version`, discovery documents, and the like.
    pub resource_request: bool,
    pub api_group: String,
    pub api_version: String,
    pub namespace: String,
    pub resource: String,
    pub subresource: String,
    pub name: String,
    /// The request path as the API server sees it (no query string).
    pub path: String,
}

/// `%XX` decoded (invalid escapes are left as they are), as Go's
/// `url.PathUnescape` does for a path segment.
#[must_use]
pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(hex) = s.get(i + 1..i + 3)
            && let Ok(b) = u8::from_str_radix(hex, 16)
        {
            out.push(b);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether the query turns the boolean parameter `name` on, the way the API
/// server reads it: the first occurrence wins, keys and values are
/// percent-decoded, and the value is Go's `strconv.ParseBool` (`1 t T TRUE
/// true True`). A bare `?watch` counts as on.
fn query_flag(query: &str, name: &str) -> bool {
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if percent_decode(&key.replace('+', " ")) == name {
            let value = percent_decode(&value.replace('+', " "));
            return value.is_empty()
                || matches!(value.as_str(), "1" | "t" | "T" | "TRUE" | "true" | "True");
        }
    }
    false
}

/// The long-lived stream subresources of pods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamSubresource {
    Exec,
    Attach,
    PortForward,
}

impl RequestInfo {
    /// Classify `method path?query`. `query` may be empty and is not decoded
    /// beyond what is needed (`watch=`).
    #[must_use]
    pub fn parse(method: &str, path: &str, query: &str) -> Self {
        let mut info = Self {
            path: path.to_owned(),
            verb: method.to_ascii_lowercase(),
            ..Self::default()
        };
        // The API server routes on the decoded path, so classify what it will see.
        let decoded: Vec<String> = path
            .split('/')
            .filter(|p| !p.is_empty())
            .map(percent_decode)
            .collect();
        let parts: Vec<&str> = decoded.iter().map(String::as_str).collect();
        let rest: &[&str] = match parts.as_slice() {
            ["api", version, rest @ ..] => {
                (*version).clone_into(&mut info.api_version);
                rest
            }
            ["apis", group, version, rest @ ..] => {
                (*group).clone_into(&mut info.api_group);
                (*version).clone_into(&mut info.api_version);
                rest
            }
            _ => return info,
        };
        if rest.is_empty() {
            return info; // `/api/v1` and `/apis/apps/v1` are discovery.
        }
        info.resource_request = true;
        let verb = match method {
            "POST" => "create",
            "GET" | "HEAD" => "get",
            "PUT" => "update",
            "PATCH" => "patch",
            "DELETE" => "delete",
            other => {
                info.resource_request = false;
                info.verb = other.to_ascii_lowercase();
                return info;
            }
        };
        verb.clone_into(&mut info.verb);

        let mut rest = rest;
        if let ["watch", tail @ ..] = rest {
            info.verb = "watch".into();
            rest = tail;
        }
        // `namespaces/<ns>/<resource>...` scopes the request; `namespaces/<name>`
        // (and its `finalize` and `status`) is the Namespace resource itself.
        if let ["namespaces", ns, tail @ ..] = rest
            && !tail.is_empty()
            && !matches!(tail, ["finalize" | "status"])
        {
            (*ns).clone_into(&mut info.namespace);
            rest = tail;
        }
        if let [resource, tail @ ..] = rest {
            (*resource).clone_into(&mut info.resource);
            if let [name, sub @ ..] = tail {
                (*name).clone_into(&mut info.name);
                info.subresource = sub.join("/");
            }
        }
        let watching = query_flag(query, "watch");
        if info.verb == "get" && watching {
            info.verb = "watch".into();
        } else if info.verb == "get" && info.name.is_empty() {
            info.verb = "list".into();
        } else if info.verb == "delete" && info.name.is_empty() {
            info.verb = "deletecollection".into();
        }
        info
    }

    /// `exec`, `attach`, or `port-forward` on a pod: the requests that upgrade
    /// to a stream.
    #[must_use]
    pub fn stream_subresource(&self) -> Option<StreamSubresource> {
        if self.resource != "pods" || !self.api_group.is_empty() {
            return None;
        }
        match self.subresource.as_str() {
            "exec" => Some(StreamSubresource::Exec),
            "attach" => Some(StreamSubresource::Attach),
            "portforward" => Some(StreamSubresource::PortForward),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(method: &str, uri: &str) -> RequestInfo {
        let (path, query) = uri.split_once('?').unwrap_or((uri, ""));
        RequestInfo::parse(method, path, query)
    }

    #[test]
    fn core_resources() {
        let i = parse("GET", "/api/v1/namespaces/dev/pods");
        assert_eq!(
            (i.verb.as_str(), i.namespace.as_str(), i.resource.as_str()),
            ("list", "dev", "pods")
        );
        let i = parse("GET", "/api/v1/namespaces/dev/pods/web-1/log");
        assert_eq!(
            (i.verb.as_str(), i.name.as_str(), i.subresource.as_str()),
            ("get", "web-1", "log")
        );
        let i = parse("GET", "/api/v1/pods?watch=true");
        assert_eq!((i.verb.as_str(), i.namespace.as_str()), ("watch", ""));
        let i = parse("GET", "/api/v1/watch/namespaces/dev/pods");
        assert_eq!(i.verb, "watch");
        assert_eq!(i.namespace, "dev");
        let i = parse("DELETE", "/api/v1/namespaces/dev/pods");
        assert_eq!(i.verb, "deletecollection");
        let i = parse("POST", "/api/v1/namespaces/dev/pods/web-1/exec");
        assert_eq!(i.verb, "create");
        assert_eq!(i.stream_subresource(), Some(StreamSubresource::Exec));
    }

    #[test]
    fn namespaces_are_resources_too() {
        let i = parse("GET", "/api/v1/namespaces/dev");
        assert_eq!(
            (i.namespace.as_str(), i.resource.as_str(), i.name.as_str()),
            ("", "namespaces", "dev")
        );
        let i = parse("PUT", "/api/v1/namespaces/dev/status");
        assert_eq!(
            (i.resource.as_str(), i.subresource.as_str()),
            ("namespaces", "status")
        );
        let i = parse("GET", "/api/v1/namespaces");
        assert_eq!(
            (i.resource.as_str(), i.verb.as_str()),
            ("namespaces", "list")
        );
    }

    #[test]
    fn grouped_resources() {
        let i = parse("PATCH", "/apis/apps/v1/namespaces/dev/deployments/web");
        assert_eq!(
            (
                i.api_group.as_str(),
                i.api_version.as_str(),
                i.resource.as_str(),
                i.verb.as_str()
            ),
            ("apps", "v1", "deployments", "patch")
        );
        assert_eq!(i.stream_subresource(), None);
    }

    #[test]
    fn non_resource_urls() {
        for path in [
            "/healthz",
            "/version",
            "/openapi/v3",
            "/api",
            "/api/v1",
            "/apis/apps/v1",
        ] {
            let i = parse("GET", path);
            assert!(!i.resource_request, "{path}");
            assert_eq!(i.verb, "get");
        }
    }

    #[test]
    fn only_pods_in_the_core_group_stream() {
        let i = parse("GET", "/apis/example.com/v1/namespaces/a/pods/b/exec");
        assert_eq!(i.stream_subresource(), None);
        let i = parse("GET", "/api/v1/namespaces/a/pods/b/portforward");
        assert_eq!(i.stream_subresource(), Some(StreamSubresource::PortForward));
    }

    #[test]
    fn classification_reads_what_the_api_server_reads() {
        // An encoded name is the same name.
        let i = parse("GET", "/api/v1/namespaces/dev/%73ecrets/db");
        assert_eq!((i.resource.as_str(), i.name.as_str()), ("secrets", "db"));
        let i = parse("GET", "/%61pi/v1/namespaces/dev/pods/web/%65xec");
        assert_eq!(i.stream_subresource(), Some(StreamSubresource::Exec));
        // Booleans are Go's ParseBool; keys and values may be encoded.
        for q in [
            "watch=true",
            "watch=True",
            "watch=TRUE",
            "watch=t",
            "watch=T",
            "watch=1",
            "watch",
            "%77atch=%74rue",
        ] {
            let i = parse("GET", &format!("/api/v1/pods?{q}"));
            assert_eq!(i.verb, "watch", "{q}");
        }
        for q in [
            "watch=false",
            "watch=0",
            "watch=f",
            "watch=no",
            "wat=true",
            "limit=5",
        ] {
            let i = parse("GET", &format!("/api/v1/pods?{q}"));
            assert_eq!(i.verb, "list", "{q}");
        }
        // The first occurrence wins, as it does in the API server.
        assert_eq!(
            parse("GET", "/api/v1/pods?watch=false&watch=true").verb,
            "list"
        );
        assert_eq!(
            parse("GET", "/api/v1/pods?watch=true&watch=false").verb,
            "watch"
        );
    }

    #[test]
    fn percent_decoding_leaves_bad_escapes_alone() {
        assert_eq!(percent_decode("a%20b%2Fc"), "a b/c");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
    }
}
