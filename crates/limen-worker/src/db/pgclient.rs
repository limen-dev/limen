//! A small PostgreSQL client for the role bootstrap (ADR-0033 section 6): the
//! simple query protocol, text results. It reuses the relay's login code, so
//! the admin connection gets the same TLS and SCRAM handling.

use limen_core::secret::Secret;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::pg::{self, Backend};
use super::target::Target;

/// A failed statement.
#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error("{message} (SQLSTATE {code})")]
    Server { code: String, message: String },
    #[error("{0}")]
    Other(String),
}

/// A row of text values; `None` is NULL.
pub type Row = Vec<Option<String>>;

pub struct Client {
    backend: Backend,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Client")
    }
}

impl Client {
    pub async fn connect(
        target: &Target,
        user: &str,
        password: &Secret<String>,
        database: &str,
        application: &str,
    ) -> Result<Self, String> {
        let params = vec![
            ("user".to_owned(), user.to_owned()),
            ("database".to_owned(), database.to_owned()),
            ("application_name".to_owned(), application.to_owned()),
            ("client_encoding".to_owned(), "UTF8".to_owned()),
        ];
        let backend = pg::connect_backend(target, user, password, application, &params)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self { backend })
    }

    /// Run `sql` (one or more statements) and return the rows of the last
    /// statement that produced any.
    pub async fn query(&mut self, sql: &str) -> Result<Vec<Row>, QueryError> {
        let mut body = sql.as_bytes().to_vec();
        body.push(0);
        let io = |e: std::io::Error| QueryError::Other(e.to_string());
        self.backend
            .writer
            .write_all(&pg::frame(b'Q', &body))
            .await
            .map_err(io)?;
        let mut rows = Vec::new();
        let mut error = None;
        loop {
            let (kind, body) = pg::read_frame(&mut self.backend.reader, pg::MAX_HANDSHAKE_FRAME)
                .await
                .map_err(|e| QueryError::Other(e.to_string()))?;
            match kind {
                b'T' => rows.clear(),
                b'D' => rows.push(
                    parse_row(&body)
                        .ok_or_else(|| QueryError::Other("malformed DataRow".into()))?,
                ),
                b'E' => {
                    let fields = pg::error_fields(&body);
                    error.get_or_insert(QueryError::Server {
                        code: pg::field(&fields, b'C').unwrap_or("").to_owned(),
                        message: pg::field(&fields, b'M').unwrap_or("error").to_owned(),
                    });
                }
                b'Z' => break,
                _ => {}
            }
        }
        match error {
            Some(e) => Err(e),
            None => Ok(rows),
        }
    }

    pub async fn execute(&mut self, sql: &str) -> Result<(), QueryError> {
        self.query(sql).await.map(|_| ())
    }

    /// A single value, or `None` for no rows or NULL.
    pub async fn scalar(&mut self, sql: &str) -> Result<Option<String>, QueryError> {
        Ok(self
            .query(sql)
            .await?
            .into_iter()
            .next()
            .and_then(|r| r.into_iter().next())
            .flatten())
    }

    pub async fn close(mut self) {
        let _ = self.backend.writer.write_all(&pg::frame(b'X', &[])).await;
        let _ = self.backend.writer.shutdown().await;
        let mut sink = [0u8; 1];
        let _ = self.backend.reader.read(&mut sink).await;
    }
}

fn parse_row(body: &[u8]) -> Option<Row> {
    let count = usize::from(u16::from_be_bytes([*body.first()?, *body.get(1)?]));
    let mut at = 2;
    let mut row = Vec::with_capacity(count);
    for _ in 0..count {
        let len = i32::from_be_bytes(body.get(at..at + 4)?.try_into().ok()?);
        at += 4;
        if len < 0 {
            row.push(None);
        } else {
            let end = at + usize::try_from(len).ok()?;
            row.push(Some(
                String::from_utf8_lossy(body.get(at..end)?).into_owned(),
            ));
            at = end;
        }
    }
    Some(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rows_with_nulls() {
        let mut body = 3u16.to_be_bytes().to_vec();
        for v in [Some("ab"), None, Some("")] {
            match v {
                Some(s) => {
                    body.extend_from_slice(&i32::try_from(s.len()).expect("short").to_be_bytes());
                    body.extend_from_slice(s.as_bytes());
                }
                None => body.extend_from_slice(&(-1i32).to_be_bytes()),
            }
        }
        assert_eq!(
            parse_row(&body),
            Some(vec![Some("ab".into()), None, Some(String::new())])
        );
        assert_eq!(parse_row(&body[..5]), None);
    }
}
