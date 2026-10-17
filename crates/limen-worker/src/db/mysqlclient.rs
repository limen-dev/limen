//! A small MySQL client for the role bootstrap and for tests (ADR-0033): text
//! protocol, one statement at a time. It logs in with the relay's code, so it
//! gets the same TLS and authentication handling.

use limen_core::secret::Secret;

use super::mysql::{self, Login, Packet, is_eof, lenenc, parse_err, read_packet, write_packet};
use super::pgclient::{QueryError, Row};
use super::target::{BoxedIo, Target};

pub struct Client {
    io: BoxedIo,
    connection_id: u32,
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
        Self::connect_with(target, user, password, database, application, 0).await
    }

    /// `client_flags` are MySQL capability bits to ask for, such as
    /// `0x1_0000` (`CLIENT_MULTI_STATEMENTS`).
    pub async fn connect_with(
        target: &Target,
        user: &str,
        password: &Secret<String>,
        database: &str,
        application: &str,
        client_flags: u32,
    ) -> Result<Self, String> {
        let login = Login {
            user,
            password,
            database,
            session: application,
        };
        let up = mysql::connect_upstream(target, &login, client_flags, 45)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Self {
            io: up.io,
            connection_id: up.thread_id,
        })
    }

    /// The connection id in the server's greeting (for `KILL`).
    #[must_use]
    pub fn connection_id(&self) -> u32 {
        self.connection_id
    }

    async fn send(&mut self, payload: Vec<u8>) -> Result<(), QueryError> {
        write_packet(&mut self.io, &Packet { seq: 0, payload })
            .await
            .map_err(|e| QueryError::Other(e.to_string()))
    }

    async fn recv(&mut self) -> Result<Packet, QueryError> {
        read_packet(&mut self.io)
            .await
            .map_err(|e| QueryError::Other(e.to_string()))
    }

    /// Read one or more results (several for `CALL` or multi-statements) and
    /// return the rows of the last. `binary` marks prepared-statement results.
    async fn results(&mut self) -> Result<Vec<Row>, QueryError> {
        loop {
            let first = self.recv().await?;
            let (rows, more) = match first.payload.first() {
                Some(0x00) => (Vec::new(), ok_status(&first.payload) & MORE_RESULTS != 0),
                Some(0xff) => return Err(server_error(&first.payload)),
                _ => {
                    let (columns, _) = lenenc(&first.payload)
                        .ok_or_else(|| QueryError::Other("bad column count".into()))?;
                    for _ in 0..columns {
                        self.recv().await?;
                    }
                    self.recv().await?; // EOF after the columns
                    let mut rows = Vec::new();
                    let status = loop {
                        let p = self.recv().await?;
                        if is_eof(&p) {
                            break p
                                .payload
                                .get(3..5)
                                .map_or(0, |b| u16::from_le_bytes([b[0], b[1]]));
                        }
                        if p.payload.first() == Some(&0xff) {
                            return Err(server_error(&p.payload));
                        }
                        rows.push(
                            parse_row(&p.payload, columns)
                                .ok_or_else(|| QueryError::Other("malformed row".into()))?,
                        );
                    };
                    (rows, status & MORE_RESULTS != 0)
                }
            };
            if !more {
                return Ok(rows);
            }
        }
    }

    /// Run `sql`; the rows are text, `None` is NULL. With several statements,
    /// the rows of the last one.
    pub async fn query(&mut self, sql: &str) -> Result<Vec<Row>, QueryError> {
        let mut payload = vec![0x03];
        payload.extend_from_slice(sql.as_bytes());
        self.send(payload).await?;
        self.results().await
    }

    /// Prepare and execute a statement without parameters, and return how
    /// many rows it produced (binary protocol).
    pub async fn run_prepared(&mut self, sql: &str) -> Result<usize, QueryError> {
        let mut payload = vec![0x16];
        payload.extend_from_slice(sql.as_bytes());
        self.send(payload).await?;
        let first = self.recv().await?;
        if first.payload.first() == Some(&0xff) {
            return Err(server_error(&first.payload));
        }
        let p = &first.payload;
        let id = [p[1], p[2], p[3], p[4]];
        let columns = u16::from_le_bytes([p[5], p[6]]);
        let params = u16::from_le_bytes([p[7], p[8]]);
        for count in [params, columns] {
            if count > 0 {
                for _ in 0..count {
                    self.recv().await?;
                }
                self.recv().await?;
            }
        }
        let mut exec = vec![0x17];
        exec.extend_from_slice(&id);
        exec.extend_from_slice(&[0, 1, 0, 0, 0]); // no cursor, one iteration
        self.send(exec).await?;
        let first = self.recv().await?;
        let rows = match first.payload.first() {
            Some(0xff) => return Err(server_error(&first.payload)),
            Some(0x00) => 0,
            _ => {
                let (cols, _) = lenenc(&first.payload)
                    .ok_or_else(|| QueryError::Other("bad column count".into()))?;
                for _ in 0..cols {
                    self.recv().await?;
                }
                self.recv().await?;
                let mut rows = 0;
                loop {
                    let p = self.recv().await?;
                    if is_eof(&p) {
                        break;
                    }
                    if p.payload.first() == Some(&0xff) {
                        return Err(server_error(&p.payload));
                    }
                    rows += 1;
                }
                rows
            }
        };
        let mut close = vec![0x19];
        close.extend_from_slice(&id);
        self.send(close).await?;
        Ok(rows)
    }

    /// Send a raw command and return the first packet of the answer.
    pub async fn raw_command(&mut self, payload: Vec<u8>) -> Result<Vec<u8>, QueryError> {
        self.send(payload).await?;
        Ok(self.recv().await?.payload)
    }

    pub async fn execute(&mut self, sql: &str) -> Result<(), QueryError> {
        self.query(sql).await.map(|_| ())
    }

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
        let _ = self.send(vec![0x01]).await;
    }
}

const MORE_RESULTS: u16 = 0x0008;

/// The status flags of an OK packet.
fn ok_status(payload: &[u8]) -> u16 {
    let (_, a) = lenenc(payload.get(1..).unwrap_or(&[])).unwrap_or((0, 1));
    let (_, b) = lenenc(payload.get(1 + a..).unwrap_or(&[])).unwrap_or((0, 1));
    payload
        .get(1 + a + b..1 + a + b + 2)
        .map_or(0, |s| u16::from_le_bytes([s[0], s[1]]))
}

fn server_error(payload: &[u8]) -> QueryError {
    let (state, number, message) = parse_err(payload);
    QueryError::Server {
        code: number.to_string(),
        message: format!("{message} [{state}]"),
    }
}

fn parse_row(payload: &[u8], columns: u64) -> Option<Row> {
    let mut at = 0;
    let mut row = Vec::new();
    for _ in 0..columns {
        if payload.get(at) == Some(&0xfb) {
            row.push(None);
            at += 1;
            continue;
        }
        let (len, used) = lenenc(payload.get(at..)?)?;
        at += used;
        let end = at + usize::try_from(len).ok()?;
        row.push(Some(
            String::from_utf8_lossy(payload.get(at..end)?).into_owned(),
        ));
        at = end;
    }
    Some(row)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_have_nulls_and_values() {
        let payload = [2, b'a', b'b', 0xfb, 0];
        assert_eq!(
            parse_row(&payload, 3),
            Some(vec![Some("ab".into()), None, Some(String::new())])
        );
        assert_eq!(parse_row(&payload[..2], 1), None);
    }
}
