//! One database handle over SQLite and PostgreSQL.
//!
//! The 277 direct rusqlite call sites are synchronous code inside async
//! handlers. `Repo` uses sqlx, which is async, so porting a call site to it
//! means rewriting the function — and its callers — as async. That is the
//! version of this project measured in months.
//!
//! So this uses the BLOCKING postgres driver instead. A call site keeps its
//! shape: `db.execute(sql, params)` / `db.query_row(sql, params, |r| …)`, with
//! the same borrow pattern and no `.await`. What changes is the row type, which
//! is why [`AnyRow`] exists.
//!
//! SQL is translated on the way through by [`crate::sql_translate`], so call
//! sites keep writing the SQLite dialect they already use.
//!
//! Deliberately NOT a general-purpose abstraction: it covers the shapes this
//! codebase actually uses. Anything else should fail to compile rather than be
//! silently approximated.

use crate::sql_translate::to_postgres;

/// A value that can be bound to a statement on either backend.
///
/// Small closed set on purpose: every bound parameter in this codebase is a
/// string, integer, float, bool, blob or null. A closed enum makes the
/// conversion total, and an unsupported type a compile error rather than a
/// runtime surprise.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
    Bool(bool),
}

impl From<i64> for SqlValue {
    fn from(v: i64) -> Self {
        SqlValue::Int(v)
    }
}
impl From<i32> for SqlValue {
    fn from(v: i32) -> Self {
        SqlValue::Int(v as i64)
    }
}
impl From<f64> for SqlValue {
    fn from(v: f64) -> Self {
        SqlValue::Real(v)
    }
}
impl From<bool> for SqlValue {
    fn from(v: bool) -> Self {
        SqlValue::Bool(v)
    }
}
impl From<&str> for SqlValue {
    fn from(v: &str) -> Self {
        SqlValue::Text(v.to_string())
    }
}
impl From<String> for SqlValue {
    fn from(v: String) -> Self {
        SqlValue::Text(v)
    }
}
impl From<&String> for SqlValue {
    fn from(v: &String) -> Self {
        SqlValue::Text(v.clone())
    }
}
impl From<Vec<u8>> for SqlValue {
    fn from(v: Vec<u8>) -> Self {
        SqlValue::Blob(v)
    }
}
impl<T: Into<SqlValue>> From<Option<T>> for SqlValue {
    fn from(v: Option<T>) -> Self {
        match v {
            Some(inner) => inner.into(),
            None => SqlValue::Null,
        }
    }
}

/// Column access that reads the same on both backends.
///
/// Typed getters rather than a generic `get::<T>()`: the backends disagree about
/// which Rust types a column maps to (SQLite is dynamically typed and hands back
/// i64 for anything integral; Postgres is strict and distinguishes INT4/INT8/
/// BOOL). Naming the intent at the call site removes that ambiguity.
pub trait AnyRow {
    fn get_i64(&self, idx: usize) -> Result<i64, String>;
    fn get_string(&self, idx: usize) -> Result<String, String>;
    fn get_bool(&self, idx: usize) -> Result<bool, String>;
    fn get_f64(&self, idx: usize) -> Result<f64, String>;
    fn get_blob(&self, idx: usize) -> Result<Vec<u8>, String>;
    fn get_opt_string(&self, idx: usize) -> Result<Option<String>, String>;
    fn get_opt_i64(&self, idx: usize) -> Result<Option<i64>, String>;
}

impl AnyRow for rusqlite::Row<'_> {
    fn get_i64(&self, idx: usize) -> Result<i64, String> {
        self.get::<_, i64>(idx).map_err(|e| e.to_string())
    }
    fn get_string(&self, idx: usize) -> Result<String, String> {
        self.get::<_, String>(idx).map_err(|e| e.to_string())
    }
    fn get_bool(&self, idx: usize) -> Result<bool, String> {
        // SQLite stores booleans as 0/1 integers; some columns are declared
        // BOOLEAN and some INTEGER, and rusqlite will refuse the wrong one, so
        // accept either rather than making every call site care.
        match self.get::<_, i64>(idx) {
            Ok(v) => Ok(v != 0),
            Err(_) => self.get::<_, bool>(idx).map_err(|e| e.to_string()),
        }
    }
    fn get_f64(&self, idx: usize) -> Result<f64, String> {
        self.get::<_, f64>(idx).map_err(|e| e.to_string())
    }
    fn get_blob(&self, idx: usize) -> Result<Vec<u8>, String> {
        self.get::<_, Vec<u8>>(idx).map_err(|e| e.to_string())
    }
    fn get_opt_string(&self, idx: usize) -> Result<Option<String>, String> {
        self.get::<_, Option<String>>(idx)
            .map_err(|e| e.to_string())
    }
    fn get_opt_i64(&self, idx: usize) -> Result<Option<i64>, String> {
        self.get::<_, Option<i64>>(idx).map_err(|e| e.to_string())
    }
}

/// Which backend a handle talks to. Kept separate from the handle so callers can
/// branch on it for the few places where behaviour genuinely differs (retry on
/// serialization failure, for instance) without matching on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    Sqlite,
    Postgres,
}

impl Backend {
    /// The statement this backend should actually receive.
    pub fn prepare_sql(&self, sql: &str) -> String {
        match self {
            Backend::Sqlite => sql.to_string(),
            Backend::Postgres => to_postgres(sql),
        }
    }
}

impl AnyRow for postgres::Row {
    fn get_i64(&self, idx: usize) -> Result<i64, String> {
        // Postgres is strict about width, and this schema mixes BIGINT (new
        // migrations) with INTEGER (older ones). Try the declared width, then
        // the narrower one, so a call site does not have to know which.
        self.try_get::<_, i64>(idx)
            .or_else(|_| self.try_get::<_, i32>(idx).map(i64::from))
            .map_err(|e| e.to_string())
    }
    fn get_string(&self, idx: usize) -> Result<String, String> {
        self.try_get::<_, String>(idx).map_err(|e| e.to_string())
    }
    fn get_bool(&self, idx: usize) -> Result<bool, String> {
        // Mirrors the SQLite side: a column may be a real BOOLEAN or the 0/1
        // integer this codebase writes.
        self.try_get::<_, bool>(idx)
            .or_else(|_| self.try_get::<_, i64>(idx).map(|v| v != 0))
            .or_else(|_| self.try_get::<_, i32>(idx).map(|v| v != 0))
            .map_err(|e| e.to_string())
    }
    fn get_f64(&self, idx: usize) -> Result<f64, String> {
        self.try_get::<_, f64>(idx)
            .or_else(|_| self.try_get::<_, f32>(idx).map(f64::from))
            .map_err(|e| e.to_string())
    }
    fn get_blob(&self, idx: usize) -> Result<Vec<u8>, String> {
        self.try_get::<_, Vec<u8>>(idx).map_err(|e| e.to_string())
    }
    fn get_opt_string(&self, idx: usize) -> Result<Option<String>, String> {
        self.try_get::<_, Option<String>>(idx)
            .map_err(|e| e.to_string())
    }
    fn get_opt_i64(&self, idx: usize) -> Result<Option<i64>, String> {
        self.try_get::<_, Option<i64>>(idx)
            .or_else(|_| {
                self.try_get::<_, Option<i32>>(idx)
                    .map(|v| v.map(i64::from))
            })
            .map_err(|e| e.to_string())
    }
}

/// A NULL that fits any column.
///
/// rust-postgres asks the server for each parameter's type and then calls
/// `to_sql` with it, so `None::<i64>` is a NULL *typed int8* and Postgres
/// refuses it for a TEXT column ("error serializing parameter"). SQLite has no
/// such notion — NULL is NULL. This accepts whatever type the server asks for
/// and writes nothing, which is what the call sites mean.
#[derive(Debug)]
struct AnyNull;

impl postgres::types::ToSql for AnyNull {
    fn to_sql(
        &self,
        _ty: &postgres::types::Type,
        _out: &mut postgres::types::private::BytesMut,
    ) -> Result<postgres::types::IsNull, Box<dyn std::error::Error + Sync + Send>> {
        Ok(postgres::types::IsNull::Yes)
    }

    fn accepts(_ty: &postgres::types::Type) -> bool {
        true
    }

    postgres::types::to_sql_checked!();
}

impl SqlValue {
    /// Booleans bind as 0/1 integers, because that is how this schema stores
    /// them: there is not a single BOOLEAN column in migrations/postgres — every
    /// flag (`revoked`, `confirmed`, `broadcast`, `no_real_money`, …) is
    /// INTEGER, mirroring SQLite, which has no boolean type at all.
    ///
    /// Binding a Rust `bool` to those columns makes Postgres refuse the
    /// statement with "error serializing parameter", which is how the
    /// dual-backend test caught this. Normalising here keeps every call site
    /// free to pass a bool and read one back.
    fn normalized_for_pg(&self) -> SqlValue {
        match self {
            SqlValue::Bool(v) => SqlValue::Int(i64::from(*v)),
            other => other.clone(),
        }
    }

    /// Borrow as a postgres parameter. Call on the output of
    /// [`SqlValue::normalized_for_pg`], never on a raw `Bool`.
    fn as_pg(&self) -> &(dyn postgres::types::ToSql + Sync) {
        match self {
            SqlValue::Null => &AnyNull,
            SqlValue::Int(v) => v,
            SqlValue::Real(v) => v,
            SqlValue::Text(v) => v,
            SqlValue::Blob(v) => v,
            // Unreachable via the query paths, which normalise first. Binding
            // a real bool would only be correct against a BOOLEAN column, and
            // this schema has none.
            SqlValue::Bool(v) => v,
        }
    }

    fn as_sqlite(&self) -> rusqlite::types::Value {
        match self {
            SqlValue::Null => rusqlite::types::Value::Null,
            SqlValue::Int(v) => rusqlite::types::Value::Integer(*v),
            SqlValue::Real(v) => rusqlite::types::Value::Real(*v),
            SqlValue::Text(v) => rusqlite::types::Value::Text(v.clone()),
            SqlValue::Blob(v) => rusqlite::types::Value::Blob(v.clone()),
            // SQLite has no boolean type; this codebase stores 0/1 integers.
            SqlValue::Bool(v) => rusqlite::types::Value::Integer(i64::from(*v)),
        }
    }
}

/// A connection to whichever backend is configured.
///
/// Borrowed, not owned: call sites already hold a pooled SQLite connection, so
/// this wraps a borrow and keeps their lifetimes unchanged.
pub enum AnyConn<'a> {
    Sqlite(&'a rusqlite::Connection),
    Postgres(&'a mut postgres::Client),
}

/// A column type readable from either backend's row.
///
/// This exists so row closures can keep saying `row.get(3)?` and let the binding
/// site's type drive the decode, exactly as rusqlite does. Without it, porting a
/// query means rewriting every field of its closure into a named getter
/// (`get_string`, `get_i64`, …), which is per-site work with a per-site chance
/// of pairing the wrong column with the wrong type.
pub trait FromAnyRow: Sized {
    fn from_any_row(row: &dyn AnyRow, idx: usize) -> Result<Self, String>;
}

impl FromAnyRow for String {
    fn from_any_row(row: &dyn AnyRow, idx: usize) -> Result<Self, String> {
        row.get_string(idx)
    }
}
impl FromAnyRow for i64 {
    fn from_any_row(row: &dyn AnyRow, idx: usize) -> Result<Self, String> {
        row.get_i64(idx)
    }
}
impl FromAnyRow for bool {
    fn from_any_row(row: &dyn AnyRow, idx: usize) -> Result<Self, String> {
        row.get_bool(idx)
    }
}
impl FromAnyRow for f64 {
    fn from_any_row(row: &dyn AnyRow, idx: usize) -> Result<Self, String> {
        row.get_f64(idx)
    }
}
impl FromAnyRow for Vec<u8> {
    fn from_any_row(row: &dyn AnyRow, idx: usize) -> Result<Self, String> {
        row.get_blob(idx)
    }
}
impl FromAnyRow for Option<String> {
    fn from_any_row(row: &dyn AnyRow, idx: usize) -> Result<Self, String> {
        row.get_opt_string(idx)
    }
}
impl FromAnyRow for Option<i64> {
    fn from_any_row(row: &dyn AnyRow, idx: usize) -> Result<Self, String> {
        row.get_opt_i64(idx)
    }
}

/// Inference-driven column access, mirroring `rusqlite::Row::get`.
///
/// Kept off [`AnyRow`] itself because a generic method would make the trait
/// non-object-safe, and the query helpers hand closures a `&dyn AnyRow`.
pub trait AnyRowGet {
    fn get<T: FromAnyRow>(&self, idx: usize) -> Result<T, String>;
}

impl AnyRowGet for dyn AnyRow + '_ {
    fn get<T: FromAnyRow>(&self, idx: usize) -> Result<T, String> {
        T::from_any_row(self, idx)
    }
}

/// Borrow a connection as an [`AnyConn`].
///
/// The call-site sweep replaced `db.query_row(..)` with
/// `AnyConn::Sqlite(&db).query_row(..)`, which fixed the SQL dialect but wrote
/// the backend choice into every one of those sites — so switching to Postgres
/// would mean editing them all a second time. Going through this trait keeps the
/// choice in one place: when the handle can yield a Postgres client, call sites
/// follow with no further edits.
pub trait AsAnyConn {
    fn any_conn(&self) -> AnyConn<'_>;
}

impl AsAnyConn for rusqlite::Connection {
    fn any_conn(&self) -> AnyConn<'_> {
        AnyConn::Sqlite(self)
    }
}

impl AnyConn<'_> {
    pub fn backend(&self) -> Backend {
        match self {
            AnyConn::Sqlite(_) => Backend::Sqlite,
            AnyConn::Postgres(_) => Backend::Postgres,
        }
    }

    /// Read one row, or fail with the caller's error.
    ///
    /// Collapses the shape that appears at nearly every required-row read:
    /// distinct handling for "the query failed" and "there is no such row" that
    /// produces the same response either way. `err` is a closure because the
    /// error is usually built from owned data and is needed twice.
    pub fn require<T, E>(
        &mut self,
        sql: &str,
        params: &[SqlValue],
        map: impl FnOnce(&dyn AnyRow) -> Result<T, String>,
        err: impl Fn() -> E,
    ) -> Result<T, E> {
        match self.query_row(sql, params, map) {
            Ok(Some(v)) => Ok(v),
            Ok(None) | Err(_) => Err(err()),
        }
    }

    /// Read one row, falling back to `default` when it is missing OR the query
    /// failed.
    ///
    /// This is the deliberate best-effort shape — the one that used to be
    /// written `.ok().flatten().unwrap_or(x)`. Naming it makes the sites that
    /// swallow errors greppable, instead of each one looking like an accident.
    pub fn scalar_or<T>(
        &mut self,
        sql: &str,
        params: &[SqlValue],
        map: impl FnOnce(&dyn AnyRow) -> Result<T, String>,
        default: T,
    ) -> T {
        self.query_row(sql, params, map)
            .ok()
            .flatten()
            .unwrap_or(default)
    }

    /// Run a statement, returning rows affected.
    pub fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, String> {
        match self {
            AnyConn::Sqlite(conn) => {
                let values: Vec<rusqlite::types::Value> =
                    params.iter().map(SqlValue::as_sqlite).collect();
                let refs: Vec<&dyn rusqlite::ToSql> =
                    values.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                conn.execute(sql, refs.as_slice())
                    .map(|n| n as u64)
                    .map_err(|e| e.to_string())
            }
            AnyConn::Postgres(client) => {
                let translated = to_postgres(sql);
                let owned: Vec<SqlValue> = params.iter().map(SqlValue::normalized_for_pg).collect();
                let bound: Vec<&(dyn postgres::types::ToSql + Sync)> =
                    owned.iter().map(SqlValue::as_pg).collect();
                client
                    .execute(translated.as_str(), bound.as_slice())
                    .map_err(|e| e.to_string())
            }
        }
    }

    /// Run a query expected to return exactly one row. `Ok(None)` when empty,
    /// matching the `QueryReturnedNoRows` case call sites already handle.
    pub fn query_row<T>(
        &mut self,
        sql: &str,
        params: &[SqlValue],
        map: impl FnOnce(&dyn AnyRow) -> Result<T, String>,
    ) -> Result<Option<T>, String> {
        match self {
            AnyConn::Sqlite(conn) => {
                let values: Vec<rusqlite::types::Value> =
                    params.iter().map(SqlValue::as_sqlite).collect();
                let refs: Vec<&dyn rusqlite::ToSql> =
                    values.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
                let mut rows = stmt.query(refs.as_slice()).map_err(|e| e.to_string())?;
                match rows.next().map_err(|e| e.to_string())? {
                    Some(row) => map(row as &dyn AnyRow).map(Some),
                    None => Ok(None),
                }
            }
            AnyConn::Postgres(client) => {
                let translated = to_postgres(sql);
                let owned: Vec<SqlValue> = params.iter().map(SqlValue::normalized_for_pg).collect();
                let bound: Vec<&(dyn postgres::types::ToSql + Sync)> =
                    owned.iter().map(SqlValue::as_pg).collect();
                let rows = client
                    .query(translated.as_str(), bound.as_slice())
                    .map_err(|e| e.to_string())?;
                match rows.first() {
                    Some(row) => map(row as &dyn AnyRow).map(Some),
                    None => Ok(None),
                }
            }
        }
    }

    /// Run a query and map every row.
    pub fn query_map<T>(
        &mut self,
        sql: &str,
        params: &[SqlValue],
        mut map: impl FnMut(&dyn AnyRow) -> Result<T, String>,
    ) -> Result<Vec<T>, String> {
        match self {
            AnyConn::Sqlite(conn) => {
                let values: Vec<rusqlite::types::Value> =
                    params.iter().map(SqlValue::as_sqlite).collect();
                let refs: Vec<&dyn rusqlite::ToSql> =
                    values.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
                let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
                let mut rows = stmt.query(refs.as_slice()).map_err(|e| e.to_string())?;
                let mut out = Vec::new();
                while let Some(row) = rows.next().map_err(|e| e.to_string())? {
                    out.push(map(row as &dyn AnyRow)?);
                }
                Ok(out)
            }
            AnyConn::Postgres(client) => {
                let translated = to_postgres(sql);
                let owned: Vec<SqlValue> = params.iter().map(SqlValue::normalized_for_pg).collect();
                let bound: Vec<&(dyn postgres::types::ToSql + Sync)> =
                    owned.iter().map(SqlValue::as_pg).collect();
                let rows = client
                    .query(translated.as_str(), bound.as_slice())
                    .map_err(|e| e.to_string())?;
                rows.iter().map(|r| map(r as &dyn AnyRow)).collect()
            }
        }
    }
}

/// Bind list for [`AnyConn`] calls: `params![a, b]`.
#[macro_export]
macro_rules! sql_params {
    () => { &[] as &[$crate::any_db::SqlValue] };
    ($($v:expr),+ $(,)?) => {
        &[$($crate::any_db::SqlValue::from($v)),+] as &[$crate::any_db::SqlValue]
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_statements_pass_through_untouched() {
        let sql = "INSERT OR IGNORE INTO t (a) VALUES (?1)";
        assert_eq!(Backend::Sqlite.prepare_sql(sql), sql);
    }

    #[test]
    fn postgres_statements_are_translated() {
        assert_eq!(
            Backend::Postgres.prepare_sql("SELECT IFNULL(a, 0) FROM t WHERE b = ?1"),
            "SELECT COALESCE(a, 0) FROM t WHERE b = $1"
        );
    }

    #[test]
    fn values_convert_from_the_types_call_sites_actually_bind() {
        assert_eq!(SqlValue::from(7i64), SqlValue::Int(7));
        assert_eq!(SqlValue::from("x"), SqlValue::Text("x".into()));
        assert_eq!(SqlValue::from(true), SqlValue::Bool(true));
        assert_eq!(SqlValue::from(None::<i64>), SqlValue::Null);
        assert_eq!(SqlValue::from(Some(3i64)), SqlValue::Int(3));
        assert_eq!(SqlValue::from(vec![1u8, 2]), SqlValue::Blob(vec![1, 2]));
    }

    #[test]
    fn sqlite_rows_read_integer_booleans() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE t (i INTEGER, s TEXT, b INTEGER, f REAL, blob BLOB, opt TEXT);
             INSERT INTO t VALUES (42, 'hello', 1, 1.5, X'0102', NULL);",
        )
        .unwrap();
        conn.query_row("SELECT i, s, b, f, blob, opt FROM t", [], |r| {
            assert_eq!(r.get_i64(0).unwrap(), 42);
            assert_eq!(r.get_string(1).unwrap(), "hello");
            assert!(r.get_bool(2).unwrap(), "0/1 integers must read as bool");
            assert_eq!(r.get_f64(3).unwrap(), 1.5);
            assert_eq!(r.get_blob(4).unwrap(), vec![1u8, 2]);
            assert_eq!(r.get_opt_string(5).unwrap(), None);
            Ok(())
        })
        .unwrap();
    }
}
