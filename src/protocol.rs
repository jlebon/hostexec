// Wire protocol types shared by client and server.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Maximum message size.
pub const MAX_MSG: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Request {
    Run { cmd: Vec<String>, cwd: PathBuf },
    Notify { hook: String },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Response {
    // The request was denied.
    Denied,
    // An error occurred while handling the request.
    Error { message: String },
    // The request was approved and the command exited with code.
    Exit { code: i32 },
}
