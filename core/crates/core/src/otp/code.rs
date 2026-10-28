// SPDX-License-Identifier: GPL-3.0-or-later
//! Computed codes, the only OTP output that leaves the core.

use core::fmt;

use zeroize::Zeroizing;

/// A one-time code: ASCII digits, or five characters of the Steam alphabet.
///
/// Zeroed on drop; `Debug` is redacted, so codes never end up in logs
/// (rule 3). Read it with [`Code::as_str`].
#[derive(Clone, PartialEq, Eq)]
pub struct Code(Zeroizing<String>);

impl Code {
    pub(crate) fn new(text: String) -> Self {
        Self(Zeroizing::new(text))
    }

    /// The code as shown to the user, for example `"287082"` or `"PV9M4"`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Code(<redacted>)")
    }
}

/// A time-based code and how long it stays valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimedCode {
    pub(crate) code: Code,
    pub(crate) remaining_s: u32,
    pub(crate) period_s: u32,
}

impl TimedCode {
    /// The code.
    pub fn code(&self) -> &Code {
        &self.code
    }

    /// Seconds until the next code, 1 to `period_s`.
    pub fn remaining_s(&self) -> u32 {
        self.remaining_s
    }

    /// Length of one time step in seconds.
    pub fn period_s(&self) -> u32 {
        self.period_s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let timed = TimedCode {
            code: Code::new("123456".into()),
            remaining_s: 7,
            period_s: 30,
        };
        let debug = format!("{timed:?}");
        assert!(!debug.contains("123456"));
        assert!(debug.contains("<redacted>"));
    }
}
