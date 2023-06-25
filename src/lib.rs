#[macro_use]
extern crate slog;
extern crate atty;
extern crate chrono;
extern crate libflate;
extern crate notify;
extern crate slog_atomic;
extern crate slog_scope;
extern crate slog_stdlog;
extern crate slog_term;
extern crate term;
extern crate viperus;

#[macro_use]
extern crate lazy_static;

pub use slog_scope::{
    crit as slog_scope_crit, debug as slog_scope_debug, error as slog_scope_error,
    info as slog_scope_info, trace as slog_scope_trace, warn as slog_scope_warn,
};

pub mod config;
pub mod logger;

#[cfg(all(target_family = "unix", feature = "asyncshell", not(target_os = "windows")))]
#[allow(unused)]
pub mod shell;

#[cfg(all(target_family = "unix", feature = "asyncudev", not(target_os = "windows")))]
#[allow(unused)]
pub mod udevs;

#[macro_export]
macro_rules! wait {
    ($($function_no_args: path),*) => {{
        $($function_no_args();)*
    }};
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
