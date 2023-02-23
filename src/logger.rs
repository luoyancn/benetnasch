use std::cell::RefCell;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Mutex, Once,
};
use std::thread;
use std::time::{Duration, Instant};
use std::u64;

use atty;
use libflate::gzip::Encoder as GzipEncoder;
use notify::Watcher;
use slog::{Drain, OwnedKVList, Record};
use slog_term::{CountingWriter, RecordDecorator, ThreadSafeTimestampFn};
use term;

pub use slog::Level;

use crate::config;

const TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.9f";

pub const BITE: u64 = 1;
pub const KB: u64 = BITE * 1024;
pub const MB: u64 = KB * 1024;
pub const GB: u64 = MB * 1024;

static INIT: Once = Once::new();

lazy_static! {
    pub static ref LOG_PATH: Mutex<String> = Mutex::new(String::from("logs"));
    pub static ref LOG_KEEP: Mutex<i32> = Mutex::new(0);
    pub static ref LOG_MAX_SIZE_MB: Mutex<i32> = Mutex::new(100);
    pub static ref LOG_LEVEL: Mutex<Level> = Mutex::new(Level::Debug);
    pub static ref LOG_VERBOSE: Mutex<bool> = Mutex::new(false);
    pub static ref LOG_STD_COLORED: Mutex<bool> = Mutex::new(true);
    pub static ref LOG_FILE_ENABLE: Mutex<bool> = Mutex::new(false);
    pub static ref LOG_STD_ENABLE: Mutex<bool> = Mutex::new(true);
    static ref ATOMIC_DRAIN_SWITCH: slog_atomic::AtomicSwitchCtrl<(), io::Error> =
        slog_atomic::AtomicSwitch::new(slog::Discard.map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "should not happen")
        }))
        .ctrl();
    static ref ATOMIC_DRAIN_SWITCH_STATE: AtomicBool = AtomicBool::new(false);
    static ref SWITCH_SCHEDULED: AtomicBool = AtomicBool::new(false);
}

#[macro_export]
macro_rules! crit( ($($args:tt)+) => {
    $crate::slog_scope_crit![$($args)+];
    std::process::exit(-1);
};);

#[macro_export]
macro_rules! error( ($($args:tt)+) => {
    $crate::slog_scope_error![$($args)+]
};);

#[macro_export]
macro_rules! warn( ($($args:tt)+) => {
    $crate::slog_scope_warn![$($args)+]
};);

#[macro_export]
macro_rules! info( ($($args:tt)+) => {
    $crate::slog_scope_info![$($args)+]
};);

#[macro_export]
macro_rules! debug( ($($args:tt)+) => {
    $crate::slog_scope_debug![$($args)+]
};);

#[macro_export]
macro_rules! trace( ($($args:tt)+) => {
    $crate::slog_scope_trace![$($args)+]
};);

enum AnyTerminal {
    /// Stdout terminal
    Stdout {
        term: Box<term::StdoutTerminal>,
        supports_reset: bool,
        supports_color: bool,
    },
    /// Stderr terminal
    Stderr {
        term: Box<term::StderrTerminal>,
        supports_reset: bool,
        supports_color: bool,
    },
    FallbackStdout,
    FallbackStderr,
}

impl AnyTerminal {
    fn should_use_color(&self) -> bool {
        match *self {
            AnyTerminal::Stdout { .. } => atty::is(atty::Stream::Stdout),
            AnyTerminal::Stderr { .. } => atty::is(atty::Stream::Stderr),
            AnyTerminal::FallbackStdout => false,
            AnyTerminal::FallbackStderr => false,
        }
    }
}

struct ColoredTermDecorator {
    term: RefCell<AnyTerminal>,
    use_color: bool,
}

impl ColoredTermDecorator {
    /// Start building `TermDecorator`
    #[allow(clippy::new_ret_no_self)]
    fn new() -> ColoredTermDecoratorBuilder {
        ColoredTermDecoratorBuilder::new()
    }

    /// `Level` color
    ///
    /// Standard level to Unix color conversion used by `TermDecorator`
    fn level_to_color(level: slog::Level) -> u16 {
        match level {
            Level::Critical => 129,
            Level::Error => 196,
            Level::Warning => 214,
            Level::Info => 2,
            Level::Debug => 39,
            Level::Trace => 51,
        }
    }
}

impl slog_term::Decorator for ColoredTermDecorator {
    fn with_record<F>(
        &self,
        record: &Record,
        _logger_values: &OwnedKVList,
        f: F,
    ) -> io::Result<()>
    where
        F: FnOnce(&mut dyn RecordDecorator) -> io::Result<()>,
    {
        let mut term = self.term.borrow_mut();
        let mut deco = ColoredTermRecordDecorator {
            term: &mut *term,
            level: record.level(),
            use_color: self.use_color,
        };
        {
            f(&mut deco)
        }
    }
}

/// Record decorator used by `TermDecorator`
struct ColoredTermRecordDecorator<'a> {
    term: &'a mut AnyTerminal,
    level: slog::Level,
    use_color: bool,
}

impl<'a> io::Write for ColoredTermRecordDecorator<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match *self.term {
            AnyTerminal::Stdout { ref mut term, .. } => term.write(buf),
            AnyTerminal::Stderr { ref mut term, .. } => term.write(buf),
            AnyTerminal::FallbackStdout => std::io::stdout().write(buf),
            AnyTerminal::FallbackStderr => std::io::stderr().write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match *self.term {
            AnyTerminal::Stdout { ref mut term, .. } => term.flush(),
            AnyTerminal::Stderr { ref mut term, .. } => term.flush(),
            AnyTerminal::FallbackStdout => std::io::stdout().flush(),
            AnyTerminal::FallbackStderr => std::io::stderr().flush(),
        }
    }
}

impl<'a> Drop for ColoredTermRecordDecorator<'a> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

impl<'a> RecordDecorator for ColoredTermRecordDecorator<'a> {
    fn reset(&mut self) -> io::Result<()> {
        if !self.use_color {
            return Ok(());
        }
        match *self.term {
            AnyTerminal::Stdout {
                ref mut term,
                supports_reset,
                ..
            } if supports_reset => term.reset(),
            AnyTerminal::Stderr {
                ref mut term,
                supports_reset,
                ..
            } if supports_reset => term.reset(),
            _ => Ok(()),
        }
        .map_err(term_error_to_io_error)
    }

    fn start_level(&mut self) -> io::Result<()> {
        if !self.use_color {
            return Ok(());
        }
        let color = ColoredTermDecorator::level_to_color(self.level);
        match *self.term {
            AnyTerminal::Stdout {
                ref mut term,
                supports_color,
                ..
            } if supports_color => term.fg(color as term::color::Color),
            AnyTerminal::Stderr {
                ref mut term,
                supports_color,
                ..
            } if supports_color => term.fg(color as term::color::Color),
            _ => Ok(()),
        }
        .map_err(term_error_to_io_error)
    }

    fn start_key(&mut self) -> io::Result<()> {
        if !self.use_color {
            return Ok(());
        }
        let color = ColoredTermDecorator::level_to_color(self.level);
        match self.term {
            &mut AnyTerminal::Stdout {
                ref mut term,
                supports_color,
                ..
            } => {
                //if supports_bold {
                //    term.attr(term::Attr::Bold)?;
                //}
                if supports_color {
                    term.fg(color as term::color::Color)?;
                }
                Ok(())
            }
            &mut AnyTerminal::Stderr {
                ref mut term,
                supports_color,
                ..
            } => {
                //if supports_bold {
                //    term.attr(term::Attr::Bold)?;
                //}
                if supports_color {
                    term.fg(color as term::color::Color)?;
                }
                Ok(())
            }
            &mut AnyTerminal::FallbackStdout
            | &mut AnyTerminal::FallbackStderr => Ok(()),
        }
        .map_err(term_error_to_io_error)
    }

    fn start_timestamp(&mut self) -> io::Result<()> {
        self.start_level()
    }

    fn start_location(&mut self) -> io::Result<()> {
        self.start_level()
    }

    fn start_msg(&mut self) -> io::Result<()> {
        // msg is just like key
        //self.start_key()
        Ok(())
    }
}

fn term_error_to_io_error(e: term::Error) -> io::Error {
    match e {
        term::Error::Io(e) => e,
        e => io::Error::new(io::ErrorKind::Other, format!("term error: {}", e)),
    }
}

struct ColoredTermDecoratorBuilder {
    use_stderr: bool,
    color: Option<bool>,
}

impl ColoredTermDecoratorBuilder {
    fn new() -> Self {
        ColoredTermDecoratorBuilder {
            use_stderr: true,
            color: None,
        }
    }

    /// Force colored output
    fn force_color(mut self) -> Self {
        self.color = Some(true);
        self
    }

    /// Force plain output
    fn force_plain(mut self) -> Self {
        self.color = Some(false);
        self
    }

    /// Build `TermDecorator`
    ///
    /// Unlike `try_build` this it will fall-back to using plain `stdout`/`stderr`
    /// if it wasn't able to use terminal directly.
    fn build(self) -> ColoredTermDecorator {
        let io = if self.use_stderr {
            term::stderr()
                .map(|t| {
                    let supports_reset = t.supports_reset();
                    let supports_color = t.supports_color();
                    AnyTerminal::Stderr {
                        term: t,
                        supports_reset,
                        supports_color,
                    }
                })
                .unwrap_or(AnyTerminal::FallbackStderr)
        } else {
            term::stdout()
                .map(|t| {
                    let supports_reset = t.supports_reset();
                    let supports_color = t.supports_color();
                    AnyTerminal::Stdout {
                        term: t,
                        supports_reset,
                        supports_color,
                    }
                })
                .unwrap_or(AnyTerminal::FallbackStdout)
        };

        let use_color = self.color.unwrap_or_else(|| io.should_use_color());
        ColoredTermDecorator {
            term: RefCell::new(io),
            use_color,
        }
    }
}

struct FileAppender {
    path: PathBuf,
    file: Option<BufWriter<File>>,
    truncate: bool,
    written_size: u64,
    rotate_size: u64,
    rotate_keep: usize,
    rotate_compress: bool,
    wait_compression: Option<mpsc::Receiver<io::Result<()>>>,
    next_reopen_check: Instant,
    reopen_check_interval: Duration,
}

impl FileAppender {
    fn new<P: AsRef<Path>>(
        path: P,
        truncate: bool,
        rotate_size: u64,
        rotate_keep: usize,
        rotate_compress: bool,
    ) -> Self {
        FileAppender {
            path: path.as_ref().to_path_buf(),
            file: None,
            truncate: truncate,
            written_size: 0,
            rotate_size: rotate_size,
            rotate_keep: rotate_keep,
            rotate_compress: rotate_compress,
            wait_compression: None,
            next_reopen_check: Instant::now(),
            reopen_check_interval: Duration::from_millis(1000),
        }
    }

    fn reopen_if_needed(&mut self) -> io::Result<()> {
        let now = Instant::now();
        let path_exists = if now >= self.next_reopen_check {
            self.next_reopen_check = now + self.reopen_check_interval;
            self.path.exists()
        } else {
            true
        };

        if self.file.is_none() || !path_exists {
            let mut file_builder = OpenOptions::new();
            file_builder.create(true);
            if self.truncate {
                file_builder.truncate(true);
            }
            self.file = None;
            let file = file_builder
                .append(!self.truncate)
                .write(true)
                .open(&self.path)?;
            self.written_size = file.metadata()?.len();
            self.file = Some(BufWriter::new(file));
        }
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        {
            if let Some(ref mut rx) = self.wait_compression {
                use std::sync::mpsc::TryRecvError;
                match rx.try_recv() {
                    Err(TryRecvError::Empty) => {
                        return Ok(());
                    }
                    Err(TryRecvError::Disconnected) => {
                        let e = io::Error::new(
                            io::ErrorKind::Other,
                            "Log file compression thread aborted",
                        );
                        return Err(e);
                    }
                    Ok(result) => {
                        result?;
                    }
                }
            }
            self.wait_compression = None;
        }
        let _ = self.file.take();

        for i in (1..=self.rotate_keep).rev() {
            let from = self.rotated_path(i)?;
            let to = self.rotated_path(i + 1)?;
            if from.exists() {
                fs::rename(from, to)?;
            }
        }
        if self.path.exists() {
            let rotated_path = self.rotated_path(1)?;
            {
                if self.rotate_compress {
                    let (plain_path, temp_gz_path) =
                        self.rotated_paths_for_compression()?;
                    let (tx, rx) = mpsc::channel();

                    fs::rename(&self.path, &plain_path)?;
                    thread::spawn(move || {
                        let result = Self::compress(
                            plain_path,
                            temp_gz_path,
                            rotated_path,
                        );
                        let _ = tx.send(result);
                    });

                    self.wait_compression = Some(rx);
                } else {
                    fs::rename(&self.path, rotated_path)?;
                }
            }
        }

        let delete_path = self.rotated_path(self.rotate_keep + 1)?;
        if delete_path.exists() {
            fs::remove_file(delete_path)?;
        }

        self.written_size = 0;
        self.next_reopen_check = Instant::now();
        self.reopen_if_needed()?;
        Ok(())
    }

    fn rotated_path(&self, i: usize) -> io::Result<PathBuf> {
        let path = self.path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Non UTF-8 log file path: {:?}", self.path),
            )
        })?;
        {
            if self.rotate_compress {
                Ok(PathBuf::from(format!("{}.{}.gz", path, i)))
            } else {
                Ok(PathBuf::from(format!("{}.{}", path, i)))
            }
        }
    }

    fn rotated_paths_for_compression(&self) -> io::Result<(PathBuf, PathBuf)> {
        let path = self.path.to_str().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Non UTF-8 log file path: {:?}", self.path),
            )
        })?;
        Ok((
            PathBuf::from(format!("{}.1", path)),
            PathBuf::from(format!("{}.1.gz.temp", path)),
        ))
    }

    fn compress(
        input_path: PathBuf,
        temp_path: PathBuf,
        output_path: PathBuf,
    ) -> io::Result<()> {
        let mut input = File::open(&input_path)?;
        let mut temp = GzipEncoder::new(File::create(&temp_path)?)?;
        io::copy(&mut input, &mut temp)?;
        temp.finish().into_result()?;

        fs::rename(temp_path, output_path)?;
        fs::remove_file(input_path)?;
        Ok(())
    }
}

impl Write for FileAppender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.reopen_if_needed()?;
        let size = if let Some(ref mut f) = self.file {
            f.write(buf)?
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Cannot open file: {:?}", self.path),
            ));
        };

        self.written_size += size as u64;
        Ok(size)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(ref mut f) = self.file {
            f.flush()?;
        }
        if self.written_size >= self.rotate_size {
            self.rotate()?;
        }
        Ok(())
    }
}

fn timestamp_custom(io: &mut dyn io::Write) -> io::Result<()> {
    write!(io, "{}", chrono::Local::now().format(TIMESTAMP_FORMAT))
}

fn custom_print_msg_header(
    fn_timestamp: &dyn ThreadSafeTimestampFn<Output = io::Result<()>>,
    mut rd: &mut dyn RecordDecorator,
    record: &Record,
    use_file_location: bool,
) -> io::Result<bool> {
    rd.start_timestamp()?;
    fn_timestamp(&mut rd)?;

    rd.start_whitespace()?;
    write!(rd, " ")?;

    rd.start_level()?;
    write!(rd, "[{:^8}]", record.level().as_str())?;
    if use_file_location {
        rd.start_whitespace()?;
        write!(rd, " ")?;
        rd.start_location()?;
        write!(
            rd,
            "[{}:{}]",
            record.location().file,
            record.location().line,
        )?;
    }
    rd.start_whitespace()?;
    write!(rd, " ")?;

    rd.start_msg()?;
    let mut count_rd = CountingWriter::new(&mut rd);
    write!(count_rd, "{}", record.msg())?;
    Ok(count_rd.count() != 0)
}

fn __get_std_drain__(
    std_colored: bool,
    detail: bool,
) -> slog_term::FullFormatBuilder<ColoredTermDecorator> {
    let decorator_builder = ColoredTermDecorator::new();
    let decorator = if std_colored && cfg!(not(windows)) {
        decorator_builder.force_color().build()
    } else {
        decorator_builder.force_plain().build()
    };
    let mut __inter__ = slog_term::FullFormat::new(decorator)
        .use_custom_timestamp(timestamp_custom)
        .use_custom_header_print(custom_print_msg_header);
    if detail {
        __inter__ = __inter__.use_file_location();
    }
    __inter__
}

fn __get_file_drain__(
    logfile: &str,
    filesize: u64,
    detail: bool,
    keep_num: usize,
) -> slog_term::FullFormatBuilder<slog_term::PlainSyncDecorator<FileAppender>> {
    let adapter = FileAppender::new(
        logfile,
        false,
        filesize as u64 * MB,
        keep_num as usize,
        false,
    );
    let decorator_file = slog_term::PlainSyncDecorator::new(adapter);
    let mut __inter__ = slog_term::FullFormat::new(decorator_file)
        .use_custom_timestamp(timestamp_custom)
        .use_custom_header_print(custom_print_msg_header);
    if detail {
        __inter__ = __inter__.use_file_location();
    }
    __inter__
}

fn initlogger(
    std_enabled: bool,
    std_colored: bool,
    file_enabled: bool,
    logfile: &str,
    filesize: u64,
    log_level: Level,
    detail: bool,
    keep_num: usize,
    _compress: bool,
) -> slog::Logger {
    if file_enabled && std_enabled {
        let __file_wrapper__ =
            __get_file_drain__(logfile, filesize, detail, keep_num).build();
        let __std_wrapper__ =
            Mutex::new(__get_std_drain__(std_colored, detail).build());
        let __multi__ = slog::Duplicate::new(__std_wrapper__, __file_wrapper__);
        slog::Logger::root(__multi__.filter_level(log_level).fuse(), o!())
    } else if file_enabled && !std_enabled {
        let __file_wrapper__ =
            __get_file_drain__(logfile, filesize, detail, keep_num);
        slog::Logger::root(
            Mutex::new(__file_wrapper__.build().filter_level(log_level).fuse())
                .fuse(),
            o!(),
        )
    } else if !file_enabled && std_enabled {
        let __std_wrapper__ = __get_std_drain__(std_colored, detail);
        slog::Logger::root(
            Mutex::new(__std_wrapper__.build().filter_level(log_level).fuse())
                .fuse(),
            o!(),
        )
    } else {
        slog::Logger::root(slog::Discard, o!())
    }
}

pub fn setup_logger(
    std_enabled: bool,
    std_colored: bool,
    file_enabled: bool,
    logfile: &str,
    filesize: u64,
    log_level: Level,
    detail: bool,
    keep_num: usize,
    compress: bool,
) {
    let logger = initlogger(
        std_enabled,
        std_colored,
        file_enabled,
        logfile,
        filesize,
        log_level,
        detail,
        keep_num,
        compress,
    );
    let guard = slog_scope::set_global_logger(logger);
    slog_stdlog::init().unwrap();
    guard.cancel_reset();
}

fn notifylevel(lf: Vec<String>) {
    std::thread::spawn(move || {
        let (tx, rx) = mpsc::channel();
        let mut watcher: notify::RecommendedWatcher = notify::Watcher::new(
            tx,
            notify::Config::default()
                .with_poll_interval(Duration::from_secs(2))
                .with_compare_contents(true),
        )
        .unwrap();

        for f in lf {
            watcher
                .watch(Path::new(&f), notify::RecursiveMode::NonRecursive)
                .unwrap();
        }
        loop {
            match rx.recv() {
                Ok(_) => {
                    atomic_drain_switch();
                }
                Err(e) => error!("watch error: {:?}", e),
            }
        }
    });
}

pub fn setup_logger_with_cfg() {
    setup_logger(
        LOG_STD_ENABLE.lock().unwrap().to_owned(),
        LOG_STD_COLORED.lock().unwrap().to_owned(),
        LOG_FILE_ENABLE.lock().unwrap().to_owned(),
        LOG_PATH.lock().unwrap().as_str(),
        LOG_MAX_SIZE_MB.lock().unwrap().to_owned() as u64 * MB,
        LOG_LEVEL.lock().unwrap().to_owned(),
        LOG_VERBOSE.lock().unwrap().to_owned(),
        LOG_KEEP.lock().unwrap().to_owned() as usize,
        false,
    );
}

/// Setup logger with config file, and enable change the loglevel
/// in the runtime
///
/// # Example
///
/// ```
///
///    let def_log_conf = DefaultLogConfig {};
///    def_log_conf.set_default();
///
///    read_config("/tmp/example.toml", vec![Box::new(def_log_conf)]);
///    viperus::watch_all().unwrap();
///    benetnasch::logger::setup_logger_with_cfg_dynamic(vec!["/tmp/example.toml".to_owned()]);
/// ```
///
pub fn setup_logger_with_cfg_dynamic(loaded_configs: Vec<String>) {
    let drain = ATOMIC_DRAIN_SWITCH.drain().fuse();
    let drain = Mutex::new(drain)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "mutex error"))
        .fuse();
    let logger = slog::Logger::root(drain.fuse(), o!());
    let guard = slog_scope::set_global_logger(logger);
    slog_stdlog::init().unwrap();
    guard.cancel_reset();
    atomic_drain_switch();
    notifylevel(loaded_configs);
}

pub struct DefaultLogConfig();

impl config::ConfigTrait for DefaultLogConfig {
    fn set_default(&self) {
        INIT.call_once(|| {
            viperus::add_default("default.log_path", "logs".to_owned());
            viperus::add_default("default.log_keep", 7);
            viperus::add_default("default.log_max_size_mb", 100);
            viperus::add_default("default.log_level", 5);
            viperus::add_default("default.log_verbose", false);
            viperus::add_default("default.log_file_enable", false);
            viperus::add_default("default.log_std_enable", true);
            viperus::add_default("default.log_std_colored", true);
        });
    }

    fn overwrite(&self) {
        if let Some(overwrited) = viperus::get::<String>("default.log_path") {
            if let Ok(mut log_path) = LOG_PATH.lock() {
                *log_path = overwrited;
            }
        }
        if let Some(overwrited) = viperus::get::<i32>("default.log_keep") {
            if let Ok(mut log_keep) = LOG_KEEP.lock() {
                *log_keep = overwrited;
            }
        }
        if let Some(overwrited) = viperus::get::<i32>("default.log_max_size_mb")
        {
            if let Ok(mut log_max_size_mb) = LOG_MAX_SIZE_MB.lock() {
                *log_max_size_mb = overwrited;
            }
        }
        if let Some(overwrited) = viperus::get::<i32>("default.log_level") {
            if let Ok(mut log_level) = LOG_LEVEL.lock() {
                if overwrited <= 6 && overwrited > 0 {
                    *log_level =
                        Level::from_usize(overwrited as usize).unwrap();
                }
            }
        }
        if let Some(overwrited) = viperus::get::<bool>("default.log_verbose") {
            if let Ok(mut log_verbose) = LOG_VERBOSE.lock() {
                *log_verbose = overwrited;
            }
        }
        if let Some(overwrited) =
            viperus::get::<bool>("default.log_file_enable")
        {
            if let Ok(mut log_file_enable) = LOG_FILE_ENABLE.lock() {
                *log_file_enable = overwrited;
            }
        }
        if let Some(overwrited) = viperus::get::<bool>("default.log_std_enable")
        {
            if let Ok(mut log_std_enable) = LOG_STD_ENABLE.lock() {
                *log_std_enable = overwrited;
            }
        }
        if let Some(overwrited) =
            viperus::get::<bool>("default.log_std_colored")
        {
            if let Ok(mut log_std_colored) = LOG_STD_COLORED.lock() {
                *log_std_colored = overwrited;
            }
        }
    }
}

fn atomic_drain_switch() {
    SWITCH_SCHEDULED.swap(true, Ordering::Relaxed);
    ATOMIC_DRAIN_SWITCH_STATE.fetch_nand(true, Ordering::Relaxed);

    let log_level = match viperus::get::<i32>("default.log_level") {
        Some(level) if level > 0 && level <= 6 => {
            Level::from_usize(level as usize).unwrap()
        }
        _ => Level::Info,
    };

    let log_std_enabled =
        viperus::get::<bool>("default.log_std_enable").unwrap_or(true);
    let std_colored =
        viperus::get::<bool>("default.log_std_colored").unwrap_or(true);
    let file_log_enabled =
        viperus::get::<bool>("default.log_file_enable").unwrap_or(false);
    let logfile = viperus::get::<String>("default.log_path")
        .unwrap_or_else(|| "logs".to_owned());
    let filesize =
        viperus::get::<i32>("default.log_max_size_mb").unwrap_or(100);
    let keep_num = viperus::get::<i32>("default.log_keep").unwrap_or(7);
    let detail = viperus::get::<bool>("default.log_verbose").unwrap_or(false);

    let std_wrapper = __get_std_drain__(std_colored, detail);
    let file_wraper = __get_file_drain__(
        &logfile,
        filesize as u64 * MB,
        detail,
        keep_num as usize,
    );

    if log_std_enabled && file_log_enabled {
        let __std_wrapper__ = Mutex::new(std_wrapper.build());
        let __file_wrapper__ = file_wraper.build();
        let multi = slog::Duplicate::new(__std_wrapper__, __file_wrapper__);
        ATOMIC_DRAIN_SWITCH.set(
            Mutex::new(multi.filter_level(log_level).fuse()).map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "mutex error")
            }),
        )
    } else if log_std_enabled && !file_log_enabled {
        ATOMIC_DRAIN_SWITCH.set(
            Mutex::new(std_wrapper.build().filter_level(log_level).fuse())
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "mutex error")
                }),
        )
    } else if !log_std_enabled && file_log_enabled {
        ATOMIC_DRAIN_SWITCH.set(
            Mutex::new(file_wraper.build().filter_level(log_level).fuse())
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "mutex error")
                }),
        )
    }
}
