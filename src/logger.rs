use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Mutex, Once};
use std::thread;
use std::time::{Duration, Instant};
use std::u64;

use libflate::gzip::Encoder as GzipEncoder;
use slog::{Drain, Record};
use slog_term::{CountingWriter, RecordDecorator, ThreadSafeTimestampFn};

pub use slog::Level;

use crate::config;

const TIMESTAMP_FORMAT: &str = "%Y-%m-%d %H:%M:%S%.9f";

pub const BITE: u64 = 1;
pub const KB: u64 = BITE * 1024;
pub const MB: u64 = KB * 1024;
pub const GB: u64 = MB * 1024;

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
                    let (plain_path, temp_gz_path) = self.rotated_paths_for_compression()?;
                    let (tx, rx) = mpsc::channel();

                    fs::rename(&self.path, &plain_path)?;
                    thread::spawn(move || {
                        let result = Self::compress(plain_path, temp_gz_path, rotated_path);
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

    fn compress(input_path: PathBuf, temp_path: PathBuf, output_path: PathBuf) -> io::Result<()> {
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

fn initlogger(
    std_enabled: bool,
    file_enabled: bool,
    logfile: &str,
    filesize: u64,
    log_level: Level,
    detail: bool,
    keep_num: usize,
    compress: bool,
) -> slog::Logger {
    fn __get_std_drain__<D: Drain>(
        log_level: Level,
        detail: bool,
    ) -> slog::LevelFilter<std::sync::Mutex<slog_term::FullFormat<slog_term::TermDecorator>>> {
        let decorator = slog_term::TermDecorator::new().build();
        let mut iner = slog_term::FullFormat::new(decorator)
            .use_custom_timestamp(timestamp_custom)
            .use_custom_header_print(custom_print_msg_header);
        if detail {
            iner = iner.use_file_location();
        }
        let drain = Mutex::new(iner.build());
        slog::LevelFilter::new(drain, log_level)
    }

    fn __get_file_drain__<D: Drain>(
        logfile: &str,
        filesize: u64,
        log_level: Level,
        detail: bool,
        keep_num: usize,
        compress: bool,
    ) -> slog::LevelFilter<slog_term::FullFormat<slog_term::PlainSyncDecorator<FileAppender>>> {
        let adapter = FileAppender::new(logfile, false, filesize, keep_num, compress);
        let decorator_file = slog_term::PlainSyncDecorator::new(adapter);
        let mut file_iner = slog_term::FullFormat::new(decorator_file)
            .use_custom_timestamp(timestamp_custom)
            .use_custom_header_print(custom_print_msg_header);
        if detail {
            file_iner = file_iner.use_file_location();
        }
        let drain_file = file_iner.build();
        slog::LevelFilter::new(drain_file, log_level)
    }

    if file_enabled && std_enabled {
        slog::Logger::root(
            slog::Duplicate::new(
                __get_std_drain__::<
                    std::sync::Mutex<slog_term::FullFormat<slog_term::TermDecorator>>,
                >(log_level, detail),
                __get_file_drain__::<
                    slog_term::FullFormat<slog_term::PlainSyncDecorator<FileAppender>>,
                >(logfile, filesize, log_level, detail, keep_num, compress),
            )
            .fuse(),
            o!(),
        )
    } else if file_enabled && !std_enabled {
        slog::Logger::root(
            __get_file_drain__::<slog_term::FullFormat<slog_term::PlainSyncDecorator<FileAppender>>>(
                logfile, filesize, log_level, detail, keep_num, compress,
            )
            .fuse(),
            o!(),
        )
    } else if !file_enabled && std_enabled {
        slog::Logger::root(
            __get_std_drain__::<std::sync::Mutex<slog_term::FullFormat<slog_term::TermDecorator>>>(
                log_level, detail,
            )
            .fuse(),
            o!(),
        )
    } else {
        slog::Logger::root(slog::Discard, o!())
    }
}

pub fn setup_logger(
    std_enabled: bool,
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

pub fn setup_logger_with_cfg() {
    setup_logger(
        LOG_STD_ENABLE.lock().unwrap().to_owned(),
        LOG_FILE_ENABLE.lock().unwrap().to_owned(),
        LOG_PATH.lock().unwrap().as_str(),
        LOG_MAX_SIZE_MB.lock().unwrap().to_owned() as u64 * MB,
        LOG_LEVEL.lock().unwrap().to_owned(),
        LOG_VERBOSE.lock().unwrap().to_owned(),
        LOG_KEEP.lock().unwrap().to_owned() as usize,
        false,
    );
}

static INIT: Once = Once::new();

lazy_static! {
    pub static ref LOG_PATH: Mutex<String> = Mutex::new(String::from("logs"));
    pub static ref LOG_KEEP: Mutex<i32> = Mutex::new(0);
    pub static ref LOG_MAX_SIZE_MB: Mutex<i32> = Mutex::new(100);
    pub static ref LOG_LEVEL: Mutex<Level> = Mutex::new(Level::Debug);
    pub static ref LOG_VERBOSE: Mutex<bool> = Mutex::new(false);
    pub static ref LOG_FILE_ENABLE: Mutex<bool> = Mutex::new(false);
    pub static ref LOG_STD_ENABLE: Mutex<bool> = Mutex::new(true);
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
        if let Some(overwrited) = viperus::get::<i32>("default.log_max_size_mb") {
            if let Ok(mut log_max_size_mb) = LOG_MAX_SIZE_MB.lock() {
                *log_max_size_mb = overwrited;
            }
        }
        if let Some(overwrited) = viperus::get::<i32>("default.log_level") {
            if let Ok(mut log_level) = LOG_LEVEL.lock() {
                if overwrited <= 6 && overwrited > 0 {
                    *log_level = Level::from_usize(overwrited as usize).unwrap();
                }
            }
        }
        if let Some(overwrited) = viperus::get::<bool>("default.log_verbose") {
            if let Ok(mut log_verbose) = LOG_VERBOSE.lock() {
                *log_verbose = overwrited;
            }
        }
        if let Some(overwrited) = viperus::get::<bool>("default.log_file_enable") {
            if let Ok(mut log_file_enable) = LOG_FILE_ENABLE.lock() {
                *log_file_enable = overwrited;
            }
        }
        if let Some(overwrited) = viperus::get::<bool>("default.log_std_enable") {
            if let Ok(mut log_std_enable) = LOG_STD_ENABLE.lock() {
                *log_std_enable = overwrited;
            }
        }
    }
}
