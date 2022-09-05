use std::path::PathBuf;
pub enum ValidValue<'a> {
    Str(&'a str),
    Int(i32),
    Bool(bool),
}

pub type ConfigMap<'a> = std::collections::HashMap<&'a str, ValidValue<'a>>;

/// Trait of set the (default or overwrite) global configurations from toml file
///
/// The implements must be include the set_default and overwrite method
/// Notice: This Trait is recommend to use with the crate named viperus
/// (https://crates.io/crates/viperus)
///
/// An valid implement of this Trait maybe like follows:
///
/// # Examples
///
/// ```
/// static INIT: Once = Once::new();
///
/// lazy_static! {
///     pub static ref LOG_STD_ENABLE: Mutex<bool> = Mutex::new(true);
/// }
///
/// pub struct DefaultLogConfig();
///
/// impl config::ConfigTrait for DefaultLogConfig {
///     fn set_default(&self) {
///         INIT.call_once(|| {
///             viperus::add_default("default.log_std_enable", true);
///         });
///     }
///
///     fn overwrite(&self) {
///         if let Some(overwrited) = viperus::get::<bool>("default.log_std_enable") {
///             if let Ok(mut log_std_enable) = LOG_STD_ENABLE.lock() {
///                 *log_std_enable = overwrited;
///             }
///         }
///     }
/// }
/// ```
///
pub trait ConfigTrait {
    fn set_default(&self);
    fn overwrite(&self);
}

/// Read the toml config file and overwrite the global configurations
///
/// This function is recommend to use with the implements of ConfigTrait
///
/// # Examples
///
/// ```
/// let def_log_conf = DefaultLogConfig {};
/// def_log_conf.set_default();
/// read_config("/tmp/example.toml", vec![Box::new(def_log_conf)]);
/// setup_logger(LOG_STD_ENABLE.lock().unwrap().to_owned())
/// ```
///
pub fn read_config(config_file: &str, configs: Vec<Box<dyn ConfigTrait>>) {
    match PathBuf::from(config_file).canonicalize() {
        Err(err) => {
            println!(
                "Cannot read the config file {}:{:?}, Use default config values instead",
                config_file, err
            );
            return;
        }

        Ok(config_file_buf) => {
            if let Err(err) = viperus::load_file(
                config_file_buf.as_os_str().to_str().unwrap(),
                viperus::Format::TOML,
            ) {
                println!(
                    "Cannot read the config file {}:{:?}, Use default config values instead",
                    config_file, err
                );
                return;
            }
        }
    }

    for config in configs {
        config.overwrite();
    }
}
