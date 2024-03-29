extern crate tokio;
#[macro_use]
extern crate benetnasch;

//#[cfg(all(target_family = "unix", feature="asyncudev", not(target_os = "windows")))]
use benetnasch::udevs;
use benetnasch::shell;
#[cfg(all(target_family = "unix", not(target_os = "windows")))]
use std::thread;

fn hello() {
    info!("hello world");
}

fn goodbye() {
    info!("goodbye");
}

fn main() {
    benetnasch::logger::setup_logger(
        true,
        true,
        false,
        "",
        0,
        benetnasch::logger::Level::Info,
        false,
        0,
        false,
    );
    info!("hello");
    wait!(hello, goodbye);
    trace!("hello trace");

    #[cfg(all(target_family = "unix", feature="asyncudev", not(target_os = "windows")))]
    if let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(32);

        let coloned = rt.handle().clone();
        let handler = thread::spawn(move || {
            coloned.block_on(async {
                udevs::udev_monitor(sender, "block", "disk", "ID_MODEL_ID", "0749").await;
            });
        });

        rt.block_on(async {
            let (_, fdisk_result, _) =
                shell::linux_commands(vec![("cat", vec!["/opt/workrusts/benetnasch/Cargo.toml"])])
                    .await;
            info!("The command result is \n{}\n", fdisk_result);
            while let Some(res) = receiver.recv().await {
                info!("The device inserted is: {}", res);
            }
        });

        if let Err(error) = handler.join() {
            info!("Cannot start the thread:{:?}", error);
        }
    }
}
