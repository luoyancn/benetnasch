use std::{convert::TryInto, ffi::OsStr};

use futures_util::stream::StreamExt;
use tokio_udev::{AsyncMonitorSocket, EventType, MonitorBuilder};

use crate::error;

/// Create a udev add/insert event monitor, and return the udev device path
/// through tokio mpsc channel
///
/// # Examples
///
/// ```
/// if let Ok(rt) = tokio::runtime::Builder::new_multi_thread()
///     .enable_all()
///     .build()
/// {
///     let (sender, mut receiver) = tokio::sync::mpsc::channel(32);
///     let coloned = rt.handle().clone();
///     let handler = thread::spawn(move || {
///         coloned.block_on(async {
///             benetnasch::udevs::udev_monitor(sender, "block", "disk", "ID_MODEL_ID", "0749")
///                 .await;
///         });
///     });
///     rt.block_on(async {
///         while let Some(res) = receiver.recv().await {
///             info!("The device inserted is: {}", res);
///         }
///     });
///     if let Err(error) = handler.join() {
///         info!("Cannot start the thread:{:?}", error);
///     }
/// }
/// ```
///
pub async fn udev_monitor(
    sender: tokio::sync::mpsc::Sender<String>,
    subsystem: &str,
    devtype: &str,
    dev_property: &str,
    dev_property_value: &str,
) {
    /*
    if let Ok(__builder__) = MonitorBuilder::new() {
        if let Ok(_builder_) = __builder__.match_subsystem_devtype(subsystem, devtype) {
            if let Ok(__socket__) = _builder_.listen() {
                if let Ok(monitor) = TryInto::<AsyncMonitorSocket>::try_into(__socket__) {
                    monitor
                        .for_each(|event| async {
                            if let Ok(event) = event {
                                if EventType::Add == event.event_type()
                                    && Some(OsStr::new(dev_property_value))
                                        == event.property_value(dev_property)
                                {
                                    let devnode = event.devnode().unwrap();
                                    if sender
                                        .send(String::from(devnode.to_str().unwrap()))
                                        .await
                                        .is_ok()
                                    {}
                                }
                            }
                        })
                        .await
                }
            }
        }
    }
    */

    match MonitorBuilder::new() {
        Ok(__builder__) => match __builder__.match_subsystem_devtype(subsystem, devtype) {
            Ok(_builder_) => match _builder_.listen() {
                Ok(__socket__) => match TryInto::<AsyncMonitorSocket>::try_into(__socket__) {
                    Ok(monitor) => {
                        monitor
                            .for_each(|event| async {
                                if let Ok(event) = event {
                                    if EventType::Add == event.event_type()
                                        && Some(OsStr::new(dev_property_value))
                                            == event.property_value(dev_property)
                                    {
                                        let devnode = event.devnode().unwrap();
                                        if sender
                                            .send(String::from(devnode.to_str().unwrap()))
                                            .await
                                            .is_ok()
                                        {}
                                    }
                                }
                            })
                            .await
                    }
                    Err(error) => {
                        error!("Cannot create the AsyncMonitorSocket: {:?}", error)
                    }
                },
                Err(error) => error!("Cannot create the MonitorSocket: {:?}", error),
            },
            Err(error) => error!(
                "Cannot Add filter for device {}, {}, {:?}",
                subsystem, devtype, error
            ),
        },
        Err(error) => error!("Cannot create builder: {:?}", error),
    }
}
