use std::process::Stdio;

extern crate tokio;

use crate::{error, info};

pub async fn linux_commands_with_bash_env(cmd: &str) -> (bool, &str, &str) {
    let res = tokio::process::Command::new("bash")
        .arg("-c")
        .arg(cmd)
        .output()
        .await
        .unwrap();
    let std_out = res.stdout.leak();
    let std_err = res.stderr.leak();
    return (
        res.status.success(),
        std::str::from_utf8(std_out).unwrap(),
        std::str::from_utf8(std_err).unwrap(),
    );
}

pub async fn linux_commands<'a>(cmds: Vec<(&str, Vec<&str>)>) -> (bool, &'a str, &'a str) {
    let pipeline_size = cmds.len() - 1;
    if 0 == pipeline_size {
        let (cmd, args) = &cmds[0];
        let linux_command = tokio::process::Command::new(cmd)
            .args(args.clone())
            .output();
        match linux_command.await {
            Ok(result) => {
                if result.status.success() {
                    info!("Sucess to execute the command {} with args {:?}", cmd, args);
                    let std_out = result.stdout.leak();
                    let std_err = result.stderr.leak();
                    return (
                        result.status.success(),
                        std::str::from_utf8(std_out).unwrap(),
                        std::str::from_utf8(std_err).unwrap(),
                    );
                } else {
                    error!(
                        "Failed to execute the command {}: {}",
                        cmd,
                        String::from_utf8(result.stderr).unwrap()
                    );
                    return (false, "", "");
                }
            }
            Err(err) => {
                error!(
                    "Cannot execute the command {} with args {:?} : {:?}",
                    cmd, args, err
                );
                return (false, "", "");
            }
        }
    }

    let mut stdin_pipe: Vec<Stdio> = Vec::with_capacity(1);
    let mut handler: Vec<_> = vec![];
    let mut handler_rest: Vec<_> = vec![];
    let mut handler_last: Vec<_> = vec![];
    for (idx, (c_cmd, c_args)) in cmds.iter().enumerate() {
        if 0 == idx {
            match tokio::process::Command::new(c_cmd)
                .args(c_args)
                .stdout(Stdio::piped())
                .spawn()
            {
                Ok(mut begin) => {
                    stdin_pipe.push(begin.stdout.take().unwrap().try_into().unwrap());
                    handler.push(begin);
                }
                Err(err) => {
                    error!(
                        "Cannot spawn the command `{}` with args {:?}: {:?}",
                        c_cmd, c_args, err
                    );
                    return (false, "", "");
                }
            }
        } else {
            match tokio::process::Command::new(c_cmd)
                .args(c_args)
                .stdin(stdin_pipe.pop().unwrap())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
            {
                Ok(mut child) => {
                    if idx != pipeline_size {
                        stdin_pipe.push(child.stdout.take().unwrap().try_into().unwrap());
                        handler_rest.push(child);
                    } else {
                        handler_last.push(child);
                    }
                }
                Err(err) => {
                    error!(
                        "Cannot spawn the child command `{}` with args {:?}: {:?}",
                        c_cmd, c_args, err
                    );
                    return (false, "", "");
                }
            }
        }
    }

    match handler.pop().unwrap().wait().await {
        Ok(_) => {
            for handle in handler_rest {
                match handle.wait_with_output().await {
                    Ok(tmp) => {
                        if !tmp.status.success() {
                            error!(
                                "Failed to execute command: {}",
                                std::str::from_utf8(&tmp.stderr).unwrap()
                            );
                            return (false, "", "");
                        }
                    }
                    Err(err) => {
                        error!("Cannot execute the child command:{:?}", err);
                        return (false, "", "");
                    }
                }
            }

            match handler_last.pop().unwrap().wait_with_output().await {
                Ok(latest) => {
                    let std_out = latest.stdout.leak();
                    let std_err = latest.stderr.leak();
                    return (
                        latest.status.success(),
                        std::str::from_utf8(std_out).unwrap(),
                        std::str::from_utf8(std_err).unwrap(),
                    );
                }
                Err(err) => {
                    error!("Cannot execute last the command:{:?}", err);
                    (false, "", "")
                }
            }
        }
        Err(err) => {
            error!("Cannot execute the command:{:?}", err);
            (false, "", "")
        }
    }
}
