#![allow(unknown_lints)]
#![recursion_limit = "1024"]
#![cfg_attr(feature = "nightly", feature(start))]
#![cfg_attr(feature = "nightly", feature(alloc_system))]
#![allow(unused)]
extern crate caps;
#[macro_use]
extern crate clap;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate lazy_static;
extern crate libc;
#[macro_use]
extern crate log;
extern crate nix;
extern crate num_traits;
extern crate prctl;
#[macro_use]
extern crate scopeguard;
extern crate oci;
extern crate seccomp_sys;

pub mod capabilities;
pub mod cgroups;
pub mod errors;
pub mod logger;
pub mod mounts;
pub mod nix_ext;
pub mod seccomp;
pub mod selinux;
pub mod signals;
pub mod sync;

use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use errors::*;
use lazy_static::initialize;
use nix::errno::Errno;
use nix::fcntl::{open, OFlag};
use nix::poll::{poll, EventFlags, PollFd};
use nix::sched::{setns, unshare, CloneFlags};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::socket::{accept, bind, connect, listen, sendmsg, socket};
use nix::sys::socket::{AddressFamily, SockAddr, SockFlag, SockType, UnixAddr};
use nix::sys::socket::{ControlMessage, MsgFlags};
use nix::sys::stat::{fstat, Mode};
use nix::unistd::{chdir, execvp, getpid, sethostname, setresgid, setresuid};
use nix::unistd::{close, dup2, fork, pipe2, read, setsid, write, ForkResult};

use nix_ext::{clearenv, putenv, setgroups, setrlimit};
use oci::{Linux, LinuxIDMapping, LinuxRlimit, Spec};
use oci::{LinuxDevice, LinuxDeviceType};
use std::collections::HashMap;
use std::ffi::CString;
use std::fs::{canonicalize, create_dir, create_dir_all, remove_dir_all, File};
use std::io::{Read, Write};
use std::os::unix::fs::symlink;
use std::os::unix::io::{FromRawFd, RawFd};
use std::result::Result as StdResult;
use sync::Cond;
use nix::unistd::Pid;
use pipe::load_console_sockets;

lazy_static! {
    pub static ref DEFAULT_DEVICES: Vec<LinuxDevice> = {
        let mut v = Vec::new();
        v.push(LinuxDevice {
            path: "/dev/null".to_string(),
            typ: LinuxDeviceType::c,
            major: 1,
            minor: 3,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice {
            path: "/dev/zero".to_string(),
            typ: LinuxDeviceType::c,
            major: 1,
            minor: 5,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice {
            path: "/dev/full".to_string(),
            typ: LinuxDeviceType::c,
            major: 1,
            minor: 7,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice {
            path: "/dev/tty".to_string(),
            typ: LinuxDeviceType::c,
            major: 5,
            minor: 0,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice {
            path: "/dev/urandom".to_string(),
            typ: LinuxDeviceType::c,
            major: 1,
            minor: 9,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v.push(LinuxDevice {
            path: "/dev/random".to_string(),
            typ: LinuxDeviceType::c,
            major: 1,
            minor: 8,
            file_mode: Some(0o066),
            uid: None,
            gid: None,
        });
        v
    };
}

lazy_static! {
    pub static ref NAMESPACES: HashMap<CloneFlags, &'static str> = {
        let mut result = HashMap::new();
        // 隔离 System V IPC 和 POSIX 消息队列
        result.insert(CloneFlags::CLONE_NEWIPC, "ipc");
        // 隔离主机名和域名
        result.insert(CloneFlags::CLONE_NEWUTS, "uts");
        // 隔离网络资源
        result.insert(CloneFlags::CLONE_NEWNET, "net");
        // 隔离进程 ID
        result.insert(CloneFlags::CLONE_NEWPID, "pid");
        // 隔离文件系统挂载点
        result.insert(CloneFlags::CLONE_NEWNS, "mnt");
        // 资源限制
        result.insert(CloneFlags::CLONE_NEWCGROUP, "cgroup");
        // 隔离用户 ID 和组 ID
        result.insert(CloneFlags::CLONE_NEWUSER, "user");
        result
    };
}

pub const CONFIG: &'static str = "config.json";
pub const INIT_PID: &'static str = "init.pid";
pub const PROCESS_PID: &'static str = "process.pid";
pub const TSOCKETFD: RawFd = 9;

/// Prctl interface with error_china.
pub mod process {
    use errors::*;
    use capabilities;
    use nix::unistd::{Gid, Pid, Uid};
    use nix::unistd::{chdir, execvp, getpid, sethostname, setresgid, setresuid};

    #[cfg(feature = "nightly")]
    pub fn set_name(name: &str) -> Result<()> {
        match prctl::set_name(name) {
            Err(i) => bail!(format!("set name returned {}", i)),
            Ok(_) => (),
        };
        unsafe {
            let init =
                std::ffi::CString::new(name).chain_err(|| "invalid process name")?;
            let len = std::ffi::CStr::from_ptr(*ARGV as *const u8).to_bytes().len();
            // after fork, ARGV points to the thread's local
            // copy of arg0.
            libc::strncpy(*ARGV, init.as_ptr(), len);
            // no need to set the final character to 0 since
            // the initial string was already null-terminated.
        }
        Ok(())
    }

    #[cfg(not(feature = "nightly"))]
    pub fn set_name(name: &str) -> Result<()> {
        if let Err(e) = prctl::set_name(name) {
            bail!(format!("set name returned {}", e));
        };
        Ok(())
    }

    pub fn setid(uid: Uid, gid: Gid) -> Result<()> {
        // set uid/gid
        if let Err(e) = prctl::set_keep_capabilities(true) {
            bail!(format!("set keep capabilities returned {}", e));
        };
        {
            setresgid(gid, gid, gid)?;
        }
        {
            setresuid(uid, uid, uid)?;
        }
        // if we change from zero, we lose effective caps
        if uid != Uid::from_raw(0) {
            capabilities::reset_effective()?;
        }
        if let Err(e) = prctl::set_keep_capabilities(false) {
            bail!(format!("set keep capabilities returned {}", e));
        };
        Ok(())
    }

    use nix::errno::Errno;
    use nix::sys::wait::WaitPidFlag;
    use nix::sys::wait::{waitpid, WaitStatus};

    /// Get children status
    pub fn reap_children() -> Result<(WaitStatus)> {
        let mut result = WaitStatus::Exited(Pid::from_raw(0), 0);
        loop {
            match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                Err(e) => {
                    if e != ::nix::Error::Sys(Errno::ECHILD) {
                        return Err(e).chain_err(|| "could not waitpid")?;
                    }
                    // ECHILD means no processes are left
                    break;
                }
                Ok(s) => {
                    result = s;
                    if result == WaitStatus::StillAlive {
                        break;
                    }
                }
            }
        }
        Ok(result)
    }

    use signals::*;
    use nix::sys::signal::{SigSet, Signal};

    pub fn exit(exit_code: i8, sig: Option<Signal>) -> Result<()> {
        match sig {
            Some(signal) => {
                debug!("child exited with signal {:?}", signal);

                raise_for_parent(signal)?;
                // wait for normal signal handler to deal with us
                loop {
                    wait_for_signal()?;
                }
            }
            None => {
                debug!("child exited with code {:?}", exit_code);
                std::process::exit(exit_code as i32)
            }
        }
    }

    /// Wait on all children, but only return if we match child.
    pub fn wait_for_child(child: Pid) -> Result<(i32, Option<Signal>)> {
        loop {
            // wait on all children, but only return if we match child.
            let result = match waitpid(Pid::from_raw(-1), None) {
                Err(::nix::Error::Sys(errno)) => {
                    // ignore EINTR as it gets sent when we get a SIGCHLD
                    if errno == Errno::EINTR {
                        continue;
                    }
                    let msg = format!("could not waitpid on {}", child);
                    return Err(::nix::Error::Sys(errno)).chain_err(|| msg)?;
                }
                Err(e) => {
                    return Err(e)?;
                }
                Ok(s) => s,
            };
            match result {
                WaitStatus::Exited(pid, code) => {
                    if child != Pid::from_raw(-1) && pid != child {
                        continue;
                    }
                    reap_children()?;
                    return Ok((code as i32, None));
                }
                WaitStatus::Signaled(pid, signal, _) => {
                    if child != Pid::from_raw(-1) && pid != child {
                        continue;
                    }
                    reap_children()?;
                    return Ok((0, Some(signal)));
                }
                _ => {}
            };
        }
    }

    use nix::unistd::{fork, ForkResult};

    /// do the first fork right away because we must fork before we can
    /// mount proc. The child will be in the pid namespace.
    pub fn fork_enter_pid(init: bool, daemonize: bool) -> Result<()> {
        // do the first fork right away because we must fork before we can
        // mount proc. The child will be in the pid namespace.
        match fork()? {
            ForkResult::Child => {
                if init {
                    set_name("rc-init")?;
                } else if daemonize {
                    // NOTE: if we are daemonizing non-init, we need an additional
                    //       fork to allow process to be reparented to init
                    match fork()? {
                        ForkResult::Child => {
                            // child continues
                        }
                        ForkResult::Parent { .. } => {
                            debug!("third parent exiting for daemonization");
                            exit(0, None)?;
                        }
                    }
                }
                // child continues
            }
            ForkResult::Parent { .. } => {
                debug!("second parent exiting");
                exit(0, None)?;
            }
        };
        Ok(())
    }

    use std::os::unix::io::RawFd;

    /// Fork again so child becomes pid 2
    pub fn fork_final_child(wfd: RawFd, tfd: RawFd, daemonize: bool) -> Result<()> {
        // fork again so child becomes pid 2
        match fork()? {
            ForkResult::Child => {
                // child continues on
                Ok(())
            }
            ForkResult::Parent { .. } => {
                if tfd != -1 {
                    close(tfd).chain_err(|| "could not close trigger fd")?;
                }
                do_init(wfd, daemonize)?;
                Ok(())
            }
        }
    }

    use cgroups;
    use pipe::*;
    use runtime::*;
    use sync::Cond;
    use oci::{Linux, LinuxRlimit};
    use nix::unistd::pipe2;
    use std::fs::File;
    use nix_ext::setrlimit;
    use nix::sched::unshare;
    use std::io::prelude::*;
    use oci::{Spec, Hooks, Root};
    use nix::fcntl::OFlag;
    use nix::sched::CloneFlags;

    ///
    pub fn fork_first(
        id: &str,
        init_pid: Pid,
        enter_pid: bool,
        init_only: bool,
        daemonize: bool,
        userns: bool,
        linux: &Linux,
        rlimits: &[LinuxRlimit],
        cpath: &str,
        spec: &Spec,
    ) -> Result<(Pid, RawFd)> {
        fork_first_without_spec(id, init_pid, enter_pid, init_only, daemonize, userns, linux,
                                rlimits, cpath, &spec.hooks, &spec.root.path)
    }

    use oci::State;

    pub fn fork_first_without_spec(
        id: &str,
        init_pid: Pid,
        enter_pid: bool,
        init_only: bool,
        daemonize: bool,
        userns: bool,
        linux: &Linux,
        rlimits: &[LinuxRlimit],
        cpath: &str,
        hooks: &Option<Hooks>,
        root: &String,
    ) -> Result<(Pid, RawFd)> {
        let ccond = Cond::new().chain_err(|| "failed to create cond")?;
        let pcond = Cond::new().chain_err(|| "failed to create cond")?;
        let (rfd, wfd) =
            pipe2(OFlag::O_CLOEXEC).chain_err(|| "failed to create pipe")?;
        match fork()? {
            ForkResult::Child => {
                close(rfd).chain_err(|| "could not close rfd")?;
                set_name("rc-user")?;

                // set oom_score_adj
                if let Some(ref r) = linux.resources {
                    if let Some(adj) = r.oom_score_adj {
                        let mut f = File::create("/proc/self/oom_score_adj")?;
                        f.write_all(adj.to_string().as_bytes())?;
                    }
                }

                // set rlimits (before entering user ns)
                for rlimit in rlimits.iter() {
                    setrlimit(rlimit.typ as i32, rlimit.soft, rlimit.hard)?;
                }

                if userns {
                    unshare(CloneFlags::CLONE_NEWUSER)
                        .chain_err(|| "failed to unshare user")?;
                }
                ccond.notify().chain_err(|| "failed to notify parent")?;
                pcond.wait().chain_err(|| "failed to wait for parent")?;
                if userns {
                    setid(Uid::from_raw(0), Gid::from_raw(0))
                        .chain_err(|| "failed to setid")?;
                }
                // child continues on
            }
            ForkResult::Parent { child } => {
                close(wfd).chain_err(|| "could not close wfd")?;
                ccond.wait().chain_err(|| "failed to wait for child")?;
                if userns {
                    // write uid/gid map
                    write_mappings(
                        &format!("/proc/{}/uid_map", child),
                        &linux.uid_mappings,
                    ).chain_err(|| "failed to write uid mappings")?;
                    write_mappings(
                        &format!("/proc/{}/gid_map", child),
                        &linux.gid_mappings,
                    ).chain_err(|| "failed to write gid mappings")?;
                }
                // setup cgroups
                let schild = child.to_string();
                cgroups::apply(&linux.resources, &schild, cpath)?;
                // notify child
                pcond.notify().chain_err(|| "failed to notify child")?;

                // NOTE: if we are entering pid, we wait for the next
                //       child to exit so we can adopt its grandchild
                if enter_pid {
                    let (_, _) = wait_for_child(child)?;
                }
                let mut pid = Pid::from_raw(-1);
                wait_for_pipe_zero(rfd, -1)?;
                // get the actual pid of the process from cgroup
                let procs = cgroups::get_procs("cpuset", cpath);
                for p in procs {
                    if p != init_pid {
                        debug!("actual pid of child is {}", p);
                        pid = p;
                        break;
                    }
                }
                if !init_only {
                    debug!("running prestart hooks");
                    if let Some(ref hooks) = hooks {
                        let st = state(id, "running", init_pid, &root);
                        for h in &hooks.prestart {
                            execute_hook(h, &st)
                                .chain_err(|| "failed to execute prestart hooks")?;
                        }
                    }
                    wait_for_pipe_zero(rfd, -1)?;
                    debug!("running poststart hooks");
                    if let Some(ref hooks) = hooks {
                        let st = state(id, "running", init_pid, &root);
                        for h in &hooks.poststart {
                            if let Err(e) = execute_hook(h, &st) {
                                warn!("failed to execute poststart hook: {}", e);
                            }
                        }
                    }
                }
                if daemonize {
                    debug!("first parent exiting for daemonization");
                    return Ok((pid, wfd));
                }
                signals::pass_signals(pid)?;
                let sig = wait_for_pipe_sig(rfd, -1)?;
                let (exit_code, _) = wait_for_child(pid)?;
                cgroups::remove(cpath)?;
                exit(exit_code as i8, sig)?;
            }
        };
        Ok((Pid::from_raw(-1), wfd))
    }


    use signals;
    use nix::unistd::write;
    use nix::unistd::close;
    use execute_hook;
    use state;

    pub fn do_init(wfd: RawFd, daemonize: bool) -> Result<()> {
        if daemonize {
            close(wfd).chain_err(|| "could not close wfd")?;
        }
        let s = SigSet::all();
        s.thread_block()?;
        loop {
            let signal = s.wait()?;
            if signal == Signal::SIGCHLD {
                debug!("got a sigchld");
                let mut sig = None;
                let code;
                match reap_children()? {
                    WaitStatus::Exited(_, c) => code = c as i32,
                    WaitStatus::Signaled(_, s, _) => {
                        sig = Some(s);
                        code = 128 + s as libc::c_int;
                    }
                    _ => continue,
                };
                if !daemonize {
                    if let Some(s) = sig {
                        // raising from pid 1 doesn't work as you would
                        // expect, so write signal to pipe.
                        let data: &[u8] = &[s as u8];
                        write(wfd, data).chain_err(|| "failed to write signal")?;
                    }
                    close(wfd).chain_err(|| "could not close wfd")?;
                }
                debug!("all children terminated, exiting with {}", code);
                std::process::exit(code)
            }
            debug!("passing {:?} on to children", signal);
            if let Err(e) = signals::signal_process(Pid::from_raw(-1), signal) {
                warn!("failed to signal children, {}", e);
            }
        }
    }
}

/// Pipe wrapper with error_chain.
pub mod pipe {
    use errors::*;
    use signals::*;
    use nix::errno::Errno;
    use nix::poll::{poll, EventFlags, PollFd};
    use nix::sys::signal::{SigSet, Signal};
    use std::os::unix::io::{FromRawFd, RawFd};
    use nix::fcntl::{open, OFlag};
    use nix::sys::stat::{fstat, Mode};
    use nix::unistd::{close, read, dup2};

    pub fn wait_for_pipe_sig(rfd: RawFd, timeout: i32) -> Result<Option<Signal>> {
        let result = wait_for_pipe_vec(rfd, timeout, 1)?;
        if result.len() < 1 {
            return Ok(None);
        }
        let chain = || "invalid signal";
        let s = Signal::from_c_int(result[0] as i32).chain_err(chain)?;
        Ok(Some(s))
    }

    pub fn wait_for_pipe_zero(rfd: RawFd, timeout: i32) -> Result<()> {
        let result = wait_for_pipe_vec(rfd, timeout, 1)?;
        if result.len() < 1 {
            let msg = "file descriptor closed unexpectedly".to_string();
            return Err(ErrorKind::PipeClosed(msg).into());
        }
        if result[0] != 0 {
            let msg = format! {"got {} from pipe instead of 0", result[0]};
            return Err(ErrorKind::InvalidValue(msg).into());
        }
        Ok(())
    }

    pub fn wait_for_pipe_vec(rfd: RawFd, timeout: i32, num: usize) -> Result<(Vec<u8>)> {
        let mut result = Vec::new();
        while result.len() < num {
            let pfds =
                &mut [PollFd::new(rfd, EventFlags::POLLIN | EventFlags::POLLHUP)];
            match poll(pfds, timeout) {
                Err(e) => {
                    if e != ::nix::Error::Sys(Errno::EINTR) {
                        return Err(e).chain_err(|| "unable to poll rfd")?;
                    }
                    continue;
                }
                Ok(n) => {
                    if n == 0 {
                        return Err(ErrorKind::Timeout(timeout).into());
                    }
                }
            }
            let events = pfds[0].revents();
            if events.is_none() {
                // continue on no events
                continue;
            }
            if events.unwrap() == EventFlags::POLLNVAL {
                let msg = "file descriptor closed unexpectedly".to_string();
                return Err(ErrorKind::PipeClosed(msg).into());
            }
            if !events
                .unwrap()
                .intersects(EventFlags::POLLIN | EventFlags::POLLHUP)
            {
                // continue on other events (should not happen)
                debug!("got a continue on other events {:?}", events);
                continue;
            }
            let data: &mut [u8] = &mut [0];
            let n = read(rfd, data).chain_err(|| "could not read from rfd")?;
            if n == 0 {
                // the wfd was closed so close our end
                close(rfd).chain_err(|| "could not close rfd")?;
                break;
            }
            result.extend(data.iter().cloned());
        }
        Ok(result)
    }

    pub fn reopen_dev_null() -> Result<()> {
        let null_fd = open("/dev/null", OFlag::O_WRONLY, Mode::empty())?;
        let null_stat = fstat(null_fd)?;
        defer!(close(null_fd).unwrap());
        for fd in 0..3 {
            if let Ok(stat) = fstat(fd) {
                if stat.st_rdev == null_stat.st_rdev {
                    if fd == 0 {
                        // close and reopen to get RDONLY
                        close(fd)?;
                        open("/dev/null", OFlag::O_RDONLY, Mode::empty())?;
                    } else {
                        // we already have wronly fd, so duplicate it
                        dup2(null_fd, fd)?;
                    }
                }
            }
        }
        Ok(())
    }

    use nix::sys::socket::{accept, bind, connect, listen, sendmsg, socket};
    use nix::sys::socket::{AddressFamily, SockAddr, SockFlag, SockType, UnixAddr};

    pub fn load_console_sockets() -> Result<(RawFd, RawFd)> {
        let csocket = "console-socket";
        let mut csocketfd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )?;
        csocketfd =
            match connect(csocketfd, &SockAddr::Unix(UnixAddr::new(&*csocket)?)) {
                Err(e) => {
                    if e != ::nix::Error::Sys(Errno::ENOENT) {
                        let msg = format!("failed to open {}", csocket);
                        return Err(e).chain_err(|| msg)?;
                    }
                    -1
                }
                Ok(()) => csocketfd,
            };
        let console = "console";
        let consolefd =
            match open(&*console, OFlag::O_NOCTTY | OFlag::O_RDWR, Mode::empty()) {
                Err(e) => {
                    if e != ::nix::Error::Sys(Errno::ENOENT) {
                        let msg = format!("failed to open {}", console);
                        return Err(e).chain_err(|| msg)?;
                    }
                    -1
                }
                Ok(fd) => fd,
            };
        Ok((csocketfd, consolefd))
    }
}

pub mod runtime {
    use errors::*;
    use nix::fcntl::{open, OFlag};
    use nix::unistd::{close, write};
    use nix::sys::stat::Mode;
    use nix::errno::Errno;

    pub fn set_sysctl(key: &str, value: &str) -> Result<()> {
        let path = format! {"/proc/sys/{}", key.replace(".", "/")};
        let fd = match open(&*path, OFlag::O_RDWR, Mode::empty()) {
            Err(::nix::Error::Sys(errno)) => {
                if errno != Errno::ENOENT {
                    let msg = format!("could not set sysctl {} to {}", key, value);
                    Err(::nix::Error::Sys(errno)).chain_err(|| msg)?;
                }
                warn!("could not set {} because it doesn't exist", key);
                return Ok(());
            }
            Err(e) => Err(e)?,
            Ok(fd) => fd,
        };
        defer!(close(fd).unwrap());
        write(fd, value.as_bytes())?;
        Ok(())
    }

    use oci::LinuxIDMapping;

    pub fn write_mappings(path: &str, maps: &[LinuxIDMapping]) -> Result<()> {
        let mut data = String::new();
        for m in maps {
            let val = format!("{} {} {}\n", m.container_id, m.host_id, m.size);
            data = data + &val;
        }
        if !data.is_empty() {
            let fd = open(path, OFlag::O_WRONLY, Mode::empty())?;
            defer!(close(fd).unwrap());
            write(fd, data.as_bytes())?;
        }
        Ok(())
    }

    use std::ffi::CString;
    use nix_ext::{clearenv, putenv};
    use nix::unistd::execvp;

    pub fn do_exec(path: &str, args: &[String], env: &[String]) -> Result<()> {
        let p = CString::new(path.to_string()).unwrap();
        let a: Vec<CString> = args
            .iter()
            .map(|s| CString::new(s.to_string()).unwrap_or_default())
            .collect();
        let env: Vec<CString> = env
            .iter()
            .map(|s| CString::new(s.to_string()).unwrap_or_default())
            .collect();
        // execvp doesn't use env for the search path, so we set env manually
        clearenv()?;
        for e in &env {
            debug!("adding {:?} to env", e);
            putenv(e)?;
        }
        execvp(&p, &a).chain_err(|| "failed to exec")?;
        // should never reach here
        Ok(())
    }
}

pub fn execute_hook(hook: &oci::Hook, state: &oci::State) -> Result<()> {
    debug!("executing hook {:?}", hook);
    let (rfd, wfd) =
        pipe2(OFlag::O_CLOEXEC).chain_err(|| "failed to create pipe")?;
    match fork()? {
        ForkResult::Child => {
            close(rfd).chain_err(|| "could not close rfd")?;
            let (rstdin, wstdin) =
                pipe2(OFlag::empty()).chain_err(|| "failed to create pipe")?;
            // fork second child to execute hook
            match fork()? {
                ForkResult::Child => {
                    close(0).chain_err(|| "could not close stdin")?;
                    dup2(rstdin, 0).chain_err(|| "could not dup to stdin")?;
                    close(rstdin).chain_err(|| "could not close rstdin")?;
                    close(wstdin).chain_err(|| "could not close wstdin")?;
                    runtime::do_exec(&hook.path, &hook.args, &hook.env)?;
                }
                ForkResult::Parent { child } => {
                    close(rstdin).chain_err(|| "could not close rstdin")?;
                    unsafe {
                        // closes the file descriptor autmotaically
                        state
                            .to_writer(File::from_raw_fd(wstdin))
                            .chain_err(|| "could not write state")?;
                    }
                    let (exit_code, sig) = process::wait_for_child(child)?;
                    if let Some(signal) = sig {
                        // write signal to pipe.
                        let data: &[u8] = &[signal as u8];
                        write(wfd, data)
                            .chain_err(|| "failed to write signal hook")?;
                    }
                    close(wfd).chain_err(|| "could not close wfd")?;
                    std::process::exit(exit_code as i32);
                }
            }
        }
        ForkResult::Parent { child } => {
            // the wfd is only used by the child so close it
            close(wfd).chain_err(|| "could not close wfd")?;
            let mut timeout = -1 as i32;
            if let Some(t) = hook.timeout {
                timeout = t as i32 * 1000;
            }
            // a timeout will cause a failure and child will be killed on exit
            if let Some(sig) = pipe::wait_for_pipe_sig(rfd, timeout)? {
                let msg = format! {"hook exited with signal: {:?}", sig};
                return Err(ErrorKind::InvalidHook(msg).into());
            }
            let (exit_code, _) = process::wait_for_child(child)?;
            if exit_code != 0 {
                let msg = format! {"hook exited with exit code: {}", exit_code};
                return Err(ErrorKind::InvalidHook(msg).into());
            }
        }
    };
    Ok(())
}

pub fn state(id: &str, status: &str, pid: Pid, bundle: &str) -> oci::State {
    oci::State {
        version: "0.2.0".to_string(),
        id: id.to_string(),
        status: status.to_string(),
        pid: pid.into(), // TODO implement serde ser/de for Pid/Gid/..
        bundle: bundle.to_string(),
        annotations: HashMap::new(),
    }
}

#[inline]
pub fn instance_dir(id: &str, state_dir: &str) -> String {
    format!("{}/{}", state_dir, id)
}

// must be in instance_dir
pub fn get_init_pid() -> Result<(Pid)> {
    let mut pid = Pid::from_raw(-1);
    if let Ok(mut f) = File::open(INIT_PID) {
        let mut result = String::new();
        f.read_to_string(&mut result)?;
        if let Ok(process_pid) = result.parse::<i32>() {
            pid = Pid::from_raw(process_pid);
        }
    }
    Ok(pid)
}

pub fn state_from_dir(id: &str, state_dir: &str) -> Result<(oci::State)> {
    let dir = instance_dir(id, state_dir);
    chdir(&*dir).chain_err(|| format!("instance {} doesn't exist", id))?;
    let mut status = "creating";
    let mut root = String::new();
    let pid = get_init_pid()?;
    if let Ok(spec) = Spec::load(CONFIG) {
        root = spec.root.path.to_owned();
        status = "created";
        if let Ok(mut f) = File::open(PROCESS_PID) {
            status = "running";
            let mut result = String::new();
            f.read_to_string(&mut result)?;
            if let Ok(process_pid) = result.parse::<i32>() {
                if signals::signal_process(Pid::from_raw(process_pid), None)
                    .is_err()
                {
                    status = "stopped";
                }
            } else {
                // not safe to log during state because shim combines
                // stdout and stderr
                // warn!("invalid process pid: {}", result);
            }
        } else {
            // not safe to log during state because shim combines
            // stdout and stderr
            // warn!("could not open process pid");
        }
    }
    let st = state(id, status, pid, &root);
    Ok(st)
}

pub fn pseudo_tyy(tty: bool) -> Result<(RawFd, RawFd, RawFd)> {
    if !tty {
        let tsocket = "trigger-socket";
        let tmpfd = socket(
            AddressFamily::Unix,
            SockType::Stream,
            SockFlag::empty(),
            None,
        )?;
        // NOTE(vish): we might overwrite fds 0, 1, 2 with the console
        //             so make sure tsocketfd is a high fd that won't
        //             get overwritten
        dup2(tmpfd, TSOCKETFD).chain_err(|| "could not dup tsocketfd")?;
        close(tmpfd).chain_err(|| "could not close tsocket tmpfd")?;
        let tsocketfd = TSOCKETFD;
        bind(tsocketfd, &SockAddr::Unix(UnixAddr::new(&*tsocket)?))?;
        let (csocketfd, consolefd) = load_console_sockets()?;
        Ok((csocketfd, consolefd, tsocketfd))
    } else {
        Ok((-1, -1, -1))
    }
}

pub fn collectns() {

}