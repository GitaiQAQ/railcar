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
extern crate railcar;

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
use nix::sys::wait::WaitPidFlag;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chdir, execvp, getpid, sethostname, setresgid, setresuid};
use nix::unistd::{close, dup2, fork, pipe2, read, setsid, write, ForkResult};
use nix::unistd::{Gid, Pid, Uid};
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

use railcar::{capabilities, cgroups, mounts, nix_ext, seccomp, selinux, signals, sync};
use railcar::{errors, logger};

use railcar::{DEFAULT_DEVICES, NAMESPACES, CONFIG, INIT_PID, PROCESS_PID, TSOCKETFD};
use railcar::process::*;
use railcar::pipe::*;
use railcar::runtime::*;
use railcar::state;
use railcar::execute_hook;
use railcar::state_from_dir;
use railcar::instance_dir;
use railcar::get_init_pid;
use railcar::pseudo_tyy;

#[cfg(feature = "nightly")]
static mut ARGC: isize = 0 as isize;
#[cfg(feature = "nightly")]
static mut ARGV: *mut *mut i8 = 0 as *mut *mut i8;

// using start instead of main to get direct access to arg0
#[cfg(feature = "nightly")]
#[start]
fn start(argc: isize, argv: *const *const u8) -> isize {
    unsafe {
        // store args so we can access them later
        ARGC = argc;
        ARGV = argv as *mut *mut i8;
    }

    // enable stack unwinding
    if std::panic::catch_unwind(main).is_err() {
        101
    } else {
        0
    }
}

// only show backtrace in debug mode
#[cfg(not(debug_assertions))]
fn print_backtrace(_: &Error) {}

#[cfg(debug_assertions)]
fn print_backtrace(e: &Error) {
    match e.backtrace() {
        Some(backtrace) => error!("{:?}", backtrace),
        None => error!("to view backtrace, use RUST_BACKTRACE=1"),
    }
}

#[cfg(feature = "nightly")]
fn get_args() -> Vec<String> {
    // we parse args directly since we didn't call the runtime
    // lang_start() function to parse them.
    let mut args = Vec::new();
    unsafe {
        for i in 0..ARGC {
            let cstr = std::ffi::CStr::from_ptr(*ARGV.offset(i) as *const u8);
            args.push(cstr.to_string_lossy().into_owned());
        }
    }
    args
}

#[cfg(not(feature = "nightly"))]
fn get_args() -> Vec<String> {
    std::env::args().collect()
}

fn main() {
    std::env::set_var("RUST_BACKTRACE", "1");

    let _ = log::set_logger(&logger::SIMPLE_LOGGER)
        .map(|()| log::set_max_level(log::LevelFilter::Debug));

    if let Err(ref e) = run() {
        error!("{}", e);

        for e in e.iter().skip(1) {
            error!("caused by: {}", e);
        }

        print_backtrace(e);
        ::std::process::exit(1);
    }
    ::std::process::exit(0);
}

#[allow(needless_pass_by_value)]
fn id_validator(val: String) -> StdResult<(), String> {
    if val.contains("..") || val.contains('/') {
        return Err(format!("id {} may cannot contain '..' or '/'", val));
    }
    Ok(())
}

fn run() -> Result<()> {
    let id_arg = Arg::with_name("id")
        .required(true)
        .takes_value(true)
        .validator(id_validator)
        .help("Unique identifier");
    let bundle_arg = Arg::with_name("bundle")
        .required(true)
        .default_value(".")
        .long("bundle")
        .short("b")
        .help("Directory containing config.json");
    let pid_arg = Arg::with_name("p")
        .takes_value(true)
        .long("pid-file")
        .short("p")
        .help("Additional location to write pid");
    let init_arg = Arg::with_name("n")
        .help("Do not create an init process")
        .long("no-init")
        .short("n");

    let matches = App::new("Railcar")
        .about("Railcar - run a container from an oci-runtime spec file")
        .setting(AppSettings::ColoredHelp)
        .author(crate_authors!("\n"))
        .setting(AppSettings::SubcommandRequired)
        .version(crate_version!())
        .arg(
            Arg::with_name("v")
                .multiple(true)
                .help("Sets the level of verbosity")
                .short("v"),
        )
        .arg(
            Arg::with_name("d")
                .help("Daemonize the process")
                .long("daemonize")
                .short("d"),
        )
        .arg(
            Arg::with_name("log")
                .help("Compatibility (ignored)")
                .long("log")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("log-format")
                .help("Compatibility (ignored)")
                .long("log-format")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("r")
                .default_value("/run/railcar")
                .help("Dir for state")
                .long("root")
                .short("r")
                .takes_value(true),
        )
        .subcommand(
            SubCommand::with_name("run")
                .setting(AppSettings::ColoredHelp)
                .arg(&id_arg)
                .arg(&bundle_arg)
                .arg(&pid_arg)
                .arg(&init_arg)
                .about("Run a container"),
        )
        .subcommand(
            SubCommand::with_name("create")
                .setting(AppSettings::ColoredHelp)
                .arg(&id_arg)
                .arg(&bundle_arg)
                .arg(&pid_arg)
                .arg(&init_arg)
                // NOTE(vish): if no-trigger is specified, console
                //             and console-socket will be loaded
                //             by start instead of create, so
                //             no output will appear from the init
                //             process.
                .arg(
                    Arg::with_name("t")
                        .help("Double fork instead of trigger")
                        .long("no-trigger")
                        .short("t"),
                )
                .arg(
                    Arg::with_name("c")
                        .help("Console to use")
                        .long("console")
                        .short("c")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("console-socket")
                        .help("socket to pass master of console")
                        .long("console-socket")
                        .takes_value(true),
                )
                .about("Create a container (to be started later)"),
        )
        .subcommand(
            SubCommand::with_name("start")
                .setting(AppSettings::ColoredHelp)
                .arg(&id_arg)
                .about("Start a (previously created) container"),
        )
        .subcommand(
            SubCommand::with_name("state")
                .setting(AppSettings::ColoredHelp)
                .arg(&id_arg)
                .about(
                    "Get the (json) state of a (previously created) container",
                ),
        )
        .subcommand(
            SubCommand::with_name("kill")
                .setting(AppSettings::ColoredHelp)
                .arg(&id_arg)
                .arg(
                    Arg::with_name("a")
                        .help("Compatibility (ignored)")
                        .long("all")
                        .short("a"),
                )
                .arg(
                    Arg::with_name("signal")
                        .default_value("TERM")
                        .required(true)
                        .takes_value(true)
                        .help("Signal to send to container"),
                )
                .about("Signal a (previously created) container"),
        )
        .subcommand(
            SubCommand::with_name("delete")
                .setting(AppSettings::ColoredHelp)
                .arg(&id_arg)
                .arg(
                    Arg::with_name("f")
                        .help("Kill process if still running")
                        .long("force")
                        .short("f"),
                )
                .about("Delete a (previously created) container"),
        )
        .subcommand(
            SubCommand::with_name("ps")
                .setting(AppSettings::ColoredHelp)
                .arg(&id_arg)
                .arg(
                    Arg::with_name("f")
                        .help("Compatibility (ignored)")
                        .long("format")
                        .short("f")
                        .takes_value(true),
                )
                .about("List processes in a (previously created) container"),
        )
        .get_matches_from(get_args());
    let level = match matches.occurrences_of("v") {
        0 => log::LevelFilter::Info, //default
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    let _ = log::set_logger(&logger::SIMPLE_LOGGER)
        .map(|()| log::set_max_level(level));

    // create empty log file to avoid warning
    let lpath = matches.value_of("log").unwrap_or_default();
    if lpath != "" {
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(lpath)?;
    }

    let state_dir = matches.value_of("r").unwrap().to_string();
    debug!("ensuring railcar state dir {}", &state_dir);
    let chain = || format!("ensuring railcar state dir {} failed", &state_dir);
    create_dir_all(&state_dir).chain_err(chain)?;

    match matches.subcommand() {
        ("create", Some(create_matches)) => cmd_create(
            create_matches.value_of("id").unwrap(),
            &state_dir,
            create_matches,
        ),
        ("delete", Some(delete_matches)) => cmd_delete(
            delete_matches.value_of("id").unwrap(),
            &state_dir,
            delete_matches,
        ),
        ("kill", Some(kill_matches)) => cmd_kill(
            kill_matches.value_of("id").unwrap(),
            &state_dir,
            kill_matches,
        ),
        ("ps", Some(ps_matches)) => {
            cmd_ps(ps_matches.value_of("id").unwrap(), &state_dir)
        }
        ("run", Some(run_matches)) => {
            cmd_run(run_matches.value_of("id").unwrap(), run_matches)
        }
        ("start", Some(start_matches)) => {
            cmd_start(start_matches.value_of("id").unwrap(), &state_dir)
        }
        ("state", Some(state_matches)) => {
            cmd_state(state_matches.value_of("id").unwrap(), &state_dir)
        }
        // We should never reach here because clap already enforces this
        _ => bail!("command not recognized"),
    }
}

fn cmd_state(id: &str, state_dir: &str) -> Result<()> {
    debug!("Performing state");
    let st = state_from_dir(id, state_dir)?;
    println!("{}", st.to_string().chain_err(|| "invalid state")?);
    Ok(())
}

fn cmd_create(id: &str, state_dir: &str, matches: &ArgMatches) -> Result<()> {
    debug!("Performing create");
    let bundle = matches.value_of("bundle").unwrap();
    chdir(&*bundle).chain_err(|| format!("failed to chdir to {}", bundle))?;
    let dir = instance_dir(id, state_dir);
    debug!("creating state dir {}", &dir);
    if let Err(e) = create_dir(&dir) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            let chain = || format!("creating state dir {} failed", &dir);
            Err(e).chain_err(chain)?;
        }
        bail!("Container with id {} already exists", id);
    }
    if let Err(e) = finish_create(id, &dir, matches) {
        let _ = remove_dir_all(&dir);
        Err(e)
    } else {
        Ok(())
    }
}


fn finish_create(id: &str, dir: &str, matches: &ArgMatches) -> Result<()> {
    let spec =
        Spec::load(CONFIG).chain_err(|| format!("failed to load {}", CONFIG))?;

    let rootfs = canonicalize(&spec.root.path)
        .chain_err(|| format! {"failed to find root path {}", &spec.root.path})?
        .to_string_lossy()
        .into_owned();

    chdir(&*dir).chain_err(|| format!("failed to chdir to {}", &dir))?;
    // NOTE: There are certain configs where we will not be able to create a
    //       console during start, so this could potentially create the
    //       console during init and pass to the process via sendmsg. This
    //       would also allow us to write debug data from the init process
    //       to the console and allow us to pass stdoutio from init to the
    //       process, fixing the lack of stdout collection if -t is not
    //       specified when using docker run.
    let csocket = matches.value_of("console-socket").unwrap_or_default();
    if csocket != "" {
        let lnk = format!("{}/console-socket", dir);
        symlink(&csocket, lnk)?;
    }
    // symlink the console
    let cons = matches.value_of("c").unwrap_or_default();
    if cons != "" {
        let lnk = format!("{}/console", dir);
        symlink(&cons, lnk)?;
    }
    let (csocketfd, consolefd, tsocketfd) = pseudo_tyy(!matches.is_present("t"))?;

    let pidfile = matches.value_of("p").unwrap_or_default();

    let child_pid = safe_run_container(
        id,
        &rootfs,
        &spec,
        Pid::from_raw(-1),
        true,
        true,
        true,
        csocketfd,
        consolefd,
        tsocketfd,
    )?;
    if child_pid != Pid::from_raw(-1) {
        debug!("writing init pid file {}", child_pid);
        let mut f = File::create(INIT_PID)?;
        f.write_all(child_pid.to_string().as_bytes())?;
        if pidfile != "" {
            debug!("writing process {} pid to file {}", child_pid, pidfile);
            let mut f = File::create(pidfile)?;
            f.write_all(child_pid.to_string().as_bytes())?;
        }
        let linux = spec.linux.as_ref().unwrap();
        // update namespaces to enter only
        let mut namespaces = Vec::new();
        for ns in &linux.namespaces {
            let space = CloneFlags::from_bits_truncate(ns.typ as i32);
            if let Some(name) = NAMESPACES.get(&space) {
                let path = format!("/proc/{}/ns/{}", child_pid, name);
                let n = oci::LinuxNamespace {
                    typ: ns.typ,
                    path: path,
                };
                namespaces.push(n);
            }
        }
        let updated_linux = oci::Linux {
            uid_mappings: linux.uid_mappings.clone(),
            gid_mappings: linux.gid_mappings.clone(),
            sysctl: HashMap::new(),
            resources: None,
            cgroups_path: linux.cgroups_path.to_owned(),
            namespaces: namespaces,
            devices: Vec::new(),
            seccomp: None,
            rootfs_propagation: "".to_string(),
            masked_paths: Vec::new(),
            readonly_paths: Vec::new(),
            mount_label: "".to_string(),
        };
        let updated = Spec {
            version: spec.version,
            platform: spec.platform,
            process: spec.process,
            root: oci::Root {
                path: rootfs,
                readonly: spec.root.readonly,
            },
            hostname: "".to_string(), // hostname not needed
            mounts: Vec::new(),       // remove mounts
            hooks: spec.hooks,
            annotations: spec.annotations,
            linux: Some(updated_linux),
            solaris: spec.solaris,
            windows: spec.windows,
        };
        debug!("writing updated config");
        updated
            .save(CONFIG)
            .chain_err(|| format!("failed to save {}", CONFIG))?;
    }
    Ok(())
}

fn cmd_start(id: &str, state_dir: &str) -> Result<()> {
    debug!("Performing start");

    // we use instance dir for config written out by create
    let dir = instance_dir(id, state_dir);
    chdir(&*dir).chain_err(|| format!("instance {} doesn't exist", id))?;

    let spec =
        Spec::load(CONFIG).chain_err(|| format!("failed to load {}", CONFIG))?;

    let init_pid = get_init_pid()?;

    let tsocket = "trigger-socket";
    let mut tsocketfd = socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )?;
    tsocketfd =
        match connect(tsocketfd, &SockAddr::Unix(UnixAddr::new(&*tsocket)?)) {
            Err(e) => {
                if e != ::nix::Error::Sys(Errno::ENOENT) {
                    let msg = format!("failed to open {}", tsocket);
                    return Err(e).chain_err(|| msg)?;
                }
                -1
            }
            Ok(()) => tsocketfd,
        };

    // if we are triggering just trigger and exit
    if tsocketfd != -1 {
        debug!("running prestart hooks");
        if let Some(ref hooks) = spec.hooks {
            let st = state(id, "running", init_pid, &spec.root.path);
            for h in &hooks.prestart {
                execute_hook(h, &st)
                    .chain_err(|| "failed to execute prestart hooks")?;
            }
        }
        let linux = spec.linux.as_ref().unwrap();
        let cpath = if linux.cgroups_path == "" {
            format! {"/{}", id}
        } else {
            linux.cgroups_path.clone()
        };
        // get the actual pid of the process from cgroup
        let mut child_pid = Pid::from_raw(-1);
        let procs = cgroups::get_procs("cpuset", &cpath);
        for p in procs {
            if p != init_pid {
                debug!("actual pid of child is {}", p);
                child_pid = p;
                break;
            }
        }
        let mut f = File::create(PROCESS_PID)?;
        f.write_all(child_pid.to_string().as_bytes())?;
        debug!("running poststart hooks");
        if let Some(ref hooks) = spec.hooks {
            let st = state(id, "running", init_pid, &spec.root.path);
            for h in &hooks.poststart {
                if let Err(e) = execute_hook(h, &st) {
                    warn!("failed to execute poststart hook: {}", e);
                }
            }
        }
        debug!("writing zero to trigger socket to start exec");
        let data: &[u8] = &[0];
        write(tsocketfd, data).chain_err(|| "failed to write zero")?;
        return Ok(());
    }

    let (csocketfd, consolefd) = load_console_sockets()?;

    let child_pid = safe_run_container(
        id,
        &spec.root.path,
        &spec,
        init_pid,
        false,
        false,
        true,
        csocketfd,
        consolefd,
        -1,
    )?;
    if child_pid != Pid::from_raw(-1) {
        debug!("writing process {} pid file", child_pid);
        let mut f = File::create(PROCESS_PID)?;
        f.write_all(child_pid.to_string().as_bytes())?;
    }
    Ok(())
}

fn cmd_kill(id: &str, state_dir: &str, matches: &ArgMatches) -> Result<()> {
    debug!("Performing kill");
    let signal = signals::to_signal(matches.value_of("signal").unwrap())
        .unwrap_or(Signal::SIGTERM);
    let dir = instance_dir(id, state_dir);
    chdir(&*dir).chain_err(|| format!("instance {} doesn't exist", id))?;
    let mut f = File::open(INIT_PID).chain_err(|| "failed to find pid")?;
    let mut result = String::new();
    f.read_to_string(&mut result)?;
    if let Ok(init_pid) = result.parse::<i32>() {
        if signals::signal_process(Pid::from_raw(init_pid), signal).is_err() {
            warn!("failed signal init process {}, may have exited", init_pid);
        }
    } else {
        warn!("invalid process pid: {}", result);
    }
    Ok(())
}

fn cmd_ps(id: &str, state_dir: &str) -> Result<()> {
    debug!("Performing ps");
    let dir = instance_dir(id, state_dir);
    chdir(&*dir).chain_err(|| format!("instance {} doesn't exist", id))?;
    let mut f = File::open(PROCESS_PID).chain_err(|| "failed to find pid")?;
    let mut result = String::new();
    f.read_to_string(&mut result)?;
    // TODO: return any other execed processes
    let mut pids = Vec::new();
    if let Ok(process_pid) = result.parse::<i32>() {
        pids.push(Pid::from_raw(process_pid));
    } else {
        warn!("invalid process pid: {}", result);
    }
    let pids = pids
        .into_iter()
        .map(|pid: Pid| -> i32 { pid.into() })
        .collect::<Vec<i32>>();
    println!(
        "{}",
        oci::serialize::to_string(&pids)
            .chain_err(|| "could not serialize pids")?
    );
    Ok(())
}

fn cmd_delete(id: &str, state_dir: &str, matches: &ArgMatches) -> Result<()> {
    debug!("Performing delete");
    let dir = instance_dir(id, state_dir);
    if chdir(&*dir).is_err() {
        debug!("instance {} doesn't exist", id);
        warn!("returning zero to work around docker bug");
        return Ok(());
    }
    if let Ok(mut f) = File::open(PROCESS_PID) {
        let mut result = String::new();
        f.read_to_string(&mut result)?;
        if let Ok(process_pid) = result.parse::<i32>() {
            let process_pid = Pid::from_raw(process_pid);

            if signals::signal_process(process_pid, None).is_ok() {
                if matches.is_present("f") {
                    if let Err(e) =
                    signals::signal_process(process_pid, Signal::SIGKILL)
                    {
                        let chain = || {
                            format!("failed to kill process {} ", process_pid)
                        };
                        if let Error(ErrorKind::Nix(nixerr), _) = e {
                            if nixerr == ::nix::Error::Sys(Errno::ESRCH) {
                                debug!("container process is already dead");
                            } else {
                                Err(e).chain_err(chain)?;
                            }
                        } else {
                            Err(e).chain_err(chain)?;
                        }
                    }
                } else {
                    bail!("container process {} is still running", process_pid)
                }
            }
        } else {
            warn!("invalid process pid: {}", result);
        }
    } else {
        debug!("process doesn't exist");
    }
    if let Ok(mut f) = File::open(INIT_PID) {
        debug!("killing init process");
        let mut result = String::new();
        f.read_to_string(&mut result)?;
        if let Ok(ipid) = result.parse::<i32>() {
            if let Err(e) =
            signals::signal_process(Pid::from_raw(ipid), Signal::SIGKILL)
            {
                let chain = || format!("failed to kill init {} ", ipid);
                if let Error(ErrorKind::Nix(nixerr), _) = e {
                    if let ::nix::Error::Sys(errno) = nixerr {
                        if errno == Errno::ESRCH {
                            debug!("init process is already dead");
                        }
                        Err(e).chain_err(chain)?;
                    } else {
                        Err(e).chain_err(chain)?;
                    }
                } else {
                    Err(e).chain_err(chain)?;
                }
            }
        } else {
            warn!("invalid init pid: {}", result);
        }
    } else {
        debug!("init process doesn't exist");
    }
    if let Ok(spec) = Spec::load(CONFIG) {
        let linux = spec.linux.as_ref().unwrap();
        let cpath = if linux.cgroups_path == "" {
            format! {"/{}", id}
        } else {
            linux.cgroups_path.clone()
        };
        debug!("removing cgroups");
        if let Err(Error(ErrorKind::Io(e), _)) = cgroups::remove(&cpath) {
            if e.kind() != std::io::ErrorKind::NotFound {
                warn!("failed to remove cgroup dir: {}", e);
            }
        }
        debug!("running poststop hooks");
        if let Some(ref hooks) = spec.hooks {
            let st = state_from_dir(id, state_dir)?;
            for h in &hooks.poststop {
                execute_hook(h, &st)
                    .chain_err(|| "failed to execute poststop hooks")?;
            }
        }
    } else {
        debug!("config could not be loaded");
    }
    debug!("removing state dir {}", &dir);
    if let Err(e) = remove_dir_all(&dir) {
        if e.kind() != std::io::ErrorKind::NotFound {
            let chain = || format!("removing state dir {} failed", &dir);
            Err(e).chain_err(chain)?;
        }
        bail!("State dir for {} disappeared", id);
    }

    Ok(())
}

fn cmd_run(id: &str, matches: &ArgMatches) -> Result<()> {
    let bundle = matches.value_of("bundle").unwrap();
    chdir(&*bundle).chain_err(|| format!("failed to chdir to {}", bundle))?;
    let spec =
        Spec::load(CONFIG).chain_err(|| format!("failed to load {}", CONFIG))?;

    let child_pid = safe_run_container(
        id,
        &spec.root.path,
        &spec,
        Pid::from_raw(-1),
        !matches.is_present("n"),
        false,
        matches.is_present("d"),
        -1,
        -1,
        -1,
    )?;
    info!("Container running with pid {}", child_pid);
    Ok(())
}

fn safe_run_container(
    id: &str,
    rootfs: &str,
    spec: &Spec,
    init_pid: Pid,
    init: bool,
    init_only: bool,
    daemonize: bool,
    csocketfd: RawFd,
    consolefd: RawFd,
    tsocketfd: RawFd,
) -> Result<Pid> {
    let pid = getpid();
    match run_container(
        id, rootfs, spec, init_pid, init, init_only, daemonize, csocketfd,
        consolefd, tsocketfd,
    ) {
        Err(e) => {
            // if we are the top level thread, kill all children
            if pid == getpid() {
                signals::signal_children(Signal::SIGTERM).unwrap();
            }
            Err(e)
        }
        Ok(child_pid) => Ok(child_pid),
    }
}

fn run_container(
    id: &str,
    rootfs: &str,
    spec: &Spec,
    init_pid: Pid,
    mut init: bool,
    mut init_only: bool,
    daemonize: bool,
    csocketfd: RawFd,
    mut consolefd: RawFd,
    tsocketfd: RawFd,
) -> Result<Pid> {
    if let Err(e) = prctl::set_dumpable(false) {
        bail!(format!("set dumpable returned {}", e));
    };

    // if selinux is disabled, set will fail so print a warning
    if !spec.process.selinux_label.is_empty() {
        if let Err(e) = selinux::setexeccon(&spec.process.selinux_label) {
            warn!(
                "could not set label to {}: {}",
                spec.process.selinux_label, e
            );
        };
    }

    if spec.linux.is_none() {
        let msg = "linux config is empty".to_string();
        return Err(ErrorKind::InvalidSpec(msg).into());
    }

    let linux = spec.linux.as_ref().unwrap();

    // initialize static variables before forking
    initialize(&DEFAULT_DEVICES);
    initialize(&NAMESPACES);
    cgroups::init();

    // collect namespaces
    let mut cf = CloneFlags::empty();
    let mut to_enter = Vec::new();
    let mut enter_pid = false;

    for ns in &linux.namespaces {
        let space = CloneFlags::from_bits_truncate(ns.typ as i32);
        if space == CloneFlags::CLONE_NEWPID {
            // new sub PID namespace
            enter_pid = true;
        }
        if ns.path.is_empty() {
            cf |= space;
        } else {
            let fd = open(&*ns.path, OFlag::empty(), Mode::empty())
                .chain_err(|| format!("failed to open file for {:?}", space))?;
            to_enter.push((space, fd));
        }
    }

    if !enter_pid {
        init = false;
        init_only = false;
    }

    let cpath = if linux.cgroups_path == "" {
        format! {"/{}", id}
    } else {
        linux.cgroups_path.clone()
    };

    let mut bind_devices = false;
    let mut userns = false;
    let rlimits = &spec.process.rlimits;
    // fork for userns and cgroups
    if cf.contains(CloneFlags::CLONE_NEWUSER) {
        bind_devices = true;
        userns = true;
    }

    if !daemonize {
        if let Err(e) = prctl::set_child_subreaper(true) {
            bail!(format!("set subreaper returned {}", e));
        };
    }
    let (child_pid, wfd) = fork_first(
        id, init_pid, enter_pid, init_only, daemonize, userns, linux, rlimits,
        &cpath, spec,
    )?;

    // parent returns child pid and exits
    if child_pid != Pid::from_raw(-1) {
        return Ok(child_pid);
    }

    let mut mount_fd = -1;
    // enter path namespaces
    for &(space, fd) in &to_enter {
        if space == CloneFlags::CLONE_NEWNS {
            // enter mount ns last
            mount_fd = fd;
            continue;
        }
        setns(fd, space).chain_err(|| format!("failed to enter {:?}", space))?;
        close(fd)?;
        if space == CloneFlags::CLONE_NEWUSER {
            setid(Uid::from_raw(0), Gid::from_raw(0))
                .chain_err(|| "failed to setid")?;
            bind_devices = true;
        }
    }

    // TODO: handle systemd-style cgroup_path
    if !cpath.starts_with('/') {
        let msg = "cgroup path must be absolute".to_string();
        return Err(ErrorKind::InvalidSpec(msg).into());
    }

    // unshare other ns
    let chain = || format!("failed to unshare {:?}", cf);
    unshare(cf & !CloneFlags::CLONE_NEWUSER).chain_err(chain)?;

    if enter_pid {
        fork_enter_pid(init, daemonize)?;
    };

    if cf.contains(CloneFlags::CLONE_NEWUTS) {
        sethostname(&spec.hostname)?;
    }

    if cf.contains(CloneFlags::CLONE_NEWNS) {
        mounts::init_rootfs(spec, rootfs, &cpath, bind_devices)
            .chain_err(|| "failed to init rootfs")?;
    }

    if !init_only {
        // notify first parent that it can continue
        debug!("writing zero to pipe to trigger prestart");
        let data: &[u8] = &[0];
        write(wfd, data).chain_err(|| "failed to write zero")?;
    }

    if mount_fd != -1 {
        setns(mount_fd, CloneFlags::CLONE_NEWNS).chain_err(|| {
            "failed to enter CloneFlags::CLONE_NEWNS".to_string()
        })?;
        close(mount_fd)?;
    }

    if cf.contains(CloneFlags::CLONE_NEWNS) {
        mounts::pivot_rootfs(&*rootfs).chain_err(|| "failed to pivot rootfs")?;

        // only set sysctls in newns
        for (key, value) in &linux.sysctl {
            set_sysctl(key, value)?;
        }

        // NOTE: apparently criu has problems if pointing to an fd outside
        //       the filesystem namespace.
        reopen_dev_null()?;
    }

    if csocketfd != -1 {
        let mut slave: libc::c_int = unsafe { std::mem::uninitialized() };
        let mut master: libc::c_int = unsafe { std::mem::uninitialized() };
        let ret = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        Errno::result(ret).chain_err(|| "could not openpty")?;
        defer!(close(master).unwrap());
        let data: &[u8] = b"/dev/ptmx";
        let iov = [nix::sys::uio::IoVec::from_slice(data)];
        //let fds = [master.as_raw_fd()];
        let fds = [master];
        let cmsg = ControlMessage::ScmRights(&fds);
        sendmsg(csocketfd, &iov, &[cmsg], MsgFlags::empty(), None)?;
        consolefd = slave;
        close(csocketfd).chain_err(|| "could not close csocketfd")?;
    }
    if consolefd != -1 {
        setsid()?;
        if unsafe { libc::ioctl(consolefd, libc::TIOCSCTTY) } < 0 {
            warn!("could not TIOCSCTTY");
        };
        dup2(consolefd, 0).chain_err(|| "could not dup tty to stdin")?;
        dup2(consolefd, 1).chain_err(|| "could not dup tty to stdout")?;
        dup2(consolefd, 2).chain_err(|| "could not dup tty to stderr")?;

        if consolefd > 2 {
            close(consolefd).chain_err(|| "could not close consolefd")?;
        }

        // NOTE: we may need to fix up the mount of /dev/console
    }

    if cf.contains(CloneFlags::CLONE_NEWNS) {
        mounts::finish_rootfs(spec).chain_err(|| "failed to finish rootfs")?;
    }

    // change to specified working directory
    if !spec.process.cwd.is_empty() {
        chdir(&*spec.process.cwd)?;
    }

    debug!("setting ids");

    // set uid/gid/groups
    let uid = Uid::from_raw(spec.process.user.uid);
    let gid = Gid::from_raw(spec.process.user.gid);
    setid(uid, gid)?;
    if !spec.process.user.additional_gids.is_empty() {
        setgroups(&spec.process.user.additional_gids)?;
    }

    // NOTE: if we want init to pass signals to other processes, we may want
    //       to hold on to cap kill until after the final fork.
    if spec.process.no_new_privileges {
        if let Err(e) = prctl::set_no_new_privileges(true) {
            bail!(format!("set no_new_privs returned {}", e));
        };
        // drop privileges
        if let Some(ref c) = spec.process.capabilities {
            capabilities::drop_privileges(c)?;
        }
        if let Some(ref seccomp) = linux.seccomp {
            seccomp::initialize_seccomp(seccomp)?;
        }
    } else {
        // NOTE: if we have not set no new priviliges, we must set up seccomp
        //       before capset, which will error if seccomp blocks it
        if let Some(ref seccomp) = linux.seccomp {
            seccomp::initialize_seccomp(seccomp)?;
        }
        // drop privileges
        if let Some(ref c) = spec.process.capabilities {
            capabilities::drop_privileges(c)?;
        }
    }

    // notify first parent that it can continue
    debug!("writing zero to pipe to trigger poststart");
    let data: &[u8] = &[0];
    write(wfd, data).chain_err(|| "failed to write zero")?;

    if init {
        if init_only && tsocketfd == -1 {
            do_init(wfd, daemonize)?;
        } else {
            fork_final_child(wfd, tsocketfd, daemonize)?;
        }
    }

    // we nolonger need wfd, so close it
    close(wfd).chain_err(|| "could not close wfd")?;

    // wait for trigger
    if tsocketfd != -1 {
        listen(tsocketfd, 1)?;
        let fd = accept(tsocketfd)?;
        wait_for_pipe_zero(fd, -1)?;
        close(fd).chain_err(|| "could not close accept fd")?;
        close(tsocketfd).chain_err(|| "could not close trigger fd")?;
    }

    do_exec(&spec.process.args[0], &spec.process.args, &spec.process.env)?;
    Ok(Pid::from_raw(-1))
}