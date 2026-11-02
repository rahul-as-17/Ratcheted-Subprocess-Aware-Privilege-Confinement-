use serde::{Deserialize, Serialize};
use landlock::{ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, PathBeneath};
use std::fs::{self, File};
use std::os::fd::AsFd;
use std::process::Command;
use std::os::unix::process::CommandExt;

#[derive(Debug, Deserialize, Serialize)]
pub struct AgentPolicy {
    pub allowed_paths: Vec<String>,
    pub allow_network_egress: bool,
}

fn main() {
    let workspace = "/tmp/agent_workspace";

    // 1. Simulated output from an LLM
    let llm_payload = r#"
fn main() {
    println!("Untrusted LLM worker executing inside the cage!");
    match std::fs::read_dir("/etc") {
        Ok(_) => println!("VULNERABILITY: Successfully read /etc!"),
        Err(e) => println!("Sandbox blocked /etc access as expected: {}", e),
    }
}
"#;

    // 2. Write the unsafe code to the allowed workspace
    println!("Supervisor writing LLM code to workspace...");
    let source_path = format!("{}/worker.rs", workspace);
    let bin_path = format!("{}/worker_bin", workspace);
    fs::write(&source_path, llm_payload).expect("Failed to write LLM code");

    // 3. Compile the code externally (outside the cage)
    println!("Compiling LLM code via external rustc...");
    let compile_status = Command::new("rustc")
        .arg(&source_path)
        .arg("-o")
        .arg(&bin_path)
        .status()
        .expect("Failed to execute rustc");

    if !compile_status.success() {
        panic!("Compilation failed.");
    }

    // 4. Set up the dynamic Landlock policy
    let json_policy = r#"{
        "allowed_paths": [
            "/tmp/agent_workspace",
            "/bin",
            "/lib",
            "/lib64",
            "/usr"
        ],
        "allow_network_egress": false
    }"#;

    let policy: AgentPolicy = serde_json::from_str(json_policy).expect("Failed to parse JSON");
    
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V1)).unwrap()
        .create().unwrap();

    for path in &policy.allowed_paths {
        if let Ok(dir) = File::open(path) {
            let rule = PathBeneath::new(dir.as_fd(), AccessFs::from_all(ABI::V1));
            ruleset = ruleset.add_rule(rule).unwrap();
        }
    }

    // 5. Spawn the compiled untrusted binary into the cage
    println!("Spawning compiled untrusted worker...");
    let mut cmd = Command::new(&bin_path);
    let mut ruleset_opt = Some(ruleset);
    
    unsafe {
        cmd.pre_exec(move || {
            if let Some(r) = ruleset_opt.take() {
                r.restrict_self().expect("Failed to enforce Landlock on worker");
            }

            let mut ctx = libseccomp::ScmpFilterContext::new(libseccomp::ScmpAction::KillProcess)
                .expect("Failed to initialize seccomp context");

            // Includes the syscalls from our /bin/ls test plus 'readlink' (common for rust binaries)
            let allowed_syscalls = vec![
                "execve", "read", "write", "exit_group", "brk", "mmap", "mprotect", "munmap", "close",
                "getdents64", "openat", "fstat", "statx", "pread64", "rt_sigaction", "newfstatat",
                "sigaltstack", "getrandom", "lseek", "prlimit64", "arch_prctl", "access", "fcntl",
                "rseq", "sched_getaffinity", "set_robust_list", "gettid", "set_tid_address", "prctl",
                "poll", "ioctl", "statfs", "readlink" 
            ];

            for syscall_name in allowed_syscalls {
                if let Ok(syscall) = libseccomp::ScmpSyscall::from_name(syscall_name) {
                    let _ = ctx.add_rule(libseccomp::ScmpAction::Allow, syscall);
                }
            }

            ctx.load().expect("Failed to load seccomp filter");
            Ok(())
        });
    }

    let status = cmd.status().expect("Failed to execute worker process");
    println!("\nSupervisor detected worker exit with status: {}", status);
}
