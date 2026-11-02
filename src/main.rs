use axum::{routing::post, Json, Router};
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

#[derive(Deserialize)]
struct ExecuteRequest {
    code: String,
}

#[derive(Serialize)]
struct ExecuteResponse {
    success: bool,
    stdout: String,
    stderr: String,
}

#[tokio::main]
async fn main() {
    // 1. Define the HTTP route
    let app = Router::new().route("/execute", post(execute_handler));

    // 2. Bind to 0.0.0.0 so other devices on the local network can access it
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Supervisor API listening on port 3000...");
    
    axum::serve(listener, app).await.unwrap();
}

// 3. The handler that runs when the LLM sends code
async fn execute_handler(Json(payload): Json<ExecuteRequest>) -> Json<ExecuteResponse> {
    let workspace = "/tmp/agent_workspace";
    let source_path = format!("{}/worker.rs", workspace);
    let bin_path = format!("{}/worker_bin", workspace);

    // Write LLM payload to file
    if let Err(e) = fs::write(&source_path, &payload.code) {
        return Json(ExecuteResponse { success: false, stdout: "".into(), stderr: format!("Write error: {}", e) });
    }

    // Compile externally
    let compile_output = Command::new("rustc")
        .arg(&source_path)
        .arg("-o")
        .arg(&bin_path)
        .output()
        .expect("Failed to execute rustc");

    if !compile_output.status.success() {
        return Json(ExecuteResponse {
            success: false,
            stdout: "".into(),
            stderr: String::from_utf8_lossy(&compile_output.stderr).into_owned(),
        });
    }

    // Set up the strict Landlock policy
    let json_policy = r#"{
        "allowed_paths": ["/tmp/agent_workspace", "/bin", "/lib", "/lib64", "/usr"],
        "allow_network_egress": false
    }"#;
    let policy: AgentPolicy = serde_json::from_str(json_policy).unwrap();
    
    let mut ruleset = Ruleset::default().handle_access(AccessFs::from_all(ABI::V1)).unwrap().create().unwrap();
    for path in &policy.allowed_paths {
        if let Ok(dir) = File::open(path) {
            let rule = PathBeneath::new(dir.as_fd(), AccessFs::from_all(ABI::V1));
            ruleset = ruleset.add_rule(rule).unwrap();
        }
    }

    // Execute the sandboxed binary
    let mut cmd = Command::new(&bin_path);
    let mut ruleset_opt = Some(ruleset);
    
    unsafe {
        cmd.pre_exec(move || {
            if let Some(r) = ruleset_opt.take() {
                r.restrict_self().expect("Failed to enforce Landlock");
            }

            let mut ctx = libseccomp::ScmpFilterContext::new(libseccomp::ScmpAction::KillProcess).unwrap();
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
            ctx.load().unwrap();
            Ok(())
        });
    }

    // Capture the standard output/error to send back over HTTP
    let run_output = cmd.output().expect("Failed to execute worker");
    
    Json(ExecuteResponse {
        success: run_output.status.success(),
        stdout: String::from_utf8_lossy(&run_output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&run_output.stderr).into_owned(),
    })
}
