use serde::{Deserialize, Serialize};
use landlock::{ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, PathBeneath};
use std::fs::File;
use std::os::fd::AsFd;
use std::process::Command;
use std::os::unix::process::CommandExt;

#[derive(Debug, Deserialize, Serialize)]
pub struct AgentPolicy {
    pub allowed_paths: Vec<String>,
    pub allowed_binaries: Vec<String>,
    pub allow_network_egress: bool,
}

fn main() {
    // Added system directories required to execute binaries
    let json_policy = r#"{
        "allowed_paths": [
            "/tmp/agent_workspace",
            "/bin",
            "/lib",
            "/lib64",
            "/usr"
        ],
        "allowed_binaries": ["/bin/ls"],
        "allow_network_egress": false
    }"#;

    let policy: AgentPolicy = serde_json::from_str(json_policy).expect("Failed to parse JSON");
    
    let mut ruleset = Ruleset::default()
        .handle_access(AccessFs::from_all(ABI::V1)).unwrap()
        .create().unwrap();

    for path in &policy.allowed_paths {
        let dir = File::open(path).expect(&format!("Failed to open allowed path: {}", path));
        let rule = PathBeneath::new(dir.as_fd(), AccessFs::from_all(ABI::V1));
        ruleset = ruleset.add_rule(rule).unwrap();
    }

    println!("Supervisor remaining privileged. Spawning untrusted worker...");
    println!("Worker will attempt to list both /tmp/agent_workspace (Allowed) and /etc (Blocked)...\n");

    let mut cmd = Command::new(&policy.allowed_binaries[0]);
    cmd.arg("/tmp/agent_workspace"); // Allowed path
    cmd.arg("/etc");                 // Blocked path

    let mut ruleset_opt = Some(ruleset);
    
    unsafe {
        cmd.pre_exec(move || {
            if let Some(r) = ruleset_opt.take() {
                r.restrict_self().expect("Failed to enforce Landlock on worker");
            }
            Ok(())
        });
    }

    let status = cmd.status().expect("Failed to execute worker process");
    println!("\nSupervisor detected worker exit with status: {}", status);
}
