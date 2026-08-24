//! Core-dump suppression for seed-handling processes (docker-artifact-signer
                                               
//!
//! A non-dumpable process is dumped by NEITHER the file nor the pipe
//! `core_pattern` path — kernel `fs/coredump.c` gates on dumpability BEFORE
//! dispatching to either — so a crash while plaintext seed material is live
//! (keygen generate, sign unwrap, future re-delegation) cannot write the
//! seed+passphrase to host disk on ANY host configuration. This is the robust
//! control; `--ulimit core=0` (RLIMIT_CORE) is belt-and-suspenders ONLY — a
//! piping `core_pattern` (systemd-coredump / apport / abrt) makes the kernel
//! ignore RLIMIT_CORE and the handler decide (man core(5)), which is exactly
                              
//!
                                                                            
//! orchard's OWN `main()` — post-exec, unconditional, before subcommand
//! dispatch. A docker `--entrypoint` wrapper cannot do this job: the normal
//! execve from the wrapper (or from `cargo run`) into `orchard` resets the
//! dumpable flag back to 1 (SUID_DUMP_USER), so only the seed-holding process
//! itself, after its final exec, can durably clear it.

/// Mark this process non-dumpable: `prctl(PR_SET_DUMPABLE, 0)`.
///
/// Returns the errno on failure. Host invocations treat a failure as a
/// warning (they hold no seed); the in-container seed subcommands assert
                                                                               
pub fn set_process_non_dumpable() -> std::io::Result<()> {
                                                                             
                                                   
    let rc = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_process_non_dumpable_makes_get_dumpable_zero() {
                                                                            
                                                                              
                                                                          
                                                                                 
                                                                             
                                  
        unsafe {
            let parent_dumpable_before = libc::prctl(libc::PR_GET_DUMPABLE);
            let pid = libc::fork();
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                let ok = set_process_non_dumpable().is_ok();
                let d = libc::prctl(libc::PR_GET_DUMPABLE);
                libc::_exit(if ok && d == 0 { 0 } else { 1 });
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid, "waitpid");
            assert!(libc::WIFEXITED(status), "child did not exit normally");
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "child PR_GET_DUMPABLE was not 0 after set_process_non_dumpable"
            );
                                                                       
            assert_eq!(
                libc::prctl(libc::PR_GET_DUMPABLE),
                parent_dumpable_before,
                "the child's prctl leaked into the parent"
            );
        }
    }
}
