// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Windows process-tree cancellation for commands launched with Tokio.
//!
//! The command starts suspended and joins a dedicated Job Object before it can
//! launch subprocesses. Windows puts those subprocesses in the same job.
//! Callers can terminate the job on timeout or cancellation, even if the
//! original process has already exited. Closing the last job handle also stops
//! any remaining processes in the job.

// Tokio handles spawning and I/O. Job assignment, thread resumption, and
// process-tree termination require direct Win32 calls.
#![allow(unsafe_code)]

use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};

use tokio::process::{Child, Command};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, GetProcessIdOfThread, OpenThread, ResumeThread,
    THREAD_QUERY_LIMITED_INFORMATION, THREAD_SUSPEND_RESUME,
};
use windows::core::PCWSTR;

pub struct ExecJob(OwnedHandle);

impl ExecJob {
    /// Put the command in its job before any workload code runs.
    ///
    /// A command that starts running before job assignment could launch a
    /// subprocess that survives a timeout. Starting suspended lets us keep
    /// Tokio's argument and pipe handling while assigning the command to its
    /// job before resuming it.
    pub(super) fn spawn(command: &mut Command) -> io::Result<(Child, Self)> {
        let job = Self::new()?;

        // Kill the child on setup failure, even before it joins the job.
        let child = command
            .creation_flags(CREATE_SUSPENDED.0)
            .kill_on_drop(true)
            .spawn()?;
        let process = child
            .raw_handle()
            .ok_or_else(|| io::Error::other("missing MXC exec process handle"))?;
        let pid = child
            .id()
            .ok_or_else(|| io::Error::other("missing MXC exec process ID"))?;
        // SAFETY: the child and the job own these handles throughout the call.
        unsafe { AssignProcessToJobObject(job.handle(), HANDLE(process)) }.map_err(|error| {
            io::Error::other(format!("assign process to MXC exec job: {error}"))
        })?;
        resume_initial_thread(pid)
            .map_err(|error| io::Error::other(format!("resume suspended MXC exec: {error}")))?;
        Ok((child, job))
    }

    fn new() -> io::Result<Self> {
        // SAFETY: the null arguments request an unnamed job with a
        // non-inheritable handle.
        let handle = unsafe { CreateJobObjectW(None, PCWSTR::null()) }.map_err(io::Error::from)?;
        // SAFETY: CreateJobObjectW returned a new handle. Transfer it once to
        // OwnedHandle, which will close it.
        let job = Self(unsafe { OwnedHandle::from_raw_handle(handle.0) });
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the job owns a valid handle and the buffer matches the info class.
        unsafe {
            SetInformationJobObject(
                job.handle(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .map_err(io::Error::other)?,
            )
        }
        .map_err(io::Error::from)?;
        Ok(job)
    }

    fn handle(&self) -> HANDLE {
        HANDLE(self.0.as_raw_handle())
    }

    pub(super) fn terminate(&self) -> io::Result<()> {
        // SAFETY: the job owns a valid handle. Termination does not close it.
        unsafe { TerminateJobObject(self.handle(), 1) }.map_err(io::Error::from)
    }
}

fn resume_initial_thread(pid: u32) -> io::Result<()> {
    // Tokio returns only the process handle. Find the suspended primary thread
    // using the Win32 thread snapshot.
    // SAFETY: snapshot creation has no pointer arguments and returns an owned handle.
    let snapshot =
        unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }.map_err(io::Error::from)?;
    // SAFETY: the snapshot call returned a new handle. OwnedHandle takes
    // sole responsibility for closing it.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot.0) };
    let mut entry = THREADENTRY32 {
        dwSize: u32::try_from(size_of::<THREADENTRY32>()).map_err(io::Error::other)?,
        ..Default::default()
    };
    let snapshot_handle = HANDLE(snapshot.as_raw_handle());
    // SAFETY: the snapshot is valid and entry is a writable, correctly sized buffer.
    unsafe { Thread32First(snapshot_handle, &raw mut entry) }.map_err(io::Error::from)?;
    while entry.th32OwnerProcessID != pid {
        // SAFETY: same handle and buffer as above. The API reports end of list as an error.
        unsafe { Thread32Next(snapshot_handle, &raw mut entry) }.map_err(io::Error::from)?;
    }
    // SAFETY: the call returns a new owned handle or an error.
    let thread = unsafe {
        OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
            false,
            entry.th32ThreadID,
        )
    }
    .map_err(io::Error::from)?;
    // SAFETY: OpenThread returned a new handle. OwnedHandle takes sole
    // responsibility for closing it.
    let thread = unsafe { OwnedHandle::from_raw_handle(thread.0) };
    let handle = HANDLE(thread.as_raw_handle());
    // SAFETY: the owned thread handle is open with query rights.
    if unsafe { GetProcessIdOfThread(handle) } != pid {
        return Err(io::Error::other(
            "MXC exec thread does not belong to its process",
        ));
    }
    // SAFETY: the thread handle is open with resume rights, and its owner
    // was verified above.
    match unsafe { ResumeThread(handle) } {
        1 => Ok(()),
        u32::MAX => Err(io::Error::last_os_error()),
        _ => Err(io::Error::other("unexpected MXC exec thread suspend count")),
    }
}
