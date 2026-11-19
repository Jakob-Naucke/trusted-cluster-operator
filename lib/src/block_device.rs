// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use blockdev::{BlockDevice, DeviceType, parse_lsblk};

/// Finds the block device backing the `/sysroot` mount, given the output of `lsblk -J`.
pub fn find_root_device(lsblk_output: &str) -> Result<String> {
    let devices = parse_lsblk(lsblk_output).context("failed to parse lsblk output")?;
    let is_root = |m: &str| m == "/sysroot";
    let has_root_mount = |d: &BlockDevice| {
        d.device_type == DeviceType::Crypt && d.active_mountpoints_iter().any(is_root)
    };
    let has_root_child = |d: &&BlockDevice| d.children_iter().any(has_root_mount);
    let ctx = "no block device's child mounted at /sysroot";
    let dev = devices.iter_all().find(has_root_child).context(ctx)?;
    Ok(dev.name.clone())
}
