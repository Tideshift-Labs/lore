// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::ffi::CString;
use std::ffi::c_char;

use lore_revision::fs::filesystem_provider::FileInfo;
use lore_revision::fs::swfs::api_interface::swfs_api::SWFSFile;
use lore_revision::fs::swfs::file::SwfsFile;
use lore_revision::fs::swfs::file::SwfsFileArray;

#[test]
fn swfs_file_sizing() {
    let files = SwfsFileArray::new(vec![
        SwfsFile::new(CString::new("a").unwrap(), &FileInfo::NotExist, None).unwrap(),
        SwfsFile::new(CString::new("b").unwrap(), &FileInfo::NotExist, None).unwrap(),
    ]);
    let file_a = files.array_ptr();
    unsafe {
        let file_b = (*file_a).next;
        assert!(std::ptr::addr_eq(file_a.offset(1), file_b));
        assert_eq!(size_of::<SwfsFile>(), size_of::<SWFSFile>());
        assert_eq!(*(*file_a).path, 'a' as c_char);
        assert_eq!(*(*file_a).path.offset(1), '\0' as c_char);
        assert_eq!(*(*file_b).path, 'b' as c_char);
        assert_eq!(*(*file_b).path.offset(1), '\0' as c_char);
    }
}
