/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use std::alloc::{GlobalAlloc, Layout, System};

struct LeakingAllocator;

unsafe impl GlobalAlloc for LeakingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static mut ALLOCATOR: LeakingAllocator = LeakingAllocator;
