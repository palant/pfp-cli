/*
 * This Source Code is subject to the terms of the Mozilla Public License
 * version 2.0 (the "License"). You can obtain a copy of the License at
 * http://mozilla.org/MPL/2.0/.
 */

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::Write;

struct LoggingAllocator {
    pub allocations: Option<std::sync::Mutex<Vec<(usize, backtrace::Backtrace)>>>,
}

impl LoggingAllocator {
    fn shutdown(&self) {
        if let Some(mutex) = &self.allocations {
            let mut file =
                std::fs::File::create(format!("alloc_{}.log", std::process::id())).unwrap();
            for (ptr, bt) in mutex.lock().unwrap().iter() {
                write!(file, "Allocation of {:x}:\n{:?}\n", ptr, bt).unwrap();
            }
        }
    }
}

unsafe impl GlobalAlloc for LoggingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ret = System.alloc(layout);
        if let Some(mutex) = &self.allocations {
            if let Ok(mut allocations) = mutex.try_lock() {
                allocations.push((ret as usize, backtrace::Backtrace::new()));
            }
        }
        ret
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static mut ALLOCATOR: LoggingAllocator = LoggingAllocator { allocations: None };

pub fn init_allocator() {
    unsafe {
        ALLOCATOR.allocations = Some(std::sync::Mutex::new(Vec::new()));
    }
}

pub fn shutdown_allocator() {
    unsafe {
        ALLOCATOR.shutdown();
    }
}
