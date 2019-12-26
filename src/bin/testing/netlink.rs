//
//   Copyright 2019 Delphix
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//

use nix::sys::socket::{AddressFamily, SockAddr, SockType, bind};
use nix::errno::Errno;

use std::fs::File;
use std::os::raw::c_int;

extern crate nix;

const NETLINK_ROUTE: c_int = 0;

fn main() {
    // Use libc crate directly instead of nix because nix's 'socket' method doesn't have ability to
    // specify netlink socket protocol.
    let fd = unsafe {
        libc::socket(AddressFamily::Netlink as c_int,
        SockType::Datagram as c_int,
        NETLINK_ROUTE)
    };

    let fd = Errno::result(fd).unwrap();

    bind(fd, &SockAddr::new_netlink(0, 0)).unwrap();

    // Signal parent process (the test process) that this process is ready to be observed by the
    // ptool being tested.
    File::create("/tmp/ptools-test-ready").unwrap();

    // Wait for the parent finish running the ptool and then kill us.
    loop {}
}

