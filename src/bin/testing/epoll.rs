use nix::sys::epoll;
use nix::unistd::pipe2;
use nix::fcntl::OFlag;

use std::fs::File;

extern crate nix;

fn main() {

    let (readfd, _writefd) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).unwrap();

    let epollfd = epoll::epoll_create().unwrap();
    let mut event = epoll::EpollEvent::new(epoll::EpollFlags::EPOLLIN, 0);
    epoll::epoll_ctl(epollfd, epoll::EpollOp::EpollCtlAdd, readfd, Some(&mut event)).unwrap();

    // Signal parent process (the test process) that this process is ready to be observed by the
    // ptool being tested.
    File::create("/tmp/ptools-test-ready").unwrap();

    // Wait for the parent finish running the ptool and then kill us.
    loop {}
}

