// Copyright 2016-2020 Chang Lan
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use libc::*;
use std::io::{Read, Write};
use std::mem;
use std::os::fd::{AsRawFd, RawFd};
#[cfg(target_os = "macos")]
use std::os::fd::FromRawFd;
use std::{fs, io};

const MTU: i32 = 1380;
const IFNAMSIZ: usize = 16;

// Interface ioctl request numbers (Linux / BSD share these values).
const SIOCGIFFLAGS: c_ulong = 0x8913;
const SIOCSIFFLAGS: c_ulong = 0x8914;
const SIOCSIFADDR: c_ulong = 0x8916;
const SIOCSIFDSTADDR: c_ulong = 0x8918;
const SIOCSIFNETMASK: c_ulong = 0x891c;
const SIOCSIFMTU: c_ulong = 0x8922;

#[cfg(target_os = "linux")]
use std::path;
#[cfg(target_os = "linux")]
const IFF_TUN: c_short = 0x0001;
#[cfg(target_os = "linux")]
const IFF_NO_PI: c_short = 0x1000;
#[cfg(all(target_os = "linux", target_env = "musl"))]
const TUNSETIFF: c_int = 0x400454ca;
#[cfg(all(target_os = "linux", not(target_env = "musl")))]
const TUNSETIFF: c_ulong = 0x400454ca;

#[cfg(target_os = "macos")]
const AF_SYS_CONTROL: u16 = 2;
#[cfg(target_os = "macos")]
const AF_SYSTEM: u8 = 32;
#[cfg(target_os = "macos")]
const PF_SYSTEM: c_int = AF_SYSTEM as c_int;
#[cfg(target_os = "macos")]
const SYSPROTO_CONTROL: c_int = 2;
#[cfg(target_os = "macos")]
const UTUN_OPT_IFNAME: c_int = 2;
#[cfg(target_os = "macos")]
const CTLIOCGINFO: c_ulong = 0xc0644e03;
#[cfg(target_os = "macos")]
const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

/// Minimal `ifreq`-compatible layout for address / flags / MTU ioctls.
///
/// The kernel only inspects `ifr_name` plus the active member of the union; we
/// store address payloads as a full `sockaddr_in` and flags/mtu as integer
/// views over the same trailing storage.
#[repr(C)]
struct IfReq {
    ifr_name: [u8; IFNAMSIZ],
    ifr_ifru: IfReqData,
}

#[repr(C)]
union IfReqData {
    addr: sockaddr_in,
    flags: c_short,
    mtu: c_int,
    /// Padding so the union is at least as large as the kernel's `ifr_ifru`.
    _pad: [u8; 24],
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct TunSetIffReq {
    ifr_name: [u8; IFNAMSIZ],
    ifr_flags: c_short,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

pub struct Tun {
    handle: fs::File,
    if_name: String,
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.handle.as_raw_fd()
    }
}

/// RAII wrapper around a datagram socket used only for interface ioctls.
struct IoctlSocket {
    fd: RawFd,
}

impl IoctlSocket {
    fn open() -> io::Result<Self> {
        let fd = unsafe { socket(AF_INET, SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    fn ioctl(&self, request: c_ulong, req: &mut IfReq) -> io::Result<()> {
        let res = unsafe { ioctl(self.fd, request, req as *mut IfReq) };
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

impl Drop for IoctlSocket {
    fn drop(&mut self) {
        unsafe {
            close(self.fd);
        }
    }
}

fn ifreq_named(if_name: &str) -> IfReq {
    let mut ifr_name = [0u8; IFNAMSIZ];
    let bytes = if_name.as_bytes();
    let len = bytes.len().min(IFNAMSIZ - 1);
    ifr_name[..len].copy_from_slice(&bytes[..len]);
    IfReq {
        ifr_name,
        ifr_ifru: IfReqData { _pad: [0; 24] },
    }
}

fn ipv4_sockaddr(octets: [u8; 4]) -> sockaddr_in {
    let mut addr: sockaddr_in = unsafe { mem::zeroed() };
    addr.sin_family = AF_INET as _;
    // `sin_addr` is network byte order.
    addr.sin_addr = in_addr {
        s_addr: u32::from_ne_bytes(octets),
    };
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    {
        addr.sin_len = mem::size_of::<sockaddr_in>() as u8;
    }
    addr
}

fn configure_interface(if_name: &str, self_id: u8) -> io::Result<()> {
    let sock = IoctlSocket::open()?;
    let ip = [10, 10, 10, self_id];
    let netmask = [255, 255, 255, 0];

    // Address: 10.10.10.{self_id}
    let mut req = ifreq_named(if_name);
    req.ifr_ifru.addr = ipv4_sockaddr(ip);
    sock.ioctl(SIOCSIFADDR, &mut req)?;

    // On macOS utun we set the destination to the VPN gateway; on Linux TUN we
    // mirror the local address. Ignore failure: some kernels reject this ioctl
    // on non-P2P interfaces.
    let mut req = ifreq_named(if_name);
    let dst = if cfg!(target_os = "macos") {
        [10, 10, 10, 1]
    } else {
        ip
    };
    req.ifr_ifru.addr = ipv4_sockaddr(dst);
    let _ = sock.ioctl(SIOCSIFDSTADDR, &mut req);

    // Netmask: /24
    let mut req = ifreq_named(if_name);
    req.ifr_ifru.addr = ipv4_sockaddr(netmask);
    sock.ioctl(SIOCSIFNETMASK, &mut req)?;

    // MTU
    let mut req = ifreq_named(if_name);
    req.ifr_ifru.mtu = MTU;
    sock.ioctl(SIOCSIFMTU, &mut req)?;

    // Bring the interface up (preserve existing flags, add IFF_UP | IFF_RUNNING).
    let mut req = ifreq_named(if_name);
    sock.ioctl(SIOCGIFFLAGS, &mut req)?;
    let flags = unsafe { req.ifr_ifru.flags } | IFF_UP as c_short | IFF_RUNNING as c_short;
    let mut req = ifreq_named(if_name);
    req.ifr_ifru.flags = flags;
    sock.ioctl(SIOCSIFFLAGS, &mut req)?;

    Ok(())
}

impl Tun {
    #[cfg(target_os = "linux")]
    pub fn create(name: u8) -> Result<Tun, io::Error> {
        let path = path::Path::new("/dev/net/tun");
        let file = fs::OpenOptions::new().read(true).write(true).open(path)?;

        let mut req = TunSetIffReq {
            ifr_name: {
                let mut buffer = [0u8; IFNAMSIZ];
                let full_name = format!("tun{}", name);
                buffer[..full_name.len()].copy_from_slice(full_name.as_bytes());
                buffer
            },
            ifr_flags: IFF_TUN | IFF_NO_PI,
        };

        let res = unsafe { ioctl(file.as_raw_fd(), TUNSETIFF, &mut req) };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }

        let size = req.ifr_name.iter().position(|&r| r == 0).unwrap();
        Ok(Tun {
            handle: file,
            if_name: String::from_utf8(req.ifr_name[..size].to_vec()).unwrap(),
        })
    }

    #[cfg(target_os = "macos")]
    pub fn create(name: u8) -> Result<Tun, io::Error> {
        let handle = {
            let fd = unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            unsafe { fs::File::from_raw_fd(fd) }
        };

        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: {
                let mut buffer = [0u8; 96];
                buffer[..UTUN_CONTROL_NAME.len()].copy_from_slice(UTUN_CONTROL_NAME.as_bytes());
                buffer
            },
        };

        let res = unsafe { ioctl(handle.as_raw_fd(), CTLIOCGINFO, &mut info) };
        if res != 0 {
            return Err(io::Error::last_os_error());
        }

        let addr = SockaddrCtl {
            sc_id: info.ctl_id,
            sc_len: mem::size_of::<SockaddrCtl>() as u8,
            sc_family: AF_SYSTEM,
            ss_sysaddr: AF_SYS_CONTROL,
            sc_unit: name as u32 + 1,
            sc_reserved: [0; 5],
        };

        let res = unsafe {
            let addr_ptr = &addr as *const SockaddrCtl;
            connect(
                handle.as_raw_fd(),
                addr_ptr as *const sockaddr,
                mem::size_of_val(&addr) as socklen_t,
            )
        };
        if res != 0 {
            return Err(io::Error::last_os_error());
        }

        let mut name_buf = [0u8; 64];
        let mut name_length: socklen_t = 64;
        let res = unsafe {
            getsockopt(
                handle.as_raw_fd(),
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                &mut name_buf as *mut _ as *mut c_void,
                &mut name_length as *mut socklen_t,
            )
        };
        if res != 0 {
            return Err(io::Error::last_os_error());
        }

        let res = unsafe { fcntl(handle.as_raw_fd(), F_SETFL, O_NONBLOCK) };
        if res == -1 {
            return Err(io::Error::last_os_error());
        }

        let res = unsafe { fcntl(handle.as_raw_fd(), F_SETFD, FD_CLOEXEC) };
        if res == -1 {
            return Err(io::Error::last_os_error());
        }

        let len = name_buf.iter().position(|&r| r == 0).unwrap();
        Ok(Tun {
            handle,
            if_name: String::from_utf8(name_buf[..len].to_vec()).unwrap(),
        })
    }

    pub fn name(&self) -> &str {
        &self.if_name
    }

    /// Assign `10.10.10.{self_id}/24`, set MTU, and bring the interface up via
    /// direct ioctl — no external `ifconfig`/`ip` dependency.
    pub fn up(&self, self_id: u8) {
        configure_interface(&self.if_name, self_id)
            .unwrap_or_else(|e| panic!("failed to configure {}: {}", self.if_name, e));
    }
}

impl Read for Tun {
    #[cfg(target_os = "linux")]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handle.read(buf)
    }

    #[cfg(target_os = "macos")]
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut data = [0u8; 1600];
        let result = self.handle.read(&mut data);
        match result {
            Ok(len) => {
                buf[..len - 4].copy_from_slice(&data[4..len]);
                Ok(len.saturating_sub(4))
            }
            Err(e) => Err(e),
        }
    }
}

impl Write for Tun {
    #[cfg(target_os = "linux")]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handle.write(buf)
    }

    #[cfg(target_os = "macos")]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ip_v = buf[0] & 0xf;
        let mut data: Vec<u8> = if ip_v == 6 {
            vec![0, 0, 0, 10]
        } else {
            vec![0, 0, 0, 2]
        };
        data.write_all(buf).unwrap();
        match self.handle.write(&data) {
            Ok(len) => Ok(len.saturating_sub(4)),
            Err(e) => Err(e),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.handle.flush()
    }
}

#[cfg(test)]
mod tests {
    use crate::device::*;
    use crate::utils;
    use std::fs;

    #[test]
    fn create_tun_test() {
        if !utils::is_root() {
            eprintln!("skipping create_tun_test: requires root");
            return;
        }

        let tun = Tun::create(10).unwrap();
        let name = tun.name();

        // Interface should appear under /sys/class/net without needing ifconfig.
        #[cfg(target_os = "linux")]
        {
            let sys_path = format!("/sys/class/net/{}", name);
            assert!(
                fs::metadata(&sys_path).is_ok(),
                "expected interface {} to exist at {}",
                name,
                sys_path
            );
        }

        tun.up(1);
    }
}
