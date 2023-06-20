# A Backdoor Locksmith

This tool is a rewrite of my [backdoor lockpick](https://github.com/oblivia-simplex/backdoor-lockpick) for backdoors
on Phicomm routers. For details on the Phicomm backdoors, including an analysis and reconstructed history of the
Phicomm backdoor protocol, and analysis of (what was at the time of discovery) a 0-day vulnerability in every 
iteration of the Phicomm backdoor, see [my writeup on the Tenable Techblog](https://medium.com/tenable-techblog/a-backdoor-lockpick-d847a83f4496) or my [talk at REcon Montreal, 2023](https://cfp.recon.cx/2023/talk/JBQEMS/), the slides for which can be found in the `slides/` directory.


## Demos and Testing

Requirements: fzf, qemu, wget, tar, telnet

If you trust me, you can go into the `demo/` directory and run `getfw.sh`. This will grab a tarball containing my Phicomm router firmware collection from a private server, and unpack it. It will unpack it as root, so as to populate the various `dev/*` special character block devices.

Then you can run `run.sh` in the `demo/` directory. This will present you with an `fzf` menu where you can choose a firmware image to test against. 

You can then run the locksmith tool in another terminal with

```
RUST_LOG=trace cargo run -- -t 127.0.0.1 -p $RELEVANT_PROTOCOL
```

Due to limitations with the QEMU emulator, you won't actually get a shell on most of these images, but you should either see "illegal instruction" errors popping up in the terminal where `run.sh` is running -- these occur on certain MIPS VMs when the process tries to issue the `clone()` system call. If you see this, this means that the attack worked. On other images, you'll be greeted with a telnet login that immediately crashes. This, too, means you've won.


