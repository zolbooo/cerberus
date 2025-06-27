# Create an encrypted volume on the running machine

This is a guide to create an encrypted volume on a running machine and resize the root partition.

References:

- https://unix.stackexchange.com/questions/226872/how-to-shrink-root-filesystem-without-booting-a-livecd/227318#227318
- https://help.ubuntu.com/community/Full_Disk_Encryption_Howto_2019

## Unmount unused partitions

```bash
umount -a
```

## Prepare a temporary root partition

```bash
mkdir /tmp/tmproot
mount -t tmpfs none /tmp/tmproot
mkdir /tmp/tmproot/{proc,sys,dev,run,usr,var,tmp,oldroot}
cp -ax /{bin,etc,mnt,sbin,lib,lib64,root} /tmp/tmproot/
cp -ax /usr/{bin,sbin,lib,lib64} /tmp/tmproot/usr/
cp -ax /var/{account,empty,lib,local,lock,nis,opt,preserve,run,spool,tmp,yp} /tmp/tmproot/var/
```

## Pivot into the temporary root partition

```bash
mount --make-rprivate /
pivot_root /tmp/tmproot /tmp/tmproot/oldroot
for i in dev proc sys run; do mount --move /oldroot/$i /$i; done
```

## Restart SSH daemon

```bash
systemctl restart sshd
systemctl status sshd
```

## Restart services using the temporary root partition

```bash
systemctl | grep running | awk '{print $1}' | xargs -I {} systemctl restart {}
systemctl daemon-reexec
fuser -vm /oldroot
```

## Unmount the old root partition

```bash
umount /oldroot
```

## Shrink the root partition

```bash
parted /dev/vda resizepart 1 15G
```

## Create a new partition

```bash
parted /dev/vda mkpart primary 15G 100%
```

## Remount root partition

```bash
mount /dev/vda1 /oldroot
mount --make-rprivate /
pivot_root /oldroot /oldroot/tmp/tmproot
for i in dev proc sys run; do mount --move /tmp/tmproot/$i /$i; done
```

## Restart SSH daemon

```bash
systemctl restart sshd
```

## Restart services using the temporary root partition

```bash
systemctl | grep running | awk '{print $1}' | xargs -I {} systemctl restart {}
systemctl daemon-reexec
fuser -vm /tmp/tmproot
```

## Dispose of the temporary root partition

```bash
umount /tmp/tmproot
rmdir /tmp/tmproot
```

## Restart failed services

```bash
systemctl | grep failed | awk '{print $1}' | xargs -I {} systemctl restart {}
systemctl | grep failed | awk '{print $2}' | xargs -I {} systemctl restart {}
```

## Restore the original root partition

```bash
mount --make-rshared /
```

## Prepare an encrypted volume

```bash
cryptsetup luksFormat /dev/vda2
```

## Unlock a LUKS volume

```bash
cryptsetup luksOpen /dev/vda2 vda2_crypt
```

## Format the encrypted volume

```bash
mkfs.ext4 /dev/mapper/vda2_crypt
```

## Mount the encrypted volume

```bash
mkdir /mnt/secure
mount /dev/mapper/vda2_crypt /mnt/secure
```
