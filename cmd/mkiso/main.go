package main

import (
"bytes"
"encoding/binary"
"fmt"
"os"
"path/filepath"
"strings"
)

func putBoth16(b []byte, v uint16) {
binary.LittleEndian.PutUint16(b[0:2], v)
binary.BigEndian.PutUint16(b[2:4], v)
}

func putBoth32(b []byte, v uint32) {
binary.LittleEndian.PutUint32(b[0:4], v)
binary.BigEndian.PutUint32(b[4:8], v)
}

// Extract a file from the existing Alpine ISO by matching its base name
func extractFromAlpineISO(iso []byte, target string) []byte {
pvdOff := 16 * 2048
rootRecord := iso[pvdOff+156 : pvdOff+156+34]
rootLBA := int(binary.LittleEndian.Uint32(rootRecord[2:6]))
rootLen := int(binary.LittleEndian.Uint32(rootRecord[10:14]))

visited := make(map[int]bool)
var found []byte

var walk func(lba, length int)
walk = func(lba, length int) {
if visited[lba] || lba <= 0 || found != nil {
return
}
visited[lba] = true
baseOff := lba * 2048
pos := 0
for pos < length {
recOff := baseOff + pos
recLen := int(iso[recOff])
if recLen == 0 {
nextSector := ((pos / 2048) + 1) * 2048
if nextSector >= length {
break
}
pos = nextSector
continue
}
extLBA := int(binary.LittleEndian.Uint32(iso[recOff+2 : recOff+6]))
extLen := int(binary.LittleEndian.Uint32(iso[recOff+10 : recOff+14]))
flags := iso[recOff+25]
nameLen := int(iso[recOff+32])
rawName := string(iso[recOff+33 : recOff+33+nameLen])
cleanRaw := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(rawName, ";1"), "."))

if rawName != "\x00" && rawName != "\x01" {
if (flags & 0x02) != 0 {
walk(extLBA, extLen)
} else if cleanRaw == target {
out := make([]byte, extLen)
copy(out, iso[extLBA*2048:extLBA*2048+extLen])
found = out
return
}
}
pos += recLen
}
}
walk(rootLBA, rootLen)
return found
}

func makeDirRecord(name string, lba, size uint32, isDir bool) []byte {
var id []byte
if name == "\x00" || name == "\x01" {
id = []byte(name)
} else if isDir {
id = []byte(name)
} else {
id = []byte(name + ";1")
}
recLen := 33 + len(id)
if recLen%2 == 1 {
recLen++
}
rec := make([]byte, recLen)
rec[0] = byte(recLen)
putBoth32(rec[2:10], lba)
putBoth32(rec[10:18], size)
if isDir {
rec[25] = 0x02
}
putBoth16(rec[28:32], 1) // Volume sequence number 1
rec[32] = byte(len(id))
copy(rec[33:], id)
return rec
}

func main() {
workDir := os.Args[1]
srcIsoPath := filepath.Join(workDir, "alpine-virt-3.20.0-x86_64.iso")
outIsoPath := filepath.Join(workDir, "PureGoHardened-Hybrid.iso")

alpineIso, err := os.ReadFile(srcIsoPath)
if err != nil {
panic(fmt.Errorf("failed to read alpine iso: %w", err))
}

isolinuxBin := extractFromAlpineISO(alpineIso, "isolinux.bin")
ldlinuxC32 := extractFromAlpineISO(alpineIso, "ldlinux.c32")
if isolinuxBin == nil || ldlinuxC32 == nil {
panic("failed to extract isolinux.bin or ldlinux.c32 from Alpine ISO")
}

vmlinuzBytes, err := os.ReadFile(filepath.Join(workDir, "vmlinuz-virt"))
if err != nil {
vmlinuzBytes = extractFromAlpineISO(alpineIso, "vmlinuz_virt")
if vmlinuzBytes == nil {
panic("failed to find vmlinuz-virt")
}
}

initramfsBytes, err := os.ReadFile(filepath.Join(workDir, "initramfs.cpio.gz"))
if err != nil {
panic(fmt.Errorf("failed to read initramfs.cpio.gz: %w", err))
}

fmt.Printf("[*] Building clean ISO with vmlinuz (%d bytes) and initramfs.cpio.gz (%d bytes)\n", len(vmlinuzBytes), len(initramfsBytes))

// Use short 8.3 uppercase filenames in root directory so ISOLINUX finds everything immediately without path/RockRidge issues
syslinuxCfg := []byte("SERIAL 0 115200\nDEFAULT linux\nPROMPT 0\nTIMEOUT 0\n\nLABEL linux\n  KERNEL /VMLINUZ\n  INITRD /INITRD.GZ\n  APPEND console=ttyS0,115200 earlyprintk=serial,ttyS0,115200 panic=-1\n")

// Layout of ISO sectors (2048 bytes each):
// 0..15: System area (isohdpfx.bin from Alpine ISO sector 0)
// 16: Primary Volume Descriptor (PVD)
// 17: El Torito Boot Record Volume Descriptor (BRVD)
// 18: Volume Descriptor Set Terminator (VDST)
// 19: Path Table (Little Endian)
// 20: Path Table (Big Endian)
// 21: Root Directory (1 sector = 2048 bytes)
// 22: Boot Catalog (1 sector = 2048 bytes)
// 23..: File extents (ISOLINUX.BIN, LDLINUX.C32, SYSLINUX.CFG, VMLINUZ, INITRD.GZ)

var iso bytes.Buffer
padSector := func() {
rem := iso.Len() % 2048
if rem != 0 {
iso.Write(make([]byte, 2048-rem))
}
}
curLBA := func() uint32 {
return uint32(iso.Len() / 2048)
}

// Reserve sectors 0..22 (23 sectors)
iso.Write(make([]byte, 23*2048))

// Prepare ISOLINUX.BIN (must have fresh zeroed hybrid/block area at 24..64 before patching boot-info-table)
isoBinCopy := make([]byte, len(isolinuxBin))
copy(isoBinCopy, isolinuxBin)
if len(isoBinCopy)%4 != 0 {
isoBinCopy = append(isoBinCopy, make([]byte, 4-(len(isoBinCopy)%4))...)
}

isolinuxLBA := curLBA()
isolinuxSize := uint32(len(isoBinCopy))

// Patch El Torito Boot Info Table into isolinux.bin at offset 8..64
for i := 8; i < 64; i++ {
isoBinCopy[i] = 0
}
var csum uint32
for i := 64; i < len(isoBinCopy); i += 4 {
csum += binary.LittleEndian.Uint32(isoBinCopy[i : i+4])
}
binary.LittleEndian.PutUint32(isoBinCopy[8:12], 16)           // bi_pvd: LBA 16
binary.LittleEndian.PutUint32(isoBinCopy[12:16], isolinuxLBA) // bi_file: LBA of isolinux.bin
binary.LittleEndian.PutUint32(isoBinCopy[16:20], isolinuxSize)
binary.LittleEndian.PutUint32(isoBinCopy[20:24], csum)

iso.Write(isoBinCopy)
padSector()

ldlinuxLBA := curLBA()
ldlinuxSize := uint32(len(ldlinuxC32))
iso.Write(ldlinuxC32)
padSector()

sysCfgLBA := curLBA()
sysCfgSize := uint32(len(syslinuxCfg))
iso.Write(syslinuxCfg)
padSector()

vmlinuzLBA := curLBA()
vmlinuzSize := uint32(len(vmlinuzBytes))
iso.Write(vmlinuzBytes)
padSector()

initrdLBA := curLBA()
initrdSize := uint32(len(initramfsBytes))
iso.Write(initramfsBytes)
padSector()

totalSectors := curLBA()
out := iso.Bytes()

// Write Root Directory at LBA 21
rootLBA := uint32(21)
rootSize := uint32(2048)
var rootDir bytes.Buffer
rootDir.Write(makeDirRecord("\x00", rootLBA, rootSize, true))
rootDir.Write(makeDirRecord("\x01", rootLBA, rootSize, true))
rootDir.Write(makeDirRecord("ISOLINUX.BIN", isolinuxLBA, isolinuxSize, false))
rootDir.Write(makeDirRecord("LDLINUX.C32", ldlinuxLBA, ldlinuxSize, false))
rootDir.Write(makeDirRecord("SYSLINUX.CFG", sysCfgLBA, sysCfgSize, false))
rootDir.Write(makeDirRecord("VMLINUZ", vmlinuzLBA, vmlinuzSize, false))
rootDir.Write(makeDirRecord("INITRD.GZ", initrdLBA, initrdSize, false))
copy(out[21*2048:], rootDir.Bytes())

// Write Path Tables at LBA 19 (LE) and LBA 20 (BE)
// Root path table entry is 10 bytes: len_di(1)=1, ext_attr(1)=0, lba(4), parent(2)=1, name(1)=0, pad(1)=0
ptLE := make([]byte, 10)
ptLE[0] = 1
binary.LittleEndian.PutUint32(ptLE[2:6], rootLBA)
binary.LittleEndian.PutUint16(ptLE[6:8], 1)
copy(out[19*2048:], ptLE)

ptBE := make([]byte, 10)
ptBE[0] = 1
binary.BigEndian.PutUint32(ptBE[2:6], rootLBA)
binary.BigEndian.PutUint16(ptBE[6:8], 1)
copy(out[20*2048:], ptBE)

// Write Boot Catalog at LBA 22
bootCatLBA := uint32(22)
cat := out[bootCatLBA*2048 : (bootCatLBA+1)*2048]
// Validation Entry (32 bytes)
cat[0] = 0x01 // Header ID
cat[1] = 0x00 // Platform 80x86
copy(cat[4:28], []byte("PUREGO HARDENED ISO     "))
cat[30] = 0x55
cat[31] = 0xAA
var wsum uint16
for i := 0; i < 32; i += 2 {
wsum += binary.LittleEndian.Uint16(cat[i : i+2])
}
binary.LittleEndian.PutUint16(cat[28:30], -wsum)

// Initial/Default Entry (32 bytes at offset 32)
cat[32] = 0x88 // Bootable
cat[33] = 0x00 // No emulation
binary.LittleEndian.PutUint16(cat[38:40], 4) // Load 4 virtual sectors (2048 bytes) per El Torito Isolinux spec
binary.LittleEndian.PutUint32(cat[40:44], isolinuxLBA)

// Write Primary Volume Descriptor (PVD) at LBA 16
pvd := out[16*2048 : 17*2048]
pvd[0] = 1
copy(pvd[1:6], "CD001")
pvd[6] = 1
copy(pvd[8:40], fmt.Sprintf("%-32s", "LINUX"))
copy(pvd[40:72], fmt.Sprintf("%-32s", "PUREGO_HARDENED"))
putBoth32(pvd[80:88], totalSectors)
putBoth16(pvd[120:124], 1)    // Volume Set Size
putBoth16(pvd[124:128], 1)    // Volume Sequence Number
putBoth16(pvd[128:132], 2048) // Logical Block Size
putBoth32(pvd[132:140], 10)   // Path Table Size
binary.LittleEndian.PutUint32(pvd[140:144], 19)
binary.BigEndian.PutUint32(pvd[148:152], 20)
rootRec := makeDirRecord("\x00", rootLBA, rootSize, true)
copy(pvd[156:156+len(rootRec)], rootRec)
pvd[881] = 1 // File Structure Version

// Write El Torito Boot Record Volume Descriptor (BRVD) at LBA 17
brvd := out[17*2048 : 18*2048]
brvd[0] = 0
copy(brvd[1:6], "CD001")
brvd[6] = 1
copy(brvd[7:39], "EL TORITO SPECIFICATION")
binary.LittleEndian.PutUint32(brvd[71:75], bootCatLBA)

// Write Volume Descriptor Set Terminator (VDST) at LBA 18
vdst := out[18*2048 : 19*2048]
vdst[0] = 255
copy(vdst[1:6], "CD001")
vdst[6] = 1

if err := os.WriteFile(outIsoPath, out, 0644); err != nil {
panic(err)
}
fmt.Printf("[+] Built clean bootable ISO from scratch: %s (%d bytes, %d sectors)\n", outIsoPath, len(out), totalSectors)
}


