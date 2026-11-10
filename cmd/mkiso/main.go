package main

import (
"bytes"
"encoding/binary"
"fmt"
"os"
"path/filepath"
"strings"
)

func extractFileFromISO(iso []byte, target string) []byte {
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

func putBoth32(b []byte, v uint32) {
binary.LittleEndian.PutUint32(b[0:4], v)
binary.BigEndian.PutUint32(b[4:8], v)
}

func putBoth16(b []byte, v uint16) {
binary.LittleEndian.PutUint16(b[0:2], v)
binary.BigEndian.PutUint16(b[2:4], v)
}

func makeDirRecord(name string, lba uint32, size uint32, isDir bool) []byte {
var nameBytes []byte
if name == "\x00" || name == "\x01" {
nameBytes = []byte(name)
} else {
nameBytes = []byte(name)
}
recLen := 33 + len(nameBytes)
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
putBoth16(rec[28:32], 1)
rec[32] = byte(len(nameBytes))
copy(rec[33:], nameBytes)
return rec
}

func main() {
workDir := "."
if len(os.Args) > 1 {
workDir = os.Args[1]
}

alpineIso, err := os.ReadFile(filepath.Join(workDir, "alpine-virt-3.20.0-x86_64.iso"))
if err != nil {
panic(err)
}

isolinuxBin := extractFileFromISO(alpineIso, "isolinux.bin")
ldlinuxC32 := extractFileFromISO(alpineIso, "ldlinux.c32")
if isolinuxBin == nil || ldlinuxC32 == nil {
panic("failed to extract isolinux.bin or ldlinux.c32 from Alpine ISO")
}

vmlinuz, err := os.ReadFile(filepath.Join(workDir, "vmlinuz-virt"))
if err != nil {
panic(err)
}
initramfs, err := os.ReadFile(filepath.Join(workDir, "initramfs.cpio.gz"))
if err != nil {
panic(err)
}
isolinuxCfg := []byte("DEFAULT linux\nLABEL linux\n  KERNEL /vmlinuz\n  INITRD /initrd.gz\n  APPEND console=ttyS0 console=tty0 quiet\n")

const sectorSize = 2048
sectorsFor := func(n int) int {
if n == 0 {
return 1
}
return (n + sectorSize - 1) / sectorSize
}

rootDirLBA := uint32(19)
bootCatLBA := uint32(20)
isolinuxBinLBA := uint32(21)
ldlinuxLBA := isolinuxBinLBA + uint32(sectorsFor(len(isolinuxBin)))
cfgLBA := ldlinuxLBA + uint32(sectorsFor(len(ldlinuxC32)))
vmlinuzLBA := cfgLBA + uint32(sectorsFor(len(isolinuxCfg)))
initrdLBA := vmlinuzLBA + uint32(sectorsFor(len(vmlinuz)))
totalSectors := initrdLBA + uint32(sectorsFor(len(initramfs))) + 16

iso := make([]byte, int(totalSectors)*sectorSize)

// Patch boot info table into isolinux.bin
isoBinCopy := make([]byte, len(isolinuxBin))
copy(isoBinCopy, isolinuxBin)
binary.LittleEndian.PutUint32(isoBinCopy[8:12], 16)
binary.LittleEndian.PutUint32(isoBinCopy[12:16], isolinuxBinLBA)
binary.LittleEndian.PutUint32(isoBinCopy[16:20], uint32(len(isoBinCopy)))
var csum uint32
for i := 64; i+4 <= len(isoBinCopy); i += 4 {
csum += binary.LittleEndian.Uint32(isoBinCopy[i : i+4])
}
binary.LittleEndian.PutUint32(isoBinCopy[20:24], csum)

// Root directory
var rootBuf bytes.Buffer
rootBuf.Write(makeDirRecord("\x00", rootDirLBA, sectorSize, true))
rootBuf.Write(makeDirRecord("\x01", rootDirLBA, sectorSize, true))
rootBuf.Write(makeDirRecord("BOOT.CAT;1", bootCatLBA, 2048, false))
rootBuf.Write(makeDirRecord("ISOLINUX.BIN;1", isolinuxBinLBA, uint32(len(isoBinCopy)), false))
rootBuf.Write(makeDirRecord("LDLINUX.C32;1", ldlinuxLBA, uint32(len(ldlinuxC32)), false))
rootBuf.Write(makeDirRecord("ISOLINUX.CFG;1", cfgLBA, uint32(len(isolinuxCfg)), false))
rootBuf.Write(makeDirRecord("VMLINUZ.;1", vmlinuzLBA, uint32(len(vmlinuz)), false))
rootBuf.Write(makeDirRecord("INITRD.GZ;1", initrdLBA, uint32(len(initramfs)), false))
copy(iso[int(rootDirLBA)*sectorSize:], rootBuf.Bytes())

// PVD (Sector 16)
pvd := iso[16*sectorSize : 17*sectorSize]
pvd[0] = 1
copy(pvd[1:6], "CD001")
pvd[6] = 1
copy(pvd[8:40], fmt.Sprintf("%-32s", "LINUX"))
copy(pvd[40:72], fmt.Sprintf("%-32s", "PUREGO_HARDENED"))
putBoth32(pvd[80:88], totalSectors)
putBoth16(pvd[120:124], 1)
putBoth16(pvd[124:128], 1)
putBoth16(pvd[128:132], sectorSize)
rootRec := makeDirRecord("\x00", rootDirLBA, sectorSize, true)
copy(pvd[156:156+len(rootRec)], rootRec)

// El Torito Boot Record (Sector 17)
br := iso[17*sectorSize : 18*sectorSize]
br[0] = 0
copy(br[1:6], "CD001")
br[6] = 1
copy(br[7:39], "EL TORITO SPECIFICATION")
binary.LittleEndian.PutUint32(br[71:75], bootCatLBA)

// Volume Descriptor Set Terminator (Sector 18)
term := iso[18*sectorSize : 19*sectorSize]
term[0] = 255
copy(term[1:6], "CD001")
term[6] = 1

// Boot Catalog (Sector 20)
cat := iso[int(bootCatLBA)*sectorSize : int(bootCatLBA+1)*sectorSize]
cat[0] = 1
cat[30] = 0x55
cat[31] = 0xAA
var sum uint16
for i := 0; i < 32; i += 2 {
sum += binary.LittleEndian.Uint16(cat[i : i+2])
}
binary.LittleEndian.PutUint16(cat[28:30], uint16(0)-sum)
cat[32] = 0x88
binary.LittleEndian.PutUint16(cat[38:40], 4)
binary.LittleEndian.PutUint32(cat[40:44], isolinuxBinLBA)

// Write payloads
copy(iso[int(isolinuxBinLBA)*sectorSize:], isoBinCopy)
copy(iso[int(ldlinuxLBA)*sectorSize:], ldlinuxC32)
copy(iso[int(cfgLBA)*sectorSize:], isolinuxCfg)
copy(iso[int(vmlinuzLBA)*sectorSize:], vmlinuz)
copy(iso[int(initrdLBA)*sectorSize:], initramfs)

outPath := filepath.Join(workDir, "purego-appliance.iso")
if err := os.WriteFile(outPath, iso, 0644); err != nil {
panic(err)
}
fmt.Printf("[+] Built bootable purego-appliance.iso (%d bytes)\n", len(iso))
}
