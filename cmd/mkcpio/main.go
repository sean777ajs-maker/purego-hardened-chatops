package main

import (
"bytes"
"compress/gzip"
"encoding/binary"
"fmt"
"io"
"os"
"path/filepath"
"strings"
)

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

func writeCpioEntry(buf *bytes.Buffer, name string, mode uint32, data []byte, ino uint32) {
nameBytes := append([]byte(name), 0)
hdr := fmt.Sprintf("070701%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X%08X",
ino, mode, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nameBytes), 0)
buf.WriteString(hdr)
buf.Write(nameBytes)
for buf.Len()%4 != 0 {
buf.WriteByte(0)
}
buf.Write(data)
for buf.Len()%4 != 0 {
buf.WriteByte(0)
}
}

func main() {
workDir := os.Args[1]
alpineIso, err := os.ReadFile(filepath.Join(workDir, "alpine-virt-3.20.0-x86_64.iso"))
if err != nil {
panic(err)
}
vmlinuz := extractFromAlpineISO(alpineIso, "vmlinuz_virt")
if vmlinuz == nil {
vmlinuz = extractFromAlpineISO(alpineIso, "vmlinuz-virt")
}
if err := os.WriteFile(filepath.Join(workDir, "vmlinuz-virt"), vmlinuz, 0644); err != nil {
panic(err)
}

baseInitrd := extractFromAlpineISO(alpineIso, "initramfs_virt")
if baseInitrd == nil {
baseInitrd = extractFromAlpineISO(alpineIso, "initramfs-virt")
}

initBin, err := os.ReadFile(filepath.Join(workDir, "init"))
if err != nil {
panic(err)
}

var cpioBuf bytes.Buffer
writeCpioEntry(&cpioBuf, "init", 0100755, initBin, 99999)
writeCpioEntry(&cpioBuf, "TRAILER!!!", 0, nil, 0)

var overlayGz bytes.Buffer
gw := gzip.NewWriter(&overlayGz)
if _, err := io.Copy(gw, &cpioBuf); err != nil {
panic(err)
}
gw.Close()

combined := append(baseInitrd, overlayGz.Bytes()...)
if err := os.WriteFile(filepath.Join(workDir, "initramfs.cpio.gz"), combined, 0644); err != nil {
panic(err)
}
fmt.Printf("[+] Packed concatenated initramfs.cpio.gz (%d bytes total)\n", len(combined))
}
