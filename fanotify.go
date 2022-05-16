//go:build linux
// +build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

/* Variable length info record following event metadata */
type FanotifyEventInfoHeader struct {
	InfoType uint8
	pad      uint8
	Len      uint16
}

type kernelFSID struct {
	val [2]int32
}

// Unique file identifier info record.
// This structure is used for records of types FAN_EVENT_INFO_TYPE_FID,
// FAN_EVENT_INFO_TYPE_DFID and FAN_EVENT_INFO_TYPE_DFID_NAME.
// For FAN_EVENT_INFO_TYPE_DFID_NAME there is additionally a null terminated
// name immediately after the file handle.
type FanotifyEventInfoFID struct {
	Header FanotifyEventInfoHeader
	fsid   kernelFSID
	// Following is an opaque struct file_handle that can be passed as
	// an argument to open_by_handle_at(2).
	fileHandle byte
}

var (
	watchDir            string
	ErrInvalidData      = errors.New("i/o error: unexpected data length")
	initFlags           uint
	initFileStatusFlags uint
	markFlags           uint
	markMaskFlags       uint64
)

const (
	SizeOfFanotifyEventMetadata = uint32(unsafe.Sizeof(unix.FanotifyEventMetadata{}))
)

func init() {
	flag.StringVar(&watchDir, "watchdir", "", "path to directory to be watched")
}

func usage() {
	fmt.Printf("%s -watchdir /directory/to/monitor\n", os.Args[0])
}

func main() {
	flag.Parse()
	if watchDir == "" {
		usage()
		os.Exit(1)
	}
	watch(watchDir)
}

// fileAccessedOrModified raises event when
// (1) "file" is created or modified under the monitored directory.
// The metadata.Fd is the file descriptor to the file created/modified.
// (2) "file" is read
func fileAccessedOrModified() (uint, uint64) {
	flags := uint(unix.FAN_CLASS_NOTIF | unix.FD_CLOEXEC)
	mask := uint64(unix.FAN_ACCESS | unix.FAN_MODIFY | unix.FAN_EVENT_ON_CHILD)
	return flags, mask
}

// fileCloseWriteNoWrite raises event when
// (1) "file" is accessed / read and closed then "close-no-write" is
// raised.
// (2) "file" is written or updated and closed then "close-write" is
// raised.
// NOTE multiple close-no-writes are raised for files opened by editors
func fileCloseWriteNoWrite() (uint, uint64) {
	flags := uint(unix.FAN_CLASS_NOTIF | unix.FD_CLOEXEC)
	mask := uint64(unix.FAN_CLOSE_WRITE | unix.FAN_CLOSE_NOWRITE | unix.FAN_EVENT_ON_CHILD)
	return flags, mask
}

// fileOpenExec raises event when
// (1) if "file" is opened raises FAN_OPEN
// (2) if "file" is executed raises FAN_OPEN and FAN_OPEN_EXEC
func fileOpenExec() (uint, uint64) {
	flags := uint(unix.FAN_CLASS_NOTIF | unix.FD_CLOEXEC)
	mask := uint64(unix.FAN_OPEN | unix.FAN_OPEN_EXEC | unix.FAN_EVENT_ON_CHILD)
	return flags, mask
}

// fileOrDirCreated raises event when "file" or "directory" is created under
// the monitored directory. The FileHandle only has information about the
// parent path and not the child that was created.
//
// NOTE (Caveat) the subdirectory created is not returned. Hence it does not
// seem possible to selectively monitor subdirectories. The only
// option is to use FAN_MARK_MOUNT or FAN_MARK_FILESYSTEM and then selectively
// ignore
func fileOrDirCreated() (uint, uint64) {
	flags := uint(unix.FAN_CLASS_NOTIF | unix.FD_CLOEXEC | unix.FAN_REPORT_FID)
	mask := uint64(unix.FAN_CREATE | unix.FAN_EVENT_ON_CHILD | unix.FAN_ONDIR)
	return flags, mask
}

func MaskValues(m uint64) []string {
	return mask(m, true)
}

func MaskDescriptions(m uint64) []string {
	return mask(m, false)
}

func mask(mask uint64, values bool) []string {
	var maskTable = map[int]struct {
		value string
		desc  string
	}{
		unix.FAN_ACCESS: {
			"access",
			"Create an event when a file or directory (but see BUGS) is accessed (read)",
		},
		unix.FAN_MODIFY: {
			"modify",
			"Create an event when a file is modified (write).",
		},
		unix.FAN_ONDIR: {
			"ondir",
			"Create events for directories when readdir, opendir, closedir are called",
		},
		unix.FAN_EVENT_ON_CHILD: {
			"onchild",
			"Events for the immediate children of marked directories shall be created",
		},
		unix.FAN_CLOSE_WRITE: {
			"close-write",
			"Create an event when a writable file is closed.",
		},
		unix.FAN_CLOSE_NOWRITE: {
			"close-no-write",
			"Create an event when a read-only file or directory is closed.",
		},
		unix.FAN_OPEN: {
			"open",
			"Create an event when a file or directory is opened.",
		},
		unix.FAN_OPEN_EXEC: {
			"exec",
			"Create an event when a file is opened with the intent to be executed.",
		},
		unix.FAN_ATTRIB: {
			"attrib",
			"Create an event when the metadata for a file or directory has changed.",
		},
		unix.FAN_CREATE: {
			"create",
			"Create an event when a file or directory has been created in a marked parent directory.",
		},
		unix.FAN_DELETE: {
			"delete",
			"Create an event when a file or directory has been deleted in a marked parent directory.",
		},
		unix.FAN_DELETE_SELF: {
			"delete-self",
			"Create an event when a marked file or directory itself is deleted.",
		},
		unix.FAN_MOVED_FROM: {
			"moved-from",
			"Create an event when a file or directory has been moved from a marked parent directory.",
		},
		unix.FAN_MOVED_TO: {
			"moved-to",
			"Create an event when a file or directory has been moved to a marked parent directory.",
		},
		unix.FAN_MOVE_SELF: {
			"move-self",
			"Create an event when a marked file or directory itself has been moved.",
		},
	}
	maskValues := func(m uint64) []string {
		var ret []string
		for k, v := range maskTable {
			if m&uint64(k) != 0 {
				if values {
					ret = append(ret, v.value)
				} else {
					ret = append(ret, v.desc)
				}
			}
		}
		return ret
	}
	return maskValues(mask)
}

// watch watches only the specified directory
func watch(watchDir string) {
	var fd int

	initFlags, markMaskFlags = fileOpenExec()

	// initialize fanotify certain flags need CAP_SYS_ADMIN
	initFileStatusFlags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_LARGEFILE
	fd, errno := unix.FanotifyInit(initFlags, initFileStatusFlags)
	if errno != nil {
		log.Fatalf("FanotifyInit: %v", errno)
	}

	// fanotify_mark
	markFlags = unix.FAN_MARK_ADD
	desc := MaskDescriptions(markMaskFlags)
	errno = unix.FanotifyMark(fd, markFlags, markMaskFlags, -1, watchDir)
	if errno != nil {
		log.Fatalf("FanotifyMark: %v", errno)
	}
	// poll for events
	var fds [1]unix.PollFd
	fds[0].Fd = int32(fd)
	fds[0].Events = unix.POLLIN

	// determine mount_id
	_, mountID, errno := unix.NameToHandleAt(-1, watchDir, unix.AT_SYMLINK_FOLLOW)
	if errno != nil {
		log.Fatalf("NameToHandleAt:", errno)
	}

	// get mount_fd from the mount_id
	mountInfo, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		log.Fatalf("Error opening /proc/self/mountinfo:", err)
	}
	scanner := bufio.NewScanner(mountInfo)
	scanner.Split(bufio.ScanLines)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	mountInfo.Close()

	var mountPoint string
	for _, line := range lines {
		toks := strings.Split(line, " ")
		if toks[0] == strconv.Itoa(mountID) {
			log.Println("Found mount entry:", line)
			mountPoint = toks[4] // 5th entry is the mount point
			break
		}
	}
	mountFd, err := unix.Open(mountPoint, unix.O_RDONLY|unix.O_DIRECTORY, unix.S_IRUSR)
	if err != nil {
		log.Fatalf("Error opening:", mountPoint, err)
	}

	log.Println("Listening to events on", watchDir)
	for _, d := range desc {
		log.Println(d)
	}
	for {
		n, errno := unix.Poll(fds[:], -1) // blocking
		if n == 0 {
			continue
		}
		if errno != nil {
			if errno == unix.EINTR {
				continue
			}
			log.Fatalf("Poll: %v", errno)
		}
		readEvents(fd, mountFd)
	}
}

func FanotifyEventOK(meta *unix.FanotifyEventMetadata, n int) bool {
	return (n >= int(SizeOfFanotifyEventMetadata) &&
		meta.Event_len >= SizeOfFanotifyEventMetadata &&
		int(meta.Event_len) <= n)
}

func getFileHandle(metadataLen uint16, buf []byte, i int) *unix.FileHandle {
	var fhSize uint32
	var fhType int32

	sizeOfFanotifyEventInfoHeader := uint32(unsafe.Sizeof(FanotifyEventInfoHeader{}))
	sizeOfKernelFSIDType := uint32(unsafe.Sizeof(kernelFSID{}))
	sizeOfUint32 := uint32(unsafe.Sizeof(fhSize))
	j := uint32(i) + uint32(metadataLen) + sizeOfFanotifyEventInfoHeader + sizeOfKernelFSIDType
	binary.Read(bytes.NewReader(buf[j:j+sizeOfUint32]), binary.LittleEndian, &fhSize)
	j += sizeOfUint32
	binary.Read(bytes.NewReader(buf[j:j+sizeOfUint32]), binary.LittleEndian, &fhType)
	j += sizeOfUint32
	handle := unix.NewFileHandle(fhType, buf[j:j+fhSize])
	return &handle
}

func readEvents(fd, mountFd int) error {
	var fid *FanotifyEventInfoFID
	var buf [4096 * SizeOfFanotifyEventMetadata]byte
	var metadata *unix.FanotifyEventMetadata
	var name [unix.PathMax]byte

	for {
		n, errno := unix.Read(fd, buf[:])
		if errno == unix.EINTR {
			continue
		}
		switch {
		case n == 0:
			return io.EOF
		case n < int(SizeOfFanotifyEventMetadata):
			return ErrInvalidData
		case errno != nil:
			return errno
		}
		i := 0
		metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
		for FanotifyEventOK(metadata, n) {
			if metadata.Vers != unix.FANOTIFY_METADATA_VERSION {
				log.Fatalf("Incompatible fanotify version. Rebuild your code.")
			}
			// If FanotifyInit was initialized with FAN_REPORT_FID then
			// expect metadata.Fd to be FAN_NOFD
			if initFlags&unix.FAN_REPORT_FID != 0 && metadata.Fd != unix.FAN_NOFD {
				log.Fatalf("Error FanotifyInit called with FAN_REPORT_FID. Unexpected Fd:", metadata.Fd)
			}
			if initFlags&unix.FAN_REPORT_FID != 0 {
				log.Print("init flag has FAN_REPORT_FID set.")
				fid = (*FanotifyEventInfoFID)(unsafe.Pointer(&buf[i+int(metadata.Metadata_len)]))
				handle := getFileHandle(metadata.Metadata_len, buf[:], i)
				log.Printf("Handle type (%d), size (%d), bytes (%v)", handle.Type(), handle.Size(), handle.Bytes())
				if fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_FID {
					fd, errno := unix.OpenByHandleAt(mountFd, *handle, unix.O_RDONLY)
					if errno != nil {
						log.Println("OpenByHandleAt:", errno)
						i += int(metadata.Event_len)
						n -= int(metadata.Event_len)
						metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
						continue
					}
					fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
					n1, errno := unix.Readlink(fdPath, name[:])
					log.Printf("Path: %s; Mask: %s", string(name[:n1]), MaskValues(metadata.Mask))
					unix.Close(fd)
				} else {
					log.Fatalf("Unexpected InfoType %d expected %d", fid.Header.InfoType, unix.FAN_EVENT_INFO_TYPE_FID)
				}
			}
			if metadata.Fd != unix.FAN_NOFD {
				log.Print("init flag does not have FAN_REPORT_FID set.")
				procFdPath := fmt.Sprintf("/proc/self/fd/%d", metadata.Fd)
				n1, errno := unix.Readlink(procFdPath, name[:])
				if errno != nil {
					log.Fatalf("Readlink for path %s failed %v", procFdPath, errno)
				}
				log.Printf("Path: %s; Mask: %s", string(name[:n1]), MaskValues(metadata.Mask))
			}
			i += int(metadata.Event_len)
			n -= int(metadata.Event_len)
			metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
		}
	}
}
