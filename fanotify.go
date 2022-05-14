//go:build linux
// +build linux

package main

import (
	"bufio"
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
	fileHandle unix.FileHandle
}

var (
	watchDir            string
	_m                  unix.FanotifyEventMetadata
	ErrInvalidData      = errors.New("i/o error: unexpected data length")
	initFlags           uint
	initFileStatusFlags uint
	markFlags           uint
	markMaskFlags       uint64
)

const (
	SizeOfFanotifyEventMetadata = uint32(unsafe.Sizeof(_m))
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

// Mask function to help experiment with various mask settings
// - FAN_ACCESS with FAN_ONDIR does not notify file open/close operations
func Mask() (uint64, []string) {
	var maskTable = map[int]string{
		unix.FAN_ACCESS:         "Create an event when a file or directory (but see BUGS) is accessed (read)",
		unix.FAN_MODIFY:         "Create an event when a file is modified (write).",
		unix.FAN_ONDIR:          "Create events for directories when readdir, opendir, closedir are called",
		unix.FAN_EVENT_ON_CHILD: "Events for the immediate children of marked directories shall be created",
	}
	getDesc := func(m uint64) []string {
		var ret []string
		for k, v := range maskTable {
			if m&uint64(k) != 0 {
				ret = append(ret, v)
			}
		}
		return ret
	}
	// Trying FAN_ACCESS without FAN_REPORT_FID
	mask := uint64(unix.FAN_ACCESS | unix.FAN_MODIFY | unix.FAN_EVENT_ON_CHILD)
	desc := getDesc(mask)
	return mask, desc
}

// watch watches only the specified directory
func watch(watchDir string) {
	var fd int

	// initialize fanotify
	initFlags = unix.FAN_CLASS_NOTIF | unix.FD_CLOEXEC
	initFileStatusFlags = unix.O_RDONLY | unix.O_CLOEXEC
	fd, errno := unix.FanotifyInit(initFlags, initFileStatusFlags) // requires CAP_SYS_ADMIN
	if errno != nil {
		log.Fatalf("FanotifyInit: %v", errno)
	}

	// fanotify_mark
	markFlags = unix.FAN_MARK_ADD
	markMaskFlags, desc := Mask()
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
		// process events
		i := 0
		metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
		for FanotifyEventOK(metadata, n) {
			if metadata.Vers != unix.FANOTIFY_METADATA_VERSION {
				log.Fatalf("Incompatible fanotify version. Rebuild your code.")
			}
			// If fanotify_init was initialized with FAN_REPORT_FID then
			// expect metadata.Fd to be FAN_NOFD
			if initFlags&unix.FAN_REPORT_FID != 0 && metadata.Fd != unix.FAN_NOFD {
				log.Fatalf("Error FanotifyInit called with FAN_REPORT_FID. Unexpected Fd:", metadata.Fd)
			}
			if initFlags&unix.FAN_REPORT_FID != 0 {
				fid = (*FanotifyEventInfoFID)(unsafe.Pointer(&buf[i+int(metadata.Metadata_len)]))
				switch {
				case fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_FID:
					log.Println("FAN_EVENT_INFO_TYPE_FID: identifies non directory object")
				default:
					log.Fatalf("Unexpected InfoType %d expected %d", fid.Header.InfoType, unix.FAN_EVENT_INFO_TYPE_FID)
				}
				if fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_FID {
					// event from FAN_REPORT_FID
					log.Println("FAN_EVENT_INFO_TYPE_FID case")
					fd, errno := unix.OpenByHandleAt(mountFd, fid.fileHandle, unix.O_RDONLY)
					if errno != nil {
						log.Println("OpenByHandleAt:", errno)
						i += int(metadata.Event_len)
						n -= int(metadata.Event_len)
						metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
						continue
					}
					fdPath := fmt.Sprintf("/proc/self/fd/%d", fd)
					n1, errno := unix.Readlink(fdPath, name[:])
					fname := string(name[:n1])
					log.Printf("Path: %s; Mask: %s", fname, EventMask(metadata.Mask))
					unix.Close(fd)
				}
			}
			log.Println("FanotifyEventMetadata:", *metadata)
			if metadata.Fd != unix.FAN_NOFD {
				procFdPath := fmt.Sprintf("/proc/self/fd/%d", metadata.Fd)
				n1, errno := unix.Readlink(procFdPath, name[:])
				if errno != nil {
					log.Fatalf("Readlink for path %s failed %v", procFdPath, errno)
				}
				fname := string(name[:n1])
				log.Printf("Path: %s; Mask: %s", fname, EventMask(metadata.Mask))
			}
			i += int(metadata.Event_len)
			n -= int(metadata.Event_len)
			metadata = (*unix.FanotifyEventMetadata)(unsafe.Pointer(&buf[i]))
		}
	}
}

var masks = map[int]string{
	unix.FAN_ACCESS:        "access",
	unix.FAN_MODIFY:        "modify",
	unix.FAN_CLOSE_WRITE:   "close-write",
	unix.FAN_CLOSE_NOWRITE: "close-no-write",
	unix.FAN_OPEN:          "open",
	unix.FAN_OPEN_EXEC:     "exec",
	unix.FAN_ATTRIB:        "attrib",
	unix.FAN_CREATE:        "create",
	unix.FAN_DELETE:        "delete",
	unix.FAN_DELETE_SELF:   "delete-self",
	unix.FAN_MOVED_FROM:    "moved-from",
	unix.FAN_MOVED_TO:      "moved-to",
	unix.FAN_MOVE_SELF:     "move-self",
}

func EventMask(mask uint64) string {
	var maskStr []string
	for m, s := range masks {
		if uint64(m)&mask != 0 {
			maskStr = append(maskStr, s)
		}
	}
	return strings.Join(maskStr, ",")
}
