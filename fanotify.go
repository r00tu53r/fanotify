//go:build linux
// +build linux

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
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
	val [2]int
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
	watchDir       string
	_m             unix.FanotifyEventMetadata
	ErrInvalidData = errors.New("i/o error: unexpected data length")
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

// watch watches only the specified directory
func watch(watchDir string) {
	var flags uint
	var fileStatusFlag uint
	var mask uint64
	var fd int

	// initialize fanotify
	flags = unix.FAN_CLASS_NOTIF | unix.FD_CLOEXEC | unix.FAN_REPORT_FID
	fileStatusFlag = unix.O_RDONLY | unix.O_CLOEXEC
	fd, errno := unix.FanotifyInit(flags, fileStatusFlag) // requires CAP_SYS_ADMIN
	if errno != nil {
		log.Fatalf("FanotifyInit: %v", errno)
	}
	// mark watch directory for events
	flags = unix.FAN_MARK_ADD | unix.FAN_MARK_DONT_FOLLOW | unix.FAN_MARK_ONLYDIR
	mask = unix.FAN_CREATE | unix.FAN_ATTRIB | unix.FAN_DELETE | unix.FAN_MODIFY
	mask = mask | unix.FAN_DELETE_SELF | unix.FAN_MOVED_FROM | unix.FAN_MOVED_TO
	mask = mask | unix.FAN_EVENT_ON_CHILD
	errno = unix.FanotifyMark(fd, flags, mask, unix.AT_FDCWD, watchDir)
	if errno != nil {
		log.Fatalf("FanotifyMark: %v", errno)
	}
	// poll for events
	var fds [1]unix.PollFd
	fds[0].Fd = int32(fd)
	fds[0].Events = unix.POLLIN
	log.Println("Listening to events on", watchDir)
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
		readEvents(fd)
	}
}

func FanotifyEventOK(meta *unix.FanotifyEventMetadata, n int) bool {
	return (n >= int(SizeOfFanotifyEventMetadata) &&
		meta.Event_len >= SizeOfFanotifyEventMetadata &&
		int(meta.Event_len) <= n)
}

func readEvents(fd int) error {
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
			fid = (*FanotifyEventInfoFID)(unsafe.Pointer(&buf[i+int(metadata.Metadata_len)]))
			switch {
			case fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_FID:
				log.Println("FAN_EVENT_INFO_TYPE_FID: identifies non directory object")
			case fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_DFID:
				log.Println("FAN_EVENT_INFO_TYPE_DFID: identifies parent object")
			}
			if fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_FID {
				// event from FAN_REPORT_FID
				fd, errno := unix.OpenByHandleAt(unix.AT_FDCWD, fid.fileHandle, unix.O_RDONLY)
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
			log.Println("FanotifyEventMetadata:", *metadata)
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
		if uint64(m)&mask == 1 {
			maskStr = append(maskStr, s)
		}
	}
	return strings.Join(maskStr, ",")
}
