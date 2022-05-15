//go:build linux
// +build linux

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
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

func fileAccessedOrModified() (uint, uint64) {
	flags := uint(unix.FAN_CLASS_NOTIF | unix.FD_CLOEXEC)
	mask := uint64(unix.FAN_ACCESS | unix.FAN_MODIFY | unix.FAN_EVENT_ON_CHILD)
	return flags, mask
}

func fileOrDirCreated() (uint, uint64) {
	flags := uint(unix.FAN_CLASS_NOTIF | unix.FD_CLOEXEC | unix.FAN_REPORT_FID)
	mask := uint64(unix.FAN_CREATE | unix.FAN_EVENT_ON_CHILD | unix.FAN_ONDIR)
	return flags, mask
}

func Mask(mask uint64) []string {
	var maskTable = map[int]string{
		unix.FAN_ACCESS:         "Create an event when a file or directory (but see BUGS) is accessed (read)",
		unix.FAN_MODIFY:         "Create an event when a file is modified (write).",
		unix.FAN_ONDIR:          "Create events for directories when readdir, opendir, closedir are called",
		unix.FAN_EVENT_ON_CHILD: "Events for the immediate children of marked directories shall be created",
		unix.FAN_CLOSE_WRITE:    "Create an event when a writable file is closed.",
		unix.FAN_CLOSE_NOWRITE:  "Create an event when a read-only file or directory is closed.",
		unix.FAN_OPEN:           "Create an event when a file or directory is opened.",
		unix.FAN_OPEN_EXEC:      "Create  an  event  when a file is opened with the intent to be executed.",
		unix.FAN_ATTRIB:         "Create an event when the metadata for a file or directory has changed.",
		unix.FAN_CREATE:         "Create an event when a file or directory has been created in a marked parent directory.",
		unix.FAN_DELETE:         "Create an event when a file or directory has been deleted in a marked parent directory.",
		unix.FAN_DELETE_SELF:    "Create an event when a marked file or directory itself is deleted.",
		unix.FAN_MOVED_FROM:     "Create an event when a file or directory has been moved from a marked parent directory.",
		unix.FAN_MOVED_TO:       "Create an event when a file or directory has been moved to a marked parent directory.",
		unix.FAN_MOVE_SELF:      "Create an event when a marked file or directory itself has been moved.",
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
	desc := getDesc(mask)
	return desc
}

// watch watches only the specified directory
func watch(watchDir string) {
	var fd int

	initFlags, markMaskFlags = fileOrDirCreated()

	// initialize fanotify certain flags need CAP_SYS_ADMIN
	initFileStatusFlags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_LARGEFILE
	fd, errno := unix.FanotifyInit(initFlags, initFileStatusFlags)
	if errno != nil {
		log.Fatalf("FanotifyInit: %v", errno)
	}

	// fanotify_mark
	markFlags = unix.FAN_MARK_ADD
	desc := Mask(markMaskFlags)
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

func debugFIDStruct(metadata *unix.FanotifyEventMetadata, buf []byte, i int) *unix.FileHandle {

	log.Println("***** FID BUFFER DUMP START *****")
	// buffer test - start
	fidBuffer := bytes.Buffer{}
	var idx uint32
	var jidx uint32
	idx = uint32(i) + uint32(metadata.Metadata_len)
	sizeOfFanotifyEventInfoHeader := uint32(unsafe.Sizeof(FanotifyEventInfoHeader{}))
	for jidx < sizeOfFanotifyEventInfoHeader {
		fidBuffer.WriteByte(buf[idx])
		idx += 1
		jidx += 1
	}
	log.Printf("FID.Header (%d) bytes. Idx: %d", sizeOfFanotifyEventInfoHeader, idx)
	log.Print(hex.Dump(fidBuffer.Bytes()))

	fidBuffer2 := bytes.Buffer{}
	jidx = 0
	sizeOfKernelFSIDType := uint32(unsafe.Sizeof(jidx) * 2)
	for jidx < sizeOfKernelFSIDType {
		fidBuffer2.WriteByte(buf[idx])
		idx += 1
		jidx += 1
	}
	log.Printf("FID.FSID (%d) bytes. Idx: %d", sizeOfKernelFSIDType, idx)
	log.Println(hex.Dump(fidBuffer2.Bytes()))

	var fhSize uint32
	fidBuffer3 := bytes.Buffer{}
	sizeOfUint32 := uint32(unsafe.Sizeof(fhSize)) // filehandle.size
	jidx = 0
	for jidx < sizeOfUint32 {
		fidBuffer3.WriteByte(buf[idx])
		idx += 1
		jidx += 1
	}
	log.Printf("FID.file_handle.handle_bytes (%d) bytes, idx: %d", sizeOfUint32, idx)
	log.Println(hex.Dump(fidBuffer3.Bytes()))
	binary.Read(bytes.NewReader(fidBuffer3.Bytes()), binary.LittleEndian, &fhSize)
	log.Println("FID.file_handle.handle_bytes =", fhSize)

	var fhType int32
	sizeOfInt32 := uint32(unsafe.Sizeof(fhType)) // filehandle.type
	fidBuffer4 := bytes.Buffer{}
	jidx = 0
	for jidx < sizeOfInt32 {
		fidBuffer4.WriteByte(buf[idx])
		idx += 1
		jidx += 1
	}
	log.Printf("FID.file_handle.handle_type (%d) bytes, idx: %d", sizeOfInt32, idx)
	log.Println(hex.Dump(fidBuffer4.Bytes()))
	binary.Read(bytes.NewReader(fidBuffer4.Bytes()), binary.LittleEndian, &fhType)
	log.Println("FID.filehandle.handle_type =", fhType)

	fidBuffer5 := bytes.Buffer{}
	jidx = 0
	for jidx < fhSize {
		fidBuffer5.WriteByte(buf[idx])
		idx += 1
		jidx += 1
	}
	log.Printf("FID.file_handle.handle idx: %d", idx)
	log.Println(hex.Dump(fidBuffer5.Bytes()))
	handle := unix.NewFileHandle(fhType, fidBuffer5.Bytes())

	// buffer test - end
	log.Println("***** FID BUFFER DUMP END *****")

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
				log.Println("FID (Struct):", fid)
				var handle *unix.FileHandle
				handle = debugFIDStruct(metadata, buf[:], i)
				log.Print("Handle:")
				log.Print("Handle.Type:", handle.Type())
				log.Print("Handle.Size:", handle.Size())
				log.Print("Handle.Bytes:", handle.Bytes())
				switch {
				case fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_FID:
					log.Println("FAN_EVENT_INFO_TYPE_FID: identifies non directory object")
				default:
					log.Fatalf("Unexpected InfoType %d expected %d", fid.Header.InfoType, unix.FAN_EVENT_INFO_TYPE_FID)
				}
				if fid.Header.InfoType == unix.FAN_EVENT_INFO_TYPE_FID {
					// event from FAN_REPORT_FID
					log.Println("FAN_EVENT_INFO_TYPE_FID case")
					log.Println("handle type:", handle.Type())
					log.Println("handle size:", handle.Size())
					log.Printf("handle bytes: %v", hex.Dump(handle.Bytes()))

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
