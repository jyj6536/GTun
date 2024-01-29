package event

import (
	"syscall"
	"time"
)

const (
	MinConnections       = 512
	RBufMaxLen           = 65535
	WBufMaxLen           = 65535
	HeaderLen            = 4
	CallbackNum          = 4
	TcpIndex             = 0
	TunIndex             = 1
	IcmpIndex            = 2
	UnixIndex            = 3
	INT64_MAX      int64 = 9223372036854775807
)

var readCallback [CallbackNum]Callback
var writeCallback [CallbackNum]Callback
var errorCallback [CallbackNum]Callback

type Callback func(*FileEvent, int32)
type FileProc func(int32)
type TimeProc func(interface{})

var FdProcs map[int32]*FileEvent = map[int32]*FileEvent{}

var currTimeCached int64

func GetCurrentTime() int64 {
	return currTimeCached
}

func setCurrentTime() {
	currTimeCached = time.Now().UnixNano() / int64(time.Millisecond)
}

type FileEvent struct {
	Mask                uint32
	RProc, WProc, EPorc FileProc
	CallbackIndex       int
	RBuf                []byte
	ReadingContent      bool
	RLen                int
	RCnt                int
	Err                 bool
	WLen                int
	WCnt                int
	WBuf                []byte
	WHeaderBuf          []byte
	WritingContent      bool
	MoreToSend          bool
	Addr                syscall.Sockaddr
}

type TimeEvent struct {
	When       int64
	ClientData interface{}
	TProc      TimeProc
	Next       *TimeEvent
}

var timeEventHead *TimeEvent = &TimeEvent{}

/*
when: timeout after when seconds
clientData: user specified data
tProc: callbacl function
*/
func AddTimeEvent(when int64, clientData interface{}, tProc TimeProc) *TimeEvent {
	te := &TimeEvent{When: when*1000 + currTimeCached, ClientData: clientData, TProc: tProc}
	te.Next = timeEventHead.Next
	timeEventHead.Next = te
	return te
}

func DelTimeEvent(te *TimeEvent) {
	te.Next = te.Next.Next
}

type EventLoop struct {
	Epfd   int
	Events []syscall.EpollEvent
}

var el = &EventLoop{}

func EventInit(connections int, rCallback, wCallback, eCallback [CallbackNum]Callback) error {
	for i := 0; i < CallbackNum; i++ {
		readCallback[i] = rCallback[i]
		writeCallback[i] = wCallback[i]
		errorCallback[i] = eCallback[i]
	}
	var err error
	el.Epfd, err = syscall.EpollCreate1(syscall.EPOLL_CLOEXEC)
	if err != nil {
		return err
	}
	if connections == 0 || connections < MinConnections {
		connections = MinConnections
	}
	el.Events = make([]syscall.EpollEvent, connections)
	return nil
}

func EventRun() {
	for {
		var timeout = INT64_MAX
		for node := timeEventHead; node.Next != nil; node = node.Next {
			if timeout > node.Next.When {
				timeout = node.Next.When
			}
		}
		if timeout == INT64_MAX {
			timeout = -1
		} else {
			timeout = timeout - currTimeCached
		}
		n, _ := syscall.EpollWait(el.Epfd, el.Events, int(timeout))
		if n == -1 {
			continue
		}
		setCurrentTime()
		for i := 0; i < n; i++ {
			fd := el.Events[i].Fd
			fe := FdProcs[fd]
			if el.Events[i].Events&(syscall.EPOLLERR|syscall.EPOLLHUP|syscall.EPOLLRDHUP) != 0 {
				fe.Err = true
			}
			if el.Events[i].Events&syscall.EPOLLIN != 0 {
				if fe.RProc != nil {
					fe.RProc(fd)
				}
			}
			if el.Events[i].Events&syscall.EPOLLOUT != 0 {
				if fe.WProc != nil {
					fe.WProc(fd)
				}
			}
			if fe.Err {
				if fe.EPorc != nil {
					fe.EPorc(fd)
				}
			}
		}
		for node := timeEventHead; node.Next != nil; {
			if currTimeCached > node.Next.When {
				node.Next.TProc(node.Next.ClientData)
				DelTimeEvent(node)
			} else {
				node = node.Next
			}
		}
	}
}

func AddFileEvent(fd int32, rp, wp, ep FileProc, mask uint32, callbackIndex int) error {
	var op int
	e := &syscall.EpollEvent{Fd: fd}
	fe, exist := FdProcs[fd]
	if exist {
		fe.Mask = mask
		e.Events = fe.Mask
		op = syscall.EPOLL_CTL_MOD
	} else {
		e.Events = mask
		e.Fd = fd
		fe = &FileEvent{Mask: mask, RProc: rp, WProc: wp, EPorc: ep, CallbackIndex: callbackIndex}
		fe.RBuf = make([]byte, RBufMaxLen)
		fe.WBuf = make([]byte, WBufMaxLen)
		op = syscall.EPOLL_CTL_ADD
		FdProcs[fd] = fe
	}
	return syscall.EpollCtl(el.Epfd, op, int(fd), e)
}

func DelFileEvent(fd int32) {
	delete(FdProcs, fd)
	syscall.EpollCtl(el.Epfd, syscall.EPOLL_CTL_DEL, int(fd), &syscall.EpollEvent{Fd: fd})
}

func DisableEpollout(fd int32) error {
	fe := FdProcs[fd]
	if fe.Mask&syscall.EPOLLOUT == 0 {
		return nil
	}
	e := &syscall.EpollEvent{Fd: fd}
	fe.Mask &= ^uint32(syscall.EPOLLOUT)
	e.Events = fe.Mask
	return syscall.EpollCtl(el.Epfd, syscall.EPOLL_CTL_MOD, int(fd), e)
}

func EnableEpollout(fd int32) error {
	fe := FdProcs[fd]
	if fe.Mask&syscall.EPOLLOUT != 0 {
		return nil
	}
	e := &syscall.EpollEvent{Fd: fd}
	fe.Mask |= syscall.EPOLLOUT
	e.Events = fe.Mask
	return syscall.EpollCtl(el.Epfd, syscall.EPOLL_CTL_MOD, int(fd), e)
}
