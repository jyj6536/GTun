package event

import (
	"syscall"
)

func UnixListenerInit(unixPath string, backlog int) error {
	syscall.Unlink(unixPath)
	fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return err
	}

	err = syscall.SetNonblock(fd, true)
	if err != nil {
		return err
	}

	addr := &syscall.SockaddrUnix{Name: unixPath}
	err = syscall.Bind(fd, addr)
	if err != nil {
		return err
	}

	err = syscall.Listen(fd, backlog)
	if err != nil {
		return err
	}

	return AddFileEvent(int32(fd), unixAcceptHandler, nil, nil, syscall.EPOLLIN, UnixIndex)
}

func unixAcceptHandler(fd int32) {
	for nfd, _, err := syscall.Accept(int(fd)); err != syscall.EAGAIN; nfd, _, err = syscall.Accept(int(fd)) {
		err = syscall.SetNonblock(nfd, true)
		if err != nil {
			syscall.Close(nfd)
			continue
		}

		err = AddFileEvent(int32(nfd), unixReadHandler, unixWriteHandler, unixErrorHandler, syscall.EPOLLIN, UnixIndex)
		if err != nil {
			syscall.Close(nfd)
		}
	}
}

func unixReadHandler(fd int32) {
	fe, exist := FdProcs[fd]
	if !exist || fe.Err {
		return
	}
	n, err := syscall.Read(int(fd), fe.RBuf)
	if err != nil {
		fe.Err = true
		return
	}
	fe.RLen = n
	if readCallback[fe.CallbackIndex] != nil {
		readCallback[fe.CallbackIndex](fe, fd)
	}
}

func unixWriteHandler(fd int32) {
	fe, exist := FdProcs[fd]
	if !exist || fe.Err {
		return
	}
	if writeCallback[fe.CallbackIndex] != nil {
		writeCallback[fe.CallbackIndex](fe, fd)
	}
	_, err := syscall.Write(int(fd), fe.WBuf)
	if err != nil {
		fe.Err = true
		return
	}
	if !fe.MoreToSend {
		err := DisableEpollout(fd)
		if err != nil {
			fe.Err = true
		}
	}
}

func unixErrorHandler(fd int32) {
	fe, exist := FdProcs[fd]
	if exist {
		errorCallback[fe.CallbackIndex](fe, fd)
	}
}
