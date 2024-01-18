package event

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"time"
)

func TcpListenerInit(ip string, port int, backlog int) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}

	err = syscall.SetNonblock(fd, true)
	if err != nil {
		return err
	}

	addr := syscall.SockaddrInet4{Port: port}
	copy(addr.Addr[:], net.ParseIP(ip))

	err = syscall.Bind(fd, &addr)
	if err != nil {
		return err
	}

	err = syscall.Listen(fd, backlog)
	if err != nil {
		return err
	}

	return AddFileEvent(int32(fd), tcpAccetpHandler, nil, nil, syscall.EPOLLIN, 0)
}

func tcpAccetpHandler(fd int32) {
	for nfd, _, err := syscall.Accept(int(fd)); err != syscall.EAGAIN; nfd, _, err = syscall.Accept(int(fd)) {
		err = syscall.SetNonblock(nfd, true)
		if err != nil {
			syscall.Close(nfd)
			continue
		}

		err = AddFileEvent(int32(nfd), tcpReadHandler, tcpWriteHandler, tcpErrorHandler, syscall.EPOLLIN|syscall.EPOLLRDHUP, TcpIndex)
		if err != nil {
			syscall.Close(nfd)
			continue
		}
	}
}

func tcpReadHandler(fd int32) {
	fe, exist := FdProcs[fd]
	if !exist || fe.Err {
		return
	}
	if len(fe.RBuf) == 0 {
		fe.RBuf = make([]byte, HeaderLen)
		fe.RLen = HeaderLen
		fe.RCnt = 0
		fe.ReadingContent = false
	}
	for fe.RCnt < fe.RLen {
		n, err := syscall.Read(int(fd), fe.RBuf[fe.RCnt:])
		if n == 0 || err != nil {
			/*
				n==0 connection is closed
				err == EAGAIN wait for more data
				err != EAGAIN and err != nil connection encountered an error
			*/
			if err == syscall.EAGAIN {
				return
			}
			fe.Err = true
			return
		}
		fe.RCnt += n
	}
	if !fe.ReadingContent {
		fe.RCnt = 0
		fe.RLen = int(binary.LittleEndian.Uint32(fe.RBuf))

		if fe.RLen > RBufMaxLen { //bad header
			fe.Err = true
			return
		}

		fe.RBuf = make([]byte, fe.RLen)
		fe.ReadingContent = true
		return
	}
	//now, invoke a data processing function
	if readCallback[fe.CallbackIndex] != nil {
		readCallback[fe.CallbackIndex](fe, fd)
	}
	fe.RBuf = nil
}

func tcpWriteHandler(fd int32) {
	fe, exist := FdProcs[fd]
	if !exist || fe.Err {
		return
	}
	//now, invoke a data processing function
	if writeCallback[fe.CallbackIndex] != nil {
		writeCallback[fe.CallbackIndex](fe, fd)
	}
	if fe.WBuf != nil {
		if fe.WHeaderBuf == nil {
			fe.WLen = HeaderLen
			fe.WCnt = 0
			fe.WHeaderBuf = make([]byte, HeaderLen)
			binary.LittleEndian.PutUint32(fe.WHeaderBuf, uint32(len(fe.WBuf)))
		}
		for fe.WCnt < fe.WLen {
			var n int
			var err error
			if fe.WritingContent {
				n, err = syscall.Write(int(fd), fe.WBuf[fe.WCnt:])
			} else {
				n, err = syscall.Write(int(fd), fe.WHeaderBuf[fe.WCnt:])
			}
			if n == 0 || err != nil {
				/*
					n==0 connection is closed
					err == EAGAIN wait for more data
					err != EAGAIN and err != nil connection encountered an error
				*/
				if err == syscall.EAGAIN {
					return
				}
				fe.Err = true
				return
			}
			fe.WCnt += n
		}
		if !fe.WritingContent {
			fe.WCnt = 0
			fe.WLen = len(fe.WBuf)

			if fe.WLen > WBufMaxLen { //too long to send
				fe.Err = true
				return
			}

			fe.WritingContent = true
			return
		}
		fe.WBuf = nil
		fe.WHeaderBuf = nil
		fe.WritingContent = false
		if !fe.MoreToSend {
			err := DisableEpollout(fd)
			if err != nil {
				fe.Err = true
				return
			}
		}
	}
}

func tcpErrorHandler(fd int32) {
	// DelFileEvent(fd)
	// syscall.Close(int(fd))
	fe, exist := FdProcs[fd]
	if exist {
		errorCallback[fe.CallbackIndex](fe, fd)
	}
}

func TcpWrite(conn net.TCPConn, data []byte, timeout int) error {
	dataLen := len(data)
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, uint32(dataLen))
	len := 4
	currLen := 0
	for currLen < len {
		if timeout > 0 {
			err := conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
			if err != nil {
				return err
			}
		}
		n, err := conn.Write(lenBuf[currLen:])
		if err != nil {
			return err
		}
		currLen += n
	}
	len = dataLen
	currLen = 0
	for currLen < len {
		if timeout > 0 {
			err := conn.SetWriteDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
			if err != nil {
				return err
			}
		}
		n, err := conn.Write(data[currLen:len])
		if err != nil {
			return err
		}
		currLen += n
	}

	//reset writedeadline for tcp conn
	if timeout > 0 {
		err := conn.SetWriteDeadline(time.Time{})
		if err != nil {
			return err
		}
	}
	return nil
}

func TcpRead(conn net.TCPConn, data []byte, timeout int) (int, error) {
	dataLen := make([]byte, 4)
	len := 4
	currLen := 0
	for currLen < len {
		if timeout > 0 {
			err := conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
			if err != nil {
				return 0, err
			}
		}
		n, err := conn.Read(dataLen[currLen:4])
		if err != nil {
			return 0, err
		}
		currLen += n
	}
	len = int(binary.LittleEndian.Uint32(dataLen))
	if len > cap(data) {
		return 0, errors.New("bad request")
	}
	currLen = 0
	for currLen < len {
		if timeout > 0 {
			err := conn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(timeout)))
			if err != nil {
				return 0, err
			}
		}
		n, err := conn.Read(data[currLen:len])
		if err != nil {
			return 0, err
		}
		currLen += n
	}

	//reset readdeadline for tcp conn
	if timeout > 0 {
		err := conn.SetReadDeadline(time.Time{})
		if err != nil {
			return 0, nil
		}
	}
	return len, nil
}
