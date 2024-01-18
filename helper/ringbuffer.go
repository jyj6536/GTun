package helper

type RingBuffer[T any] struct {
	buffer  []T
	maxSize int
	head    int
	tail    int
	full    bool
}

func RingBufferCreate[T any](size int) *RingBuffer[T] {
	return &RingBuffer[T]{
		buffer:  make([]T, size),
		maxSize: size,
		head:    0,
		tail:    0,
		full:    false,
	}
}

func (rb *RingBuffer[T]) Write(value T) {
	if rb.full {
		rb.head = (rb.head + 1) % rb.maxSize
	}
	rb.buffer[rb.tail] = value
	rb.tail = (rb.tail + 1) % rb.maxSize
	rb.full = rb.head == rb.tail
}

func (rb *RingBuffer[T]) Read() (T, bool) {
	if !rb.full && rb.head == rb.tail {
		return rb.buffer[0], false
	}
	value := rb.buffer[rb.head]
	rb.head = (rb.head + 1) % rb.maxSize
	rb.full = false
	return value, true
}

func (rb *RingBuffer[T]) IsEmpty() bool {
	return !rb.full && rb.tail == rb.head
}
