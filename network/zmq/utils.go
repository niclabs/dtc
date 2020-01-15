package zmq

import (
	"github.com/niclabs/dtcnode/v3/message"
	"time"
)

// doForNTimeout listens for N messages from a channel, or until a timeout is raised.
// It only counts the messages without error.
func doForNTimeout(ch chan *message.Message, n int, timeout time.Duration, fn func(*message.Message) error) error {
	timer := time.After(timeout)
	acked := 0
	for {
		select {
		case msg := <-ch:
			if err := fn(msg); err != nil {
				continue // Ignores the message
			}
			acked++
			if acked == n {
				return nil
			}
		case <-timer:
			return TimeoutError
		}
	}
}
