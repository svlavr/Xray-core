package pubsub

import (
	"errors"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/common/task"
)

type Subscriber struct {
	buffer chan interface{}
	done   *done.Instance
}

func (s *Subscriber) push(msg interface{}) {
	select {
	case s.buffer <- msg:
	default:
	}
}

func (s *Subscriber) Wait() <-chan interface{} {
	return s.buffer
}

func (s *Subscriber) Close() error {
	return s.done.Close()
}

func (s *Subscriber) IsClosed() bool {
	return s.done.Done()
}

type Service struct {
	sync.RWMutex
	subs      map[string][]*Subscriber
	ctask     *task.Periodic
	closed    bool
	closeOnce sync.Once
	closeErr  error
}

func NewService() *Service {
	s := &Service{
		subs: make(map[string][]*Subscriber),
	}
	s.ctask = &task.Periodic{
		Execute:  s.Cleanup,
		Interval: time.Second * 30,
	}
	return s
}

// Cleanup cleans up internal caches of subscribers.
// Visible for testing only.
func (s *Service) Cleanup() error {
	s.Lock()
	defer s.Unlock()

	if len(s.subs) == 0 {
		return errors.New("nothing to do")
	}

	for name, subs := range s.subs {
		newSub := make([]*Subscriber, 0, len(s.subs))
		for _, sub := range subs {
			if !sub.IsClosed() {
				newSub = append(newSub, sub)
			}
		}
		if len(newSub) == 0 {
			delete(s.subs, name)
		} else {
			s.subs[name] = newSub
		}
	}

	if len(s.subs) == 0 {
		s.subs = make(map[string][]*Subscriber)
	}
	return nil
}

func (s *Service) Subscribe(name string) *Subscriber {
	sub := &Subscriber{
		buffer: make(chan interface{}, 16),
		done:   done.New(),
	}
	s.Lock()
	if s.closed {
		s.Unlock()
		_ = sub.Close()
		return sub
	}
	s.subs[name] = append(s.subs[name], sub)
	s.Unlock()
	common.Must(s.ctask.Start())
	return sub
}

func (s *Service) Publish(name string, message interface{}) {
	s.RLock()
	defer s.RUnlock()
	if s.closed {
		return
	}

	for _, sub := range s.subs[name] {
		if !sub.IsClosed() {
			sub.push(message)
		}
	}
}

func (s *Service) SignalStop() {
	if s == nil {
		return
	}
	s.Lock()
	if s.closed {
		s.Unlock()
		return
	}
	s.closed = true
	var subscribers []*Subscriber
	for _, group := range s.subs {
		subscribers = append(subscribers, group...)
	}
	s.subs = make(map[string][]*Subscriber)
	s.Unlock()
	for _, subscriber := range subscribers {
		_ = subscriber.Close()
	}
	_ = s.ctask.Close()
}

func (s *Service) CloseAndWait() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.SignalStop()
		s.closeErr = s.ctask.CloseAndWait()
	})
	return s.closeErr
}
