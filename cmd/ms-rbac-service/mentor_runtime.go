package main

import (
	"context"
	"crypto/tls"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/example/ms-rbac-service/internal/domain"
	natsgo "github.com/nats-io/nats.go"
)

type mentorOwnerPrepared struct {
	composition MentorOwnerCompositionConfig
	broker      natsgo.Options
}

type mentorOwnerConnection interface {
	QueueSubscribe(string, string, natsgo.MsgHandler) error
	Publish(string, []byte) error
	FlushTimeout(time.Duration) error
	LastError() error
	AuthRequired() bool
	IsConnected() bool
	Drain() error
	Close()
}

type mentorOwnerDialer func(natsgo.Options) (mentorOwnerConnection, error)

type mentorOwnerSubscription interface {
	SetPendingLimits(int, int) error
	Unsubscribe() error
}

func limitMentorSubscription(subscription mentorOwnerSubscription) error {
	if subscription == nil || (reflect.ValueOf(subscription).Kind() == reflect.Pointer && reflect.ValueOf(subscription).IsNil()) {
		return domain.ErrAuthorityUnavailable
	}
	if subscription.SetPendingLimits(128, 1<<20) != nil {
		_ = subscription.Unsubscribe()
		return domain.ErrAuthorityUnavailable
	}
	return nil
}

// MentorOwnerRuntime owns only its dedicated authenticated connection. No
// caller can replace the three production consumers or the immutable subjects.
type MentorOwnerRuntime struct {
	mu                 sync.Mutex
	connection         mentorOwnerConnection
	ready              bool
	stopped            bool
	cancel             context.CancelFunc
	done               chan struct{}
	closed             chan struct{}
	doneOnce           sync.Once
	closedOnce         sync.Once
	transportCloseOnce sync.Once
	shutdownOnce       sync.Once
	shutdownErr        error
	workers            sync.WaitGroup
}

func startMentorOwner(ctx context.Context, prepared *mentorOwnerPrepared, pool MentorOwnerPool, dial mentorOwnerDialer) (*MentorOwnerRuntime, error) {
	if prepared == nil {
		return nil, nil
	}
	if ctx == nil || ctx.Err() != nil || dial == nil {
		return nil, domain.ErrAuthorityUnavailable
	}
	composition, err := NewMentorOwnerComposition(prepared.composition, pool)
	if err != nil || !composition.ready() {
		return nil, domain.ErrAuthorityUnavailable
	}
	lifetime, cancel := context.WithCancel(ctx)
	runtime := &MentorOwnerRuntime{cancel: cancel, done: make(chan struct{}), closed: make(chan struct{})}
	startup, stopStartup := context.WithTimeout(lifetime, 5*time.Second)
	defer stopStartup()
	opts := prepared.broker
	opts.Timeout = mentorRemaining(startup)
	pinnedConfig, ok := opts.CustomDialer.(*mentorPinnedDialer)
	if !ok {
		runtime.stop()
		return nil, domain.ErrAuthorityUnavailable
	}
	pinned := &mentorPinnedDialer{context: startup, address: pinnedConfig.address}
	opts.CustomDialer = pinned
	if opts.TLSConfig == nil || opts.TLSConfig.InsecureSkipVerify || opts.TLSConfig.MinVersion < tls.VersionTLS12 {
		runtime.stop()
		return nil, domain.ErrAuthorityUnavailable
	}
	var verifiedTLS atomic.Bool
	opts.TLSConfig = opts.TLSConfig.Clone()
	// Built-in TLS verification runs first. Record provenance from this callback
	// instead of polling nats.Conn.TLSConnectionState, whose pinned v1.33 status
	// read is not synchronized. Successful Connect/IsConnected implies completion.
	opts.TLSConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if state.Version < tls.VersionTLS12 || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
			return domain.ErrAuthorityUnavailable
		}
		verifiedTLS.Store(true)
		return nil
	}
	opts.ClosedCB = func(*natsgo.Conn) { runtime.stop(); runtime.closedOnce.Do(func() { close(runtime.closed) }) }
	opts.DisconnectedErrCB = func(conn *natsgo.Conn, _ error) { runtime.fail(conn) }
	opts.AsyncErrorCB = func(conn *natsgo.Conn, _ *natsgo.Subscription, _ error) { runtime.fail(conn) }
	connection, err := dial(opts)
	if !missingMentorConnection(connection) {
		runtime.mu.Lock()
		runtime.connection = connection
		runtime.mu.Unlock()
	}
	failed := func() (*MentorOwnerRuntime, error) {
		runtime.stop()
		runtime.forceClose()
		return nil, domain.ErrAuthorityUnavailable
	}
	if err != nil || missingMentorConnection(connection) || startup.Err() != nil || !connection.IsConnected() || !connection.AuthRequired() {
		return failed()
	}
	if !verifiedTLS.Load() {
		return failed()
	}
	for _, subject := range composition.Subjects() {
		subject := subject
		err := connection.QueueSubscribe(subject, "ms-go-rbac", func(msg *natsgo.Msg) {
			if msg == nil || !validMentorInbox(msg.Reply) || len(msg.Data) == 0 || len(msg.Data) > 16384 || !utf8.Valid(msg.Data) || !runtime.admit() {
				return
			}
			defer runtime.workers.Done()
			var reply []byte
			var handleErr error
			if msg.Subject != subject {
				handleErr = domain.ErrAuthorityUnavailable
			} else {
				reply, handleErr = composition.Handle(lifetime, msg.Subject, msg.Data)
			}
			if handleErr != nil || len(reply) == 0 || len(reply) > 16384 || !utf8.Valid(reply) {
				reply = []byte(`{"error":"unavailable"}`)
			}
			if connection.Publish(msg.Reply, reply) != nil {
				runtime.fail(nil)
			}
		})
		if err != nil || startup.Err() != nil || runtime.isStopped() {
			return failed()
		}
	}
	if connection.FlushTimeout(mentorRemaining(startup)) != nil || connection.LastError() != nil || !connection.IsConnected() || startup.Err() != nil {
		return failed()
	}
	if !pinned.releaseHandshakeGuard() {
		return failed()
	}
	runtime.mu.Lock()
	if runtime.stopped || lifetime.Err() != nil {
		runtime.mu.Unlock()
		return failed()
	}
	runtime.ready = true
	runtime.mu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
			runtime.fail(nil)
		case <-runtime.done:
		}
	}()
	return runtime, nil
}

type mentorNATSConnection struct{ *natsgo.Conn }

func (c mentorNATSConnection) QueueSubscribe(subject, queue string, handle natsgo.MsgHandler) error {
	subscription, err := c.Conn.QueueSubscribe(subject, queue, handle)
	if err != nil {
		return err
	}
	return limitMentorSubscription(subscription)
}

func validMentorInbox(subject string) bool {
	if len(subject) > 256 || !strings.HasPrefix(subject, "_INBOX.") {
		return false
	}
	for _, token := range strings.Split(strings.TrimPrefix(subject, "_INBOX."), ".") {
		if token == "" {
			return false
		}
		for _, char := range token {
			if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') && !(char >= '0' && char <= '9') && char != '_' && char != '-' {
				return false
			}
		}
	}
	return true
}

func dialMentorOwner(opts natsgo.Options) (mentorOwnerConnection, error) {
	connection, err := opts.Connect()
	if err != nil {
		if connection != nil {
			connection.Close()
		}
		return nil, domain.ErrAuthorityUnavailable
	}
	return mentorNATSConnection{connection}, nil
}

func (r *MentorOwnerRuntime) Done() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.done
}

func (r *MentorOwnerRuntime) admit() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ready || r.stopped {
		return false
	}
	r.workers.Add(1)
	return true
}

func (r *MentorOwnerRuntime) isStopped() bool { r.mu.Lock(); defer r.mu.Unlock(); return r.stopped }

func (r *MentorOwnerRuntime) stop() {
	r.mu.Lock()
	r.ready = false
	r.stopped = true
	r.mu.Unlock()
	r.cancel()
	r.doneOnce.Do(func() { close(r.done) })
}

func (r *MentorOwnerRuntime) fail(connection *natsgo.Conn) {
	r.stop()
	if connection != nil {
		connection.Close()
	}
	r.forceClose()
}

func (r *MentorOwnerRuntime) forceClose() {
	r.mu.Lock()
	connection := r.connection
	r.mu.Unlock()
	if !missingMentorConnection(connection) {
		r.transportCloseOnce.Do(connection.Close)
	}
}

// Close stops admission, drains pending deliveries/replies before pool shutdown,
// and waits for actual close notification. On deadline/error it cancels owner
// work and force-closes. No retry/reconnect or background mutation is performed.
func (r *MentorOwnerRuntime) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.shutdownOnce.Do(func() {
		r.mu.Lock()
		r.ready = false
		connection := r.connection
		r.mu.Unlock()
		if ctx == nil || ctx.Err() != nil {
			r.stop()
			r.forceClose()
			r.shutdownErr = domain.ErrAuthorityUnavailable
			return
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		select {
		case <-r.closed:
		default:
			if missingMentorConnection(connection) || connection.Drain() != nil {
				r.stop()
				r.forceClose()
				r.shutdownErr = domain.ErrAuthorityUnavailable
			} else {
				select {
				case <-r.closed:
				case <-ctx.Done():
					r.stop()
					r.forceClose()
					r.shutdownErr = domain.ErrAuthorityUnavailable
				}
			}
		}
		r.stop()
		finished := make(chan struct{})
		go func() { r.workers.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-ctx.Done():
			r.shutdownErr = domain.ErrAuthorityUnavailable
		}
	})
	return r.shutdownErr
}

func missingMentorConnection(connection mentorOwnerConnection) bool {
	if connection == nil {
		return true
	}
	v := reflect.ValueOf(connection)
	return (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && v.IsNil()
}

func mentorRemaining(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return 5 * time.Second
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return time.Nanosecond
	}
	return remaining
}
