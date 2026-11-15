package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/IDisposable/docker-wyze-bridge/internal/gwell/upstream/gwell"
	"github.com/IDisposable/docker-wyze-bridge/internal/wyzeapi"
)

const (
	// gwellWakeListen bounds how long a P2P wake waits for the doorbell
	// to report itself online. In testing a sleeping Doorbell Pro
	// reported in about 3s after the wake message.
	gwellWakeListen = 10 * time.Second
	// gwellWakeBudget is how long a stream request waits on a wake.
	// go2rtc gives the shim 5s in total to answer; a wake that needs
	// longer keeps running in the background and the next attempt finds
	// the doorbell awake.
	gwellWakeBudget = 3500 * time.Millisecond
	// gwellAwakeWindow is how long after an online report the doorbell
	// is assumed still awake, so retries skip the wake. Its firmware
	// drops back to sleep roughly 20s after the last session.
	gwellAwakeWindow = 15 * time.Second
)

// errGwellWakePending means the wake is still running in the
// background; the doorbell is not confirmed awake yet.
var errGwellWakePending = errors.New("gwell p2p wake still in progress")

// gwellWaker wakes sleeping Gwell doorbells the way the Wyze app's
// IoTVideo SDK does: register with the Gwell P2P server using the
// camera's Mars credential and send the device a passthrough message
// with the wake flag. (The device-management HTTP "wakeup" action
// answers Success but does not reliably wake these doorbells.)
type gwellWaker struct {
	api *wyzeapi.Client

	// runMu serializes P2P sessions: the Gwell P2P server mixes up
	// frames when one account runs several handshakes at once.
	runMu sync.Mutex

	mu         sync.Mutex
	inflight   map[string]chan struct{} // mac -> closed when its wake ends
	lastOnline map[string]time.Time     // mac -> last confirmed online report
	lastErr    map[string]error         // mac -> result of the last finished wake
	server     string                   // P2P server that last worked (skips ~6s discovery)
	priming    bool                     // a Prime is running
	devices    []gwell.DeviceInfo       // account device list (server may omit it on back-to-back sessions)
}

func newGwellWaker(api *wyzeapi.Client) *gwellWaker {
	return &gwellWaker{
		api:        api,
		inflight:   map[string]chan struct{}{},
		lastOnline: map[string]time.Time{},
		lastErr:    map[string]error{},
	}
}

// Prime finds a working P2P server and the account's device list in
// the background, without waking anything. Server discovery costs about
// 6s when it falls back to the built-in list, which is longer than a
// stream request can wait; priming when a doorbell is first seen means
// the first real wake only has to send the message and wait for the
// doorbell to report online.
func (w *gwellWaker) Prime(mac string) {
	w.mu.Lock()
	if w.server != "" || w.priming {
		w.mu.Unlock()
		return
	}
	w.priming = true
	w.mu.Unlock()

	go func() {
		err := w.primeOnce(mac)
		w.mu.Lock()
		w.priming = false
		server := w.server
		w.mu.Unlock()
		if err != nil {
			// Not fatal: the first wake will discover for itself.
			log.Warn().Err(err).Str("cam", mac).Msg("gwell p2p prime failed")
			return
		}
		log.Info().Str("cam", mac).Str("server", server).Msg("gwell p2p server ready")
	}()
}

func (w *gwellWaker) primeOnce(mac string) error {
	w.runMu.Lock()
	defer w.runMu.Unlock()

	w.mu.Lock()
	known := w.server != ""
	w.mu.Unlock()
	if known {
		// A wake got there first.
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	accessID, accessToken, err := w.api.MarsRegisterGWUser(ctx, mac)
	if err != nil {
		return fmt.Errorf("mars credential: %w", err)
	}
	token, err := gwell.ParseAccessToken(accessID, accessToken)
	if err != nil {
		return fmt.Errorf("mars token: %w", err)
	}
	res, err := gwell.DiscoverDevices(token)
	if err != nil {
		return err
	}
	w.mu.Lock()
	w.server = res.ServerAddr
	if len(res.Devices) > 0 {
		w.devices = res.Devices
	}
	w.mu.Unlock()
	return nil
}

// Wake returns nil once the doorbell is confirmed awake. It returns
// errGwellWakePending if that takes longer than gwellWakeBudget (the
// wake carries on in the background), or the wake's own error.
func (w *gwellWaker) Wake(ctx context.Context, mac string) error {
	w.mu.Lock()
	if time.Since(w.lastOnline[mac]) < gwellAwakeWindow {
		w.mu.Unlock()
		return nil
	}
	done, running := w.inflight[mac]
	if !running {
		done = make(chan struct{})
		w.inflight[mac] = done
		go w.run(mac, done)
	}
	w.mu.Unlock()

	select {
	case <-done:
	case <-time.After(gwellWakeBudget):
		return errGwellWakePending
	case <-ctx.Done():
		return ctx.Err()
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.lastErr[mac]; err != nil {
		return err
	}
	if time.Since(w.lastOnline[mac]) < gwellAwakeWindow {
		return nil
	}
	return fmt.Errorf("gwell p2p wake sent but the doorbell did not report online within %s", gwellWakeListen)
}

// run performs one wake and records its outcome. It is not tied to the
// request that started it, so a slow wake still finishes.
func (w *gwellWaker) run(mac string, done chan struct{}) {
	online, err := w.wakeOnce(mac)
	w.mu.Lock()
	w.lastErr[mac] = err
	if err == nil && online {
		w.lastOnline[mac] = time.Now()
	}
	delete(w.inflight, mac)
	w.mu.Unlock()
	close(done)

	if err != nil {
		log.Warn().Err(err).Str("cam", mac).Msg("gwell p2p wake failed")
		return
	}
	log.Info().Str("cam", mac).Bool("online", online).Msg("gwell p2p wake sent")
}

func (w *gwellWaker) wakeOnce(mac string) (bool, error) {
	w.runMu.Lock()
	defer w.runMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	accessID, accessToken, err := w.api.MarsRegisterGWUser(ctx, mac)
	if err != nil {
		return false, fmt.Errorf("mars credential: %w", err)
	}
	token, err := gwell.ParseAccessToken(accessID, accessToken)
	if err != nil {
		return false, fmt.Errorf("mars token: %w", err)
	}

	w.mu.Lock()
	server, devices := w.server, w.devices
	w.mu.Unlock()

	try := func(server string, devices []gwell.DeviceInfo) (bool, error) {
		sess := gwell.NewSession(gwell.SessionConfig{Token: token, ServerAddr: server, DeviceName: mac, Devices: devices})
		online, err := sess.Wake(gwell.WakeOptions{Data: []byte("{}"), Wake: true, Listen: gwellWakeListen, StopOnOnline: true})
		if err == nil {
			w.mu.Lock()
			w.server = sess.ServerAddr()
			if d := sess.Devices(); len(d) > 0 {
				w.devices = d
			}
			w.mu.Unlock()
		}
		return online, err
	}
	online, err := try(server, devices)
	if err != nil && server != "" {
		// The remembered server or device list may be stale; start over.
		online, err = try("", nil)
	}
	return online, err
}
