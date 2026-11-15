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
	// longer keeps running in the background while the request goes
	// ahead, and a retry sends a fresh wake.
	gwellWakeBudget = 3500 * time.Millisecond
	// gwellPrimeRetry spaces out retries of a failed Prime.
	gwellPrimeRetry = 30 * time.Second
	gwellPrimeTries = 4
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

	mu        sync.Mutex
	inflight  map[string]chan struct{} // mac -> closed when its wake ends
	lastAwake map[string]bool          // mac -> last finished wake confirmed the doorbell awake
	lastErr   map[string]error         // mac -> error of the last finished wake
	server    string                   // P2P server that last worked (skips ~6s discovery)
	priming   bool                     // a Prime is running
	devices   []gwell.DeviceInfo       // account device list (server may omit it on back-to-back sessions)
}

func newGwellWaker(api *wyzeapi.Client) *gwellWaker {
	return &gwellWaker{
		api:       api,
		inflight:  map[string]chan struct{}{},
		lastAwake: map[string]bool{},
		lastErr:   map[string]error{},
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
		var err error
		for try := 1; try <= gwellPrimeTries; try++ {
			if err = w.primeOnce(mac); err == nil {
				break
			}
			// Not fatal: a wake discovers for itself if priming never
			// succeeds (network or Wyze down at startup).
			log.Warn().Err(err).Str("cam", mac).Int("try", try).Msg("gwell p2p prime failed")
			if try < gwellPrimeTries {
				time.Sleep(gwellPrimeRetry)
			}
		}
		w.mu.Lock()
		w.priming = false
		server := w.server
		w.mu.Unlock()
		if err == nil {
			log.Info().Str("cam", mac).Str("server", server).Msg("gwell p2p server ready")
		}
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

// Wake sends the doorbell a wake message and returns nil once it is
// confirmed awake. It returns errGwellWakePending if that takes longer
// than gwellWakeBudget (the wake carries on in the background), or the
// wake's own error.
//
// Every call sends a message and waits, even seconds after the last
// one. A Doorbell Pro that is still awake from a previous session
// ignores a WebRTC offer unless a wake message came first, and needs
// about 3s after the message just as a sleeping one does. A call made
// while a wake is already in flight joins it.
func (w *gwellWaker) Wake(ctx context.Context, mac string) error {
	w.mu.Lock()
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
	if w.lastAwake[mac] {
		return nil
	}
	return fmt.Errorf("gwell p2p wake sent but the doorbell did not report online within %s", gwellWakeListen)
}

// run performs one wake and records its outcome. It is not tied to the
// request that started it, so a slow wake still finishes.
func (w *gwellWaker) run(mac string, done chan struct{}) {
	res, err := w.wakeOnce(mac)
	w.mu.Lock()
	w.lastErr[mac] = err
	w.lastAwake[mac] = err == nil && res.Online
	delete(w.inflight, mac)
	w.mu.Unlock()
	close(done)

	if err != nil {
		log.Warn().Err(err).Str("cam", mac).Msg("gwell p2p wake failed")
		return
	}
	log.Info().Str("cam", mac).Bool("online", res.Online).
		Bool("already_awake", res.InitialState == gwell.DeviceStateAwake).Msg("gwell p2p wake sent")
}

func (w *gwellWaker) wakeOnce(mac string) (gwell.WakeResult, error) {
	w.runMu.Lock()
	defer w.runMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	accessID, accessToken, err := w.api.MarsRegisterGWUser(ctx, mac)
	if err != nil {
		return gwell.WakeResult{}, fmt.Errorf("mars credential: %w", err)
	}
	token, err := gwell.ParseAccessToken(accessID, accessToken)
	if err != nil {
		return gwell.WakeResult{}, fmt.Errorf("mars token: %w", err)
	}

	w.mu.Lock()
	server, devices := w.server, w.devices
	w.mu.Unlock()

	try := func(server string, devices []gwell.DeviceInfo) (gwell.WakeResult, error) {
		sess := gwell.NewSession(gwell.SessionConfig{Token: token, ServerAddr: server, DeviceName: mac, Devices: devices})
		res, err := sess.Wake(gwell.WakeOptions{
			Data: []byte("{}"), Wake: true,
			Listen: gwellWakeListen, StopOnOnline: true,
		})
		if err == nil {
			w.mu.Lock()
			w.server = sess.ServerAddr()
			if d := sess.Devices(); len(d) > 0 {
				w.devices = d
			}
			w.mu.Unlock()
		}
		return res, err
	}
	res, err := try(server, devices)
	if err != nil && server != "" {
		// The remembered server or device list may be stale; start over.
		res, err = try("", nil)
	}
	return res, err
}
