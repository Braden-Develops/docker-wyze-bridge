package webui

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// KVSStreamProvider mints the Wyze WebRTC signaling URL + ICE servers
// for a specific camera via /v4/camera/get_streams. Injected at startup
// so this package stays independent of internal/wyzeapi.
type KVSStreamProvider interface {
	GetCameraStream(ctx context.Context, mac, model string) (signalingURL string, iceServers []KVSIceServer, authToken string, err error)
}

// KVSWaker is optionally implemented by the KVSStreamProvider. Battery
// doorbells (Doorbell Pro lineage) sleep and ignore a WebRTC offer until
// woken, so the shim wakes them before handing go2rtc the signaling URL.
//
// WakeCamera returns nil once the camera is confirmed ready for an
// offer. It returns ErrWakePending when the wake is under way but not
// confirmed in the time the shim can spare; the shim then answers 503
// rather than hand out a signaling URL for an offer the camera would
// ignore (go2rtc would wait about 50s on it). Any other error means the
// wake could not be attempted, and the shim streams anyway in case the
// camera is up.
type KVSWaker interface {
	WakeCamera(ctx context.Context, mac, model string) error
}

// ErrWakePending is returned by KVSWaker.WakeCamera while a wake is in
// progress but not yet confirmed. The caller should retry shortly.
var ErrWakePending = errors.New("camera wake still in progress")

// kvsWakeSettle gives a freshly-woken camera a moment to join the
// signaling channel before go2rtc sends its SDP offer.
var kvsWakeSettle = 300 * time.Millisecond

// KVSIceServer matches the shape go2rtc's kinesis client deserializes
// (pkg/webrtc UnmarshalICEServers reads "urls"; with "url" it silently gets
// no ICE servers, so only host candidates work and remote cameras fail).
type KVSIceServer struct {
	URL        string `json:"urls"`
	Username   string `json:"username"`
	Credential string `json:"credential"`
}

// SetKVSProvider attaches the Wyze get_streams provider.
func (s *Server) SetKVSProvider(p KVSStreamProvider) {
	s.kvs = p
}

// handleShimKVSSignaling is the one-shot bootstrap go2rtc's #format=wyze
// source fetches when it's about to dial Wyze's KVS signaling server.
// The go2rtc YAML contains: webrtc:http://<loopback>/internal/wyze/webrtc/<cam>#format=wyze
// and go2rtc expects JSON back shaped like:
//
//	{"ClientId":"<phone_id>","cam":"<name>","result":"ok",
//	 "servers":[{"urls":...,"username":...,"credential":...}],
//	 "signalingUrl":"wss://wyze-mars-webcsrv.wyzecam.com?token=..."}
//
// ClientId's capital I matters — that's what go2rtc's wyzeKVS struct
// tag wants. go2rtc handles everything downstream (WSS dial, SDP
// negotiation, track fanout).
func (s *Server) handleShimKVSSignaling(w http.ResponseWriter, r *http.Request) {
	if s.kvs == nil {
		http.Error(w, "kvs provider not wired", http.StatusServiceUnavailable)
		return
	}
	streamID := strings.TrimPrefix(r.URL.Path, "/internal/wyze/webrtc/")
	streamID = strings.TrimSpace(streamID)
	if streamID == "" || strings.Contains(streamID, "/") {
		http.Error(w, "streamID required", http.StatusBadRequest)
		return
	}

	cam := s.camMgr.GetCamera(streamID)
	if cam == nil {
		http.NotFound(w, r)
		return
	}
	info := cam.GetInfo()
	// Camera.ForceWebRTC lets the manager promote a runtime-flipped
	// camera (see TUTK→WebRTC auto-fallback) even when the registry
	// still marks the model as TUTK-only.
	if !info.IsWebRTCStreamer() && !cam.ForceWebRTC() {
		http.Error(w, "camera does not use WebRTC streaming", http.StatusNotFound)
		return
	}

	// go2rtc gives this request 5s in total, and waking a doorbell uses
	// most of it, so the signaling URL is fetched while the wake runs.
	type streamResult struct {
		signalingURL string
		iceServers   []KVSIceServer
		err          error
	}
	streamCh := make(chan streamResult, 1)
	go func() {
		u, ice, _, err := s.kvs.GetCameraStream(r.Context(), info.MAC, info.Model)
		streamCh <- streamResult{u, ice, err}
	}()

	if waker, ok := s.kvs.(KVSWaker); ok && info.NeedsWake() {
		err := waker.WakeCamera(r.Context(), info.MAC, info.Model)
		switch {
		case errors.Is(err, ErrWakePending):
			s.log.Info().Str("cam", streamID).Msg("kvs wakeup not confirmed yet; asking the client to retry")
			w.Header().Set("Retry-After", "3")
			http.Error(w, "camera is waking up, retry shortly", http.StatusServiceUnavailable)
			return
		case err != nil:
			// Best effort: the camera may already be up (app open,
			// doorbell pressed), so still try to stream.
			s.log.Warn().Err(err).Str("cam", streamID).Msg("kvs wakeup failed")
		default:
			s.log.Debug().Str("cam", streamID).Msg("kvs wakeup confirmed")
			select {
			case <-time.After(kvsWakeSettle):
			case <-r.Context().Done():
				return
			}
		}
	}

	var res streamResult
	select {
	case res = <-streamCh:
	case <-r.Context().Done():
		return
	}
	signalingURL, iceServers, err := res.signalingURL, res.iceServers, res.err
	if err != nil {
		s.log.Warn().Err(err).Str("cam", streamID).Msg("kvs get_streams failed")
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// ClientId is the Wyze account's phone_id — matches what the app
	// uses as recipientClientId when initiating its own WebRTC session.
	clientID := ""
	if s.authPhoneID != nil {
		clientID = s.authPhoneID()
	}

	payload := map[string]interface{}{
		"ClientId":     clientID,
		"cam":          streamID,
		"result":       "ok",
		"servers":      iceServers,
		"signalingUrl": signalingURL,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}
