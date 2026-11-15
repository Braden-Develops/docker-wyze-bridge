package webui

import (
	"context"
	"encoding/json"
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
type KVSWaker interface {
	WakeCamera(ctx context.Context, mac, model string) error
}

// kvsWakeSettle gives a freshly-woken camera a moment to join the
// signaling channel before go2rtc sends its SDP offer.
var kvsWakeSettle = 500 * time.Millisecond

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

	if waker, ok := s.kvs.(KVSWaker); ok && info.NeedsWake() {
		if err := waker.WakeCamera(r.Context(), info.MAC, info.Model); err != nil {
			// Best effort: the camera may already be awake (app open,
			// doorbell pressed), so still try to stream.
			s.log.Warn().Err(err).Str("cam", streamID).Msg("kvs wakeup failed")
		} else {
			s.log.Debug().Str("cam", streamID).Msg("kvs wakeup sent")
			select {
			case <-time.After(kvsWakeSettle):
			case <-r.Context().Done():
				return
			}
		}
	}

	signalingURL, iceServers, _, err := s.kvs.GetCameraStream(r.Context(), info.MAC, info.Model)
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
