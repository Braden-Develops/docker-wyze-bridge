package gwell

// Local addition (not from upstream hacky-wyze-gwell): send a
// passthrough message with the "wake device" flag, the way the Wyze
// app's IoTVideo SDK does for sleeping battery-lineage devices.
//
// Layout recovered from giot_eif_send_passthrough_msg in the Wyze
// Android app's libiotp2pav.so (arm64):
//
//	[0]      proto (0x7F, switched to 0x7E + routing session id once the
//	         session is up, same as every other post-certify frame)
//	[1]      0xB9
//	[2:4]    frame length = len(data) + 0x34
//	[4:12]   sender id / routing session id
//	[12:16]  sqnum
//	[20:24]  gutes flags (encrypt mode in bits 16-17)
//	[24:28]  message flags; bit 1 (0x2) = wake the destination device
//	[28:36]  destination device id
//	[36:44]  sender access id
//	[44:48]  31-bit random message id
//	[48:50]  data length
//	[52:]    data

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	mrand "math/rand"
	"time"
)

const passthroughHeaderSize = 0x34

// WakeVerbose makes Wake log every distinct frame the server sends.
// The gwell-wake diagnostic turns it on; the bridge leaves it off.
var WakeVerbose bool

// Device sleep states as the P2P server reports them in a device's
// "_online" state value.
const (
	DeviceStateUnknown = 0 // the server sent no state for the device
	DeviceStateAwake   = 1
	DeviceStateAsleep  = 2
)

// WakeOptions controls one Wake call.
type WakeOptions struct {
	Data []byte // passthrough message body
	Wake bool   // set the wake-device flag
	// Listen bounds the wait for the device to report itself online
	// after the message is sent.
	Listen time.Duration
	// StopOnOnline returns as soon as the device reports online instead
	// of listening for the whole window.
	StopOnOnline bool
	// SubscribeDrain, if set, reads the state dump for this long before
	// sending. Only the diagnostic needs it (to print the dump and the
	// device's state before the message goes out).
	SubscribeDrain time.Duration
}

// WakeResult is what one Wake call observed.
type WakeResult struct {
	// Online is true when the device published a fresh online report
	// after the message.
	Online bool
	// InitialState is the device's state from the state dump the server
	// replays to a new session (DeviceStateAwake, DeviceStateAsleep, or
	// DeviceStateUnknown: the server sometimes omits the dump from a
	// session opened right after another one). It is informational. A
	// Doorbell Pro that is already awake still needs the wake message
	// and about 3s before it answers a WebRTC offer, so Wake waits for
	// the online report whatever this says.
	InitialState int
}

// BuildPassthroughMsg builds a 0xB9 passthrough frame addressed to dstID.
// It returns the encrypted frame and the message id it carries.
func BuildPassthroughMsg(token *AccessToken, routingSessionID uint64, sqnum uint32, dstID uint64, wake bool, data []byte, sessionKey, pwdKey *RC5Key) ([]byte, uint32) {
	total := passthroughHeaderSize + len(data)
	frame := make([]byte, total)

	frame[1] = SubTypeNetworkDetect // 0xB9
	binary.LittleEndian.PutUint16(frame[2:4], uint16(total))
	if routingSessionID != 0 {
		frame[0] = ProtoEncrypted
		binary.LittleEndian.PutUint64(frame[4:12], routingSessionID)
	} else {
		frame[0] = ProtoPlaintext
		binary.LittleEndian.PutUint32(frame[4:8], token.Word1())
		binary.LittleEndian.PutUint32(frame[8:12], token.Word2())
	}
	binary.LittleEndian.PutUint32(frame[12:16], sqnum)
	binary.LittleEndian.PutUint32(frame[20:24], uint32(2<<16)) // encrypt_mode=2

	var msgFlags uint32
	if wake {
		msgFlags |= 0x2
	}
	binary.LittleEndian.PutUint32(frame[24:28], msgFlags)
	binary.LittleEndian.PutUint64(frame[28:36], dstID)
	binary.LittleEndian.PutUint64(frame[36:44], token.AccessID)
	msgID := mrand.Uint32() & 0x7FFFFFFF
	binary.LittleEndian.PutUint32(frame[44:48], msgID)
	binary.LittleEndian.PutUint16(frame[48:50], uint16(len(data)))
	copy(frame[passthroughHeaderSize:], data)

	EncryptFrameMode2(frame, sessionKey, pwdKey)
	return frame, msgID
}

// ServerAddr returns the P2P server this session connected to, so a
// caller can pass it back as SessionConfig.ServerAddr and skip
// discovery next time.
func (s *Session) ServerAddr() string { return s.serverAddr }

// Devices returns the account's P2P device list as learned by this
// session. Pass it back as SessionConfig.Devices: the server sometimes
// omits the list from a session opened right after another one.
func (s *Session) Devices() []DeviceInfo { return s.devices }

// Wake registers with the P2P server, subscribes, and sends one
// passthrough message with the wake flag to the target device. It then
// waits up to opts.Listen for the device to publish a fresh "_online"
// state. It never starts a call or a media session.
func (s *Session) Wake(opts WakeOptions) (WakeResult, error) {
	defer s.Close()
	var res WakeResult

	if err := s.connect(); err != nil {
		return res, fmt.Errorf("connect: %w", err)
	}
	if err := s.certify(); err != nil {
		return res, fmt.Errorf("certify: %w", err)
	}
	if len(s.cfg.Devices) > 0 {
		s.devices = s.cfg.Devices
	}
	if err := s.initInfo(); err != nil {
		return res, fmt.Errorf("initInfo: %w", err)
	}
	if s.cfg.DeviceName != "" && s.targetDev.Name != s.cfg.DeviceName {
		return res, fmt.Errorf("device %q is not on this account's P2P device list", s.cfg.DeviceName)
	}

	// The subscribe and the wake message go out back to back: the
	// message is needed whatever the device's state, so there is no
	// reason to hold it until the state dump has arrived.
	seen := map[string]bool{}
	_, res.InitialState = s.wakeDrain(seen, "subscribe", func() {
		s.conn.Write(BuildSubscribeDevID(s.cfg.Token, s.routingSessionID, s.nextSqnum(),
			s.cfg.Token.AccessID, s.routingSessionID != 0, s.certResult.SessionKey, s.pwdKey))
		if len(s.cfg.Token.ExtraTokenData) > 0 {
			s.conn.Write(BuildSubscribeTokens(s.cfg.Token, s.routingSessionID, s.nextSqnum(),
				s.cfg.Token.ExtraTokenData, s.routingSessionID != 0, s.certResult.SessionKey, s.pwdKey))
		}
	}, opts.SubscribeDrain, false)

	online, state := s.wakeDrain(seen, "passthrough", func() {
		frame, msgID := BuildPassthroughMsg(s.cfg.Token, s.routingSessionID, s.nextSqnum(),
			s.targetDev.TID, opts.Wake, opts.Data, s.certResult.SessionKey, s.pwdKey)
		log.Printf("%s sending passthrough to %q TID=0x%016X wake=%v msgID=0x%08X (%d bytes)",
			s.prefix, s.targetDev.Name, s.targetDev.TID, opts.Wake, msgID, len(frame))
		s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		s.conn.Write(frame)
	}, opts.Listen, opts.StopOnOnline)
	if res.InitialState == DeviceStateUnknown {
		res.InitialState = state
	}
	res.Online = online
	return res, nil
}

// fromTarget reports whether body (a 0xAA device-state frame's payload)
// was published by the target device, whose id sits at body[10:18].
func (s *Session) fromTarget(body []byte) bool {
	return len(body) >= 18 && binary.LittleEndian.Uint64(body[10:18]) == s.targetDev.TID
}

// stateDumpMarker opens the full state dump the server replays to every
// new session, as opposed to an update addressed by path.
var stateDumpMarker = []byte(`{"ProReadonly":`)

// isOnlineReport reports whether body is the target device publishing a
// fresh "_online" state: an update addressed by path
// ("ProReadonly._online." or "ProReadonly." followed by the changed
// members). The replayed state dump is not a fresh report.
func (s *Session) isOnlineReport(body []byte) bool {
	if !s.fromTarget(body) || bytes.Contains(body, stateDumpMarker) {
		return false
	}
	return bytes.Contains(body, []byte("_online"))
}

// dumpState returns the target device's sleep state from body if body
// is its replayed state dump, else DeviceStateUnknown.
func (s *Session) dumpState(body []byte) int {
	if !s.fromTarget(body) || !bytes.Contains(body, stateDumpMarker) {
		return DeviceStateUnknown
	}
	const key = `"_online":{"stVal":`
	i := bytes.Index(body, []byte(key))
	if i < 0 || i+len(key) >= len(body) {
		return DeviceStateUnknown
	}
	switch body[i+len(key)] {
	case '1':
		return DeviceStateAwake
	case '2':
		return DeviceStateAsleep
	}
	return DeviceStateUnknown
}

// wakeDrain runs send, then reads frames for up to d. It returns
// whether the target device published a fresh online report, and the
// target's sleep state if its replayed state dump went by. With
// stopOnOnline it returns as soon as the online report arrives. The
// server re-sends frames we never ack, so repeats (tracked in seen) are
// ignored.
func (s *Session) wakeDrain(seen map[string]bool, phase string, send func(), d time.Duration, stopOnOnline bool) (online bool, state int) {
	send()
	buf := make([]byte, 8192)
	deadline := time.Now().Add(d)
	for {
		left := time.Until(deadline)
		if left <= 0 {
			break
		}
		if left > 500*time.Millisecond {
			left = 500 * time.Millisecond
		}
		s.conn.SetReadDeadline(time.Now().Add(left))
		n, err := s.conn.Read(buf)
		if err != nil {
			continue
		}
		dec, mode := TryDecrypt(buf, n, s.certResult.SessionKey, s.pwdKey)
		if dec == nil || n < FrameHeaderSize {
			continue
		}
		show := dec
		if len(show) > n {
			show = show[:n]
		}
		// Bytes 12:24 hold sqnum/flags/checksum that change per resend.
		key := string(show[:12]) + string(show[FrameHeaderSize:])
		if seen[key] {
			continue
		}
		seen[key] = true
		body := show[FrameHeaderSize:]
		if dec[1] != 0xAA {
			if WakeVerbose {
				log.Printf("%s %s rx: sub=0x%02X len=%d (%s) %s", s.prefix, phase, dec[1], n, mode, hex.EncodeToString(body))
			}
			continue
		}
		if s.isOnlineReport(body) {
			online = true
		}
		if st := s.dumpState(body); st != DeviceStateUnknown {
			state = st
		}
		if WakeVerbose {
			text := make([]byte, 0, len(body))
			for _, b := range body {
				if b >= 0x20 && b < 0x7f {
					text = append(text, b)
				} else {
					text = append(text, '.')
				}
			}
			log.Printf("%s %s rx: sub=0xAA len=%d (%s) %s", s.prefix, phase, n, mode, text)
		}
		if online && stopOnOnline {
			break
		}
	}
	return online, state
}
