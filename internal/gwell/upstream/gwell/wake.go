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
	// SubscribeDrain, if set, reads the server's initial state dump for
	// this long before sending. Only the diagnostic needs it (to print
	// that dump); the online check ignores the dump either way.
	SubscribeDrain time.Duration
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
// state, and reports whether it did. It never starts a call or a media
// session.
func (s *Session) Wake(opts WakeOptions) (bool, error) {
	defer s.Close()

	if err := s.connect(); err != nil {
		return false, fmt.Errorf("connect: %w", err)
	}
	if err := s.certify(); err != nil {
		return false, fmt.Errorf("certify: %w", err)
	}
	if len(s.cfg.Devices) > 0 {
		s.devices = s.cfg.Devices
	}
	if err := s.initInfo(); err != nil {
		return false, fmt.Errorf("initInfo: %w", err)
	}
	if s.cfg.DeviceName != "" && s.targetDev.Name != s.cfg.DeviceName {
		return false, fmt.Errorf("device %q is not on this account's P2P device list", s.cfg.DeviceName)
	}

	seen := map[string]bool{}
	s.wakeDrain(seen, "subscribe", func() {
		s.conn.Write(BuildSubscribeDevID(s.cfg.Token, s.routingSessionID, s.nextSqnum(),
			s.cfg.Token.AccessID, s.routingSessionID != 0, s.certResult.SessionKey, s.pwdKey))
		if len(s.cfg.Token.ExtraTokenData) > 0 {
			s.conn.Write(BuildSubscribeTokens(s.cfg.Token, s.routingSessionID, s.nextSqnum(),
				s.cfg.Token.ExtraTokenData, s.routingSessionID != 0, s.certResult.SessionKey, s.pwdKey))
		}
	}, opts.SubscribeDrain, false)

	online := s.wakeDrain(seen, "passthrough", func() {
		frame, msgID := BuildPassthroughMsg(s.cfg.Token, s.routingSessionID, s.nextSqnum(),
			s.targetDev.TID, opts.Wake, opts.Data, s.certResult.SessionKey, s.pwdKey)
		log.Printf("%s sending passthrough to %q TID=0x%016X wake=%v msgID=0x%08X (%d bytes)",
			s.prefix, s.targetDev.Name, s.targetDev.TID, opts.Wake, msgID, len(frame))
		s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		s.conn.Write(frame)
	}, opts.Listen, opts.StopOnOnline)
	return online, nil
}

// isOnlineReport reports whether body (a 0xAA device-state frame's
// payload) is the target device publishing a fresh "_online" state.
// The publishing device's id sits at body[10:18]. A fresh report is an
// update addressed by path ("ProReadonly._online." or "ProReadonly."
// followed by the changed members); the full state dump the server
// replays to every new session starts with {"ProReadonly": and says
// nothing about whether the device is awake now.
func (s *Session) isOnlineReport(body []byte) bool {
	if len(body) < 18 || binary.LittleEndian.Uint64(body[10:18]) != s.targetDev.TID {
		return false
	}
	if bytes.Contains(body, []byte(`{"ProReadonly":`)) {
		return false
	}
	return bytes.Contains(body, []byte("_online"))
}

// wakeDrain runs send, then reads frames for d. It returns true if the
// target device published a fresh online state; with stopOnOnline it
// returns as soon as that happens. The server re-sends frames we never
// ack, so repeats (tracked in seen) are ignored.
func (s *Session) wakeDrain(seen map[string]bool, phase string, send func(), d time.Duration, stopOnOnline bool) bool {
	send()
	online := false
	buf := make([]byte, 8192)
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		s.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
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
		if dec[1] == 0xAA {
			if s.isOnlineReport(body) {
				online = true
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
				return true
			}
			continue
		}
		if WakeVerbose {
			log.Printf("%s %s rx: sub=0x%02X len=%d (%s) %s", s.prefix, phase, dec[1], n, mode, hex.EncodeToString(body))
		}
	}
	return online
}
