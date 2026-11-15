package gwell

import (
	"encoding/binary"
	"testing"
)

func TestBuildPassthroughMsg(t *testing.T) {
	token := &AccessToken{AccessID: 0x8001020304050607}
	sessionKey := NewRC5Key([]byte("0123456789abcdef0123456789abcdef"))
	pwdKey := NewPasswordKey()
	const routing = uint64(0x6AF92E8E5E9C2302)
	const dst = uint64(0x000186D600132074)
	data := []byte("{}")

	for _, wake := range []bool{true, false} {
		raw, msgID := BuildPassthroughMsg(token, routing, 7, dst, wake, data, sessionKey, pwdKey)
		if len(raw) != 0x34+len(data) {
			t.Fatalf("len = %d", len(raw))
		}
		f, mode := TryDecrypt(raw, len(raw), sessionKey, pwdKey)
		if f == nil || mode != "mode-2" {
			t.Fatalf("decrypt failed (mode %q)", mode)
		}
		if f[0] != ProtoEncrypted || f[1] != 0xB9 {
			t.Errorf("proto/sub = %02X/%02X", f[0], f[1])
		}
		if got := binary.LittleEndian.Uint64(f[4:12]); got != routing {
			t.Errorf("routing id = %016X", got)
		}
		wantFlags := uint32(0)
		if wake {
			wantFlags = 0x2
		}
		if got := binary.LittleEndian.Uint32(f[24:28]); got != wantFlags {
			t.Errorf("wake=%v msg flags = %#x, want %#x", wake, got, wantFlags)
		}
		if got := binary.LittleEndian.Uint64(f[28:36]); got != dst {
			t.Errorf("dst = %016X", got)
		}
		if got := binary.LittleEndian.Uint64(f[36:44]); got != token.AccessID {
			t.Errorf("src = %016X", got)
		}
		if got := binary.LittleEndian.Uint32(f[44:48]); got != msgID || msgID&0x80000000 != 0 {
			t.Errorf("msg id = %08X, returned %08X", got, msgID)
		}
		if got := binary.LittleEndian.Uint16(f[48:50]); int(got) != len(data) {
			t.Errorf("data len = %d", got)
		}
		if string(f[0x34:0x34+len(data)]) != string(data) {
			t.Errorf("data = %q", f[0x34:])
		}
	}
}

func TestIsOnlineReport(t *testing.T) {
	s := &Session{targetDev: DeviceInfo{TID: 0x000186D600132074}}
	withBody := func(tid uint64, text string) []byte {
		b := make([]byte, 19)
		binary.LittleEndian.PutUint64(b[10:18], tid)
		return append(b, text...)
	}
	if !s.isOnlineReport(withBody(s.targetDev.TID, `ProReadonly._online.{"stVal":1}`)) {
		t.Error("partial _online update from the target not recognised")
	}
	if !s.isOnlineReport(withBody(s.targetDev.TID, `ProReadonly.{"_online":{"stVal":1},"power":{}}`)) {
		t.Error("grouped update with _online from the target not recognised")
	}
	if s.isOnlineReport(withBody(s.targetDev.TID, `{"ProReadonly":{"_online":{"stVal":1}},"Action":{}}`)) {
		t.Error("replayed full state dump counted as a fresh online report")
	}
	if s.isOnlineReport(withBody(s.targetDev.TID, `ProReadonly.power.{"stVal":{}}`)) {
		t.Error("power update counted as online")
	}
	if s.isOnlineReport(withBody(0x000186D600134B6C, `ProReadonly._online.{"stVal":1}`)) {
		t.Error("another device's state counted as the target's")
	}
}

func TestDumpState(t *testing.T) {
	s := &Session{targetDev: DeviceInfo{TID: 0x000186D600132074}}
	withBody := func(tid uint64, text string) []byte {
		b := make([]byte, 19)
		binary.LittleEndian.PutUint64(b[10:18], tid)
		return append(b, text...)
	}
	cases := []struct {
		tid  uint64
		text string
		want int
	}{
		{s.targetDev.TID, `{"ProReadonly":{"_online":{"stVal":1,"t":1794763130},"power":{}}}`, DeviceStateAwake},
		{s.targetDev.TID, `{"ProReadonly":{"_online":{"stVal":2,"t":1794763024},"power":{}}}`, DeviceStateAsleep},
		// A fresh update is not the replayed dump.
		{s.targetDev.TID, `ProReadonly._online.{"stVal":1,"t":1794763130}`, DeviceStateUnknown},
		// Another device's dump (the chime) says nothing about the target.
		{0x000186D600134B6C, `{"ProReadonly":{"_online":{"stVal":1,"t":1}}}`, DeviceStateUnknown},
		{s.targetDev.TID, `{"ProReadonly":{"power":{}}}`, DeviceStateUnknown},
		{s.targetDev.TID, `{"ProReadonly":{"_online":{"stVal":`, DeviceStateUnknown},
	}
	for _, c := range cases {
		if got := s.dumpState(withBody(c.tid, c.text)); got != c.want {
			t.Errorf("dumpState(%q) = %d, want %d", c.text, got, c.want)
		}
	}
}
