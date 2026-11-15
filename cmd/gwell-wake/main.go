// Command gwell-wake is a diagnostic: it asks the Gwell P2P server to
// wake one sleeping camera by sending it a passthrough message with the
// wake flag, without starting a call. It gets the Gwell credential from
// the bridge's loopback shim, like gwell-proxy does.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/IDisposable/docker-wyze-bridge/internal/gwell/upstream/gwell"
)

func main() {
	shim := flag.String("shim-url", "http://127.0.0.1:5080/internal/wyze", "bridge wyze-shim base URL")
	device := flag.String("device", "", "camera id, e.g. GW_BE1_AABBCCDDEEFF")
	payload := flag.String("payload", "{}", "passthrough message body")
	wake := flag.Bool("wake", true, "set the wake-device flag")
	listen := flag.Duration("listen", 10*time.Second, "how long to log server replies after sending")
	server := flag.String("server", "", "P2P server host:port to use, skipping discovery (the bridge logs it as \"gwell p2p server ready\")")
	drain := flag.Duration("drain", 2*time.Second, "how long to read the server's state dump before sending")
	repeat := flag.Int("repeat", 0, "send the message this many more times on the same session")
	every := flag.Duration("every", 10*time.Second, "gap between repeated messages")
	heartbeat := flag.Duration("heartbeat", 0, "send a session heartbeat this often between repeated messages (0 = none)")
	tid := flag.Uint64("tid", 0, "the device's P2P id (logged as TID=0x...), for when the server omits the device list from a session opened right after another one")
	flag.Parse()
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	if *device == "" {
		log.Fatal("-device is required")
	}

	var cred struct {
		AccessID    string `json:"accessId"`
		AccessToken string `json:"accessToken"`
	}
	hc := &http.Client{Timeout: 30 * time.Second}
	resp, err := hc.Get(*shim + "/Camera/CameraToken?deviceId=" + url.QueryEscape(*device))
	if err != nil {
		log.Fatalf("shim: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("shim: HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&cred); err != nil {
		log.Fatalf("shim: %v", err)
	}
	token, err := gwell.ParseAccessToken(cred.AccessID, cred.AccessToken)
	if err != nil {
		log.Fatalf("token: %v", err)
	}

	cfg := gwell.SessionConfig{Token: token, ServerAddr: *server, DeviceName: *device}
	if *tid != 0 {
		cfg.Devices = []gwell.DeviceInfo{{TID: *tid, Name: *device}}
	}
	sess := gwell.NewSession(cfg)
	gwell.WakeVerbose = true
	res, err := sess.Wake(gwell.WakeOptions{Data: []byte(*payload), Wake: *wake, Listen: *listen, SubscribeDrain: *drain,
		StopOnOnline: *repeat > 0, Repeat: *repeat, RepeatEvery: *every, Heartbeat: *heartbeat})
	if err != nil {
		log.Fatalf("wake: %v", err)
	}
	fmt.Printf("done initial_state=%d online=%v\n", res.InitialState, res.Online)
}
