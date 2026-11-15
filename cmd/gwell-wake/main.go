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
	flag.Parse()
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

	sess := gwell.NewSession(gwell.SessionConfig{Token: token, DeviceName: *device})
	gwell.WakeVerbose = true
	res, err := sess.Wake(gwell.WakeOptions{Data: []byte(*payload), Wake: *wake, Listen: *listen, SubscribeDrain: 2 * time.Second})
	if err != nil {
		log.Fatalf("wake: %v", err)
	}
	fmt.Printf("done initial_state=%d online=%v\n", res.InitialState, res.Online)
}
