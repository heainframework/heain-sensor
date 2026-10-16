// Command heain-sensor takes readings from devices outside the trust
// boundary (Step 4.6g). Apps reach it through heain-sdk (mTLS); devices post
// to a separate HTTPS listener. Configured through the heain-sdk HEAIN_*
// variables plus the flags below; runs however the operator likes.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/heainframework/heain-sdk/heain"
	"github.com/heainframework/heain-sensor/internal/sensor"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	devListen := flag.String("device-listen", env("HEAIN_SENSOR_DEVICE_LISTEN", ":8570"), "where devices post (HTTPS)")
	devCert := flag.String("device-cert", os.Getenv("HEAIN_SENSOR_DEVICE_CERT"), "the device listener's certificate (PEM; devices pin it or its CA)")
	devKey := flag.String("device-key", os.Getenv("HEAIN_SENSOR_DEVICE_KEY"), "its private key")
	adminCallers := flag.String("admin-callers", os.Getenv("HEAIN_SENSOR_ADMIN_CALLERS"), "comma-separated app ids that may manage devices and rules (people need the sensor-admin role through heain-gateway)")
	notifyApp := flag.String("notify-app", "heain-notify", "the app that sends alerts")
	retention := flag.Duration("retention", 30*24*time.Hour, "readings older than this are removed (at most 400 days, the manifest's ceiling)")
	noticeMax := flag.Duration("notice-max-age", 24*time.Hour, "an alert notice heain-notify never took is given up after this (it is kept and retried until then)")
	rate := flag.Int("rate-per-min", 120, "posts per device per minute")
	poll := flag.Duration("poll", 3*time.Second, "how often P5 decisions are checked")
	flag.Parse()
	if *retention <= 0 || *retention > 400*24*time.Hour {
		log.Fatal("heain-sensor: -retention must be between 1s and 400 days (the manifest's ceiling)")
	}
	if *devCert == "" || *devKey == "" {
		log.Fatal("heain-sensor: -device-cert and -device-key are required (devices post over HTTPS)")
	}
	pair, err := tls.LoadX509KeyPair(*devCert, *devKey)
	if err != nil {
		log.Fatalf("heain-sensor: device certificate: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	state := env("HEAIN_STATE_DIR", "/state")
	app, err := heain.StartFromEnv(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "REFUSED: %v\n", err)
		os.Exit(2)
	}
	log.Printf("heain-sensor: registered (%s), waiting for admission", app.Status())
	if err := app.WaitActive(ctx); err != nil {
		log.Fatal(err)
	}
	inside, err := app.DataKey(ctx, "inside")
	if err != nil {
		log.Fatalf("heain-sensor: data key from core: %v", err)
	}
	st, err := sensor.Open(filepath.Join(state, "sensor.db"), inside, sensor.Keys{Sealer: app.Sealer, Destroy: app.DestroyDataKey})
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	var admins []string
	for _, a := range strings.Split(*adminCallers, ",") {
		if a = strings.TrimSpace(a); a != "" {
			admins = append(admins, a)
		}
	}
	eng := sensor.New(&sensor.Engine{Store: st, Plat: app, Logf: log.Printf,
		Cfg: sensor.Config{AdminCallers: admins, NotifyApp: *notifyApp, Retention: *retention, RatePerMin: *rate, PollEvery: *poll, NoticeMaxAge: *noticeMax}})
	go eng.Run(ctx)
	dev := &http.Server{Addr: *devListen, Handler: eng.DeviceHandler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}}
	go func() {
		log.Printf("heain-sensor: devices post to https://%s%s", *devListen, sensor.IngestPath)
		if err := dev.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatalf("heain-sensor: device listener: %v", err)
		}
	}()
	srv := app.NewServer()
	if err := eng.Register(srv); err != nil {
		log.Fatal(err)
	}
	l, err := net.Listen("tcp", heain.Listen(":19570"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("heain-sensor: active on %s", l.Addr())
	if err := srv.Serve(ctx, l); err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
	_ = dev.Shutdown(context.Background())
	_ = app.Close(context.Background())
	log.Printf("heain-sensor: deregistered")
}
