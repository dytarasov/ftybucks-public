package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fyne.io/systray"

	"ftybucks/internal/config"
)

var (
	cfg        *config.Config
	controller *TunnelController
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	cfgPath := flag.String("c", "", "path to config file")
	setup := flag.Bool("setup", false, "run setup wizard")
	flag.Parse()

	if os.Getuid() != 0 {
		fmt.Fprintln(os.Stderr, "requires root for TUN. run: sudo ./bin/ftybucks")
		os.Exit(1)
	}

	// Determine config path
	path := *cfgPath
	if *setup {
		path = runSetupWizard()
	}
	if path == "" {
		path = findConfig()
	}
	if path == "" {
		path = runSetupWizard()
	}

	var err error
	cfg, err = config.Load(path)
	if err != nil {
		log.Fatalf("[ftybucks] config error: %v", err)
	}

	log.Printf("[ftybucks] server: %s", cfg.Server)

	controller = NewTunnelController(cfg)
	systray.Run(onReady, onExit)
}

func onReady() {
	systray.SetTooltip("FtyBucks")
	setIcon(false)

	mStatus := systray.AddMenuItem("Disconnected", "")
	mStatus.Disable()

	mServer := systray.AddMenuItem(cfg.Server, "Server address")
	mServer.Disable()

	systray.AddSeparator()

	mToggle := systray.AddMenuItem("Connect", "Connect to VPN")

	systray.AddSeparator()

	mQuit := systray.AddMenuItem("Quit", "Quit FtyBucks")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("[ftybucks] ready")

	for {
		select {
		case <-mToggle.ClickedCh:
			switch controller.State() {
			case Disconnected:
				controller.Connect()
			case Connected:
				controller.Disconnect()
			}

		case state := <-controller.stateCh:
			switch state {
			case Disconnected:
				mStatus.SetTitle("Disconnected")
				if err := controller.LastError(); err != nil {
					mStatus.SetTitle(fmt.Sprintf("Error: %v", err))
				}
				mToggle.SetTitle("Connect")
				mToggle.Enable()
				setIcon(false)
			case Connecting:
				mStatus.SetTitle("Connecting...")
				mToggle.SetTitle("Disconnect")
				mToggle.Enable()
				setIcon(false)
			case Connected:
				mStatus.SetTitle("Connected")
				mToggle.SetTitle("Disconnect")
				mToggle.Enable()
				setIcon(true)
			case Disconnecting:
				mStatus.SetTitle("Disconnecting...")
				mToggle.Disable()
				setIcon(false)
			}

		case <-ticker.C:
			if controller.State() == Connected {
				uptime := time.Since(controller.StartTime()).Truncate(time.Second)
				mStatus.SetTitle(fmt.Sprintf("Connected (%s)", formatDuration(uptime)))
			}

		case <-sig:
			log.Println("[ftybucks] shutting down...")
			gracefulShutdown()
			return

		case <-mQuit.ClickedCh:
			log.Println("[ftybucks] quit")
			gracefulShutdown()
			return
		}
	}
}

func gracefulShutdown() {
	if controller.State() == Connected || controller.State() == Connecting {
		controller.Disconnect()
		for s := range controller.stateCh {
			if s == Disconnected {
				break
			}
		}
	}
	systray.Quit()
}

func onExit() {}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func setIcon(connected bool) {
	if connected {
		systray.SetTemplateIcon(iconConnected, iconConnected)
	} else {
		systray.SetTemplateIcon(iconDisconnected, iconDisconnected)
	}
}
