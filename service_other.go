//go:build !windows

package main

import "errors"

func isService() bool { return false }

func runService(func(stop <-chan struct{})) {}

func manageService(install bool, dataDir string) error {
	return errors.New("Dienste gibt es so nur unter Windows. Unter Linux: deploy/sg9.service (systemd), unter macOS: deploy/ch.gerweck.sg9.plist (launchd)")
}
