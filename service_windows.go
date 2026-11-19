//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "SG9"

func isService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

type sg9Service struct{ run func(stop <-chan struct{}) }

func (s *sg9Service) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() { s.run(stop); close(done) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				close(stop)
				select {
				case <-done:
				case <-time.After(15 * time.Second):
				}
				return false, 0
			}
		case <-done:
			return false, 0
		}
	}
}

func runService(run func(stop <-chan struct{})) {
	if err := svc.Run(serviceName, &sg9Service{run: run}); err != nil {
		fmt.Fprintln(os.Stderr, "Dienst:", err)
	}
}

// manageService richtet den Windows-Dienst ein oder entfernt ihn (braucht Administratorrechte).
func manageService(install bool, dataDir string) error {
	m, err := mgr.Connect()
	if err != nil {
		return errors.New("keine Verbindung zur Dienstverwaltung. PowerShell als Administrator öffnen und nochmals versuchen")
	}
	defer m.Disconnect()
	if !install {
		s, err := m.OpenService(serviceName)
		if err != nil {
			return errors.New("der Dienst SG9 ist nicht eingerichtet")
		}
		defer s.Close()
		_, _ = s.Control(svc.Stop)
		time.Sleep(2 * time.Second)
		if err := s.Delete(); err != nil {
			return err
		}
		fmt.Println("Dienst SG9 entfernt. Deine Daten im Ordner", dataDir, "bleiben erhalten.")
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return errors.New("der Dienst SG9 ist schon eingerichtet. Zum Neu-Einrichten zuerst -uninstall-service")
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName:  "SG9 Datei-Server",
		Description:  "FTP, SFTP, WebDAV, Browser-Zugang und Freigabe-Links",
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}, "-data", dataDir)
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 2 * time.Minute},
	}, 86400)
	if err := s.Start(); err != nil {
		return fmt.Errorf("eingerichtet, aber Start fehlgeschlagen: %v", err)
	}
	fmt.Println("Dienst SG9 eingerichtet und gestartet. Er startet ab jetzt mit Windows, auch ohne Anmeldung.")
	fmt.Println("Datenordner:", dataDir)
	return nil
}
