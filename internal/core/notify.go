package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Notify sind die Einstellungen für Benachrichtigungen.
type Notify struct {
	Ntfy  NtfySettings  `json:"ntfy"`
	Email EmailSettings `json:"email"`
	HA    HASettings    `json:"ha"`
	// On sind die Anlässe, bei denen benachrichtigt wird (siehe NotifyKinds).
	On []string `json:"on"`
	// Lang: Sprache der Nachrichten (de, en, fr, it), leer = Deutsch.
	Lang string `json:"lang"`
}

// Translator übersetzt deutsche Texte (wird von main mit ui.Translate belegt).
var Translator = func(lang, s string) string { return s }

// T übersetzt einen Text in die Sprache der Benachrichtigungen.
func (h *Hub) T(s string) string {
	l := h.Store.Snapshot().Notify.Lang
	if l == "" || l == "de" {
		return s
	}
	return Translator(l, s)
}

// NtfySettings: Push-Nachrichten über ntfy.sh oder einen eigenen ntfy-Server.
type NtfySettings struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"` // leer = https://ntfy.sh
	Topic   string `json:"topic"`
	Token   string `json:"token,omitempty"`
}

// EmailSettings: Versand über einen SMTP-Server.
type EmailSettings struct {
	Enabled  bool   `json:"enabled"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Security string `json:"security"` // starttls | tls | none
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	From     string `json:"from"`
	To       string `json:"to"`
}

// HASettings: Webhook an Home Assistant.
type HASettings struct {
	Enabled   bool   `json:"enabled"`
	URL       string `json:"url"` // z. B. http://homeassistant.local:8123
	WebhookID string `json:"webhookId"`
}

// NotifyKinds sind die wählbaren Anlässe.
var NotifyKinds = []string{"dropbox", "sharedl", "upload", "login", "loginfail", "ban", "error"}

// DefaultNotifyOn ist die Vorauswahl: nur Wichtiges.
var DefaultNotifyOn = []string{"dropbox", "ban", "error"}

type notification struct {
	Kind  string
	Title string
	Body  string
	Data  EventData
}

type notifier struct {
	hub   *Hub
	queue chan notification

	mu     sync.Mutex
	recent map[string]time.Time // Entprellen gleicher Meldungen
	sent   []time.Time          // Begrenzung pro Stunde
}

func newNotifier(h *Hub) *notifier {
	n := &notifier{hub: h, queue: make(chan notification, 100), recent: map[string]time.Time{}}
	go n.loop()
	return n
}

func (s Notify) wants(kind string) bool {
	for _, k := range s.On {
		if k == kind {
			return true
		}
	}
	return false
}

func (s Notify) anyChannel() bool { return s.Ntfy.Enabled || s.Email.Enabled || s.HA.Enabled }

// NotifyEvent stellt eine Benachrichtigung in die Warteschlange, falls der Anlass gewählt ist.
func (h *Hub) NotifyEvent(kind, title, body string) {
	h.enqueue(notification{Kind: kind, Title: title, Body: body})
}

func (h *Hub) enqueue(n notification) {
	if h.notifier == nil {
		return
	}
	st := h.Store.Snapshot().Notify
	if !st.anyChannel() || !st.wants(n.Kind) {
		return
	}
	select {
	case h.notifier.queue <- n:
	default: // Warteschlange voll: lieber eine Meldung verlieren als hängen
	}
}

// notifyFromEvent übersetzt Ereignisse in verständliche Meldungen.
func (h *Hub) notifyFromEvent(d EventData) {
	who := d.User
	if who == "" {
		who = h.T("Jemand")
	}
	size := ""
	if d.Bytes > 0 {
		size = " (" + HumanBytes(d.Bytes) + ")"
	}
	switch {
	case d.Event == "share" && strings.HasPrefix(d.Extra, "upload"):
		id := strings.Fields(d.Extra + " _")[1]
		place := ""
		cfg := h.Store.Snapshot()
		if sh := cfg.FindShare(id); sh != nil {
			if sh.Comment != "" {
				place = " (" + sh.Comment + ")"
			} else if sh.RealPath != "" {
				place = h.T(" in ") + sh.RealPath
			}
		}
		from := ""
		if strings.Contains(d.Extra, "von ") {
			from = h.T(" von ") + strings.TrimSpace(d.Extra[strings.Index(d.Extra, "von ")+4:])
		}
		h.enqueue(notification{Kind: "dropbox", Data: d, Title: h.T("Neue Datei im Briefkasten"),
			Body: fmt.Sprintf(h.T("%s%s ist angekommen%s%s."), path.Base(d.Path), size, place, from)})
	case d.Event == "share" && strings.HasPrefix(d.Extra, "download"):
		h.enqueue(notification{Kind: "sharedl", Data: d, Title: h.T("Link wurde benutzt"),
			Body: fmt.Sprintf(h.T("%s%s wurde über einen Freigabe-Link heruntergeladen (IP %s)."), path.Base(d.Path), size, d.IP)})
	case d.Event == "upload":
		h.enqueue(notification{Kind: "upload", Data: d, Title: h.T("Neue Datei"),
			Body: fmt.Sprintf(h.T("%s hat %s%s hochgeladen (%s)."), who, d.Path, size, strings.ToUpper(d.Protocol))})
	case d.Event == "login":
		h.enqueue(notification{Kind: "login", Data: d, Title: h.T("Anmeldung"),
			Body: fmt.Sprintf(h.T("%s hat sich über %s angemeldet (IP %s)."), who, strings.ToUpper(d.Protocol), d.IP)})
	case d.Event == "loginfail":
		h.enqueue(notification{Kind: "loginfail", Data: d, Title: h.T("Anmeldung fehlgeschlagen"),
			Body: fmt.Sprintf(h.T("Fehlversuch als %q über %s von %s: %s."), d.User, strings.ToUpper(d.Protocol), d.IP, d.Extra)})
	}
}

func (n *notifier) loop() {
	for msg := range n.queue {
		if !n.allow(msg) {
			continue
		}
		st := n.hub.Store.Snapshot()
		for name, err := range n.send(context.Background(), st.Settings.ServerName, st.Notify, msg) {
			if err != nil {
				n.hub.Log.Warn("Benachrichtigung über %s fehlgeschlagen: %v", name, err)
			}
		}
	}
}

// allow entprellt gleiche Meldungen (10 Minuten) und begrenzt auf 30 pro Stunde.
func (n *notifier) allow(msg notification) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	key := msg.Kind + "|" + msg.Body
	if msg.Kind == "error" || msg.Kind == "loginfail" {
		if t, ok := n.recent[key]; ok && now.Sub(t) < 10*time.Minute {
			return false
		}
	}
	n.recent[key] = now
	for k, t := range n.recent {
		if now.Sub(t) > time.Hour {
			delete(n.recent, k)
		}
	}
	kept := n.sent[:0]
	for _, t := range n.sent {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	n.sent = kept
	if len(n.sent) >= 30 {
		return false
	}
	n.sent = append(n.sent, now)
	return true
}

// send verschickt an alle eingeschalteten Kanäle und liefert das Ergebnis pro Kanal.
func (n *notifier) send(ctx context.Context, server string, st Notify, msg notification) map[string]error {
	out := map[string]error{}
	title := msg.Title
	if server != "" {
		title = server + ": " + msg.Title
	}
	if st.Ntfy.Enabled {
		out["ntfy"] = sendNtfy(ctx, st.Ntfy, title, msg)
	}
	if st.Email.Enabled {
		out["E-Mail"] = sendEmail(st.Email, title, msg.Body)
	}
	if st.HA.Enabled {
		out["Home Assistant"] = sendHA(ctx, st.HA, title, msg)
	}
	return out
}

// TestNotify verschickt sofort eine Testnachricht und meldet das Ergebnis pro Kanal.
func (h *Hub) TestNotify(ctx context.Context, st Notify) map[string]string {
	res := map[string]string{}
	tr := func(s string) string {
		if st.Lang == "" || st.Lang == "de" {
			return s
		}
		return Translator(st.Lang, s)
	}
	msg := notification{Kind: "test", Title: "Test", Body: tr("Diese Nachricht kommt von SG9. Benachrichtigungen funktionieren.")}
	for name, err := range h.notifier.send(ctx, h.Store.Settings().ServerName, st, msg) {
		if err != nil {
			res[name] = err.Error()
		} else {
			res[name] = ""
		}
	}
	return res
}

var notifyClient = &http.Client{Timeout: 20 * time.Second}

func sendNtfy(ctx context.Context, s NtfySettings, title string, msg notification) error {
	server := strings.TrimRight(strings.TrimSpace(s.Server), "/")
	if server == "" {
		server = "https://ntfy.sh"
	}
	topic := strings.Trim(strings.TrimSpace(s.Topic), "/")
	if topic == "" {
		return errors.New("Thema (Topic) fehlt")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server+"/"+topic, strings.NewReader(msg.Body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", mime.QEncoding.Encode("utf-8", title))
	tags := map[string]string{"dropbox": "inbox_tray", "sharedl": "link", "upload": "arrow_up", "login": "key",
		"loginfail": "warning", "ban": "no_entry", "error": "rotating_light", "test": "white_check_mark"}[msg.Kind]
	if tags != "" {
		req.Header.Set("Tags", tags)
	}
	if msg.Kind == "ban" || msg.Kind == "error" {
		req.Header.Set("Priority", "high")
	}
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}
	return doPost(req)
}

func sendHA(ctx context.Context, s HASettings, title string, msg notification) error {
	base := strings.TrimRight(strings.TrimSpace(s.URL), "/")
	if base == "" || strings.TrimSpace(s.WebhookID) == "" {
		return errors.New("Adresse oder Webhook-ID fehlt")
	}
	body, _ := json.Marshal(map[string]any{"title": title, "message": msg.Body, "kind": msg.Kind,
		"user": msg.Data.User, "ip": msg.Data.IP, "path": msg.Data.Path, "bytes": msg.Data.Bytes})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/webhook/"+strings.TrimSpace(s.WebhookID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return doPost(req)
}

func doPost(req *http.Request) error {
	req.Header.Set("User-Agent", "SG9")
	resp, err := notifyClient.Do(req)
	if err != nil {
		return friendlyNetErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Server antwortete mit %s", resp.Status)
	}
	return nil
}

func friendlyNetErr(err error) error {
	s := err.Error()
	switch {
	case strings.Contains(s, "no such host"):
		return errors.New("Adresse nicht gefunden (Schreibweise prüfen)")
	case strings.Contains(s, "connection refused"):
		return errors.New("Verbindung abgelehnt (läuft der Dienst, stimmt der Port?)")
	case strings.Contains(s, "timeout") || strings.Contains(s, "deadline"):
		return errors.New("keine Antwort (Adresse oder Firewall prüfen)")
	case strings.Contains(s, "certificate"):
		return errors.New("Zertifikat ungültig (bei selbst signierten Zertifikaten http:// verwenden)")
	}
	return err
}

func sendEmail(s EmailSettings, subject, body string) error {
	host := strings.TrimSpace(s.Host)
	if host == "" || strings.TrimSpace(s.To) == "" {
		return errors.New("Server oder Empfänger fehlt")
	}
	port := s.Port
	if port == 0 {
		port = map[string]int{"tls": 465, "none": 25}[s.Security]
		if port == 0 {
			port = 587
		}
	}
	from := strings.TrimSpace(s.From)
	if from == "" {
		from = s.Username
	}
	if from == "" {
		return errors.New("Absender fehlt")
	}
	var to []string
	for _, t := range strings.FieldsFunc(s.To, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
		to = append(to, t)
	}
	msg := "From: SG9 <" + from + ">\r\nTo: " + strings.Join(to, ", ") + "\r\nSubject: " + mime.QEncoding.Encode("utf-8", subject) +
		"\r\nDate: " + time.Now().Format(time.RFC1123Z) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" +
		strings.ReplaceAll(body, "\n", "\r\n") + "\r\n"
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	if s.Security == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: host})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return friendlyNetErr(err)
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return err
	}
	defer c.Close()
	if s.Security == "starttls" || s.Security == "" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("der Server bietet kein STARTTLS an (Verschlüsselung auf „keine“ oder „TLS“ stellen)")
		}
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return friendlyNetErr(err)
		}
	}
	if s.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", s.Username, s.Password, host)); err != nil {
			return fmt.Errorf("Anmeldung am Mailserver fehlgeschlagen: %v", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, t := range to {
		if err := c.Rcpt(t); err != nil {
			return fmt.Errorf("Empfänger %s abgelehnt: %v", t, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
