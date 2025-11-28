package main

import (
	"bufio"
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	influx "github.com/influxdata/influxdb1-client/v2"
	"github.com/joho/godotenv"
	mail "github.com/wneessen/go-mail"
)

const (
	defaultWatchFile      = "./watch_list.txt"
	defaultPollInterval   = 30
	defaultReloadInterval = 500
	defaultInfluxLimit    = 5000
	influxMeasurement     = "nginx_access_log"
	auditStateRowID       = 1
	defaultMailFromName   = "CIDR Watcher"
	defaultMailFromAddr   = "no-reply@melroy.org"
	defaultMailThreshold  = 10
)

type Config struct {
	InfluxAddr     string
	InfluxDB       string
	InfluxUser     string
	InfluxPass     string
	MySQLDSN       string
	WatchFile      string
	PollInterval   time.Duration
	ReloadInterval time.Duration
	InfluxLimit    int
	MailFromName   string
	MailFromAddr   string
	MailTo         string
	MailThreshold  int
}

type Watcher struct {
	cfg           Config
	influxCli     influx.Client
	sqlDB         *sql.DB
	cidrs         []*net.IPNet
	cidrsMu       sync.RWMutex
	lastProcessed int64 // unix nanoseconds
}

func main() {
	// Allow flags for quick testing
	var (
		flPoll = flag.Int("poll", 0, "poll interval seconds (overrides POLL_INTERVAL_SECONDS env)")
	)
	flag.Parse()

	// Load .env if present to allow local env var overrides
	if err := godotenv.Load(); err != nil {
		// Not fatal; log and continue. If the file isn't present, environment variables may still be set.
		log.Printf("warning: could not load .env file: %v", err)
	}

	cfg := loadConfig()
	if *flPoll > 0 {
		cfg.PollInterval = time.Duration(*flPoll) * time.Second
	}

	w := &Watcher{cfg: cfg}
	if err := w.init(); err != nil {
		log.Fatalf("init: %v", err)
	}

	// start watchlist reload ticker
	go func() {
		t := time.NewTicker(w.cfg.ReloadInterval)
		defer t.Stop()
		for range t.C {
			if err := w.loadCIDRs(); err != nil {
				log.Printf("watchlist reload error: %v", err)
			}
		}
	}()

	// main loop
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()
	for {
		err := w.pollOnce(context.Background())
		if err != nil {
			log.Printf("poll error: %v", err)
		}
		<-ticker.C
	}
}

func loadConfig() Config {
	// parse integer env vars manually and fall back to defaults if missing or invalid
	poll := defaultPollInterval
	if pv := os.Getenv("POLL_INTERVAL_SECONDS"); pv != "" {
		if vi, err := strconv.Atoi(pv); err == nil {
			poll = vi
		} else {
			log.Printf("invalid POLL_INTERVAL_SECONDS %q, using default %d: %v", pv, defaultPollInterval, err)
		}
	}

	reload := defaultReloadInterval
	if rv := os.Getenv("WATCHLIST_RELOAD_SECONDS"); rv != "" {
		if vi, err := strconv.Atoi(rv); err == nil {
			reload = vi
		} else {
			log.Printf("invalid WATCHLIST_RELOAD_SECONDS %q, using default %d: %v", rv, defaultReloadInterval, err)
		}
	}

	limit := defaultInfluxLimit
	if lv := os.Getenv("INFLUX_QUERY_LIMIT"); lv != "" {
		if vi, err := strconv.Atoi(lv); err == nil {
			limit = vi
		} else {
			log.Printf("invalid INFLUX_QUERY_LIMIT %q, using default %d: %v", lv, defaultInfluxLimit, err)
		}
	}
	// mail config
	mailFromName := os.Getenv("MAIL_FROM_NAME")
	if mailFromName == "" {
		mailFromName = defaultMailFromName
	}
	mailFromAddr := os.Getenv("MAIL_FROM_ADDR")
	if mailFromAddr == "" {
		mailFromAddr = defaultMailFromAddr
	}
	mailTo := os.Getenv("MAIL_TO")
	mailThreshold := defaultMailThreshold
	if mt := os.Getenv("ALERT_HIT_THRESHOLD"); mt != "" {
		if vi, err := strconv.Atoi(mt); err == nil {
			mailThreshold = vi
		} else {
			log.Printf("invalid ALERT_HIT_THRESHOLD %q, using default %d: %v", mt, defaultMailThreshold, err)
		}
	}
	// influx / mysql config
	influxAddr := os.Getenv("INFLUX_ADDR")
	if influxAddr == "" {
		influxAddr = "http://127.0.0.1:8086"
	}
	influxDB := os.Getenv("INFLUX_DB")
	if influxDB == "" {
		influxDB = "telegraf"
	}
	influxUser := os.Getenv("INFLUX_USER")
	influxPass := os.Getenv("INFLUX_PASS")
	mysqlDSN := os.Getenv("MYSQL_DSN")
	// Default to unix socket at /var/run/mysqld/mysqld.sock when MYSQL_DSN not provided
	if mysqlDSN == "" {
		mysqlDSN = "root:password@unix(/var/run/mysqld/mysqld.sock)/auditdb?parseTime=true"
	}
	watchFile := os.Getenv("WATCH_LIST_FILE")
	if watchFile == "" {
		watchFile = defaultWatchFile
	}

	return Config{
		InfluxAddr:     influxAddr,
		InfluxDB:       influxDB,
		InfluxUser:     influxUser,
		InfluxPass:     influxPass,
		MySQLDSN:       mysqlDSN,
		WatchFile:      watchFile,
		PollInterval:   time.Duration(poll) * time.Second,
		ReloadInterval: time.Duration(reload) * time.Second,
		InfluxLimit:    limit,
		MailFromName:   mailFromName,
		MailFromAddr:   mailFromAddr,
		MailTo:         mailTo,
		MailThreshold:  mailThreshold,
	}
}

func (w *Watcher) init() error {
	// influx client
	c, err := influx.NewHTTPClient(influx.HTTPConfig{
		Addr:     w.cfg.InfluxAddr,
		Username: w.cfg.InfluxUser,
		Password: w.cfg.InfluxPass,
		Timeout:  10 * time.Second,
	})
	if err != nil {
		return fmt.Errorf("create influx client: %w", err)
	}
	w.influxCli = c

	// mysql
	db, err := sql.Open("mysql", w.cfg.MySQLDSN)
	if err != nil {
		return fmt.Errorf("open mysql: %w", err)
	}
	db.SetMaxOpenConns(10)
	db.SetConnMaxLifetime(5 * time.Minute)
	w.sqlDB = db

	// load last processed from DB (or create row)
	if err := w.loadState(); err != nil {
		return fmt.Errorf("load state: %w", err)
	}

	// load CIDRs initially
	if err := w.loadCIDRs(); err != nil {
		log.Printf("warning: failed to load watchlist at startup: %v", err)
	}

	return nil
}

func (w *Watcher) loadCIDRs() error {
	path := w.cfg.WatchFile
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var list []*net.IPNet
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// support both plain IPs and CIDRs
		if !strings.Contains(line, "/") {
			// treat single IP as /32 or /128
			if strings.Contains(line, ":") {
				line = line + "/128"
			} else {
				line = line + "/32"
			}
		}
		_, ipnet, err := net.ParseCIDR(line)
		if err != nil {
			log.Printf("invalid cidr '%s' in watchlist: %v", scanner.Text(), err)
			continue
		}
		list = append(list, ipnet)
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	w.cidrsMu.Lock()
	w.cidrs = list
	w.cidrsMu.Unlock()
	log.Printf("loaded %d cidrs from %s", len(list), path)
	return nil
}

func (w *Watcher) loadState() error {
	// ensure audit_state row exists. Use transaction for safety.
	tx, err := w.sqlDB.Begin()
	if err != nil {
		return err
	}

	// try select
	var last sql.NullInt64
	err = tx.QueryRow("SELECT last_processed FROM audit_state WHERE id = ?", auditStateRowID).Scan(&last)
	if err != nil {
		if err == sql.ErrNoRows {
			_, err = tx.Exec("INSERT INTO audit_state (id, last_processed) VALUES (?, ?)", auditStateRowID, 0)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			w.lastProcessed = 0
		} else {
			_ = tx.Rollback()
			return err
		}
	} else {
		if last.Valid {
			w.lastProcessed = last.Int64
		} else {
			w.lastProcessed = 0
		}
	}

	if err := tx.Commit(); err != nil {
		// commit failed; attempt rollback and return the commit error
		_ = tx.Rollback()
		return err
	}
	log.Printf("last_processed loaded: %d (unix-ns)", w.lastProcessed)
	return nil
}

func (w *Watcher) pollOnce(ctx context.Context) error {
	// build query
	var q string
	if w.lastProcessed == 0 {
		q = fmt.Sprintf("SELECT time, remote_ip FROM %s ORDER BY time ASC LIMIT %d", influxMeasurement, w.cfg.InfluxLimit)
	} else {
		// convert lastProcessed (ns) -> RFC3339Nano
		t := time.Unix(0, w.lastProcessed).UTC().Format(time.RFC3339Nano)
		q = fmt.Sprintf("SELECT time, remote_ip FROM %s WHERE time > '%s' ORDER BY time ASC LIMIT %d", influxMeasurement, t, w.cfg.InfluxLimit)
	}

	resp, err := queryInflux(w.influxCli, w.cfg.InfluxDB, q)
	if err != nil {
		return fmt.Errorf("influx query: %w", err)
	}

	if len(resp) == 0 {
		// nothing new
		return nil
	}

	// process rows
	var maxSeen int64 = w.lastProcessed
	var processed int
	for _, res := range resp {
		if res.Series == nil {
			continue
		}
		for _, series := range res.Series {
			// find indices for time and remote_ip
			timeIdx := -1
			ipIdx := -1
			for i, col := range series.Columns {
				if col == "time" {
					timeIdx = i
				}
				if col == "remote_ip" {
					ipIdx = i
				}
			}
			if timeIdx == -1 {
				log.Printf("series missing time column, skipping")
				continue
			}
			if ipIdx == -1 {
				// nothing to check
				continue
			}

			for _, row := range series.Values {
				processed++
				// time is usually string in RFC3339
				timeStr, ok := row[timeIdx].(string)
				if !ok {
					continue
				}
				t, err := time.Parse(time.RFC3339Nano, timeStr)
				if err != nil {
					// try fallback to parse without nano
					t2, err2 := time.Parse(time.RFC3339, timeStr)
					if err2 != nil {
						log.Printf("failed to parse time '%v': %v / %v", timeStr, err, err2)
						continue
					}
					t = t2
				}
				ns := t.UnixNano()
				if ns > maxSeen {
					maxSeen = ns
				}

				// remote_ip column may be string or nil
				var ipStr string
				if row[ipIdx] != nil {
					ipStr, _ = row[ipIdx].(string)
				}
				if ipStr == "" {
					continue
				}

				// check cidrs
				if w.ipMatchesAny(ipStr) {
					if err := w.upsertIP(ipStr); err != nil {
						log.Printf("upsert ip %s error: %v", ipStr, err)
					}
				}
			}
		}
	}

	// update last processed if changed
	if maxSeen > w.lastProcessed {
		if err := w.updateState(maxSeen); err != nil {
			return fmt.Errorf("update state: %w", err)
		}
		w.lastProcessed = maxSeen
	}
	if processed > 0 {
		log.Printf("processed %d rows, last_processed now %d", processed, w.lastProcessed)
	}
	return nil
}

func queryInflux(c influx.Client, db, cmd string) ([]influx.Result, error) {
	q := influx.Query{
		Command:  cmd,
		Database: db,
	}
	resp, err := c.Query(q)
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, fmt.Errorf("nil response from influx")
	}
	if resp.Error() != nil {
		return nil, resp.Error()
	}
	return resp.Results, nil
}

func (w *Watcher) ipMatchesAny(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	w.cidrsMu.RLock()
	defer w.cidrsMu.RUnlock()
	for _, n := range w.cidrs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (w *Watcher) upsertIP(ip string) error {
	// perform a transaction to atomically update and capture new hit count
	tx, err := w.sqlDB.Begin()
	if err != nil {
		return err
	}

	var oldHits sql.NullInt64
	err = tx.QueryRow("SELECT hits FROM audit_ips WHERE ip = ? FOR UPDATE", ip).Scan(&oldHits)
	if err != nil {
		if err == sql.ErrNoRows {
			// insert
			_, err = tx.Exec("INSERT INTO audit_ips (ip, hits, last_seen) VALUES (?, 1, NOW())", ip)
			if err != nil {
				_ = tx.Rollback()
				return err
			}
			if err := tx.Commit(); err != nil {
				_ = tx.Rollback()
				return err
			}
			// hits == 1; no notification
			return nil
		}
		// query failed; rollback and return
		_ = tx.Rollback()
		return err
	}

	// increment
	newHits := oldHits.Int64 + 1
	_, err = tx.Exec("UPDATE audit_ips SET hits = ?, last_seen = NOW(), updated_at = NOW() WHERE ip = ?", newHits, ip)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		return err
	}

	// if we crossed the threshold, send notification
	if int(oldHits.Int64) < w.cfg.MailThreshold && int(newHits) >= w.cfg.MailThreshold {
		if err := w.sendNotification(ip, int(newHits)); err != nil {
			log.Printf("failed to send notification for %s: %v", ip, err)
		} else {
			// log success
			log.Printf("sent notification: %s reached %d hits", ip, newHits)
		}
	}
	return nil
}

func (w *Watcher) sendNotification(ip string, hits int) error {
	// If no recipient is configured then the notification is optional; do nothing and return success.
	if strings.TrimSpace(w.cfg.MailTo) == "" {
		log.Printf("notification suppressed for %s (%d hits): no MAIL_TO configured", ip, hits)
		return nil
	}
	m := mail.NewMsg()
	body := fmt.Sprintf("IP %s reached %d hits", ip, hits)
	m.SetBodyString(mail.TypeTextPlain, body)
	if err := m.FromFormat(w.cfg.MailFromName, w.cfg.MailFromAddr); err != nil {
		return fmt.Errorf("set from: %w", err)
	}
	if err := m.To(w.cfg.MailTo); err != nil {
		return fmt.Errorf("set to: %w", err)
	}
	if err := m.WriteToSendmail(); err != nil {
		return fmt.Errorf("send: %w", err)
	}
	return nil
}

func (w *Watcher) updateState(ns int64) error {
	_, err := w.sqlDB.Exec("UPDATE audit_state SET last_processed = ? WHERE id = ?", ns, auditStateRowID)
	return err
}
