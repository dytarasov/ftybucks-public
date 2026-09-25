package geoip

import (
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// DB-IP Lite Country — free, no registration, MMDB format, updated monthly.
// https://db-ip.com/db/download/ip-to-country-lite
func downloadURL() string {
	now := time.Now()
	return fmt.Sprintf("https://download.db-ip.com/free/dbip-country-lite-%d-%02d.mmdb.gz", now.Year(), now.Month())
}

type DB struct {
	reader      *maxminddb.Reader
	dbPath      string
	countryCode string

	mu      sync.RWMutex
	subnets []*net.IPNet
}

// country.iso_code — same field name in both MaxMind and DB-IP MMDB.
type countryRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

func New(dbPath, countryCode string) (*DB, error) {
	db := &DB{
		dbPath:      dbPath,
		countryCode: strings.ToUpper(countryCode),
	}

	if err := db.open(); err != nil {
		log.Printf("[geoip] database not found at %s, downloading...", dbPath)
		if dlErr := db.Download(); dlErr != nil {
			return nil, fmt.Errorf("open %s: %w; download: %v", dbPath, err, dlErr)
		}
		if err := db.open(); err != nil {
			return nil, err
		}
	}

	return db, nil
}

func (db *DB) open() error {
	reader, err := maxminddb.Open(db.dbPath)
	if err != nil {
		return fmt.Errorf("open mmdb: %w", err)
	}
	if db.reader != nil {
		db.reader.Close()
	}
	db.reader = reader
	return nil
}

// IsCountry checks if the given IP belongs to the configured country.
func (db *DB) IsCountry(ip net.IP) bool {
	var record countryRecord
	err := db.reader.Lookup(ip, &record)
	if err != nil {
		return false
	}
	return record.Country.ISOCode == db.countryCode
}

// ExtractSubnets walks the entire database and returns all IPv4 subnets for the configured country.
func (db *DB) ExtractSubnets() ([]*net.IPNet, error) {
	var subnets []*net.IPNet

	networks := db.reader.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var record countryRecord
		subnet, err := networks.Network(&record)
		if err != nil {
			continue
		}
		if record.Country.ISOCode != db.countryCode {
			continue
		}
		// Only IPv4
		if subnet.IP.To4() == nil {
			continue
		}
		subnets = append(subnets, subnet)
	}

	if err := networks.Err(); err != nil {
		return nil, fmt.Errorf("iterate networks: %w", err)
	}

	db.mu.Lock()
	db.subnets = subnets
	db.mu.Unlock()

	return subnets, nil
}

// Subnets returns the last extracted subnets.
func (db *DB) Subnets() []*net.IPNet {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.subnets
}

// Download fetches the latest DB-IP Lite Country database (.mmdb.gz).
func (db *DB) Download() error {
	url := downloadURL()
	log.Printf("[geoip] downloading %s", url)

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download geoip: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download geoip: status %d", resp.StatusCode)
	}

	// DB-IP distributes as plain .mmdb.gz (not tar.gz)
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()

	if err := os.MkdirAll(filepath.Dir(db.dbPath), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}

	tmpPath := db.dbPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}

	n, err := io.Copy(f, gz)
	f.Close()
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("write mmdb: %w", err)
	}

	if err := os.Rename(tmpPath, db.dbPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename: %w", err)
	}

	log.Printf("[geoip] downloaded %s (%.1f MB)", db.dbPath, float64(n)/1024/1024)
	return nil
}

// Update downloads the latest database and reloads it.
func (db *DB) Update() error {
	if err := db.Download(); err != nil {
		return err
	}
	return db.open()
}

// Close closes the database.
func (db *DB) Close() {
	if db.reader != nil {
		db.reader.Close()
	}
}
