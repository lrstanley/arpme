// Copyright (c) Liam Stanley <me@liamstanley.io>. All rights reserved. Use
// of this source code is governed by the MIT license that can be found in
// the LICENSE file.

// Package arpme is a simple arp scanning library.
//
// An example:
// 	scanner, err := New(Config{
// 		HandlerFunc: func(resp Response) {
// 			log.Printf("response: [%s] :: %s :: %s", resp.SourceHardwareAddr.String(), resp.SourceIP.String(), resp.Host)
// 		},
// 	})
// 	if err != nil {
// 		panic(err)
// 	}
//
// 	log.Println(scanner.Run())
package arpme

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"

	sempool "github.com/lrstanley/go-sempool"
	"github.com/mdlayher/arp"
)

// Config is the configuration struct you should pass to New().
type Config struct {
	// DisallowInterfaceError will cause Start() to return an error if it can't
	// listen to an interface.
	DisallowInterfaceError bool

	// Delay is the time between each loop of arp requests.
	Delay time.Duration

	// Interfaces to send/listen for arp requests. If this is empty, it will
	// attempt to listen to all known interfaces.
	Interfaces []net.Interface

	// HandlerFunc is executed when we receive a valid arp response. It is
	// executed in its own goroutine.
	HandlerFunc func(Response)

	// Debug is an optional writer which will be used for debug output.
	Debug io.Writer
}

// Scanner is a arp scanning client.
type Scanner struct {
	clients []*arp.Client
	closer  chan struct{}
	errs    chan error
	err     error

	log  *log.Logger
	conf *Config
}

// Response is the tailored response output from the arp packets we received.
type Response struct {
	// SourceIP is the IP of the source that responded to the arp request.
	SourceIP net.IP

	// SourceHardwareAddr is the MAC of the source that responded to the arp request.
	SourceHardwareAddr net.HardwareAddr

	// Host is the first rDNS entry returned for the source IP, if one exists.
	Host string

	// Timestamp is when the request was received.
	Timestamp time.Time
}

// New returns a new scanner.
func New(conf Config) (*Scanner, error) {
	if conf.HandlerFunc == nil {
		return nil, errors.New("no HandlerFunc provided")
	}

	if conf.Delay == 0 {
		conf.Delay = 15 * time.Second
	}

	if conf.Delay < 5*time.Second {
		return nil, fmt.Errorf("delay between arp requests is too short: %s", conf.Delay)
	}

	var err error

	if conf.Interfaces == nil || len(conf.Interfaces) == 0 {
		conf.Interfaces, err = net.Interfaces()
		if err != nil {
			return nil, fmt.Errorf("unable to obtain list of interfaces: %s", err)
		}
	}

	s := &Scanner{conf: &conf}

	if conf.Debug == nil {
		conf.Debug = ioutil.Discard
	}

	s.log = log.New(conf.Debug, "arp: ", log.LstdFlags)

	return s, nil
}

// Start initiates a scan loop on each interface, and only returns an error
// if there was one when starting the interface scans.
func (s *Scanner) Start() error {
	if s.closer != nil {
		return errors.New("scanner already started")
	}

	s.closer = make(chan struct{})
	s.clients = []*arp.Client{}
	// +1 just in case someone calls Close(), which adds a nil error into the
	// errs chan.
	s.errs = make(chan error, (2*len(s.conf.Interfaces))+1)

	for _, iface := range s.conf.Interfaces {
		c, err := s.scan(iface)
		if err != nil {
			if s.conf.DisallowInterfaceError {
				_ = c.Close()
				return fmt.Errorf("unable to scan %s: %s", iface.Name, err)
			}

			s.log.Printf("skipping interface %s: %s", iface.Name, err)
		}

		s.clients = append(s.clients, c)
	}

	go func() {
		s.err = <-s.errs
		close(s.closer)
	}()

	return nil
}

// Run calls Start(), and then Wait(). It blocks until there is an error, or
// nil if Close() is called.
func (s *Scanner) Run() error {
	if err := s.Start(); err != nil {
		return err
	}

	return s.Wait()
}

// Wait waits for the scanner to finish running. It will only finish if Close()
// is called, or an error occurs on one of the interfaces.
func (s *Scanner) Wait() error {
	<-s.closer

	return s.err
}

// Close sends a request to close all goroutines and listeners.
func (s *Scanner) Close() {
	s.errs <- nil

	for _, c := range s.clients {
		_ = c.Close()
	}
}

func (s *Scanner) scan(iface net.Interface) (*arp.Client, error) {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}

		if ip4 := ipnet.IP.To4(); ip4 != nil {
			addr = &net.IPNet{
				IP:   ip4,
				Mask: ipnet.Mask[len(ipnet.Mask)-4:],
			}

			break
		}
	}

	// Sanity-check that the interface has a good address.
	if addr == nil {
		return nil, errors.New("no network found")
	} else if addr.IP[0] == 127 {
		return nil, errors.New("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return nil, errors.New("network is too large")
	}

	client, err := arp.Dial(&iface)
	if err != nil {
		return nil, err
	}

	s.log.Printf("starting scan on %s [%s] with network: %s", iface.Name, iface.HardwareAddr, addr)

	go s.reader(client)
	go s.requester(client, addr)

	return client, nil
}

func (s *Scanner) reader(client *arp.Client) {
	var packet *arp.Packet
	var err error

	for {
		select {
		case <-s.closer:
			return
		default:
			packet, _, err = client.Read()
			if err != nil {
				s.errs <- err
				return
			}

			if packet.Operation != arp.OperationReply {
				continue
			}

			if packet.SenderHardwareAddr.String() == packet.TargetHardwareAddr.String() {
				continue
			}

			resp := Response{
				SourceIP:           packet.SenderIP,
				SourceHardwareAddr: packet.SenderHardwareAddr,
				Timestamp:          time.Now(),
			}

			names, err := net.LookupAddr(resp.SourceIP.String())
			if err == nil && len(names) > 0 {
				resp.Host = strings.ToLower(strings.TrimRight(names[0], "."))
			}

			s.log.Printf("response: [%s] %s (host: %q)", resp.SourceHardwareAddr.String(), resp.SourceIP.String(), resp.Host)
			go s.conf.HandlerFunc(resp)
		}
	}
}

func (s *Scanner) requester(client *arp.Client, addr *net.IPNet) {
	var err error

	ipList := ips(addr)
	ticker := time.NewTicker(s.conf.Delay)

	for {
		select {
		case <-s.closer:
			return
		case <-ticker.C:
			pool := sempool.New(10)

			for _, ipAddr := range ipList {
				pool.Slot()

				go func(ip net.IP) {
					defer pool.Free()

					err = client.SetWriteDeadline(time.Now().Add(3 * time.Second))
					if err != nil {
						s.log.Printf("error: %s", err)
						return
					}

					err = client.Request(ip)
					if err != nil {
						s.log.Printf("error: %s", err)
					}
				}(ipAddr)
			}

			pool.Wait()
		}
	}
}

// ips returns a list of all IPv4 addresses from a net.IPNet.
func ips(n *net.IPNet) (out []net.IP) {
	num := binary.BigEndian.Uint32([]byte(n.IP))
	mask := binary.BigEndian.Uint32([]byte(n.Mask))
	num &= mask
	for mask < 0xffffffff {
		var buf [4]byte

		binary.BigEndian.PutUint32(buf[:], num)
		out = append(out, net.IP(buf[:]))

		mask++
		num++
	}

	return
}
