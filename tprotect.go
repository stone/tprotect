package main

import (
	"bufio"
	"errors"
	"io/ioutil"
	"log"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Version of tprotect, need to remember to update this
const version = "0.1"

type PidPageFault map[int]int

var pgfaults = make(PidPageFault)

type Config struct {
	SleepInterval            time.Duration  // In seconds
	FaultThreshold           int            // Number of faults per SleepInterval
	ProcessScanningThreshold int            // Number of pagefaults between each process scanning when the protectios doesn't kick in
	CmdWhitelist             map[string]int // Whitelisted processes
	UnfreezePopRatio         int            // Ratio of POP compared to GET
}

// Global config (TODO: Add Config file)
var cfg = new(Config)

func (c *Config) SetDefaults() {
	c.SleepInterval = 3
	c.FaultThreshold = 5
	c.ProcessScanningThreshold = cfg.FaultThreshold * 5
	c.CmdWhitelist = map[string]int{"init": 1, "sshd": 1, "bash": 1, "xinit": 1, "X": 1, "chromium-browser": 1}
	c.UnfreezePopRatio = 5
}

func ScanProcesses() (worstpid int) {
	stat_files, err := filepath.Glob("/proc/*/stat")
	if err != nil {
		log.Fatal("failed get files to stat")
	}

	for pfile := range stat_files {
		fs, err := ioutil.ReadFile(stat_files[pfile])
		if err != nil {
			//fmt.Print(stat_files[pfile])
			continue
		}
		buf0 := strings.Split(stat_files[pfile], "/")[2]
		pid, err := strconv.Atoi(buf0)
		if pid == 0 {
			continue
		}
		if err != nil {
			log.Println("PID ERR: ", pid, buf0)
			continue
			// self - hoppa över? dennna redan här?
		}
		stats := strings.Split(string(fs), " ")
		majflt, err := strconv.Atoi(stats[11])
		if err != nil {
			log.Printf("Could not convert %s to an int", stats[11])
			continue
		}
		buf1 := strings.Split(stats[1][1:], "/")[0]
		cmd := strings.Split(buf1, ")")[0]
		cmd = strings.TrimSpace(cmd) // just in case
		mypid := os.Getpid()
		max := 0

		if majflt > 0 {
			prev := pgfaults[pid]
			pgfaults[pid] = majflt
			if majflt-prev > max {
				if k := cfg.CmdWhitelist[cmd]; k == 1 {
					continue
				}
				if pid == mypid {
					continue
				}
				max = majflt - prev
				worstpid = pid
			}
		}
	}

	return worstpid

}

func GetPageFaults() (int, error) {
	file, err := os.Open("/proc/vmstat")
	if err != nil {
		log.Fatal("Could not open /proc/vmstat")
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		buf := scanner.Text()
		if strings.HasPrefix(buf, "pgmajfault") {
			pf, err := strconv.Atoi(buf[12:])
			if err != nil {
				log.Fatal("Could not parse vmstat file")
			}
			return pf, nil
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return 0, errors.New("Unable to parse /proc/vmstat")
}

func freeze_something(frozen_pids []int, num_freezes int) ([]int, int) {
	pid_to_freeze := ScanProcesses()
	if pid_to_freeze == 0 {
		return frozen_pids, num_freezes
	}
	frozen_pids = append(frozen_pids, pid_to_freeze)
	num_freezes += 1

	ptf, err := os.FindProcess(pid_to_freeze)
	if err != nil {
		// Process wannished?
		return frozen_pids, num_freezes
	}
	log.Println("freezing pid: ", pid_to_freeze)
	err = ptf.Signal(syscall.SIGSTOP)
	if err != nil {
		log.Println("error sending SIGSTOP: ", err)
	}
	return frozen_pids, num_freezes
}

func unfreeze_something(frozen_pids []int, num_unfreezes int) ([]int, int) {

	var pid_to_unfreeze int

	if len(frozen_pids) > 0 {
		x := math.Remainder(float64(num_unfreezes), float64(cfg.UnfreezePopRatio))

		if x > 0 {
			// Trick to POP from an slice.. :-/
			pid_to_unfreeze, frozen_pids = frozen_pids[len(frozen_pids)-1], frozen_pids[:len(frozen_pids)-1]
		} else {
			pid_to_unfreeze = frozen_pids[0]
			frozen_pids = frozen_pids[1:]
		}

		ptuf, err := os.FindProcess(pid_to_unfreeze)
		if err != nil {
			// Process wannished?
			return frozen_pids, num_unfreezes
		}
		log.Println("Unfreezing pid: ", pid_to_unfreeze)
		err = ptuf.Signal(syscall.SIGCONT)
		if err != nil {
			log.Println("error sending SIGCONT: ", err)
		}

	}

	return frozen_pids, num_unfreezes
}

func MainLoop() {
	last_observed_pagefaults, _ := GetPageFaults()
	last_scan_pagefaults := 0
	var frozen_pids []int
	var num_freezes int = 0
	var num_unfreezes int = 0

	// Handle signals, what we are trying to do is when we quit
	// we unfreeze the freezed processes so we don't leave with
	// lots of freezed processes..
	// TODO: Need more testing.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)
	go func() {
		for sig := range c {
			log.Printf("Got %v, unfreezing freezed processes..", sig)
			for p := range frozen_pids {
				pu, err := os.FindProcess(frozen_pids[p])
				if err != nil {
					log.Println("Could not unfreeze pid: ", frozen_pids[p], err)
				}
				log.Printf("%d unfreezed", frozen_pids[p])
				pu.Signal(syscall.SIGCONT)
			}
			os.Exit(0)
		}
	}()

	for {
		current_pagefaults, err := GetPageFaults()
		if err != nil {
			log.Fatal(err)
		}
		switch {
		case current_pagefaults-last_observed_pagefaults > cfg.FaultThreshold:
			frozen_pids, num_freezes = freeze_something(frozen_pids, num_freezes)
		case current_pagefaults-last_observed_pagefaults == 0:
			frozen_pids, num_unfreezes = unfreeze_something(frozen_pids, num_unfreezes)
		}

		if current_pagefaults-last_scan_pagefaults > cfg.ProcessScanningThreshold {
			last_observed_pagefaults = current_pagefaults
		}

		time.Sleep(cfg.SleepInterval * time.Second)
	}
}

func main() {
	log.Printf("tprotect v%s start", version)
	cfg.SetDefaults()
	MainLoop()
}
