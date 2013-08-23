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

// Type Map that holds the Pid = Pagefault data
type pidPageFault map[int]int

var pgfaults = make(pidPageFault)

// Config Holds the configuration parameters
type Config struct {
	SleepInterval            time.Duration  // In seconds
	FaultThreshold           int            // Number of faults per SleepInterval
	ProcessScanningThreshold int            // Number of pagefaults between each process scanning when the protectios doesn't kick in
	CmdWhitelist             map[string]int // Whitelisted processes
	UnfreezePopRatio         int            // Ratio of POP compared to GET
}

// Global config (TODO: Add Config file)
var cfg = new(Config)

// SetDefaults sets the default Configuration
func (c *Config) SetDefaults() {
	c.SleepInterval = 3
	c.FaultThreshold = 5
	c.ProcessScanningThreshold = cfg.FaultThreshold * 5
	c.CmdWhitelist = map[string]int{"init": 1, "sshd": 1, "bash": 1, "xinit": 1, "X": 1, "chromium-browser": 1}
	c.UnfreezePopRatio = 5
}

func scanProcesses() (worstpid int) {
	statFiles, err := filepath.Glob("/proc/*/stat")
	if err != nil {
		log.Fatal("failed get files to stat")
	}

	for pfile := range statFiles {
		fs, err := ioutil.ReadFile(statFiles[pfile])
		if err != nil {
			//fmt.Print(statFiles[pfile])
			continue
		}
		buf0 := strings.Split(statFiles[pfile], "/")[2]
		pid, err := strconv.Atoi(buf0)
		if pid == 0 {
			continue
		}
		if err != nil {
			//log.Println("PID ERR: ", pid, buf0)
			continue
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

func getPageFaults() (int, error) {
	file, err := os.Open("/proc/vmstat")
	defer file.Close()
	if err != nil {
		log.Fatal("could not open /proc/vmstat")
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		buf := scanner.Text()
		if strings.HasPrefix(buf, "pgmajfault") {
			pf, err := strconv.Atoi(buf[12:])
			if err != nil {
				log.Fatal("could not parse vmstat file")
			}
			return pf, nil
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return 0, errors.New("unable to parse /proc/vmstat")
}

func freezeSomething(frozenPids []int, numFreezes int) ([]int, int) {
	pidToFreeze := scanProcesses()
	if pidToFreeze == 0 {
		return frozenPids, numFreezes
	}
	frozenPids = append(frozenPids, pidToFreeze)
	numFreezes += 1

	ptf, err := os.FindProcess(pidToFreeze)
	if err != nil {
		// Process wannished?
		return frozenPids, numFreezes
	}
	log.Println("freezing pid: ", pidToFreeze)
	err = ptf.Signal(syscall.SIGSTOP)
	if err != nil {
		log.Println("error sending SIGSTOP: ", err)
	}
	return frozenPids, numFreezes
}

func unfreezeSomething(frozenPids []int, numUnFreezes int) ([]int, int) {

	var pidToUnFreeze int

	if len(frozenPids) > 0 {
		x := math.Remainder(float64(numUnFreezes), float64(cfg.UnfreezePopRatio))

		if x > 0 {
			// Trick to POP from an slice.. :-/
			pidToUnFreeze, frozenPids = frozenPids[len(frozenPids)-1], frozenPids[:len(frozenPids)-1]
		} else {
			pidToUnFreeze = frozenPids[0]
			frozenPids = frozenPids[1:]
		}

		ptuf, err := os.FindProcess(pidToUnFreeze)
		if err != nil {
			// Process wannished?
			return frozenPids, numUnFreezes
		}
		log.Println("unfreezing pid: ", pidToUnFreeze)
		err = ptuf.Signal(syscall.SIGCONT)
		if err != nil {
			log.Println("error sending SIGCONT: ", err)
		}

	}

	return frozenPids, numUnFreezes
}

func mainLoop() {
	lastObservedPagefaults, _ := getPageFaults()
	lastScanPagefaults := 0
	var frozenPids []int
	var numFreezes int
	var numUnFreezes int

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
			for p := range frozenPids {
				pu, err := os.FindProcess(frozenPids[p])
				if err != nil {
					log.Println("could not unfreeze pid: ", frozenPids[p], err)
				}
				log.Printf("%d unfreezed", frozenPids[p])
				pu.Signal(syscall.SIGCONT)
			}
			os.Exit(0)
		}
	}()

	for {
		currentPagefaults, err := getPageFaults()
		if err != nil {
			log.Fatal(err)
		}
		switch {
		case currentPagefaults-lastObservedPagefaults > cfg.FaultThreshold:
			frozenPids, numFreezes = freezeSomething(frozenPids, numFreezes)
		case currentPagefaults-lastObservedPagefaults == 0:
			frozenPids, numUnFreezes = unfreezeSomething(frozenPids, numUnFreezes)
		}

		if currentPagefaults-lastScanPagefaults > cfg.ProcessScanningThreshold {
			lastObservedPagefaults = currentPagefaults
		}

		time.Sleep(cfg.SleepInterval * time.Second)
	}
}

func main() {
	log.Printf("tprotect v%s start", version)
	cfg.SetDefaults()
	mainLoop()
}
