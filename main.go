package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Challenge struct {
	Salt   string `json:"salt"`
	Target string `json:"target"`
}

type PowFile struct {
	Pow struct {
		Algorithm  string      `json:"algorithm"`
		Challenges []Challenge `json:"challenges"`
	} `json:"pow"`
}

func solve(salt, target string) int64 {
	var nonce int64
	for {
		h := sha256.Sum256([]byte(salt + strconv.FormatInt(nonce, 10)))
		hexHash := hex.EncodeToString(h[:])
		if strings.HasPrefix(hexHash, target) {
			return nonce
		}
		nonce++
	}
}

func solveParallel(salt, target string, workers int, window int64) int64 {
	var start int64
	for {
		found := make(chan int64, workers)
		var wg sync.WaitGroup
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(offset int64) {
				defer wg.Done()
				for n := start + offset; n < start+window; n += int64(workers) {
					h := sha256.Sum256([]byte(salt + strconv.FormatInt(n, 10)))
					hexHash := hex.EncodeToString(h[:])
					if strings.HasPrefix(hexHash, target) {
						found <- n
						return
					}
				}
			}(int64(w))
		}
		wg.Wait()
		close(found)

		best := int64(-1)
		for n := range found {
			if best == -1 || n < best {
				best = n
			}
		}
		if best != -1 {
			return best
		}
		start += window
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: powsolve <path-to.pow>")
		os.Exit(1)
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read error:", err)
		os.Exit(1)
	}

	var pf PowFile
	if err := json.Unmarshal(data, &pf); err != nil {
		fmt.Fprintln(os.Stderr, "parse error:", err)
		os.Exit(1)
	}

	fmt.Printf("algorithm: %s, %d challenge(s)\n", pf.Pow.Algorithm, len(pf.Pow.Challenges))

	t0 := time.Now()
	solutions := make([]int64, len(pf.Pow.Challenges))
	for i, c := range pf.Pow.Challenges {
		solutions[i] = solveParallel(c.Salt, c.Target, 8, 2_000_000)
	}
	elapsed := time.Since(t0)

	for i, c := range pf.Pow.Challenges {
		n := solutions[i]
		h := sha256.Sum256([]byte(c.Salt + strconv.FormatInt(n, 10)))
		fmt.Printf("[%d] salt=%s... target=%s nonce=%d hash=%s valid=%v\n",
			i, c.Salt[:12], c.Target, n, hex.EncodeToString(h[:]),
			strings.HasPrefix(hex.EncodeToString(h[:]), c.Target))
	}
	fmt.Printf("solved %d challenge(s) in %s\n", len(pf.Pow.Challenges), elapsed)
}
