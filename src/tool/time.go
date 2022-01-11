package main

import (
    "fmt"
    "time"
)

func main() {
	start := time.Now()

	fmt.Println(start.Format(time.RFC850))
	fmt.Println(start.Format(time.RFC822))
	fmt.Println(start.Format(time.UnixDate))
	fmt.Println(start.Format(time.ANSIC))
	fmt.Println(start.Format(time.RFC3339))
	//func Unix(sec int64, nsec int64) Time
	//func (t Time) UnixNano() int64
	ii := start.UnixNano()
	fmt.Println(ii)
	ntime := time.Unix(0, ii)
	fmt.Println(ntime.Format(time.RFC822))
}

