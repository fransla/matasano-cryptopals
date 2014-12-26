package main

import (
	"os"
	"strconv"
)

func main() {
	var err error
	challenge := 1

	if len(os.Args) > 1 {
		challenge, err = strconv.Atoi(os.Args[1])
		if err != nil {
			panic(err)
		}
	}

	switch {
	// Set 1
	case challenge == 1:
		Challenge1()
	case challenge == 2:
		Challenge2()
	case challenge == 3:
		Challenge3()
	case challenge == 4:
		Challenge4()
	case challenge == 5:
		Challenge5()
	case challenge == 6:
		Challenge6()
	case challenge == 7:
		Challenge7()
	case challenge == 8:
		Challenge8()

	// Set 2
	case challenge == 9:
		Challenge9()
	case challenge == 10:
		Challenge10()
	case challenge == 11:
		Challenge11()
	case challenge == 12:
		Challenge12()
	case challenge == 13:
		Challenge13()
	case challenge == 14:
		Challenge14()

	default:
		panic("Unknown set or challenge")
	}
}
