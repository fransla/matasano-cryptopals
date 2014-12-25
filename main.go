package main

import (
	"os"
	"strconv"
)

func main() {
	set := 1
	challenge := 1
	var err error

	argCount := len(os.Args)
	if argCount > 1 {
		set, err = strconv.Atoi(os.Args[1])
		if err != nil {
			panic(err)
		}
	}
	if argCount > 2 {
		challenge, err = strconv.Atoi(os.Args[2])
		if err != nil {
			panic(err)
		}
	}

	if set == 1 {
		switch challenge {
		case 1:
			Set1Challenge1()
		case 2:
			Set1Challenge2()
		case 3:
			Set1Challenge3()
		case 4:
			Set1Challenge4()
		case 5:
			Set1Challenge5()
		case 6:
			Set1Challenge6()
		case 7:
			Set1Challenge7()
		case 8:
			Set1Challenge8()
		default:
			panic("Unknown challenge")
		}
	} else {
		panic("Unknown set")
	}
}
