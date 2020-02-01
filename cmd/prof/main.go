package main

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/xapima/cmac/pkg/prof"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetOutput(os.Stdout)
}

func main() {

	papi, err := prof.NewProfApi("./test/profile.txt")
	if err != nil {
		logrus.Error(err)
	}
	fmt.Print(papi)

}
