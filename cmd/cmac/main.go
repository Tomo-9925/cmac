package main

import (
	"fmt"
	"os"

	"github.com/jandre/fanotify"
	"github.com/sirupsen/logrus"
	"github.com/xapima/cmac/pkg/hook"
	"github.com/xapima/cmac/pkg/judge"
	"github.com/xapima/cmac/pkg/prof"
)

var profPath = "./test/prof.txt"

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetOutput(os.Stdout)
}

func main() {
	if len(os.Args) != 2 {
		logrus.Error("need prof path.")
		return
	}
	profPath = os.Args[1]
	papi, err := prof.NewProfApi(profPath)
	if err != nil {
		logrus.Error(err)
		return
	}

	japi := judge.NewJudgeApi(papi)

	hapi, err := hook.NewHookApi()
	if err != nil {
		logrus.Error(err)
		return
	}
	hapi.WatchMount("/")
	hapi.WatchMount("/test")

	startMAC(hapi, japi)
}

func startMAC(h *hook.HookApi, j *judge.JudgeApi) {
	for {
		ev, err := h.Nd.GetEvent()
		if err != nil {
			logrus.Error(err)
			continue
		}

		fileName, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", ev.File.Fd()))
		if err != nil {
			logrus.Debug(err)
			fileName = "[unknown file]"
		}

		if ev.Mask&fanotify.FAN_OPEN_PERM != 0 {

			// if fileName == "/test/deny" || fileName == "/usr/bin/bash" {
			logrus.Infof("OPEN_PERM %v", fileName)
			if ok, err := j.Judge(fileName, int(ev.Pid), prof.OPEN); err != nil {
				logrus.Error(err)
				logrus.Infof("OPEN_ALLOW %v", fileName)
				h.Nd.Response(ev, true)
			} else {
				if ok {
					logrus.Infof("OPEN_ALLOW %v", fileName)
				} else {
					logrus.Infof("OPEN_DENY %v", fileName)
				}
				h.Nd.Response(ev, ok)
			}
			// } else {
			// 	h.Nd.Response(ev, true)
			// }
		}
		if ev.Mask&fanotify.FAN_ACCESS_PERM != 0 {
			logrus.Infof("ACCESS_PERM %v", fileName)
			if ok, err := j.Judge(fileName, int(ev.Pid), prof.ACCESS); err != nil {
				logrus.Error(err)
				logrus.Infof("ACCESS_ALLOW %v", fileName)
				h.Nd.Response(ev, true)
			} else {
				if ok {
					logrus.Infof("ACCESS_ALLOW %v", fileName)
				} else {
					logrus.Infof("ACCESS_DENY %v", fileName)
				}
				h.Nd.Response(ev, ok)
			}
			// h.Nd.Response(ev, true)
		}
		ev.File.Close()
	}
}
