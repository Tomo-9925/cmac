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

	startMAC(hapi, japi)
}

func startMAC(h *hook.HookApi, j *judge.JudgeApi) {
	for {
		ev, err := h.Nd.GetEvent()
		if err != nil {
			logrus.Error(err)
			continue
		}

		// procInfo, err := GetProcInfo(ev.Pid)
		// if err != nil {
		// 	// logger.Println(err)
		// 	procInfo = "[unknown process]"
		// }

		fileName, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", ev.File.Fd()))
		if err != nil {
			logrus.Debug(err)
			fileName = "[unknown file]"
		}

		if ev.Mask&fanotify.FAN_OPEN_PERM != 0 {
			logrus.Infof("OPEN_PERM %v", fileName)
			if ok, err := j.Judge(fileName, int(ev.Pid), prof.OPEN); err != nil {
				logrus.Error(err)
				h.Nd.Response(ev, true)
			} else {
				h.Nd.Response(ev, ok)
			}
			// /proc/[pid]/environがオープンできない問題を調査するためのdebugコード
			// h.Nd.Response(ev, true)
			// logrus.Debug("fileName:", fileName)
			// cmd, err := ps.Cmdline(filepath.Join("/proc", strconv.Itoa(int(ev.Pid))))
			// if err != nil {
			// 	logrus.Error(err)
			// } else {
			// 	logrus.Debug("cmd: ", cmd)
			// }
			// env, err := ps.Env(filepath.Join("/proc", strconv.Itoa(int(ev.Pid))))
			// if err != nil {
			// 	logrus.Error(err)
			// } else {
			// 	logrus.Debug("env: ", env)
			// }
		}
		if ev.Mask&fanotify.FAN_ACCESS_PERM != 0 {
			// logrus.Infof("ACCESS_PERM %v", fileName)
			// if ok, err := j.Judge(fileName, int(ev.Pid), prof.ACCESS); err != nil {
			// 	logrus.Error(err)
			// 	h.Nd.Response(ev, true)
			// } else {
			// 	h.Nd.Response(ev, ok)
			// }
			h.Nd.Response(ev, true)
		}

		ev.File.Close()
		// logrus.Infof("%v %v", acts, fileName)
		// a.Event <- &Event{acts, fileName, procInfo}
	}
}
