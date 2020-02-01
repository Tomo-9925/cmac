package psutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/xapima/conps/pkg/ps"
	"github.com/xapima/conps/pkg/util"
)

var proc = "/proc"

func ExePath(pid int) (string, error) {
	logrus.Debug("in ExePath")
	var found string
	defer logrus.Debugf("pid: %d, exe: %q", pid, found)

	cmd, err := ps.Cmdline(filepath.Join(proc, strconv.Itoa(pid)))
	if err != nil {
		return "", util.ErrorWrapFunc(err)
	}
	logrus.Debugf("cmd got: %v", cmd)
	env, err := ps.Env(filepath.Join(proc, strconv.Itoa(pid)))
	logrus.Debugf("env Got: %v", env)
	pwd := env["PWD"]
	pathList := strings.Split(env["PATH"], ":")
	logrus.Debug("pathList: %v", pathList)

	if err != nil {
		return "", util.ErrorWrapFunc(err)
	}
	if strings.HasPrefix(cmd[0], "/") {
		found = cmd[0]
		return found, nil
	}
	if strings.HasPrefix(cmd[0], ".") {
		found = filepath.Clean(filepath.Join(pwd, cmd[0]))
		return found, nil
	}
	for _, path := range pathList {
		tmpPath := filepath.Clean(filepath.Join(path, cmd[0]))
		logrus.Debug("tmpPath: %v", tmpPath)
		if isExist(tmpPath) {
			found = tmpPath
			return found, nil
		}
	}
	return "", util.ErrorWrapFunc(fmt.Errorf("cant find exe path: %v", cmd[0]))
}

func isExist(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}
