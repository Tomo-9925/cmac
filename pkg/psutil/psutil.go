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

func GetExePath(pid int) (string, error) {
	filePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err == nil {
		return filePath, nil
	} else if fmt.Sprintf("%s", err.(*os.PathError).Unwrap()) != fmt.Sprintf("%s", os.ErrPermission) {
		logrus.Debugf("not perm err: %v", err.(*os.PathError).Err)
		return "", util.ErrorWrapFunc(err)
	}
	path, err := getExePath(pid)
	if err != nil {
		return "", util.ErrorWrapFunc(err)
	}
	filePath, err = checkPath(path)
	if err != nil {
		return "", util.ErrorWrapFunc(err)
	}
	logrus.Debugf("GetExePath return %s", filePath)
	return filePath, nil
}

func getExePath(pid int) (string, error) {
	// logrus.Debug("in ExePath")
	var found string
	// defer logrus.Debugf("pid: %d, found: %q", pid, found)

	cmd, err := ps.Cmdline(filepath.Join(proc, strconv.Itoa(pid)))
	if err != nil {
		return "", util.ErrorWrapFunc(err)
	}
	// logrus.Debugf("cmd got: %v", cmd)

	envList := os.Environ()
	envMap := parseEnvList(envList)
	// logrus.Debugf("env Got: %v", envMap)
	// pwd := envMap["PWD"]
	pathList := strings.Split(envMap["PATH"], ":")
	// logrus.Debug("pathList: %v", pathList)

	if err != nil {
		return "", util.ErrorWrapFunc(err)
	}
	if strings.HasPrefix(cmd[0], "/") {
		// logrus.Debugf("prefix /: cmd: %v", cmd)
		found = cmd[0]
		// logrus.Debugf("pid: %d, found: %s", pid, found)
		return found, nil
	}
	if strings.HasPrefix(cmd[0], ".") {
		// found = filepath.Clean(filepath.Join(pwd, cmd[0]))
		return "", fmt.Errorf("Cannot know the full path of %q because it does not know the PWD at runtime", cmd[0])
	}
	for _, path := range pathList {
		tmpPath := filepath.Clean(filepath.Join(path, cmd[0]))
		// logrus.Debug("tmpPath: %v", tmpPath)
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

func parseEnvList(envList []string) map[string]string {
	m := make(map[string]string)
	for _, item := range envList {
		parts := strings.Split(item, "=")
		m[parts[0]] = strings.Join(parts[1:], "")
	}
	return m
}

func checkPath(path string) (string, error) {
	parts := strings.Split(path, "/")
	nowPath := "/"
	for index := 0; index < len(parts); index++ {
		tmpPath := filepath.Clean(filepath.Join(nowPath, parts[index]))
		// logrus.Debugf("tmpPath: %s", tmpPath)
		fi, err := os.Lstat(tmpPath)
		if err != nil {
			return "", util.ErrorWrapFunc(err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			linkPath, err := os.Readlink(tmpPath)
			if err != nil {
				return "", util.ErrorWrapFunc(err)
			}
			if !strings.HasPrefix(linkPath, "/") {
				nowPath = filepath.Clean(filepath.Join(filepath.Dir(tmpPath), linkPath))
			}
		} else {
			nowPath = tmpPath
		}
	}
	return nowPath, nil
}
