// use in docker with --cap-add CAP_SYS_ADMIN
package main

import (
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/xapima/cmac/pkg/hook"
)

func main() {
	hapi, err := hook.NewHookApi()
	if err != nil {
		logrus.Error(err)
	}
	if err := hapi.WatchMount("/"); err != nil {
		logrus.Error(errors.Wrap(err, "failed to watch"))
	}
	for ev := range hapi.Event {
		go hook.EventProcess(ev)
	}
}
