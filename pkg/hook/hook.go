package hook

import (
	"fmt"
	"os"

	"github.com/jandre/fanotify"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

type (
	HookApi struct {
		Nd    *fanotify.NotifyFD
		Event chan *Event
	}

	Event struct {
		Acts     []string
		FileName string
		// ProcessInfo string
	}
)

func EventProcess(ev *Event) {
	// if bookshelf.IsBookshelf(ev.FileName) {
	// 	return
	// }

	fmt.Printf("audit : %v", fmt.Sprintln(ev.Acts, ev.FileName))
	// fmt.Printf("audit", fmt.Sprintln(ev.Acts, ev.FileName, "by", ev.ProcessInfo))
}

func NewHookApi() (*HookApi, error) {
	// flag := fanotify.FAN_CLASS_NOTIF

	flag := fanotify.FAN_CLASS_PRE_CONTENT

	nd, err := fanotify.Initialize(flag|fanotify.FAN_CLOEXEC|fanotify.FAN_UNLIMITED_QUEUE|fanotify.FAN_UNLIMITED_MARKS, unix.O_RDONLY|unix.O_LARGEFILE)
	if err != nil {
		return nil, err
	}

	h := &HookApi{
		Nd:    nd,
		Event: make(chan *Event),
	}
	return h, nil
}

func (h *HookApi) watch(path string, addFlag int) error {
	evMask := fanotify.FAN_ALL_PERM_EVENTS
	return h.Nd.Mark(fanotify.FAN_MARK_ADD|addFlag, uint64(evMask), unix.AT_FDCWD, path)
}
func (a *HookApi) WatchFile(path string) error {
	return a.watch(path, 0)
}
func (a *HookApi) WatchMount(path string) error {
	return a.watch(path, fanotify.FAN_MARK_MOUNT)
}

func (h *HookApi) startHook() {
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

		acts := []string{}
		if ev.Mask&fanotify.FAN_OPEN_PERM != 0 {
			acts = append(acts, "OPEN_PERM")
			h.Nd.Response(ev, true)
		}
		if ev.Mask&fanotify.FAN_ACCESS_PERM != 0 {
			acts = append(acts, "ACCESS_PERM")
			h.Nd.Response(ev, true)
		}

		ev.File.Close()
		h.Event <- &Event{acts, fileName}
		// a.Event <- &Event{acts, fileName, procInfo}
	}
}
