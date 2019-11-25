package supervisor

import (
	"sync"
	"fmt"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/docker/containerd/runtime"
)

// Worker interface
type Worker interface {
	Start()
}

type startTask struct {
	Container      runtime.Container
	CheckpointPath string
	Stdin          string
	Stdout         string
	Stderr         string
	Err            chan error
	StartResponse  chan StartResponse
}

// NewWorker return a new initialized worker
func NewWorker(s *Supervisor, wg *sync.WaitGroup) Worker {
	return &worker{
		s:  s,
		wg: wg,
	}
}

type worker struct {
	wg *sync.WaitGroup
	s  *Supervisor
}

// Start runs a loop in charge of starting new containers
func (w *worker) Start() {
	defer w.wg.Done()
	for t := range w.s.startTasks {
		started := time.Now()
		process, err := t.Container.Start(t.CheckpointPath, runtime.NewStdio(t.Stdin, t.Stdout, t.Stderr))
		fmt.Printf("stupig-containerd: %#v\n", process)
		// stupig-containerd: &runtime.process{root:"/var/run/docker/libcontainerd/containerd/1a6e9f03d795a90af2b403b9782a8602f0b96be738739d6b5180d238ee2da862/init", id:"init", pid:8378, exitPipe:(*os.File)(0xc00011c800), controlPipe:(*os.File)(0xc00011c808), container:(*runtime.container)(0xc0002a0160), spec:specs.ProcessSpec{Terminal:true, User:specs.User{UID:0x0, GID:0x0, AdditionalGids:[]uint32(nil)}, Args:[]string{"bash"}, Env:[]string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "HOSTNAME=1a6e9f03d795", "TERM=xterm", "NGINX_VERSION=1.17.5", "NJS_VERSION=0.3.6", "PKG_RELEASE=1~buster"}, Cwd:"/", Capabilities:[]string{"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_FSETID", "CAP_FOWNER", "CAP_MKNOD", "CAP_NET_RAW", "CAP_SETGID", "CAP_SETUID", "CAP_SETFCAP", "CAP_SETPCAP", "CAP_NET_BIND_SERVICE", "CAP_SYS_CHROOT", "CAP_KILL", "CAP_AUDIT_WRITE"}, Rlimits:[]specs.Rlimit(nil), NoNewPrivileges:false, ApparmorProfile:"", SelinuxLabel:""}, stdio:runtime.Stdio{Stdin:"/var/run/docker/libcontainerd/1a6e9f03d795a90af2b403b9782a8602f0b96be738739d6b5180d238ee2da862/init-stdin", Stdout:"/var/run/docker/libcontainerd/1a6e9f03d795a90af2b403b9782a8602f0b96be738739d6b5180d238ee2da862/init-stdout", Stderr:"/var/run/docker/libcontainerd/1a6e9f03d795a90af2b403b9782a8602f0b96be738739d6b5180d238ee2da862/init-stderr"}, cmd:(*exec.Cmd)(0xc00021e2c0), cmdSuccess:false, cmdDoneCh:(chan struct {})(0xc00016a240), state:"running", stateLock:sync.Mutex{state:0, sema:0x0}, startTime:"1947418223"}
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"error": err,
				"id":    t.Container.ID(),
			}).Error("containerd: start container")
			t.Err <- err
			evt := &DeleteTask{
				ID:      t.Container.ID(),
				NoEvent: true,
				Process: process,
			}
			w.s.SendTask(evt)
			continue
		}
		if err := w.s.monitor.MonitorOOM(t.Container); err != nil && err != runtime.ErrContainerExited {
			if process.State() != runtime.Stopped {
				logrus.WithField("error", err).Error("containerd: notify OOM events")
			}
		}
		if err := w.s.monitorProcess(process); err != nil {
			logrus.WithField("error", err).Error("containerd: add process to monitor")
			t.Err <- err
			evt := &DeleteTask{
				ID:      t.Container.ID(),
				NoEvent: true,
				Process: process,
			}
			w.s.SendTask(evt)
			continue
		}
		// only call process start if we aren't restoring from a checkpoint
		// if we have restored from a checkpoint then the process is already started
		fmt.Printf("stupig-containerd: %#v\n", t.CheckpointPath)
		// 如果是首次创建容器，则CheckpointPath为空，执行runc start命令真正启动容器进程
		if t.CheckpointPath == "" {
			if err := process.Start(); err != nil {
				logrus.WithField("error", err).Error("containerd: start init process")
				t.Err <- err
				evt := &DeleteTask{
					ID:      t.Container.ID(),
					NoEvent: true,
					Process: process,
				}
				w.s.SendTask(evt)
				continue
			}
		}
		ContainerStartTimer.UpdateSince(started)
		t.Err <- nil
		t.StartResponse <- StartResponse{
			Container: t.Container,
		}
		w.s.notifySubscribers(Event{
			Timestamp: time.Now(),
			ID:        t.Container.ID(),
			Type:      StateStart,
		})
	}
}
