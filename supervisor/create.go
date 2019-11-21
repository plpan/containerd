package supervisor

import (
	"path/filepath"
	"fmt"
	"time"

	"github.com/docker/containerd/runtime"
)

// StartTask holds needed parameters to create a new container
type StartTask struct {
	baseTask
	ID            string
	BundlePath    string
	Stdout        string
	Stderr        string
	Stdin         string
	StartResponse chan StartResponse
	Labels        []string
	NoPivotRoot   bool
	Checkpoint    *runtime.Checkpoint
	CheckpointDir string
	Runtime       string
	RuntimeArgs   []string
}

func (s *Supervisor) start(t *StartTask) error {
	start := time.Now()
	rt := s.runtime
	rtArgs := s.runtimeArgs
	if t.Runtime != "" {
		rt = t.Runtime
		rtArgs = t.RuntimeArgs
	}
	container, err := runtime.New(runtime.ContainerOpts{
		Root:        s.stateDir,
		ID:          t.ID,
		Bundle:      t.BundlePath,
		Runtime:     rt,
		RuntimeArgs: rtArgs,
		Shim:        s.shim,
		Labels:      t.Labels,
		NoPivotRoot: t.NoPivotRoot,
		Timeout:     s.timeout,
	})
	fmt.Printf("stupig-containerd: %#v\n", container)
	// stupig-containerd: &runtime.container{root:"/var/run/docker/libcontainerd/containerd", id:"1a6e9f03d795a90af2b403b9782a8602f0b96be738739d6b5180d238ee2da862", bundle:"/var/run/docker/libcontainerd/1a6e9f03d795a90af2b403b9782a8602f0b96be738739d6b5180d238ee2da862", runtime:"docker-runc", runtimeArgs:[]string(nil), shim:"docker-containerd-shim", processes:map[string]*runtime.process{}, labels:[]string(nil), oomFds:[]int(nil), noPivotRoot:false, timeout:120000000000}
	if err != nil {
		return err
	}
	s.containers[t.ID] = &containerInfo{
		container: container,
	}
	ContainersCounter.Inc(1)
	task := &startTask{
		Err:           t.ErrorCh(),
		Container:     container,
		StartResponse: t.StartResponse,
		Stdin:         t.Stdin,
		Stdout:        t.Stdout,
		Stderr:        t.Stderr,
	}
	if t.Checkpoint != nil {
		task.CheckpointPath = filepath.Join(t.CheckpointDir, t.Checkpoint.Name)
	}

	s.startTasks <- task
	ContainerCreateTimer.UpdateSince(start)
	return errDeferredResponse
}
