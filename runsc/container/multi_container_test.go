// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package container

import (
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/testutil"
)

func createSpecs(cmds ...[]string) ([]*specs.Spec, []string) {
	var specs []*specs.Spec
	var ids []string
	rootID := testutil.UniqueContainerID()

	for i, cmd := range cmds {
		spec := testutil.NewSpecWithArgs(cmd...)
		if i == 0 {
			spec.Annotations = map[string]string{
				specutils.ContainerdContainerTypeAnnotation: specutils.ContainerdContainerTypeSandbox,
			}
			ids = append(ids, rootID)
		} else {
			spec.Annotations = map[string]string{
				specutils.ContainerdContainerTypeAnnotation: specutils.ContainerdContainerTypeContainer,
				specutils.ContainerdSandboxIDAnnotation:     rootID,
			}
			ids = append(ids, testutil.UniqueContainerID())
		}
		specs = append(specs, spec)
	}
	return specs, ids
}

func startContainers(conf *boot.Config, specs []*specs.Spec, ids []string) ([]*Container, func(), error) {
	// Setup root dir if one hasn't been provided.
	if len(conf.RootDir) == 0 {
		rootDir, err := testutil.SetupRootDir()
		if err != nil {
			return nil, nil, fmt.Errorf("error creating root dir: %v", err)
		}
		conf.RootDir = rootDir
	}

	var containers []*Container
	var bundles []string
	cleanup := func() {
		for _, c := range containers {
			c.Destroy()
		}
		for _, b := range bundles {
			os.RemoveAll(b)
		}
		os.RemoveAll(conf.RootDir)
	}
	for i, spec := range specs {
		bundleDir, err := testutil.SetupBundleDir(spec)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("error setting up container: %v", err)
		}
		bundles = append(bundles, bundleDir)

		args := Args{
			ID:        ids[i],
			Spec:      spec,
			BundleDir: bundleDir,
		}
		cont, err := New(conf, args)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("error creating container: %v", err)
		}
		containers = append(containers, cont)

		if err := cont.Start(conf); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("error starting container: %v", err)
		}
	}
	return containers, cleanup, nil
}

type execDesc struct {
	c    *Container
	cmd  []string
	want int
	desc string
}

func execMany(execs []execDesc) error {
	for _, exec := range execs {
		args := &control.ExecArgs{Argv: exec.cmd}
		if ws, err := exec.c.executeSync(args); err != nil {
			return fmt.Errorf("error executing %+v: %v", args, err)
		} else if ws.ExitStatus() != exec.want {
			return fmt.Errorf("%q: exec %q got exit status: %d, want: %d", exec.desc, exec.cmd, ws.ExitStatus(), exec.want)
		}
	}
	return nil
}

func createSharedMount(mount specs.Mount, name string, pod ...*specs.Spec) {
	for _, spec := range pod {
		spec.Annotations[path.Join(boot.MountPrefix, name, "source")] = mount.Source
		spec.Annotations[path.Join(boot.MountPrefix, name, "type")] = mount.Type
		spec.Annotations[path.Join(boot.MountPrefix, name, "share")] = "pod"
		if len(mount.Options) > 0 {
			spec.Annotations[path.Join(boot.MountPrefix, name, "options")] = strings.Join(mount.Options, ",")
		}
	}
}

// TestMultiContainerSanity checks that it is possible to run 2 dead-simple
// containers in the same sandbox.
func TestMultiContainerSanity(t *testing.T) {
	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)

		// Setup the containers.
		sleep := []string{"sleep", "100"}
		specs, ids := createSpecs(sleep, sleep)
		containers, cleanup, err := startContainers(conf, specs, ids)
		if err != nil {
			t.Fatalf("error starting containers: %v", err)
		}
		defer cleanup()

		// Check via ps that multiple processes are running.
		expectedPL := []*control.Process{
			{PID: 1, Cmd: "sleep"},
		}
		if err := waitForProcessList(containers[0], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}
		expectedPL = []*control.Process{
			{PID: 2, Cmd: "sleep"},
		}
		if err := waitForProcessList(containers[1], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}
	}
}

// TestMultiPIDNS checks that it is possible to run 2 dead-simple
// containers in the same sandbox with different pidns.
func TestMultiPIDNS(t *testing.T) {
	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)

		// Setup the containers.
		sleep := []string{"sleep", "100"}
		testSpecs, ids := createSpecs(sleep, sleep)
		testSpecs[1].Linux = &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{
					Type: "pid",
				},
			},
		}

		containers, cleanup, err := startContainers(conf, testSpecs, ids)
		if err != nil {
			t.Fatalf("error starting containers: %v", err)
		}
		defer cleanup()

		// Check via ps that multiple processes are running.
		expectedPL := []*control.Process{
			{PID: 1, Cmd: "sleep"},
		}
		if err := waitForProcessList(containers[0], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}
		expectedPL = []*control.Process{
			{PID: 1, Cmd: "sleep"},
		}
		if err := waitForProcessList(containers[1], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}
	}
}

// TestMultiPIDNSPath checks the pidns path.
func TestMultiPIDNSPath(t *testing.T) {
	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)

		// Setup the containers.
		sleep := []string{"sleep", "100"}
		testSpecs, ids := createSpecs(sleep, sleep, sleep)
		testSpecs[0].Linux = &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{
					Type: "pid",
					Path: "/proc/1/ns/pid",
				},
			},
		}
		testSpecs[1].Linux = &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{
					Type: "pid",
					Path: "/proc/1/ns/pid",
				},
			},
		}
		testSpecs[2].Linux = &specs.Linux{
			Namespaces: []specs.LinuxNamespace{
				{
					Type: "pid",
					Path: "/proc/2/ns/pid",
				},
			},
		}

		containers, cleanup, err := startContainers(conf, testSpecs, ids)
		if err != nil {
			t.Fatalf("error starting containers: %v", err)
		}
		defer cleanup()

		// Check via ps that multiple processes are running.
		expectedPL := []*control.Process{
			{PID: 1, Cmd: "sleep"},
		}
		if err := waitForProcessList(containers[0], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}
		if err := waitForProcessList(containers[2], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}

		expectedPL = []*control.Process{
			{PID: 2, Cmd: "sleep"},
		}
		if err := waitForProcessList(containers[1], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}
	}
}

func TestMultiContainerWait(t *testing.T) {
	// The first container should run the entire duration of the test.
	cmd1 := []string{"sleep", "100"}
	// We'll wait on the second container, which is much shorter lived.
	cmd2 := []string{"sleep", "1"}
	specs, ids := createSpecs(cmd1, cmd2)

	conf := testutil.TestConfig()
	containers, cleanup, err := startContainers(conf, specs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	// Check via ps that multiple processes are running.
	expectedPL := []*control.Process{
		{PID: 2, Cmd: "sleep"},
	}
	if err := waitForProcessList(containers[1], expectedPL); err != nil {
		t.Errorf("failed to wait for sleep to start: %v", err)
	}

	// Wait on the short lived container from multiple goroutines.
	wg := sync.WaitGroup{}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(c *Container) {
			defer wg.Done()
			if ws, err := c.Wait(); err != nil {
				t.Errorf("failed to wait for process %s: %v", c.Spec.Process.Args, err)
			} else if es := ws.ExitStatus(); es != 0 {
				t.Errorf("process %s exited with non-zero status %d", c.Spec.Process.Args, es)
			}
			if _, err := c.Wait(); err != nil {
				t.Errorf("wait for stopped container %s shouldn't fail: %v", c.Spec.Process.Args, err)
			}
		}(containers[1])
	}

	// Also wait via PID.
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(c *Container) {
			defer wg.Done()
			const pid = 2
			if ws, err := c.WaitPID(pid); err != nil {
				t.Errorf("failed to wait for PID %d: %v", pid, err)
			} else if es := ws.ExitStatus(); es != 0 {
				t.Errorf("PID %d exited with non-zero status %d", pid, es)
			}
			if _, err := c.WaitPID(pid); err == nil {
				t.Errorf("wait for stopped PID %d should fail", pid)
			}
		}(containers[1])
	}

	wg.Wait()

	// After Wait returns, ensure that the root container is running and
	// the child has finished.
	expectedPL = []*control.Process{
		{PID: 1, Cmd: "sleep"},
	}
	if err := waitForProcessList(containers[0], expectedPL); err != nil {
		t.Errorf("failed to wait for %q to start: %v", strings.Join(containers[0].Spec.Process.Args, " "), err)
	}
}

// TestExecWait ensures what we can wait containers and individual processes in the
// sandbox that have already exited.
func TestExecWait(t *testing.T) {
	rootDir, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer os.RemoveAll(rootDir)

	// The first container should run the entire duration of the test.
	cmd1 := []string{"sleep", "100"}
	// We'll wait on the second container, which is much shorter lived.
	cmd2 := []string{"sleep", "1"}
	specs, ids := createSpecs(cmd1, cmd2)
	conf := testutil.TestConfig()
	containers, cleanup, err := startContainers(conf, specs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	// Check via ps that process is running.
	expectedPL := []*control.Process{
		{PID: 2, Cmd: "sleep"},
	}
	if err := waitForProcessList(containers[1], expectedPL); err != nil {
		t.Fatalf("failed to wait for sleep to start: %v", err)
	}

	// Wait for the second container to finish.
	if err := waitForProcessCount(containers[1], 0); err != nil {
		t.Fatalf("failed to wait for second container to stop: %v", err)
	}

	// Get the second container exit status.
	if ws, err := containers[1].Wait(); err != nil {
		t.Fatalf("failed to wait for process %s: %v", containers[1].Spec.Process.Args, err)
	} else if es := ws.ExitStatus(); es != 0 {
		t.Fatalf("process %s exited with non-zero status %d", containers[1].Spec.Process.Args, es)
	}
	if _, err := containers[1].Wait(); err != nil {
		t.Fatalf("wait for stopped container %s shouldn't fail: %v", containers[1].Spec.Process.Args, err)
	}

	// Execute another process in the first container.
	args := &control.ExecArgs{
		Filename:         "/bin/sleep",
		Argv:             []string{"/bin/sleep", "1"},
		WorkingDirectory: "/",
		KUID:             0,
	}
	pid, err := containers[0].Execute(args)
	if err != nil {
		t.Fatalf("error executing: %v", err)
	}

	// Wait for the exec'd process to exit.
	expectedPL = []*control.Process{
		{PID: 1, Cmd: "sleep"},
	}
	if err := waitForProcessList(containers[0], expectedPL); err != nil {
		t.Fatalf("failed to wait for second container to stop: %v", err)
	}

	// Get the exit status from the exec'd process.
	if ws, err := containers[0].WaitPID(pid); err != nil {
		t.Fatalf("failed to wait for process %+v with pid %d: %v", args, pid, err)
	} else if es := ws.ExitStatus(); es != 0 {
		t.Fatalf("process %+v exited with non-zero status %d", args, es)
	}
	if _, err := containers[0].WaitPID(pid); err == nil {
		t.Fatalf("wait for stopped process %+v should fail", args)
	}
}

// TestMultiContainerMount tests that bind mounts can be used with multiple
// containers.
func TestMultiContainerMount(t *testing.T) {
	cmd1 := []string{"sleep", "100"}

	// 'src != dst' ensures that 'dst' doesn't exist in the host and must be
	// properly mapped inside the container to work.
	src, err := ioutil.TempDir(testutil.TmpDir(), "container")
	if err != nil {
		t.Fatal("ioutil.TempDir failed:", err)
	}
	dst := src + ".dst"
	cmd2 := []string{"touch", filepath.Join(dst, "file")}

	sps, ids := createSpecs(cmd1, cmd2)
	sps[1].Mounts = append(sps[1].Mounts, specs.Mount{
		Source:      src,
		Destination: dst,
		Type:        "bind",
	})

	// Setup the containers.
	conf := testutil.TestConfig()
	containers, cleanup, err := startContainers(conf, sps, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	ws, err := containers[1].Wait()
	if err != nil {
		t.Error("error waiting on container:", err)
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		t.Error("container failed, waitStatus:", ws)
	}
}

// TestMultiContainerSignal checks that it is possible to signal individual
// containers without killing the entire sandbox.
func TestMultiContainerSignal(t *testing.T) {
	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)

		// Setup the containers.
		sleep := []string{"sleep", "100"}
		specs, ids := createSpecs(sleep, sleep)
		containers, cleanup, err := startContainers(conf, specs, ids)
		if err != nil {
			t.Fatalf("error starting containers: %v", err)
		}
		defer cleanup()

		// Check via ps that container 1 process is running.
		expectedPL := []*control.Process{
			{PID: 2, Cmd: "sleep"},
		}

		if err := waitForProcessList(containers[1], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}

		// Kill process 2.
		if err := containers[1].SignalContainer(syscall.SIGKILL, false); err != nil {
			t.Errorf("failed to kill process 2: %v", err)
		}

		// Make sure process 1 is still running.
		expectedPL = []*control.Process{
			{PID: 1, Cmd: "sleep"},
		}
		if err := waitForProcessList(containers[0], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}

		// goferPid is reset when container is destroyed.
		goferPid := containers[1].GoferPid

		// Destroy container and ensure container's gofer process has exited.
		if err := containers[1].Destroy(); err != nil {
			t.Errorf("failed to destroy container: %v", err)
		}
		_, _, err = specutils.RetryEintr(func() (uintptr, uintptr, error) {
			cpid, err := syscall.Wait4(goferPid, nil, 0, nil)
			return uintptr(cpid), 0, err
		})
		if err != syscall.ECHILD {
			t.Errorf("error waiting for gofer to exit: %v", err)
		}
		// Make sure process 1 is still running.
		if err := waitForProcessList(containers[0], expectedPL); err != nil {
			t.Errorf("failed to wait for sleep to start: %v", err)
		}

		// Now that process 2 is gone, ensure we get an error trying to
		// signal it again.
		if err := containers[1].SignalContainer(syscall.SIGKILL, false); err == nil {
			t.Errorf("container %q shouldn't exist, but we were able to signal it", containers[1].ID)
		}

		// Kill process 1.
		if err := containers[0].SignalContainer(syscall.SIGKILL, false); err != nil {
			t.Errorf("failed to kill process 1: %v", err)
		}

		// Ensure that container's gofer and sandbox process are no more.
		err = blockUntilWaitable(containers[0].GoferPid)
		if err != nil && err != syscall.ECHILD {
			t.Errorf("error waiting for gofer to exit: %v", err)
		}

		err = blockUntilWaitable(containers[0].Sandbox.Pid)
		if err != nil && err != syscall.ECHILD {
			t.Errorf("error waiting for sandbox to exit: %v", err)
		}

		// The sentry should be gone, so signaling should yield an error.
		if err := containers[0].SignalContainer(syscall.SIGKILL, false); err == nil {
			t.Errorf("sandbox %q shouldn't exist, but we were able to signal it", containers[0].Sandbox.ID)
		}

		if err := containers[0].Destroy(); err != nil {
			t.Errorf("failed to destroy container: %v", err)
		}
	}
}

// TestMultiContainerDestroy checks that container are properly cleaned-up when
// they are destroyed.
func TestMultiContainerDestroy(t *testing.T) {
	app, err := testutil.FindFile("runsc/container/test_app/test_app")
	if err != nil {
		t.Fatal("error finding test_app:", err)
	}

	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)

		// First container will remain intact while the second container is killed.
		podSpecs, ids := createSpecs(
			[]string{"sleep", "100"},
			[]string{app, "fork-bomb"})

		// Run the fork bomb in a PID namespace to prevent processes to be
		// re-parented to PID=1 in the root container.
		podSpecs[1].Linux = &specs.Linux{
			Namespaces: []specs.LinuxNamespace{{Type: "pid"}},
		}
		containers, cleanup, err := startContainers(conf, podSpecs, ids)
		if err != nil {
			t.Fatalf("error starting containers: %v", err)
		}
		defer cleanup()

		// Exec more processes to ensure signal all works for exec'd processes too.
		args := &control.ExecArgs{
			Filename: app,
			Argv:     []string{app, "fork-bomb"},
		}
		if _, err := containers[1].Execute(args); err != nil {
			t.Fatalf("error exec'ing: %v", err)
		}

		// Let it brew...
		time.Sleep(500 * time.Millisecond)

		if err := containers[1].Destroy(); err != nil {
			t.Fatalf("error destroying container: %v", err)
		}

		// Check that destroy killed all processes belonging to the container and
		// waited for them to exit before returning.
		pss, err := containers[0].Sandbox.Processes("")
		if err != nil {
			t.Fatalf("error getting process data from sandbox: %v", err)
		}
		expectedPL := []*control.Process{{PID: 1, Cmd: "sleep"}}
		if !procListsEqual(pss, expectedPL) {
			t.Errorf("container got process list: %s, want: %s", procListToString(pss), procListToString(expectedPL))
		}

		// Check that cont.Destroy is safe to call multiple times.
		if err := containers[1].Destroy(); err != nil {
			t.Errorf("error destroying container: %v", err)
		}
	}
}

func TestMultiContainerProcesses(t *testing.T) {
	// Note: use curly braces to keep 'sh' process around. Otherwise, shell
	// will just execve into 'sleep' and both containers will look the
	// same.
	specs, ids := createSpecs(
		[]string{"sleep", "100"},
		[]string{"sh", "-c", "{ sleep 100; }"})
	conf := testutil.TestConfig()
	containers, cleanup, err := startContainers(conf, specs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	// Check root's container process list doesn't include other containers.
	expectedPL0 := []*control.Process{
		{PID: 1, Cmd: "sleep"},
	}
	if err := waitForProcessList(containers[0], expectedPL0); err != nil {
		t.Errorf("failed to wait for process to start: %v", err)
	}

	// Same for the other container.
	expectedPL1 := []*control.Process{
		{PID: 2, Cmd: "sh"},
		{PID: 3, PPID: 2, Cmd: "sleep"},
	}
	if err := waitForProcessList(containers[1], expectedPL1); err != nil {
		t.Errorf("failed to wait for process to start: %v", err)
	}

	// Now exec into the second container and verify it shows up in the container.
	args := &control.ExecArgs{
		Filename: "/bin/sleep",
		Argv:     []string{"/bin/sleep", "100"},
	}
	if _, err := containers[1].Execute(args); err != nil {
		t.Fatalf("error exec'ing: %v", err)
	}
	expectedPL1 = append(expectedPL1, &control.Process{PID: 4, Cmd: "sleep"})
	if err := waitForProcessList(containers[1], expectedPL1); err != nil {
		t.Errorf("failed to wait for process to start: %v", err)
	}
	// Root container should remain unchanged.
	if err := waitForProcessList(containers[0], expectedPL0); err != nil {
		t.Errorf("failed to wait for process to start: %v", err)
	}
}

// TestMultiContainerKillAll checks that all process that belong to a container
// are killed when SIGKILL is sent to *all* processes in that container.
func TestMultiContainerKillAll(t *testing.T) {
	for _, tc := range []struct {
		killContainer bool
	}{
		{killContainer: true},
		{killContainer: false},
	} {
		app, err := testutil.FindFile("runsc/container/test_app/test_app")
		if err != nil {
			t.Fatal("error finding test_app:", err)
		}

		// First container will remain intact while the second container is killed.
		specs, ids := createSpecs(
			[]string{app, "task-tree", "--depth=2", "--width=2"},
			[]string{app, "task-tree", "--depth=4", "--width=2"})
		conf := testutil.TestConfig()
		containers, cleanup, err := startContainers(conf, specs, ids)
		if err != nil {
			t.Fatalf("error starting containers: %v", err)
		}
		defer cleanup()

		// Wait until all processes are created.
		rootProcCount := int(math.Pow(2, 3) - 1)
		if err := waitForProcessCount(containers[0], rootProcCount); err != nil {
			t.Fatal(err)
		}
		procCount := int(math.Pow(2, 5) - 1)
		if err := waitForProcessCount(containers[1], procCount); err != nil {
			t.Fatal(err)
		}

		// Exec more processes to ensure signal works for exec'd processes too.
		args := &control.ExecArgs{
			Filename: app,
			Argv:     []string{app, "task-tree", "--depth=2", "--width=2"},
		}
		if _, err := containers[1].Execute(args); err != nil {
			t.Fatalf("error exec'ing: %v", err)
		}
		// Wait for these new processes to start.
		procCount += int(math.Pow(2, 3) - 1)
		if err := waitForProcessCount(containers[1], procCount); err != nil {
			t.Fatal(err)
		}

		if tc.killContainer {
			// First kill the init process to make the container be stopped with
			// processes still running inside.
			containers[1].SignalContainer(syscall.SIGKILL, false)
			op := func() error {
				c, err := Load(conf.RootDir, ids[1])
				if err != nil {
					return err
				}
				if c.Status != Stopped {
					return fmt.Errorf("container is not stopped")
				}
				return nil
			}
			if err := testutil.Poll(op, 5*time.Second); err != nil {
				t.Fatalf("container did not stop %q: %v", containers[1].ID, err)
			}
		}

		c, err := Load(conf.RootDir, ids[1])
		if err != nil {
			t.Fatalf("failed to load child container %q: %v", c.ID, err)
		}
		// Kill'Em All
		if err := c.SignalContainer(syscall.SIGKILL, true); err != nil {
			t.Fatalf("failed to send SIGKILL to container %q: %v", c.ID, err)
		}

		// Check that all processes are gone.
		if err := waitForProcessCount(containers[1], 0); err != nil {
			t.Fatal(err)
		}
		// Check that root container was not affected.
		if err := waitForProcessCount(containers[0], rootProcCount); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMultiContainerDestroyNotStarted(t *testing.T) {
	specs, ids := createSpecs(
		[]string{"/bin/sleep", "100"},
		[]string{"/bin/sleep", "100"})
	rootDir, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer os.RemoveAll(rootDir)

	conf := testutil.TestConfigWithRoot(rootDir)

	// Create and start root container.
	rootBundleDir, err := testutil.SetupBundleDir(specs[0])
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootBundleDir)

	rootArgs := Args{
		ID:        ids[0],
		Spec:      specs[0],
		BundleDir: rootBundleDir,
	}
	root, err := New(conf, rootArgs)
	if err != nil {
		t.Fatalf("error creating root container: %v", err)
	}
	defer root.Destroy()
	if err := root.Start(conf); err != nil {
		t.Fatalf("error starting root container: %v", err)
	}

	// Create and destroy sub-container.
	bundleDir, err := testutil.SetupBundleDir(specs[1])
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(bundleDir)

	args := Args{
		ID:        ids[1],
		Spec:      specs[1],
		BundleDir: bundleDir,
	}
	cont, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}

	// Check that container can be destroyed.
	if err := cont.Destroy(); err != nil {
		t.Fatalf("deleting non-started container failed: %v", err)
	}
}

// TestMultiContainerDestroyStarting attempts to force a race between start
// and destroy.
func TestMultiContainerDestroyStarting(t *testing.T) {
	cmds := make([][]string, 10)
	for i := range cmds {
		cmds[i] = []string{"/bin/sleep", "100"}
	}
	specs, ids := createSpecs(cmds...)

	rootDir, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer os.RemoveAll(rootDir)

	conf := testutil.TestConfigWithRoot(rootDir)

	// Create and start root container.
	rootBundleDir, err := testutil.SetupBundleDir(specs[0])
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootBundleDir)

	rootArgs := Args{
		ID:        ids[0],
		Spec:      specs[0],
		BundleDir: rootBundleDir,
	}
	root, err := New(conf, rootArgs)
	if err != nil {
		t.Fatalf("error creating root container: %v", err)
	}
	defer root.Destroy()
	if err := root.Start(conf); err != nil {
		t.Fatalf("error starting root container: %v", err)
	}

	wg := sync.WaitGroup{}
	for i := range cmds {
		if i == 0 {
			continue // skip root container
		}

		bundleDir, err := testutil.SetupBundleDir(specs[i])
		if err != nil {
			t.Fatalf("error setting up container: %v", err)
		}
		defer os.RemoveAll(bundleDir)

		rootArgs := Args{
			ID:        ids[i],
			Spec:      specs[i],
			BundleDir: rootBundleDir,
		}
		cont, err := New(conf, rootArgs)
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}

		// Container is not thread safe, so load another instance to run in
		// concurrently.
		startCont, err := Load(rootDir, ids[i])
		if err != nil {
			t.Fatalf("error loading container: %v", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			startCont.Start(conf) // ignore failures, start can fail if destroy runs first.
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := cont.Destroy(); err != nil {
				t.Errorf("deleting non-started container failed: %v", err)
			}
		}()
	}
	wg.Wait()
}

// TestMultiContainerDifferentFilesystems tests that different containers have
// different root filesystems.
func TestMultiContainerDifferentFilesystems(t *testing.T) {
	filename := "/foo"
	// Root container will create file and then sleep.
	cmdRoot := []string{"sh", "-c", fmt.Sprintf("touch %q && sleep 100", filename)}

	// Child containers will assert that the file does not exist, and will
	// then create it.
	script := fmt.Sprintf("if [ -f %q ]; then exit 1; else touch %q; fi", filename, filename)
	cmd := []string{"sh", "-c", script}

	// Make sure overlay is enabled, and none of the root filesystems are
	// read-only, otherwise we won't be able to create the file.
	conf := testutil.TestConfig()
	conf.Overlay = true
	specs, ids := createSpecs(cmdRoot, cmd, cmd)
	for _, s := range specs {
		s.Root.Readonly = false
	}

	containers, cleanup, err := startContainers(conf, specs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	// Both child containers should exit successfully.
	for i, c := range containers {
		if i == 0 {
			// Don't wait on the root.
			continue
		}
		if ws, err := c.Wait(); err != nil {
			t.Errorf("failed to wait for process %s: %v", c.Spec.Process.Args, err)
		} else if es := ws.ExitStatus(); es != 0 {
			t.Errorf("process %s exited with non-zero status %d", c.Spec.Process.Args, es)
		}
	}
}

// TestMultiContainerContainerDestroyStress tests that IO operations continue
// to work after containers have been stopped and gofers killed.
func TestMultiContainerContainerDestroyStress(t *testing.T) {
	app, err := testutil.FindFile("runsc/container/test_app/test_app")
	if err != nil {
		t.Fatal("error finding test_app:", err)
	}

	// Setup containers. Root container just reaps children, while the others
	// perform some IOs. Children are executed in 3 batches of 10. Within the
	// batch there is overlap between containers starting and being destroyed. In
	// between batches all containers stop before starting another batch.
	cmds := [][]string{{app, "reaper"}}
	const batchSize = 10
	for i := 0; i < 3*batchSize; i++ {
		dir, err := ioutil.TempDir(testutil.TmpDir(), "gofer-stop-test")
		if err != nil {
			t.Fatal("ioutil.TempDir failed:", err)
		}
		defer os.RemoveAll(dir)

		cmd := "find /bin -type f | head | xargs -I SRC cp SRC " + dir
		cmds = append(cmds, []string{"sh", "-c", cmd})
	}
	allSpecs, allIDs := createSpecs(cmds...)

	rootDir, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer os.RemoveAll(rootDir)

	// Split up the specs and IDs.
	rootSpec := allSpecs[0]
	rootID := allIDs[0]
	childrenSpecs := allSpecs[1:]
	childrenIDs := allIDs[1:]

	bundleDir, err := testutil.SetupBundleDir(rootSpec)
	if err != nil {
		t.Fatalf("error setting up bundle dir: %v", err)
	}
	defer os.RemoveAll(bundleDir)

	// Start root container.
	conf := testutil.TestConfigWithRoot(rootDir)
	rootArgs := Args{
		ID:        rootID,
		Spec:      rootSpec,
		BundleDir: bundleDir,
	}
	root, err := New(conf, rootArgs)
	if err != nil {
		t.Fatalf("error creating root container: %v", err)
	}
	if err := root.Start(conf); err != nil {
		t.Fatalf("error starting root container: %v", err)
	}
	defer root.Destroy()

	// Run batches. Each batch starts containers in parallel, then wait and
	// destroy them before starting another batch.
	for i := 0; i < len(childrenSpecs); i += batchSize {
		t.Logf("Starting batch from %d to %d", i, i+batchSize)
		specs := childrenSpecs[i : i+batchSize]
		ids := childrenIDs[i : i+batchSize]

		var children []*Container
		for j, spec := range specs {
			bundleDir, err := testutil.SetupBundleDir(spec)
			if err != nil {
				t.Fatalf("error setting up container: %v", err)
			}
			defer os.RemoveAll(bundleDir)

			args := Args{
				ID:        ids[j],
				Spec:      spec,
				BundleDir: bundleDir,
			}
			child, err := New(conf, args)
			if err != nil {
				t.Fatalf("error creating container: %v", err)
			}
			children = append(children, child)

			if err := child.Start(conf); err != nil {
				t.Fatalf("error starting container: %v", err)
			}

			// Give a small gap between containers.
			time.Sleep(50 * time.Millisecond)
		}
		for _, child := range children {
			ws, err := child.Wait()
			if err != nil {
				t.Fatalf("waiting for container: %v", err)
			}
			if !ws.Exited() || ws.ExitStatus() != 0 {
				t.Fatalf("container failed, waitStatus: %x (%d)", ws, ws.ExitStatus())
			}
			if err := child.Destroy(); err != nil {
				t.Fatalf("error destroying container: %v", err)
			}
		}
	}
}

// Test that pod shared mounts are properly mounted in 2 containers and that
// changes from one container is reflected in the other.
func TestMultiContainerSharedMount(t *testing.T) {
	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)

		// Setup the containers.
		sleep := []string{"sleep", "100"}
		podSpec, ids := createSpecs(sleep, sleep)
		mnt0 := specs.Mount{
			Destination: "/mydir/test",
			Source:      "/some/dir",
			Type:        "tmpfs",
			Options:     nil,
		}
		podSpec[0].Mounts = append(podSpec[0].Mounts, mnt0)

		mnt1 := mnt0
		mnt1.Destination = "/mydir2/test2"
		podSpec[1].Mounts = append(podSpec[1].Mounts, mnt1)

		createSharedMount(mnt0, "test-mount", podSpec...)

		containers, cleanup, err := startContainers(conf, podSpec, ids)
		if err != nil {
			t.Fatalf("error starting containers: %v", err)
		}
		defer cleanup()

		file0 := path.Join(mnt0.Destination, "abc")
		file1 := path.Join(mnt1.Destination, "abc")
		execs := []execDesc{
			{
				c:    containers[0],
				cmd:  []string{"/usr/bin/test", "-d", mnt0.Destination},
				desc: "directory is mounted in container0",
			},
			{
				c:    containers[1],
				cmd:  []string{"/usr/bin/test", "-d", mnt1.Destination},
				desc: "directory is mounted in container1",
			},
			{
				c:    containers[0],
				cmd:  []string{"/usr/bin/touch", file0},
				desc: "create file in container0",
			},
			{
				c:    containers[0],
				cmd:  []string{"/usr/bin/test", "-f", file0},
				desc: "file appears in container0",
			},
			{
				c:    containers[1],
				cmd:  []string{"/usr/bin/test", "-f", file1},
				desc: "file appears in container1",
			},
			{
				c:    containers[1],
				cmd:  []string{"/bin/rm", file1},
				desc: "file removed from container1",
			},
			{
				c:    containers[0],
				cmd:  []string{"/usr/bin/test", "!", "-f", file0},
				desc: "file removed from container0",
			},
			{
				c:    containers[1],
				cmd:  []string{"/usr/bin/test", "!", "-f", file1},
				desc: "file removed from container1",
			},
			{
				c:    containers[1],
				cmd:  []string{"/bin/mkdir", file1},
				desc: "create directory in container1",
			},
			{
				c:    containers[0],
				cmd:  []string{"/usr/bin/test", "-d", file0},
				desc: "dir appears in container0",
			},
			{
				c:    containers[1],
				cmd:  []string{"/usr/bin/test", "-d", file1},
				desc: "dir appears in container1",
			},
			{
				c:    containers[0],
				cmd:  []string{"/bin/rmdir", file0},
				desc: "create directory in container0",
			},
			{
				c:    containers[0],
				cmd:  []string{"/usr/bin/test", "!", "-d", file0},
				desc: "dir removed from container0",
			},
			{
				c:    containers[1],
				cmd:  []string{"/usr/bin/test", "!", "-d", file1},
				desc: "dir removed from container1",
			},
		}
		if err := execMany(execs); err != nil {
			t.Fatal(err.Error())
		}
	}
}

// Test that pod mounts are mounted as readonly when requested.
func TestMultiContainerSharedMountReadonly(t *testing.T) {
	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)

		// Setup the containers.
		sleep := []string{"sleep", "100"}
		podSpec, ids := createSpecs(sleep, sleep)
		mnt0 := specs.Mount{
			Destination: "/mydir/test",
			Source:      "/some/dir",
			Type:        "tmpfs",
			Options:     []string{"ro"},
		}
		podSpec[0].Mounts = append(podSpec[0].Mounts, mnt0)

		mnt1 := mnt0
		mnt1.Destination = "/mydir2/test2"
		podSpec[1].Mounts = append(podSpec[1].Mounts, mnt1)

		createSharedMount(mnt0, "test-mount", podSpec...)

		containers, cleanup, err := startContainers(conf, podSpec, ids)
		if err != nil {
			t.Fatalf("error starting containers: %v", err)
		}
		defer cleanup()

		file0 := path.Join(mnt0.Destination, "abc")
		file1 := path.Join(mnt1.Destination, "abc")
		execs := []execDesc{
			{
				c:    containers[0],
				cmd:  []string{"/usr/bin/test", "-d", mnt0.Destination},
				desc: "directory is mounted in container0",
			},
			{
				c:    containers[1],
				cmd:  []string{"/usr/bin/test", "-d", mnt1.Destination},
				desc: "directory is mounted in container1",
			},
			{
				c:    containers[0],
				cmd:  []string{"/usr/bin/touch", file0},
				want: 1,
				desc: "fails to write to container0",
			},
			{
				c:    containers[1],
				cmd:  []string{"/usr/bin/touch", file1},
				want: 1,
				desc: "fails to write to container1",
			},
		}
		if err := execMany(execs); err != nil {
			t.Fatal(err.Error())
		}
	}
}

// Test that shared pod mounts continue to work after container is restarted.
func TestMultiContainerSharedMountRestart(t *testing.T) {
	for _, conf := range configs(all...) {
		t.Logf("Running test with conf: %+v", conf)

		// Setup the containers.
		sleep := []string{"sleep", "100"}
		podSpec, ids := createSpecs(sleep, sleep)
		mnt0 := specs.Mount{
			Destination: "/mydir/test",
			Source:      "/some/dir",
			Type:        "tmpfs",
			Options:     nil,
		}
		podSpec[0].Mounts = append(podSpec[0].Mounts, mnt0)

		mnt1 := mnt0
		mnt1.Destination = "/mydir2/test2"
		podSpec[1].Mounts = append(podSpec[1].Mounts, mnt1)

		createSharedMount(mnt0, "test-mount", podSpec...)

		containers, cleanup, err := startContainers(conf, podSpec, ids)
		if err != nil {
			t.Fatalf("error starting containers: %v", err)
		}
		defer cleanup()

		file0 := path.Join(mnt0.Destination, "abc")
		file1 := path.Join(mnt1.Destination, "abc")
		execs := []execDesc{
			{
				c:    containers[0],
				cmd:  []string{"/usr/bin/touch", file0},
				desc: "create file in container0",
			},
			{
				c:    containers[0],
				cmd:  []string{"/usr/bin/test", "-f", file0},
				desc: "file appears in container0",
			},
			{
				c:    containers[1],
				cmd:  []string{"/usr/bin/test", "-f", file1},
				desc: "file appears in container1",
			},
		}
		if err := execMany(execs); err != nil {
			t.Fatal(err.Error())
		}

		containers[1].Destroy()

		bundleDir, err := testutil.SetupBundleDir(podSpec[1])
		if err != nil {
			t.Fatalf("error restarting container: %v", err)
		}
		defer os.RemoveAll(bundleDir)

		args := Args{
			ID:        ids[1],
			Spec:      podSpec[1],
			BundleDir: bundleDir,
		}
		containers[1], err = New(conf, args)
		if err != nil {
			t.Fatalf("error creating container: %v", err)
		}
		if err := containers[1].Start(conf); err != nil {
			t.Fatalf("error starting container: %v", err)
		}

		execs = []execDesc{
			{
				c:    containers[0],
				cmd:  []string{"/usr/bin/test", "-f", file0},
				desc: "file is still in container0",
			},
			{
				c:    containers[1],
				cmd:  []string{"/usr/bin/test", "-f", file1},
				desc: "file is still in container1",
			},
			{
				c:    containers[1],
				cmd:  []string{"/bin/rm", file1},
				desc: "file removed from container1",
			},
			{
				c:    containers[0],
				cmd:  []string{"/usr/bin/test", "!", "-f", file0},
				desc: "file removed from container0",
			},
			{
				c:    containers[1],
				cmd:  []string{"/usr/bin/test", "!", "-f", file1},
				desc: "file removed from container1",
			},
		}
		if err := execMany(execs); err != nil {
			t.Fatal(err.Error())
		}
	}
}

// Test that unsupported pod mounts options are ignored when matching master and
// slave mounts.
func TestMultiContainerSharedMountUnsupportedOptions(t *testing.T) {
	conf := testutil.TestConfig()
	t.Logf("Running test with conf: %+v", conf)

	// Setup the containers.
	sleep := []string{"/bin/sleep", "100"}
	podSpec, ids := createSpecs(sleep, sleep)
	mnt0 := specs.Mount{
		Destination: "/mydir/test",
		Source:      "/some/dir",
		Type:        "tmpfs",
		Options:     []string{"rw", "rbind", "relatime"},
	}
	podSpec[0].Mounts = append(podSpec[0].Mounts, mnt0)

	mnt1 := mnt0
	mnt1.Destination = "/mydir2/test2"
	mnt1.Options = []string{"rw", "nosuid"}
	podSpec[1].Mounts = append(podSpec[1].Mounts, mnt1)

	createSharedMount(mnt0, "test-mount", podSpec...)

	containers, cleanup, err := startContainers(conf, podSpec, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	execs := []execDesc{
		{
			c:    containers[0],
			cmd:  []string{"/usr/bin/test", "-d", mnt0.Destination},
			desc: "directory is mounted in container0",
		},
		{
			c:    containers[1],
			cmd:  []string{"/usr/bin/test", "-d", mnt1.Destination},
			desc: "directory is mounted in container1",
		},
	}
	if err := execMany(execs); err != nil {
		t.Fatal(err.Error())
	}
}

// Test that one container can send an FD to another container, even though
// they have distinct MountNamespaces.
func TestMultiContainerMultiRootCanHandleFDs(t *testing.T) {
	app, err := testutil.FindFile("runsc/container/test_app/test_app")
	if err != nil {
		t.Fatal("error finding test_app:", err)
	}

	// We set up two containers with one shared mount that is used for a
	// shared socket. The first container will send an FD over the socket
	// to the second container. The FD corresponds to a file in the first
	// container's mount namespace that is not part of the second
	// container's mount namespace. However, the second container still
	// should be able to read the FD.

	// Create a shared mount where we will put the socket.
	sharedMnt := specs.Mount{
		Destination: "/mydir/test",
		Type:        "tmpfs",
		// Shared mounts need a Source, even for tmpfs. It is only used
		// to match up different shared mounts inside the pod.
		Source: "/some/dir",
	}
	socketPath := filepath.Join(sharedMnt.Destination, "socket")

	// Create a writeable tmpfs mount where the FD sender app will create
	// files to send. This will only be mounted in the FD sender.
	writeableMnt := specs.Mount{
		Destination: "/tmp",
		Type:        "tmpfs",
	}

	// Create the specs.
	specs, ids := createSpecs(
		[]string{"sleep", "1000"},
		[]string{app, "fd_sender", "--socket", socketPath},
		[]string{app, "fd_receiver", "--socket", socketPath},
	)
	createSharedMount(sharedMnt, "shared-mount", specs...)
	specs[1].Mounts = append(specs[2].Mounts, sharedMnt, writeableMnt)
	specs[2].Mounts = append(specs[1].Mounts, sharedMnt)

	conf := testutil.TestConfig()
	containers, cleanup, err := startContainers(conf, specs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	// Both containers should exit successfully.
	for _, c := range containers[1:] {
		if ws, err := c.Wait(); err != nil {
			t.Errorf("failed to wait for process %s: %v", c.Spec.Process.Args, err)
		} else if es := ws.ExitStatus(); es != 0 {
			t.Errorf("process %s exited with non-zero status %d", c.Spec.Process.Args, es)
		}
	}
}

// Test that container is destroyed when Gofer is killed.
func TestMultiContainerGoferKilled(t *testing.T) {
	sleep := []string{"sleep", "100"}
	specs, ids := createSpecs(sleep, sleep, sleep)
	conf := testutil.TestConfig()
	containers, cleanup, err := startContainers(conf, specs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	// Ensure container is running
	c := containers[2]
	expectedPL := []*control.Process{
		{PID: 3, Cmd: "sleep"},
	}
	if err := waitForProcessList(c, expectedPL); err != nil {
		t.Errorf("failed to wait for sleep to start: %v", err)
	}

	// Kill container's gofer.
	if err := syscall.Kill(c.GoferPid, syscall.SIGKILL); err != nil {
		t.Fatalf("syscall.Kill(%d, SIGKILL)=%v", c.GoferPid, err)
	}

	// Wait until container stops.
	if err := waitForProcessList(c, nil); err != nil {
		t.Errorf("Container %q was not stopped after gofer death: %v", c.ID, err)
	}

	// Check that container isn't running anymore.
	args := &control.ExecArgs{Argv: []string{"/bin/true"}}
	if _, err := c.executeSync(args); err == nil {
		t.Fatalf("Container %q was not stopped after gofer death", c.ID)
	}

	// Check that other containers are unaffected.
	for i, c := range containers {
		if i == 2 {
			continue // container[2] has been killed.
		}
		pl := []*control.Process{
			{PID: kernel.ThreadID(i + 1), Cmd: "sleep"},
		}
		if err := waitForProcessList(c, pl); err != nil {
			t.Errorf("Container %q was affected by another container: %v", c.ID, err)
		}
		args := &control.ExecArgs{Argv: []string{"/bin/true"}}
		if _, err := c.executeSync(args); err != nil {
			t.Fatalf("Container %q was affected by another container: %v", c.ID, err)
		}
	}

	// Kill root container's gofer to bring entire sandbox down.
	c = containers[0]
	if err := syscall.Kill(c.GoferPid, syscall.SIGKILL); err != nil {
		t.Fatalf("syscall.Kill(%d, SIGKILL)=%v", c.GoferPid, err)
	}

	// Wait until sandbox stops. waitForProcessList will loop until sandbox exits
	// and RPC errors out.
	impossiblePL := []*control.Process{
		{PID: 100, Cmd: "non-existent-process"},
	}
	if err := waitForProcessList(c, impossiblePL); err == nil {
		t.Fatalf("Sandbox was not killed after gofer death")
	}

	// Check that entire sandbox isn't running anymore.
	for _, c := range containers {
		args := &control.ExecArgs{Argv: []string{"/bin/true"}}
		if _, err := c.executeSync(args); err == nil {
			t.Fatalf("Container %q was not stopped after gofer death", c.ID)
		}
	}
}

func TestMultiContainerLoadSandbox(t *testing.T) {
	sleep := []string{"sleep", "100"}
	specs, ids := createSpecs(sleep, sleep, sleep)
	conf := testutil.TestConfig()

	// Create containers for the sandbox.
	wants, cleanup, err := startContainers(conf, specs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	// Then create unrelated containers.
	for i := 0; i < 3; i++ {
		specs, ids = createSpecs(sleep, sleep, sleep)
		_, cleanup, err = startContainers(conf, specs, ids)
		if err != nil {
			t.Fatalf("error starting containers: %v", err)
		}
		defer cleanup()
	}

	// Create an unrelated directory under root.
	dir := filepath.Join(conf.RootDir, "not-a-container")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("os.MkdirAll(%q)=%v", dir, err)
	}

	// Create a valid but empty container directory.
	randomCID := testutil.UniqueContainerID()
	dir = filepath.Join(conf.RootDir, randomCID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("os.MkdirAll(%q)=%v", dir, err)
	}

	// Load the sandbox and check that the correct containers were returned.
	id := wants[0].Sandbox.ID
	gots, err := loadSandbox(conf.RootDir, id)
	if err != nil {
		t.Fatalf("loadSandbox()=%v", err)
	}
	wantIDs := make(map[string]struct{})
	for _, want := range wants {
		wantIDs[want.ID] = struct{}{}
	}
	for _, got := range gots {
		if got.Sandbox.ID != id {
			t.Errorf("wrong sandbox ID, got: %v, want: %v", got.Sandbox.ID, id)
		}
		if _, ok := wantIDs[got.ID]; !ok {
			t.Errorf("wrong container ID, got: %v, wants: %v", got.ID, wantIDs)
		}
		delete(wantIDs, got.ID)
	}
	if len(wantIDs) != 0 {
		t.Errorf("containers not found: %v", wantIDs)
	}
}

// TestMultiContainerRunNonRoot checks that child container can be configured
// when running as non-privileged user.
func TestMultiContainerRunNonRoot(t *testing.T) {
	cmdRoot := []string{"/bin/sleep", "100"}
	cmdSub := []string{"/bin/true"}
	podSpecs, ids := createSpecs(cmdRoot, cmdSub)

	// User running inside container can't list '$TMP/blocked' and would fail to
	// mount it.
	blocked, err := ioutil.TempDir(testutil.TmpDir(), "blocked")
	if err != nil {
		t.Fatalf("ioutil.TempDir() failed: %v", err)
	}
	if err := os.Chmod(blocked, 0700); err != nil {
		t.Fatalf("os.MkDir(%q) failed: %v", blocked, err)
	}
	dir := path.Join(blocked, "test")
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatalf("os.MkDir(%q) failed: %v", dir, err)
	}

	src, err := ioutil.TempDir(testutil.TmpDir(), "src")
	if err != nil {
		t.Fatalf("ioutil.TempDir() failed: %v", err)
	}

	// Set a random user/group with no access to "blocked" dir.
	podSpecs[1].Process.User.UID = 343
	podSpecs[1].Process.User.GID = 2401
	podSpecs[1].Process.Capabilities = nil

	podSpecs[1].Mounts = append(podSpecs[1].Mounts, specs.Mount{
		Destination: dir,
		Source:      src,
		Type:        "bind",
	})

	conf := testutil.TestConfig()
	pod, cleanup, err := startContainers(conf, podSpecs, ids)
	if err != nil {
		t.Fatalf("error starting containers: %v", err)
	}
	defer cleanup()

	// Once all containers are started, wait for the child container to exit.
	// This means that the volume was mounted properly.
	ws, err := pod[1].Wait()
	if err != nil {
		t.Fatalf("running child container: %v", err)
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		t.Fatalf("child container failed, waitStatus: %v", ws)
	}
}