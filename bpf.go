//go:build linux
// +build linux

package exectrace

import (
	"bytes"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"
)

var (
	errObjectsClosed  = xerrors.New("objects are closed")
	removeMemlockOnce sync.Once

	// collectionOpts used for loading the BPF objects.
	collectionOpts = &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			// While debugging, it may be helpful to set this value to be much
			// higher (i.e. * 1000).
			LogSize: ebpf.DefaultVerifierLogSize,
		},
	}
)

// loadBPFObjects reads and parses the programs and maps out of the embedded
// BPF program.
func loadBPFObjects() (*bpfObjects, error) {
	// Allow the current process to lock memory for eBPF resources. This does
	// nothing on 5.11+ kernels which don't need this.
	var err error
	removeMemlockOnce.Do(func() {
		err = rlimit.RemoveMemlock()
	})
	if err != nil {
		return nil, xerrors.Errorf("remove kernel memlock: %w", err)
	}

	r := bytes.NewReader(bpfProgram)
	spec, err := ebpf.LoadCollectionSpecFromReader(r)
	if err != nil {
		return nil, xerrors.Errorf("load collection from reader: %w", err)
	}

	objs := &bpfObjects{
		closeLock: sync.Mutex{},
		closed:    make(chan struct{}),
	}
	err = spec.LoadAndAssign(objs, collectionOpts)
	if err != nil {
		return nil, xerrors.Errorf("load and assign specs: %w", err)
	}

	return objs, nil
}

type bpfObjects struct {
	EnterExecveProg *ebpf.Program `ebpf:"enter_execve"`
	EventsMap       *ebpf.Map     `ebpf:"events"`
	FiltersMap      *ebpf.Map     `ebpf:"filters"`

	closeLock sync.Mutex
	closed    chan struct{}
}

func (o *bpfObjects) Close() error {
	o.closeLock.Lock()
	defer o.closeLock.Unlock()
	select {
	case <-o.closed:
		return errObjectsClosed
	default:
	}
	close(o.closed)
	runtime.SetFinalizer(o, nil)

	var merr error
	if o.EnterExecveProg != nil {
		err := o.EnterExecveProg.Close()
		if err != nil {
			merr = multierror.Append(merr, xerrors.Errorf(`close BPF program "enter_execve": %w`, err))
		}
	}
	if o.EventsMap != nil {
		err := o.EventsMap.Close()
		if err != nil {
			merr = multierror.Append(merr, xerrors.Errorf(`close BPF map "events": %w`, err))
		}
	}

	return merr
}
