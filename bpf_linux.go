//go:build linux
// +build linux

package exectrace

import (
	"io"
	"log"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"
)

var remvoveMemlockOnce sync.Once

var collectionOpts = &ebpf.CollectionOptions{
	Programs: ebpf.ProgramOptions{
		// While debugging, it may be helpful to set this value to be much
		// higher (i.e. * 1000).
		LogSize: ebpf.DefaultVerifierLogSize,
	},
}

// BPFObjects contains a loaded BPF program.
type BPFObjects interface {
	io.Closer

	enterExecveProg() *ebpf.Program
	eventsMap() *ebpf.Map
}

// LoadBPFObjects reads and parses the programs and maps out of the given BPF
// executable file.
func LoadBPFObjects(r io.ReaderAt) (BPFObjects, error) {
	// Allow the current process to lock memory for eBPF resources. This does
	// nothing on 5.11+ kernels which don't need this.
	var err error
	remvoveMemlockOnce.Do(func() {
		err = rlimit.RemoveMemlock()
	})
	if err != nil {
		return nil, xerrors.Errorf("remove kernel memlock: %w", err)
	}

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

	// It could be very bad if someone forgot to close this, so we'll try to
	// detect when it doesn't get closed and log a warning.
	stack := debug.Stack()
	runtime.SetFinalizer(objs, func(o *bpfObjects) {
		err := o.Close()
		if xerrors.Is(err, errObjectsClosed) {
			return
		}

		log.Printf("BPFObjects was finalized but was not closed, created at: %s", stack)
		log.Print("BPFObjects must be closed when finished with to avoid leaked kernel resources")
		if err != nil {
			log.Printf("closing BPFObjects failed: %+v", err)
		}
	})

	return objs, nil
}

type bpfObjects struct {
	EnterExecveProg *ebpf.Program `ebpf:"enter_execve"`
	EventsMap       *ebpf.Map     `ebpf:"events"`

	closeLock sync.Mutex
	closed    chan struct{}
}

var _ BPFObjects = &bpfObjects{}

func (o *bpfObjects) enterExecveProg() *ebpf.Program {
	return o.EnterExecveProg
}

func (o *bpfObjects) eventsMap() *ebpf.Map {
	return o.EventsMap
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
