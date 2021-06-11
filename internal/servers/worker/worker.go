package worker

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/vault/sdk/helper/mlock"
	ua "go.uber.org/atomic"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
)

const (
	defaultStatusGracePeriod = 15 * time.Second
	statusGracePeriodEnvVar  = "BOUNDARY_STATUS_GRACE_PERIOD"
)

type Worker struct {
	conf   *Config
	logger hclog.Logger

	baseContext context.Context
	baseCancel  context.CancelFunc
	started     *ua.Bool

	controllerStatusConn *atomic.Value
	lastStatusSuccess    *atomic.Value
	workerStartTime      time.Time
	statusGracePeriod    time.Duration

	controllerResolver *atomic.Value

	controllerSessionConn *atomic.Value
	sessionInfoMap        *sync.Map

	// We store the current set in an atomic value so that we can add
	// reload-on-sighup behavior later
	tags *atomic.Value
	// This stores whether or not to send updated tags on the next status
	// request. It can be set via startup in New below, or (eventually) via
	// SIGHUP.
	updateTags ua.Bool
}

func New(conf *Config) (*Worker, error) {
	w := &Worker{
		conf:                  conf,
		logger:                conf.Logger.Named("worker"),
		started:               ua.NewBool(false),
		controllerStatusConn:  new(atomic.Value),
		lastStatusSuccess:     new(atomic.Value),
		controllerResolver:    new(atomic.Value),
		controllerSessionConn: new(atomic.Value),
		sessionInfoMap:        new(sync.Map),
		tags:                  new(atomic.Value),
	}

	w.setStatusGracePeriod()
	w.lastStatusSuccess.Store((*LastStatusInformation)(nil))
	w.controllerResolver.Store((*manual.Resolver)(nil))

	if conf.RawConfig.Worker == nil {
		conf.RawConfig.Worker = new(config.Worker)
	}

	w.ParseAndStoreTags(conf.RawConfig.Worker.Tags)

	if conf.SecureRandomReader == nil {
		conf.SecureRandomReader = rand.Reader
	}

	var err error
	if conf.RawConfig.Worker.Name == "" {
		if conf.RawConfig.Worker.Name, err = base62.Random(10); err != nil {
			return nil, fmt.Errorf("error auto-generating worker name: %w", err)
		}
	}

	if !conf.RawConfig.DisableMlock {
		// Ensure our memory usage is locked into physical RAM
		if err := mlock.LockMemory(); err != nil {
			return nil, fmt.Errorf(
				"Failed to lock memory: %v\n\n"+
					"This usually means that the mlock syscall is not available.\n"+
					"Boundary uses mlock to prevent memory from being swapped to\n"+
					"disk. This requires root privileges as well as a machine\n"+
					"that supports mlock. Please enable mlock on your system or\n"+
					"disable Boundary from using it. To disable Boundary from using it,\n"+
					"set the `disable_mlock` configuration option in your configuration\n"+
					"file.",
				err)
		}
	}

	return w, nil
}

// setStatusGracePeriod returns the status grace period setting for this
// worker, in seconds.
//
// The grace period is the length of time we allow connections to run
// on a worker in the event of an error sending status updates. The
// period is defined the length of time since the last successful
// update.
//
// The setting is derived from one of the following:
//
//   * Through configuration,
//   * BOUNDARY_STATUS_GRACE_PERIOD, if defined, can be set to an
//   integer value to define the setting.
//   * If either of these is missing, the default (15 seconds) is
//   used.
//
// The minimum setting for this value is the default setting. Values
// below this will be reset to the default.
func (w *Worker) setStatusGracePeriod() {
	var result time.Duration
	switch {
	case w.conf.RawConfig.Worker.StatusGracePeriodDuration > 0:
		result = w.conf.RawConfig.Worker.StatusGracePeriodDuration
	case os.Getenv(statusGracePeriodEnvVar) != "":
		v := os.Getenv(statusGracePeriodEnvVar)
		n, err := strconv.Atoi(v)
		if err != nil {
			w.logger.Error("could not read setting for BOUNDARY_STATUS_GRACE_PERIOD",
				"err", err,
				"value", v,
			)
			break
		}

		result = time.Second * time.Duration(n)
	}

	if result < defaultStatusGracePeriod {
		w.logger.Debug("invalid grace period setting or none provided, using default", "value", result, "default", defaultStatusGracePeriod)
		result = defaultStatusGracePeriod
	}

	w.logger.Debug("session cleanup will disconnect connections if status report cannot be made to controllers", "grace_period", result)
	w.statusGracePeriod = result
}

func (w *Worker) Start() error {
	if w.started.Load() {
		w.logger.Info("already started, skipping")
		return nil
	}

	w.baseContext, w.baseCancel = context.WithCancel(context.Background())

	scheme := strconv.FormatInt(time.Now().UnixNano(), 36)
	controllerResolver := manual.NewBuilderWithScheme(scheme)
	w.controllerResolver.Store(controllerResolver)

	if err := w.startListeners(); err != nil {
		return fmt.Errorf("error starting worker listeners: %w", err)
	}
	if err := w.startControllerConnections(); err != nil {
		return fmt.Errorf("error making controller connections: %w", err)
	}

	w.startStatusTicking(w.baseContext)
	w.workerStartTime = time.Now()
	w.started.Store(true)

	return nil
}

// Shutdown shuts down the workers. skipListeners can be used to not stop
// listeners, useful for tests if we want to stop and start a worker. In order
// to create new listeners we'd have to migrate listener setup logic here --
// doable, but work for later.
func (w *Worker) Shutdown(skipListeners bool) error {
	if !w.started.Load() {
		w.logger.Info("already shut down, skipping")
		return nil
	}
	w.Resolver().UpdateState(resolver.State{Addresses: []resolver.Address{}})
	w.baseCancel()
	if !skipListeners {
		if err := w.stopListeners(); err != nil {
			return fmt.Errorf("error stopping worker listeners: %w", err)
		}
	}
	w.started.Store(false)
	return nil
}

func (w *Worker) Resolver() *manual.Resolver {
	raw := w.controllerResolver.Load()
	if raw == nil {
		panic("nil resolver")
	}
	return raw.(*manual.Resolver)
}

func (w *Worker) ParseAndStoreTags(incoming map[string][]string) {
	if len(incoming) == 0 {
		w.tags.Store(map[string]*servers.TagValues{})
		return
	}
	tags := make(map[string]*servers.TagValues, len(incoming))
	for k, v := range incoming {
		tags[k] = &servers.TagValues{
			Values: append(make([]string, 0, len(v)), v...),
		}
	}
	w.tags.Store(tags)
	w.updateTags.Store(true)
}
