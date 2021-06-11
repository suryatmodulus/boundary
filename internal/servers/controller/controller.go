package controller

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/cmd/config"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/scheduler/job"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/vault/sdk/helper/mlock"
	"github.com/patrickmn/go-cache"
	ua "go.uber.org/atomic"
)

const (
	defaultStatusGracePeriod = 15 * time.Second
	statusGracePeriodEnvVar  = "BOUNDARY_STATUS_GRACE_PERIOD"
)

type Controller struct {
	conf   *Config
	logger hclog.Logger

	baseContext context.Context
	baseCancel  context.CancelFunc
	started     *ua.Bool

	workerAuthCache *cache.Cache

	// Used for testing and tracking worker health
	workerStatusUpdateTimes *sync.Map

	// Used by session cleanup job to remove connections for
	// non-responsive workers
	statusGracePeriod time.Duration

	// Repo factory methods
	AuthTokenRepoFn    common.AuthTokenRepoFactory
	IamRepoFn          common.IamRepoFactory
	OidcRepoFn         common.OidcAuthRepoFactory
	PasswordAuthRepoFn common.PasswordAuthRepoFactory
	ServersRepoFn      common.ServersRepoFactory
	SessionRepoFn      common.SessionRepoFactory
	StaticHostRepoFn   common.StaticRepoFactory
	TargetRepoFn       common.TargetRepoFactory

	scheduler *scheduler.Scheduler

	kms *kms.Kms
}

func New(conf *Config) (*Controller, error) {
	c := &Controller{
		conf:                    conf,
		logger:                  conf.Logger.Named("controller"),
		started:                 ua.NewBool(false),
		workerStatusUpdateTimes: new(sync.Map),
	}

	c.setStatusGracePeriod()
	c.started.Store(false)

	if conf.SecureRandomReader == nil {
		conf.SecureRandomReader = rand.Reader
	}

	var err error
	if conf.RawConfig.Controller == nil {
		conf.RawConfig.Controller = new(config.Controller)
	}
	if conf.RawConfig.Controller.Name == "" {
		if conf.RawConfig.Controller.Name, err = base62.Random(10); err != nil {
			return nil, fmt.Errorf("error auto-generating controller name: %w", err)
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

	// Set up repo stuff
	dbase := db.New(c.conf.Database)
	kmsRepo, err := kms.NewRepository(dbase, dbase)
	if err != nil {
		return nil, fmt.Errorf("error creating kms repository: %w", err)
	}
	c.kms, err = kms.NewKms(kmsRepo, kms.WithLogger(c.logger.Named("kms")))
	if err != nil {
		return nil, fmt.Errorf("error creating kms cache: %w", err)
	}
	if err := c.kms.AddExternalWrappers(
		kms.WithRootWrapper(c.conf.RootKms),
		kms.WithWorkerAuthWrapper(c.conf.WorkerAuthKms),
		kms.WithRecoveryWrapper(c.conf.RecoveryKms),
	); err != nil {
		return nil, fmt.Errorf("error adding config keys to kms: %w", err)
	}

	jobRepoFn := func() (*job.Repository, error) {
		return job.NewRepository(dbase, dbase, c.kms)
	}
	c.scheduler, err = scheduler.New(c.conf.RawConfig.Controller.Name, jobRepoFn, c.logger)
	if err != nil {
		return nil, fmt.Errorf("error creating new scheduler: %w", err)
	}
	c.IamRepoFn = func() (*iam.Repository, error) {
		return iam.NewRepository(dbase, dbase, c.kms, iam.WithRandomReader(c.conf.SecureRandomReader))
	}
	c.StaticHostRepoFn = func() (*static.Repository, error) {
		return static.NewRepository(dbase, dbase, c.kms)
	}
	c.AuthTokenRepoFn = func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(dbase, dbase, c.kms,
			authtoken.WithTokenTimeToLiveDuration(c.conf.RawConfig.Controller.AuthTokenTimeToLiveDuration),
			authtoken.WithTokenTimeToStaleDuration(c.conf.RawConfig.Controller.AuthTokenTimeToStaleDuration))
	}
	c.ServersRepoFn = func() (*servers.Repository, error) {
		return servers.NewRepository(dbase, dbase, c.kms)
	}
	c.OidcRepoFn = func() (*oidc.Repository, error) {
		return oidc.NewRepository(dbase, dbase, c.kms)
	}
	c.PasswordAuthRepoFn = func() (*password.Repository, error) {
		return password.NewRepository(dbase, dbase, c.kms)
	}
	c.TargetRepoFn = func() (*target.Repository, error) {
		return target.NewRepository(dbase, dbase, c.kms)
	}
	c.SessionRepoFn = func() (*session.Repository, error) {
		return session.NewRepository(dbase, dbase, c.kms)
	}
	c.workerAuthCache = cache.New(0, 0)

	return c, nil
}

// setStatusGracePeriod returns the status grace period setting for this
// controller, in seconds.
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
func (c *Controller) setStatusGracePeriod() {
	var result time.Duration
	switch {
	case c.conf.RawConfig.Controller.StatusGracePeriodDuration > 0:
		result = c.conf.RawConfig.Controller.StatusGracePeriodDuration
	case os.Getenv(statusGracePeriodEnvVar) != "":
		v := os.Getenv(statusGracePeriodEnvVar)
		n, err := strconv.Atoi(v)
		if err != nil {
			c.logger.Error("could not read setting for BOUNDARY_STATUS_GRACE_PERIOD",
				"err", err,
				"value", v,
			)
			break
		}

		result = time.Second * time.Duration(n)
	}

	if result < defaultStatusGracePeriod {
		c.logger.Debug("invalid grace period setting or none provided, using default", "value", result, "default", defaultStatusGracePeriod)
		result = defaultStatusGracePeriod
	}

	c.logger.Debug("session cleanup will mark connections as closed if status reports are not received from workers", "grace_period", result)
	c.statusGracePeriod = result
}

func (c *Controller) Start() error {
	if c.started.Load() {
		c.logger.Info("already started, skipping")
		return nil
	}
	c.baseContext, c.baseCancel = context.WithCancel(context.Background())
	if err := c.registerJobs(); err != nil {
		return fmt.Errorf("error registering jobs: %w", err)
	}
	if err := c.scheduler.Start(c.baseContext); err != nil {
		return fmt.Errorf("error starting scheduler: %w", err)
	}

	if err := c.startListeners(); err != nil {
		return fmt.Errorf("error starting controller listeners: %w", err)
	}

	c.startStatusTicking(c.baseContext)
	c.startRecoveryNonceCleanupTicking(c.baseContext)
	c.startTerminateCompletedSessionsTicking(c.baseContext)
	c.startCloseExpiredPendingTokens(c.baseContext)
	c.started.Store(true)

	return nil
}

func (c *Controller) registerJobs() error {
	if err := c.registerSessionCleanupJob(); err != nil {
		return err
	}

	return nil
}

// registerSessionCleanupJob is a helper method to abstract
// registering the session cleanup job specifically.
func (c *Controller) registerSessionCleanupJob() error {
	sessionCleanupJob, err := newSessionCleanupJob(c.logger, c.ServersRepoFn, c.SessionRepoFn, c.statusGracePeriod)
	if err != nil {
		return fmt.Errorf("error creating session cleanup job: %w", err)
	}
	if err = c.scheduler.RegisterJob(c.baseContext, sessionCleanupJob); err != nil {
		return fmt.Errorf("error registering session cleanup job: %w", err)
	}

	return nil
}

func (c *Controller) Shutdown(serversOnly bool) error {
	if !c.started.Load() {
		c.logger.Info("already shut down, skipping")
		return nil
	}
	c.baseCancel()
	if err := c.stopListeners(serversOnly); err != nil {
		return fmt.Errorf("error stopping controller listeners: %w", err)
	}
	c.started.Store(false)
	return nil
}

// WorkerStatusUpdateTimes returns the map, which specifically is held in _this_
// controller, not the DB. It's used in tests to verify that a given controller
// is receiving updates from an expected set of workers, to test out balancing
// and auto reconnection.
func (c *Controller) WorkerStatusUpdateTimes() *sync.Map {
	return c.workerStatusUpdateTimes
}
