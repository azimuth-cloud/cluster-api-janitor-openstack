package openstack

import (
	"context"

	"github.com/go-logr/logr"
)

// PurgeOptions holds parameters for cleaning up OpenStack resources
// associated with a deleted Cluster API cluster.
type PurgeOptions struct {
	// CloudsYAML is the decoded content of the clouds.yaml credential file.
	CloudsYAML string
	// CloudName is the entry name within clouds.yaml to use.
	CloudName string
	// CACert is an optional PEM-encoded CA certificate for TLS verification.
	CACert string
	// ClusterName is the CAPI cluster name used to identify owned resources.
	ClusterName string
	// IncludeVolumes controls whether Cinder volumes and snapshots are deleted.
	IncludeVolumes bool
	// IncludeAppcred controls whether the OpenStack application credential is deleted.
	IncludeAppcred bool
	// Logger receives structured log messages during cleanup.
	Logger logr.Logger
}

// PurgeResources removes all OpenStack resources (FIPs, load balancers,
// security groups, volumes, snapshots, and optionally the application
// credential) created by OCCM/CSI for the given cluster.
func PurgeResources(ctx context.Context, opts PurgeOptions) error {
	session, err := Authenticate(ctx, opts.CloudsYAML, opts.CloudName, opts.CACert)
	if err != nil {
		return err
	}

	if !session.IsAuthenticated() {
		if opts.IncludeAppcred {
			opts.Logger.Info("application credential has been deleted, skipping cleanup")
			return nil
		}
		return &AuthenticationError{UserID: session.UserID()}
	}

	if err := session.DeleteFloatingIPs(ctx, opts.Logger, opts.ClusterName); err != nil {
		return err
	}
	if err := session.DeleteLoadBalancers(ctx, opts.Logger, opts.ClusterName); err != nil {
		return err
	}
	if err := session.DeleteSecurityGroups(ctx, opts.Logger, opts.ClusterName); err != nil {
		return err
	}
	if opts.IncludeVolumes {
		if err := session.DeleteSnapshots(ctx, opts.Logger, opts.ClusterName); err != nil {
			return err
		}
		if err := session.DeleteVolumes(ctx, opts.Logger, opts.ClusterName); err != nil {
			return err
		}
	}
	if opts.IncludeAppcred {
		if err := session.DeleteAppCredential(ctx, opts.Logger, opts.CloudsYAML, opts.CloudName); err != nil {
			return err
		}
	}
	return nil
}
