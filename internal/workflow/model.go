// Package workflow persists resumable, security-gated Dynamicflow operations.
// Snapshots are authoritative; the append-only event stream is diagnostic.
package workflow

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"dynamicflow/internal/sshkeys"
)

const SchemaVersion = 1

type Kind string

const (
	ControlBootstrap Kind = "control_bootstrap"
)

type Phase string

const (
	PhasePrepared           Phase = "prepared"
	PhaseAwaitingCloudVM    Phase = "awaiting_cloud_vm"
	PhaseAwaitingEndpoint   Phase = "awaiting_endpoint"
	PhaseAwaitingOOBHostKey Phase = "awaiting_oob_hostkey"
	PhaseHostKeyVerified    Phase = "hostkey_verified"
	PhaseConnectivityOK     Phase = "connectivity_verified"
	PhaseInstalling         Phase = "installing"
	PhaseAttesting          Phase = "attesting"
	PhaseReady              Phase = "ready"
	PhaseFailedSafe         Phase = "failed_safe"
	PhaseRevoked            Phase = "revoked"
)

type NextAction string

const (
	ActionCreateCloudVM   NextAction = "create_cloud_vm"
	ActionSubmitEndpoint  NextAction = "submit_endpoint"
	ActionConfirmHostKey  NextAction = "confirm_oob_hostkey"
	ActionRunConnectivity NextAction = "run_connectivity_check"
	ActionInstallControl  NextAction = "install_control"
	ActionVerifyControl   NextAction = "verify_control"
	ActionNone            NextAction = "none"
)

var (
	ErrConflict     = errors.New("workflow revision conflict")
	ErrInvalidTask  = errors.New("invalid workflow task")
	ErrInvalidPhase = errors.New("invalid workflow transition")
	ErrNotFound     = errors.New("workflow task not found")
	token           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
)

type Resource struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

// KeyReference contains public metadata only. It deliberately has no path or
// byte field capable of serializing private key material.
type KeyReference struct {
	Scope       sshkeys.Scope `json:"scope"`
	Name        string        `json:"name"`
	Generation  uint64        `json:"generation"`
	Fingerprint string        `json:"fingerprint"`
}

type Failure struct {
	Code string `json:"code"`
	Next string `json:"next"`
}

type Task struct {
	SchemaVersion int          `json:"schema_version"`
	ID            string       `json:"id"`
	SystemID      string       `json:"system_id"`
	Kind          Kind         `json:"kind"`
	Resource      Resource     `json:"resource"`
	Revision      uint64       `json:"revision"`
	Phase         Phase        `json:"phase"`
	ResumePhase   Phase        `json:"resume_phase,omitempty"`
	Attempt       uint64       `json:"attempt"`
	Key           KeyReference `json:"key"`
	RouteID       string       `json:"route_id,omitempty"`
	PlanDigest    string       `json:"plan_digest,omitempty"`
	NextAction    NextAction   `json:"next_action"`
	Failure       *Failure     `json:"failure,omitempty"`
	CreatedAt     time.Time    `json:"created_at"`
	UpdatedAt     time.Time    `json:"updated_at"`
}

type Event struct {
	SchemaVersion int       `json:"schema_version"`
	TaskID        string    `json:"task_id"`
	Revision      uint64    `json:"revision"`
	Phase         Phase     `json:"phase"`
	Status        string    `json:"status"`
	Code          string    `json:"code,omitempty"`
	Time          time.Time `json:"time"`
}

func controlTaskID(name string) string { return "control-bootstrap-" + name }

func Validate(task Task) error {
	if task.SchemaVersion != SchemaVersion || !token.MatchString(task.ID) || !token.MatchString(task.SystemID) ||
		task.Kind != ControlBootstrap || task.Resource.Type != "control" || !token.MatchString(task.Resource.Name) ||
		task.ID != controlTaskID(task.Resource.Name) || task.Revision == 0 || task.Attempt == 0 ||
		task.CreatedAt.IsZero() || task.UpdatedAt.IsZero() || task.UpdatedAt.Before(task.CreatedAt) {
		return ErrInvalidTask
	}
	if task.Key.Scope != sshkeys.Bootstrap || !token.MatchString(task.Key.Name) || task.Key.Generation == 0 ||
		!strings.HasPrefix(task.Key.Fingerprint, "SHA256:") || len(task.Key.Fingerprint) > 128 {
		return fmt.Errorf("%w: invalid public bootstrap key reference", ErrInvalidTask)
	}
	if task.RouteID != "" && !token.MatchString(task.RouteID) {
		return fmt.Errorf("%w: invalid route", ErrInvalidTask)
	}
	if task.PlanDigest != "" && (!strings.HasPrefix(task.PlanDigest, "sha256:") || len(task.PlanDigest) != 71) {
		return fmt.Errorf("%w: invalid plan digest", ErrInvalidTask)
	}
	if !validPhase(task.Phase) || !validNextAction(task.NextAction) {
		return ErrInvalidTask
	}
	if task.Phase == PhaseFailedSafe {
		if task.Failure == nil || !token.MatchString(task.Failure.Code) || task.Failure.Next == "" || len(task.Failure.Next) > 512 ||
			!validPhase(task.ResumePhase) || terminal(task.ResumePhase) {
			return fmt.Errorf("%w: invalid fail-safe state", ErrInvalidTask)
		}
	} else if task.Failure != nil || task.ResumePhase != "" {
		return fmt.Errorf("%w: failure metadata outside fail-safe state", ErrInvalidTask)
	}
	return nil
}

func validPhase(phase Phase) bool {
	switch phase {
	case PhasePrepared, PhaseAwaitingCloudVM, PhaseAwaitingEndpoint, PhaseAwaitingOOBHostKey, PhaseHostKeyVerified,
		PhaseConnectivityOK, PhaseInstalling, PhaseAttesting, PhaseReady, PhaseFailedSafe, PhaseRevoked:
		return true
	default:
		return false
	}
}

func validNextAction(action NextAction) bool {
	switch action {
	case ActionCreateCloudVM, ActionSubmitEndpoint, ActionConfirmHostKey, ActionRunConnectivity,
		ActionInstallControl, ActionVerifyControl, ActionNone:
		return true
	default:
		return false
	}
}

func terminal(phase Phase) bool { return phase == PhaseReady || phase == PhaseRevoked }

func nextAction(phase Phase) NextAction {
	switch phase {
	case PhasePrepared, PhaseAwaitingCloudVM:
		return ActionCreateCloudVM
	case PhaseAwaitingEndpoint:
		return ActionSubmitEndpoint
	case PhaseAwaitingOOBHostKey:
		return ActionConfirmHostKey
	case PhaseHostKeyVerified:
		return ActionRunConnectivity
	case PhaseConnectivityOK:
		return ActionInstallControl
	case PhaseInstalling, PhaseAttesting:
		return ActionVerifyControl
	default:
		return ActionNone
	}
}

func allowedTransition(from, to Phase, resume Phase) bool {
	if to == PhaseRevoked && from != PhaseRevoked {
		return true
	}
	if to == PhaseFailedSafe {
		return !terminal(from) && from != PhaseFailedSafe
	}
	if from == PhaseFailedSafe {
		return to == resume
	}
	allowed := map[Phase]Phase{
		PhasePrepared:           PhaseAwaitingCloudVM,
		PhaseAwaitingCloudVM:    PhaseAwaitingEndpoint,
		PhaseAwaitingEndpoint:   PhaseAwaitingOOBHostKey,
		PhaseAwaitingOOBHostKey: PhaseHostKeyVerified,
		PhaseHostKeyVerified:    PhaseConnectivityOK,
		PhaseConnectivityOK:     PhaseInstalling,
		PhaseInstalling:         PhaseAttesting,
		PhaseAttesting:          PhaseReady,
	}
	return allowed[from] == to
}
