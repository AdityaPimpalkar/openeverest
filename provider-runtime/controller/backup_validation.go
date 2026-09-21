// Copyright (C) 2026 The OpenEverest Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"errors"
	"fmt"
	"regexp"

	backupv1alpha1 "github.com/openeverest/openeverest/v2/api/backup/v1alpha1"
	apicommon "github.com/openeverest/openeverest/v2/api/common/v1alpha1"
	corev1alpha1 "github.com/openeverest/openeverest/v2/api/core/v1alpha1"
)

// LimitsExceededReason is the reason string used on BackupConfigError and
// the BackupConfigured condition when an Instance violates the limits
// declared by its BackupClass.
const LimitsExceededReason = "LimitsExceeded"

// PITRConfigInvalidReason is the reason string used on BackupConfigError and
// the BackupConfigured condition when a per-storage PITR config on an
// Instance does not conform to the schema declared by its BackupClass.
const PITRConfigInvalidReason = "PITRConfigInvalid"

// RetentionInvalidReason is the reason string used on BackupConfigError and
// the BackupConfigured condition when a schedule's retention is missing or
// malformed.
const RetentionInvalidReason = "RetentionInvalid"

// RetentionUnsupportedReason is the reason string used on BackupConfigError and
// the BackupConfigured condition when a schedule's retention type is not in
// the BackupClass's supportedRetentionTypes.
const RetentionUnsupportedReason = "RetentionUnsupported"

// ErrBackupClassLimitsExceeded is the sentinel returned by
// ValidateInstanceBackupAgainstClass when an Instance violates the limits
// declared by its BackupClass.
var ErrBackupClassLimitsExceeded = errors.New("backup class limits exceeded")

// ErrPITRConfigInvalid is the sentinel returned by
// ValidateInstanceBackupPITRParameters when per-storage PITR parameters do not
// conform to the BackupClass's providerManaged.pitrParametersSchema.
var ErrPITRConfigInvalid = errors.New("PITR config invalid")

// ErrRetentionInvalid is the sentinel returned by
// ValidateInstanceBackupRetention when a schedule is missing retention or the
// retention payload is malformed (defense in depth for CRD CEL).
var ErrRetentionInvalid = errors.New("retention invalid")

// ErrRetentionUnsupported is the sentinel returned by
// ValidateInstanceBackupRetention when a schedule uses a retention type the
// BackupClass does not advertise in supportedRetentionTypes.
var ErrRetentionUnsupported = errors.New("retention unsupported")

// ErrInvalidReference is the umbrella sentinel every reference-validation
// error below satisfies via errors.Is. Callers (e.g. the API server's
// CreateBackup/CreateRestore validation handlers) check errors.Is(err,
// ErrInvalidReference) once to classify a failure as a client-facing
// validation error, instead of enumerating every individual sentinel — so
// any reference-validation error added in the future is automatically
// classified correctly without touching that call site.
var ErrInvalidReference = errors.New("invalid reference")

// referenceError is a reference-validation sentinel. It implements Is so
// that every referenceError value satisfies errors.Is(err, ErrInvalidReference),
// in addition to satisfying errors.Is against itself.
type referenceError string

// Error implements the error interface.
func (e referenceError) Error() string {
	return string(e)
}

// Is reports whether target is ErrInvalidReference, making every
// referenceError a member of that umbrella sentinel.
func (e referenceError) Is(target error) bool {
	return target == ErrInvalidReference
}

const (
	// ErrBackupNotFound is a sentinel callers may wrap when their own lookup for
	// a referenced Backup returns not-found, so the failure can be classified
	// via errors.Is without duplicating the message across call sites. This
	// package performs no lookups itself; callers own fetching and NotFound
	// classification.
	ErrBackupNotFound referenceError = "backup not found"

	// ErrBackupClassNotFound is a sentinel callers may wrap when their own
	// lookup for a referenced BackupClass returns not-found.
	ErrBackupClassNotFound referenceError = "backup class not found"

	// ErrInstanceNotFound is a sentinel callers may wrap when their own lookup
	// for a referenced Instance returns not-found.
	ErrInstanceNotFound referenceError = "instance not found"

	// ErrBackupStorageNotFound is a sentinel callers may wrap when their own
	// lookup for a referenced BackupStorage returns not-found.
	ErrBackupStorageNotFound referenceError = "backup storage not found"

	// ErrBackupNotSucceeded is the sentinel returned by ValidateBackupSucceeded
	// when a Backup exists but has not reached the Succeeded state.
	ErrBackupNotSucceeded referenceError = "backup not succeeded"

	// ErrProviderUnsupported is the sentinel returned by
	// ValidateClassSupportsProvider when a BackupClass does not list a provider
	// in its SupportedProviders.
	ErrProviderUnsupported referenceError = "provider not supported by backup class"

	// ErrRestorePITRUnsupported is the sentinel returned by ValidateRestorePITR
	// when a Restore requests point-in-time recovery but the resolved
	// ProviderManaged BackupClass does not advertise supportsPITR.
	ErrRestorePITRUnsupported referenceError = "point-in-time recovery is not supported"

	// ErrRestorePITRDateRequired is the sentinel returned by ValidateRestorePITR
	// when a Restore requests date-based point-in-time recovery without
	// specifying spec.dataSource.backup.pitr.date.
	ErrRestorePITRDateRequired referenceError = "point-in-time recovery date is required"
)

// ValidateInstanceBackupAgainstClass enforces the generic limits declared on
// a ProviderManaged BackupClass against an Instance's backup configuration.
// It is safe to call with any combination of nil inputs:
//   - If the Instance has no backup config, no class is selected, or the
//     class is not ProviderManaged, the function is a no-op and returns nil.
//   - If the class has no limits set, the function is a no-op and returns nil.
//
// Engine-specific constraints (e.g. PSMDB's single PITR stream) are NOT
// enforced here; providers add those checks in their own Validate() and
// ConfigureBackup() implementations, typically by calling
// Context.BackupClassLimits() and adding extra rules on top.
func ValidateInstanceBackupAgainstClass(in *corev1alpha1.Instance, bc *backupv1alpha1.BackupClass) error {
	if in == nil || in.Spec.Backup == nil || !in.Spec.Backup.Enabled {
		return nil
	}
	if bc == nil || bc.Spec.ExecutionMode != backupv1alpha1.BackupExecutionModeProviderManaged {
		return nil
	}
	if bc.Spec.ProviderManaged == nil || bc.Spec.ProviderManaged.Limits == nil {
		return nil
	}
	limits := bc.Spec.ProviderManaged.Limits
	storages := in.Spec.Backup.Storages

	if limits.MaxStorages != nil && int32(len(storages)) > *limits.MaxStorages {
		return fmt.Errorf("%w: spec.backup.storages has %d entries, BackupClass %q allows at most %d",
			ErrBackupClassLimitsExceeded, len(storages), bc.Name, *limits.MaxStorages)
	}

	if limits.MaxPITREnabledStorages != nil {
		var pitrCount int32
		for _, s := range storages {
			if s.PITR != nil && s.PITR.Enabled {
				pitrCount++
			}
		}
		if pitrCount > *limits.MaxPITREnabledStorages {
			return fmt.Errorf("%w: %d storages have PITR enabled, BackupClass %q allows at most %d",
				ErrBackupClassLimitsExceeded, pitrCount, bc.Name, *limits.MaxPITREnabledStorages)
		}
	}

	if limits.MaxSchedulesPerStorage != nil {
		for _, s := range storages {
			if int32(len(s.Schedules)) > *limits.MaxSchedulesPerStorage {
				return fmt.Errorf("%w: storage %q has %d schedules, BackupClass %q allows at most %d per storage",
					ErrBackupClassLimitsExceeded, s.StorageRef.Name, len(s.Schedules), bc.Name, *limits.MaxSchedulesPerStorage)
			}
		}
	}

	return nil
}

// ValidateInstanceBackupRetention checks each schedule's retention on the
// Instance:
//   - retention is required
//   - type/count/duration shape matches the CRD rules (defense in depth)
//   - when the BackupClass declares supportedRetentionTypes, the schedule's
//     retention.type must appear in that list
//
// Empty supportedRetentionTypes means both count and time are allowed. A nil
// or Job-mode BackupClass skips the capability check but still validates
// shape. Safe to call with nil inputs.
func ValidateInstanceBackupRetention(in *corev1alpha1.Instance, bc *backupv1alpha1.BackupClass) error {
	if in == nil || in.Spec.Backup == nil || !in.Spec.Backup.Enabled {
		return nil
	}

	var allowed map[backupv1alpha1.ScheduleRetentionType]struct{}
	if bc != nil &&
		bc.Spec.ExecutionMode == backupv1alpha1.BackupExecutionModeProviderManaged &&
		bc.Spec.ProviderManaged != nil &&
		len(bc.Spec.ProviderManaged.SupportedRetentionTypes) > 0 {
		allowed = make(map[backupv1alpha1.ScheduleRetentionType]struct{}, len(bc.Spec.ProviderManaged.SupportedRetentionTypes))
		for _, t := range bc.Spec.ProviderManaged.SupportedRetentionTypes {
			allowed[t] = struct{}{}
		}
	}

	for _, st := range in.Spec.Backup.Storages {
		for _, sch := range st.Schedules {
			if sch.Retention == nil {
				return fmt.Errorf(
					"%w: storage %q schedule %q: retention is required",
					ErrRetentionInvalid, st.StorageRef.Name, sch.Name,
				)
			}
			if err := validateBackupScheduleRetention(sch.Retention); err != nil {
				return fmt.Errorf(
					"%w: storage %q schedule %q: %s",
					ErrRetentionInvalid, st.StorageRef.Name, sch.Name, err.Error(),
				)
			}
			if allowed == nil {
				continue
			}
			typ := sch.Retention.Type
			if typ == "" {
				typ = corev1alpha1.BackupScheduleRetentionTypeCount
			}
			if _, ok := allowed[backupv1alpha1.ScheduleRetentionType(typ)]; !ok {
				return fmt.Errorf(
					"%w: storage %q schedule %q uses retention type %q, BackupClass %q allows %v",
					ErrRetentionUnsupported, st.StorageRef.Name, sch.Name, typ, bc.Name,
					bc.Spec.ProviderManaged.SupportedRetentionTypes,
				)
			}
		}
	}
	return nil
}

var retentionDurationPattern = regexp.MustCompile(`^[1-9][0-9]*[dwm]$`)

func validateBackupScheduleRetention(r *corev1alpha1.BackupScheduleRetention) error {
	typ := r.Type
	if typ == "" {
		typ = corev1alpha1.BackupScheduleRetentionTypeCount
	}
	switch typ {
	case corev1alpha1.BackupScheduleRetentionTypeCount:
		if r.Duration != "" {
			return fmt.Errorf("duration is only allowed when retention type is time")
		}
	case corev1alpha1.BackupScheduleRetentionTypeTime:
		if r.Count != nil {
			return fmt.Errorf("count is only allowed when retention type is count")
		}
		if r.Duration == "" {
			return fmt.Errorf("duration is required when retention type is time")
		}
		if !retentionDurationPattern.MatchString(r.Duration) {
			return fmt.Errorf("duration %q must match Nd/Nw/Nm (e.g. 30d, 4w, 2m)", r.Duration)
		}
	default:
		return fmt.Errorf("unknown retention type %q", r.Type)
	}
	return nil
}

// ValidateInstanceBackupPITRParameters validates each per-storage PITR
// parameters payload on the Instance (.spec.backup.storages[].pitr.parameters)
// against the OpenAPI v3 schema declared by the BackupClass under
// .spec.providerManaged.pitrParametersSchema.
//
// It is safe to call with any combination of nil inputs:
//   - If the Instance has no backup config, no class is selected, or the
//     class is not ProviderManaged, the function is a no-op and returns nil.
//   - Storages without PITR parameters are skipped.
//
// PITR parameters on a class that declares no pitrParametersSchema are
// rejected, mirroring ParametersSchema.Validate's behavior for backup and
// restore parameters.
func ValidateInstanceBackupPITRParameters(in *corev1alpha1.Instance, bc *backupv1alpha1.BackupClass) error {
	if in == nil || in.Spec.Backup == nil || !in.Spec.Backup.Enabled {
		return nil
	}
	if bc == nil || bc.Spec.ExecutionMode != backupv1alpha1.BackupExecutionModeProviderManaged {
		return nil
	}

	var schema *apicommon.ParametersSchema
	if bc.Spec.ProviderManaged != nil {
		schema = bc.Spec.ProviderManaged.PITRParametersSchema
	}

	for _, s := range in.Spec.Backup.Storages {
		if s.PITR == nil || s.PITR.Parameters == nil || len(s.PITR.Parameters.Raw) == 0 {
			continue
		}
		if err := schema.Validate(s.PITR.Parameters); err != nil {
			return fmt.Errorf("%w: storage %q: %s", ErrPITRConfigInvalid, s.StorageRef.Name, err.Error())
		}
	}
	return nil
}

// RestoreStreamInstanceName returns the name of the Instance that owns the
// backup stream a point-in-time Restore reads from: the Instance named by
// .source.instanceRef, or the Restore's target Instance when none is named.
//
// A stream has no Backup CR of its own, so this Instance is also where its
// *read* class comes from -- the class describing how the data was written and
// therefore how it must be read, which may differ from the target Instance's
// own backup class.
//
// The defaulting is shared because every path that handles a Restore needs it
// and it is easy to get subtly wrong; the surrounding dispatch on
// .spec.dataSource.type stays at each call site, where the error handling and
// the object type to fetch differ.
func RestoreStreamInstanceName(restore *backupv1alpha1.Restore) string {
	if pitr := restore.Spec.DataSource.PointInTime; pitr != nil && pitr.Source.InstanceRef != nil {
		return pitr.Source.InstanceRef.Name
	}
	return restore.Spec.InstanceRef.Name
}

// ValidateBackupSucceeded returns ErrBackupNotSucceeded unless the Backup has
// reached the Succeeded state. Callers are responsible for fetching the
// Backup themselves and handling a not-found lookup error with their own
// context before calling this.
func ValidateBackupSucceeded(backup *backupv1alpha1.Backup) error {
	if backup.Status.State != backupv1alpha1.BackupStateSucceeded {
		state := backup.Status.State
		if state == "" {
			// The controller has not reconciled the Backup yet; report the
			// state a user would recognize instead of an empty string.
			state = backupv1alpha1.BackupStatePending
		}
		return fmt.Errorf("%w: '%s' is in state '%s'", ErrBackupNotSucceeded, backup.GetName(), state)
	}
	return nil
}

// ValidateClassSupportsProvider returns ErrProviderUnsupported unless bc
// lists provider in its SupportedProviders. Callers are responsible for
// fetching the BackupClass themselves.
func ValidateClassSupportsProvider(bc *backupv1alpha1.BackupClass, provider string) error {
	if !bc.Spec.SupportedProviders.Has(provider) {
		return fmt.Errorf("%w: class '%s', provider '%s'", ErrProviderUnsupported, bc.GetName(), provider)
	}
	return nil
}

// ValidateRestorePITR checks whether the point-in-time recovery options on a
// Restore are acceptable for the given BackupClass:
//   - When the resolved class is ProviderManaged, PITR may only be requested
//     if the class advertises .spec.providerManaged.supportsPITR.
//   - Job-mode classes have no PITR capability declaration; they are not
//     gated here.
//
// A nil class or a Restore that is not requesting point-in-time recovery
// passes. The CRD's CEL rule already requires date when recoveryTarget is
// "date"; the check is repeated here for defense in depth on paths that bypass
// admission.
func ValidateRestorePITR(restore *backupv1alpha1.Restore, bc *backupv1alpha1.BackupClass) error {
	if restore == nil || restore.Spec.DataSource.PointInTime == nil {
		return nil
	}
	pitr := restore.Spec.DataSource.PointInTime
	if pitr.RecoveryTarget == backupv1alpha1.RecoveryTargetDate && pitr.Date == nil {
		return fmt.Errorf(
			"%w: spec.dataSource.pointInTime.date must be set when recoveryTarget is %q",
			ErrRestorePITRDateRequired, backupv1alpha1.RecoveryTargetDate,
		)
	}
	if bc == nil || bc.Spec.ExecutionMode != backupv1alpha1.BackupExecutionModeProviderManaged {
		return nil
	}
	if bc.Spec.ProviderManaged == nil || !bc.Spec.ProviderManaged.SupportsPITR {
		return fmt.Errorf("%w: BackupClass %q", ErrRestorePITRUnsupported, bc.Name)
	}
	return nil
}

// ValidatePITRStorage checks that the storage a point-in-time Restore names is
// actually carrying a stream on the Instance that owns it.
//
// The schema already guarantees pointInTime.source.storageRef is set, so there
// is nothing to infer here -- deliberately. Inferring a storage when an
// Instance has only one would make the field conditionally required, and a
// manifest's validity would then depend on an object it does not name. What
// remains is the cross-object check CEL cannot express: the named storage must
// exist on the Instance and have PITR enabled.
//
// The supplied Instance is the one that *owns the stream*, which for a Restore
// without an explicit source.instanceRef is the restore target.
func ValidatePITRStorage(
	pitr *backupv1alpha1.DataSourcePointInTime,
	instance *corev1alpha1.Instance,
) error {
	if pitr == nil {
		return nil
	}
	if instance == nil || instance.Spec.Backup == nil {
		return fmt.Errorf("%w: instance has no backup configuration", ErrRestorePITRUnsupported)
	}

	want := pitr.Source.StorageRef.Name
	enabled := make([]string, 0, len(instance.Spec.Backup.Storages))
	for _, s := range instance.Spec.Backup.Storages {
		if s.PITR != nil && s.PITR.Enabled {
			enabled = append(enabled, s.StorageRef.Name)
			if s.StorageRef.Name == want {
				return nil
			}
		}
	}

	if len(enabled) == 0 {
		return fmt.Errorf(
			"%w: instance %q has no storage with backup.storages[].pitr.enabled=true",
			ErrRestorePITRUnsupported, instance.Name,
		)
	}
	return fmt.Errorf(
		"%w: storage %q is not a PITR-enabled storage of instance %q (PITR-enabled: %v)",
		ErrRestorePITRUnsupported, want, instance.Name, enabled,
	)
}
