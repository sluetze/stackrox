package extensions

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	"github.com/operator-framework/helm-operator-plugins/pkg/extensions"
	"github.com/pkg/errors"
	platform "github.com/stackrox/rox/operator/apis/platform/v1alpha1"
	commonExtensions "github.com/stackrox/rox/operator/pkg/common/extensions"
	"github.com/stackrox/rox/operator/pkg/types"
	"github.com/stackrox/rox/pkg/auth/htpasswd"
	"github.com/stackrox/rox/pkg/grpc/client/authn/basic"
	"github.com/stackrox/rox/pkg/renderer"
	coreV1 "k8s.io/api/core/v1"
	ctrlClient "sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	adminPasswordKey = `password`

	htpasswdKey = `htpasswd`

	defaultPasswordSecretName = `central-htpasswd`
)

// ReconcileAdminPasswordExtension returns an extension that takes care of reconciling the central-htpasswd secret.
func ReconcileAdminPasswordExtension(client ctrlClient.Client) extensions.ReconcileExtension {
	return wrapExtension(reconcileAdminPassword, client)
}

func reconcileAdminPassword(ctx context.Context, c *platform.Central, client ctrlClient.Client, statusUpdater func(updateStatusFunc), _ logr.Logger) error {
	run := &reconcileAdminPasswordExtensionRun{
		SecretReconciliator: commonExtensions.NewSecretReconciliator(client, c),
		statusUpdater:       statusUpdater,
		centralObj:          c,
	}
	return run.Execute(ctx)
}

type reconcileAdminPasswordExtensionRun struct {
	*commonExtensions.SecretReconciliator
	statusUpdater func(updateStatusFunc)

	centralObj         *platform.Central
	password           string
	passwordSecretName string
	autoGenerated      bool

	infoUpdate string
}

func (r *reconcileAdminPasswordExtensionRun) readPasswordFromReferencedSecret(ctx context.Context) error {
	if r.centralObj.Spec.Central.GetAdminPasswordSecret() == nil {
		return nil
	}

	r.passwordSecretName = r.centralObj.Spec.Central.AdminPasswordSecret.Name

	passwordSecret := &coreV1.Secret{}
	key := ctrlClient.ObjectKey{Namespace: r.centralObj.GetNamespace(), Name: r.passwordSecretName}
	if err := r.Client().Get(ctx, key, passwordSecret); err != nil {
		return errors.Wrapf(err, "failed to retrieve admin password secret %q", r.passwordSecretName)
	}

	password := strings.TrimSpace(string(passwordSecret.Data[adminPasswordKey]))
	if password == "" || strings.ContainsAny(password, "\r\n") {
		return errors.Errorf("admin password secret %s must contain a non-empty, single-line %q entry", r.passwordSecretName, adminPasswordKey)
	}

	r.password = password
	return nil
}

func (r *reconcileAdminPasswordExtensionRun) Execute(ctx context.Context) error {
	if r.centralObj.DeletionTimestamp != nil {
		return r.DeleteSecret(ctx, defaultPasswordSecretName)
	}

	if r.centralObj.Spec.Central.GetAdminPasswordGenerationDisabled() && r.centralObj.Spec.Central.GetAdminPasswordSecret() == nil {
		err := r.DeleteSecret(ctx, defaultPasswordSecretName)
		if err != nil {
			return err
		}
		r.infoUpdate = "Password generation has been disabled, if you want to enable it set spec.central.adminPasswordGenerationDisabled to false."
		r.statusUpdater(r.updateStatus)

		return nil
	}

	if err := r.readPasswordFromReferencedSecret(ctx); err != nil {
		return err
	}

	if err := r.ReconcileSecret(ctx, defaultPasswordSecretName, r.validateHtpasswdSecretData, r.generateHtpasswdSecretData, true); err != nil {
		return errors.Wrap(err, "reconciling central-htpasswd secret")
	}

	if r.infoUpdate != "" {
		r.statusUpdater(r.updateStatus)
	}

	return nil
}

func (r *reconcileAdminPasswordExtensionRun) updateStatus(status *platform.CentralStatus) bool {
	if status.Central == nil {
		status.Central = &platform.CentralComponentStatus{}
	}
	if status.Central.AdminPassword == nil {
		status.Central.AdminPassword = &platform.AdminPasswordStatus{}
	}

	secretReference := ""
	if status.Central.AdminPassword.SecretReference != nil {
		secretReference = *status.Central.AdminPassword.SecretReference
	}
	if r.infoUpdate == status.Central.AdminPassword.Info && r.passwordSecretName == secretReference {
		return false
	}

	secretNameCopy := r.passwordSecretName
	status.Central.AdminPassword.SecretReference = &secretNameCopy
	status.Central.AdminPassword.Info = r.infoUpdate
	return true
}

func (r *reconcileAdminPasswordExtensionRun) validateHtpasswdSecretData(data types.SecretDataMap, controllerOwned bool) error {
	htpasswdBytes := data[htpasswdKey]
	if len(htpasswdBytes) == 0 && !controllerOwned {
		if r.password != "" {
			return errors.New("The central-htpasswd secret has been created by the user and cannot be modified. Either remove the spec.central.adminPasswordSecret entry, or delete the existing central-htpasswd secret to allow setting the desired admin password.")
		}
		// If the secret isn't created by the operator, we allow clearing the `htpasswd` entry (we will still error on malformed
		// or mismatching entries).
		r.infoUpdate = fmt.Sprintf(
			"Login with username/password has been disabled by removing the %q entry from the central-htpasswd secret.\n"+
				"To re-enable, either remove the central-htpasswd secret, or populate the %q entry with the contents of a htpasswd file (bcrypt only).",
			htpasswdKey, htpasswdKey)
		return nil
	}

	hf, err := htpasswd.ReadHashFile(bytes.NewReader(htpasswdBytes))
	if err != nil {
		return errors.Wrap(err, "failed to read existing htpasswd data from secret")
	}
	if r.password != "" {
		if !hf.Check(basic.DefaultUsername, r.password) {
			return errors.New("Password in existing central-htpasswd secret does not match specified admin password secret. If you want to use your own central-htpasswd secret, please remove the spec.central.adminPasswordSecret entry.")
		}
		r.infoUpdate = fmt.Sprintf("The admin password is configured to match the %q entry in the %s secret.", adminPasswordKey, r.passwordSecretName)
	} else if !controllerOwned {
		r.passwordSecretName = defaultPasswordSecretName
		r.infoUpdate = "A user-defined central-htpasswd secret was found, containing htpasswd-encoded credentials."
	} else if len(data[adminPasswordKey]) != 0 {
		r.passwordSecretName = defaultPasswordSecretName
		r.infoUpdate = r.viewPasswordInstructionsMessage()
	} else {
		r.infoUpdate = "A password for the 'admin' user was automatically generated, but only the htpasswd-encoded form has been retained.\n" +
			"To re-generate a new password, delete the central-htpasswd secret."
	}

	return nil
}

func (r *reconcileAdminPasswordExtensionRun) generateHtpasswdSecretData() (types.SecretDataMap, error) {
	if r.password == "" {
		r.password = renderer.CreatePassword()
		r.autoGenerated = true
	}

	htpasswdBytes, err := renderer.CreateHtpasswd(r.password)
	if err != nil {
		return nil, errors.Wrap(err, "generating htpasswd data")
	}

	data := types.SecretDataMap{
		htpasswdKey: htpasswdBytes,
	}
	if r.autoGenerated {
		data[adminPasswordKey] = []byte(r.password)

		r.passwordSecretName = defaultPasswordSecretName
		r.infoUpdate = r.viewPasswordInstructionsMessage()
	} else {
		r.infoUpdate = fmt.Sprintf("The admin password is configured to match the %q entry in the %s secret.", adminPasswordKey, r.passwordSecretName)
	}

	return data, nil
}

func (r *reconcileAdminPasswordExtensionRun) viewPasswordInstructionsMessage() string {
	return fmt.Sprintf(
		"A password for the 'admin' user has been automatically generated and stored in the %q entry of the central-htpasswd secret.\n"+
			"To view the password see the secret reference field or run\n"+
			`  oc -n %s get secret central-htpasswd -o go-template='{{index .data "password" | base64decode}}'`,
		adminPasswordKey, r.centralObj.GetNamespace())
}
