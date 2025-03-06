package resources

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"

	"github.com/ekristen/libnuke/pkg/registry"
	"github.com/ekristen/libnuke/pkg/resource"
	libsettings "github.com/ekristen/libnuke/pkg/settings"
	"github.com/ekristen/libnuke/pkg/types"

	"github.com/ekristen/aws-nuke/v3/pkg/nuke"
)

const IAMRolePolicyResource = "IAMRolePolicy"

func init() {
	registry.Register(&registry.Registration{
		Name:     IAMRolePolicyResource,
		Scope:    nuke.Account,
		Resource: &IAMRolePolicy{},
		Lister:   &IAMRolePolicyLister{},
		Settings: []string{
			"CustomFilters",
		},
	})
}

type IAMRolePolicy struct {
	svc           iamiface.IAMAPI
	settings      *libsettings.Setting
	CustomFilters []CustomFilters
	roleID        string
	rolePath      string
	roleName      string
	policyName    string
	roleTags      []*iam.Tag
}

func (r *IAMRolePolicy) Settings(settings *libsettings.Setting) {
	r.settings = settings
	r.CustomFilters = NewCustomFilters(settings.Get("CustomFilters"))
}

func (r *IAMRolePolicy) FilterbyCustomFilters() error {
	for i := range r.CustomFilters {
		if r.CustomFilters[i].Type == IAMPathName {
			matched, _ := regexp.MatchString(r.CustomFilters[i].Value, r.rolePath) // Don't check error as we only return err on successful filter
			if matched {
				return fmt.Errorf("filtered by path custom filter")
			}
		} else if r.CustomFilters[i].Type == IAMTagName {
			for _, tag := range r.roleTags {
				matchedKey, _ := regexp.MatchString(r.CustomFilters[i].Value, *tag.Key)
				matchedValue, _ := regexp.MatchString(r.CustomFilters[i].Value, *tag.Value)
				if matchedKey {
					return fmt.Errorf("filtered by tag key custom filter")
				} else if matchedValue {
					return fmt.Errorf("filtered by tag value custom filter")
				}
			}
		}
	}
	return nil
}

func (r *IAMRolePolicy) Filter() error {
	if strings.HasPrefix(r.rolePath, "/aws-service-role/") {
		return fmt.Errorf("cannot alter service roles")
	}
	if strings.HasPrefix(r.rolePath, "/aws-reserved/sso.amazonaws.com/") {
		return fmt.Errorf("cannot alter sso roles")
	}
	return r.FilterbyCustomFilters()
}

func (r *IAMRolePolicy) Remove(_ context.Context) error {
	_, err := r.svc.DeleteRolePolicy(
		&iam.DeleteRolePolicyInput{
			RoleName:   &r.roleName,
			PolicyName: &r.policyName,
		})
	if err != nil {
		return err
	}

	return nil
}

func (r *IAMRolePolicy) Properties() types.Properties {
	properties := types.NewProperties()
	properties.Set("PolicyName", r.policyName)
	properties.Set("role:RoleName", r.roleName)
	properties.Set("role:RoleID", r.roleID)
	properties.Set("role:Path", r.rolePath)

	for _, tagValue := range r.roleTags {
		properties.SetTagWithPrefix("role", tagValue.Key, tagValue.Value)
	}
	return properties
}

func (r *IAMRolePolicy) String() string {
	return fmt.Sprintf("%s -> %s", r.roleName, r.policyName)
}

// ----------------------

type IAMRolePolicyLister struct{}

func (l *IAMRolePolicyLister) List(_ context.Context, o interface{}) ([]resource.Resource, error) {
	opts := o.(*nuke.ListerOpts)

	svc := iam.New(opts.Session)
	roleParams := &iam.ListRolesInput{}
	resources := make([]resource.Resource, 0)

	for {
		roles, err := svc.ListRoles(roleParams)
		if err != nil {
			return nil, err
		}

		for _, listedRole := range roles.Roles {
			role, err := GetIAMRole(svc, listedRole.RoleName)
			if err != nil {
				logrus.Errorf("Failed to get listed role %s: %v", *listedRole.RoleName, err)
				continue
			}

			polParams := &iam.ListRolePoliciesInput{
				RoleName: role.RoleName,
			}

			for {
				policies, err := svc.ListRolePolicies(polParams)
				if err != nil {
					logrus.
						WithError(err).
						WithField("roleName", *role.RoleName).
						Error("Failed to list policies")
					break
				}

				for _, policyName := range policies.PolicyNames {
					resources = append(resources, &IAMRolePolicy{
						svc:        svc,
						roleID:     *role.RoleId,
						roleName:   *role.RoleName,
						rolePath:   *role.Path,
						policyName: *policyName,
						roleTags:   role.Tags,
					})
				}

				if !*policies.IsTruncated {
					break
				}

				polParams.Marker = policies.Marker
			}
		}

		if !*roles.IsTruncated {
			break
		}

		roleParams.Marker = roles.Marker
	}

	return resources, nil
}
