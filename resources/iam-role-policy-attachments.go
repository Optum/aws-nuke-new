package resources

import (
	"context"
	"regexp"

	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"

	"github.com/ekristen/libnuke/pkg/registry"
	"github.com/ekristen/libnuke/pkg/resource"
	libsettings "github.com/ekristen/libnuke/pkg/settings"
	"github.com/ekristen/libnuke/pkg/types"

	"github.com/ekristen/aws-nuke/v3/pkg/nuke"
)

const IAMRolePolicyAttachmentResource = "IAMRolePolicyAttachment"

func init() {
	registry.Register(&registry.Registration{
		Name:     IAMRolePolicyAttachmentResource,
		Scope:    nuke.Account,
		Resource: &IAMRolePolicyAttachment{},
		Lister:   &IAMRolePolicyAttachmentLister{},
		DeprecatedAliases: []string{
			"IamRolePolicyAttachement",
		},
		Settings: []string{
			"CustomFilters",
		},
	})
}

type IAMRolePolicyAttachment struct {
	svc           iamiface.IAMAPI
	settings      *libsettings.Setting
	CustomFilters []CustomFilters
	policyArn     string
	policyName    string
	role          *iam.Role
}

func (r *IAMRolePolicyAttachment) Settings(settings *libsettings.Setting) {
	r.settings = settings
	r.CustomFilters = NewCustomFilters(settings.Get("CustomFilters"))
}

func (r *IAMRolePolicyAttachment) FilterbyCustomFilters() error {
	for i := range r.CustomFilters {
		if r.CustomFilters[i].Type == IAMPathName {
			matched, _ := regexp.MatchString(r.CustomFilters[i].Value, *r.role.Path) // Don't check error as we only return err on successful filter
			if matched {
				return fmt.Errorf("filtered by path custom filter")
			}
		} else if r.CustomFilters[i].Type == IAMTagName {
			for _, tag := range r.role.Tags {
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
	return r.FilterbyCustomFilters()
}

func (r *IAMRolePolicyAttachment) Filter() error {
	if strings.Contains(r.policyArn, ":iam::aws:policy/aws-service-role/") {
		return fmt.Errorf("cannot detach from service roles")
	}
	if strings.HasPrefix(*r.role.Path, "/aws-reserved/sso.amazonaws.com/") {
		return fmt.Errorf("cannot detach from SSO roles")
	}
	return nil
}

func (r *IAMRolePolicyAttachment) Remove(_ context.Context) error {
	_, err := r.svc.DetachRolePolicy(
		&iam.DetachRolePolicyInput{
			PolicyArn: &r.policyArn,
			RoleName:  r.role.RoleName,
		})
	if err != nil {
		return err
	}

	return nil
}

func (r *IAMRolePolicyAttachment) Properties() types.Properties {
	properties := types.NewProperties().
		Set("RoleName", r.role.RoleName).
		Set("RolePath", r.role.Path).
		Set("RoleLastUsed", getLastUsedDate(r.role)).
		Set("RoleCreateDate", r.role.CreateDate.Format(time.RFC3339)).
		Set("PolicyName", r.policyName).
		Set("PolicyArn", r.policyArn)

	for _, tag := range r.role.Tags {
		properties.SetTagWithPrefix("role", tag.Key, tag.Value)
	}
	return properties
}

func (r *IAMRolePolicyAttachment) String() string {
	return fmt.Sprintf("%s -> %s", *r.role.RoleName, r.policyName)
}

// -----------------------

type IAMRolePolicyAttachmentLister struct{}

func (l *IAMRolePolicyAttachmentLister) List(_ context.Context, o interface{}) ([]resource.Resource, error) {
	opts := o.(*nuke.ListerOpts)

	svc := iam.New(opts.Session)
	roleParams := &iam.ListRolesInput{}
	resources := make([]resource.Resource, 0)

	for {
		roleResp, err := svc.ListRoles(roleParams)
		if err != nil {
			return nil, err
		}

		for _, listedRole := range roleResp.Roles {
			role, err := GetIAMRole(svc, listedRole.RoleName)
			if err != nil {
				logrus.Errorf("Failed to get listed role %s: %v", *listedRole.RoleName, err)
				continue
			}

			polParams := &iam.ListAttachedRolePoliciesInput{
				RoleName: role.RoleName,
			}

			for {
				polResp, err := svc.ListAttachedRolePolicies(polParams)
				if err != nil {
					logrus.Errorf("failed to list attached policies for role %s: %v",
						*role.RoleName, err)
					break
				}
				for _, pol := range polResp.AttachedPolicies {
					resources = append(resources, &IAMRolePolicyAttachment{
						svc:        svc,
						policyArn:  *pol.PolicyArn,
						policyName: *pol.PolicyName,
						role:       role,
					})
				}

				if !*polResp.IsTruncated {
					break
				}

				polParams.Marker = polResp.Marker
			}
		}

		if !*roleResp.IsTruncated {
			break
		}

		roleParams.Marker = roleResp.Marker
	}

	return resources, nil
}
