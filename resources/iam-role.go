package resources

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/gotidy/ptr"
	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"

	"github.com/ekristen/libnuke/pkg/registry"
	"github.com/ekristen/libnuke/pkg/resource"
	libsettings "github.com/ekristen/libnuke/pkg/settings"
	"github.com/ekristen/libnuke/pkg/types"

	"github.com/ekristen/aws-nuke/v3/pkg/nuke"
)

const IAMRoleResource = "IAMRole"

func init() {
	registry.Register(&registry.Registration{
		Name:     IAMRoleResource,
		Scope:    nuke.Account,
		Resource: &IAMRole{},
		Lister:   &IAMRoleLister{},
		DependsOn: []string{
			IAMRolePolicyAttachmentResource,
			CloudFormationStackResource, // IAM roles can be used in deletion of CloudFormation stacks
		},
		DeprecatedAliases: []string{
			"IamRole",
		},
		Settings: []string{
			"IncludeServiceLinkedRoles",
			"CustomFilters",
		},
	})
}

type IAMRole struct {
	svc           iamiface.IAMAPI
	settings      *libsettings.Setting
	CustomFilters []CustomFilters
	Name          *string
	Path          *string
	CreateDate    *time.Time
	LastUsedDate  *time.Time
	Tags          []*iam.Tag
}

type CustomFilters struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func NewCustomFilters(arg interface{}) []CustomFilters {
	var filters []CustomFilters
	switch data := arg.(type) {
	case map[string]interface{}:
		filters = append(filters, CustomFilters{
			Type:  fmt.Sprintf("%v", data["type"]),
			Value: fmt.Sprintf("%v", data["value"]),
		})
	case map[interface{}]interface{}:
		stringMap := make(map[string]interface{})
		for key, value := range data {
			strKey := fmt.Sprintf("%v", key)
			stringMap[strKey] = value
		}
		nf := NewCustomFilters(stringMap)
		filters = append(filters, nf...)
	case []map[string]interface{}:
		for _, item := range data {
			nf := NewCustomFilters(item)
			filters = append(filters, nf...)
		}
	case []map[interface{}]interface{}:
		for _, item := range data {
			nf := NewCustomFilters(item)
			filters = append(filters, nf...)
		}
	case []interface{}:
		for _, item := range data {
			nf := NewCustomFilters(item)
			filters = append(filters, nf...)
		}
	default:
	}
	return filters
}

func (r *IAMRole) Settings(settings *libsettings.Setting) {
	r.settings = settings
	r.CustomFilters = NewCustomFilters(settings.Get("CustomFilters"))
}

func (r *IAMRole) FilterbyCustomFilters() error {
	for i := range r.CustomFilters {
		if r.CustomFilters[i].Type == IAMPathName {
			matched, _ := regexp.MatchString(r.CustomFilters[i].Value, *r.Path) // Don't check error as we only return err on successful filter
			if matched {
				return fmt.Errorf("filtered by path custom filter")
			}
		} else if r.CustomFilters[i].Type == IAMTagName {
			for _, tag := range r.Tags {
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

func (r *IAMRole) Filter() error {
	if strings.HasPrefix(*r.Path, "/aws-service-role/") && !r.settings.GetBool("IncludeServiceLinkedRoles") {
		return fmt.Errorf("cannot delete service roles")
	}
	if strings.HasPrefix(*r.Path, "/aws-reserved/sso.amazonaws.com/") {
		return fmt.Errorf("cannot delete SSO roles")
	}

	return r.FilterbyCustomFilters()
}

func (r *IAMRole) Remove(_ context.Context) error {
	_, err := r.svc.DeleteRole(&iam.DeleteRoleInput{
		RoleName: r.Name,
	})
	if err != nil {
		return err
	}

	return nil
}

func (r *IAMRole) Properties() types.Properties {
	return types.NewPropertiesFromStruct(r)
}

func (r *IAMRole) String() string {
	return *r.Name
}

// --------------

type IAMRoleLister struct {
	mockSvc iamiface.IAMAPI
}

func (l *IAMRoleLister) List(_ context.Context, o interface{}) ([]resource.Resource, error) {
	opts := o.(*nuke.ListerOpts)
	resources := make([]resource.Resource, 0)

	var svc iamiface.IAMAPI
	if l.mockSvc != nil {
		svc = l.mockSvc
	} else {
		svc = iam.New(opts.Session)
	}

	params := &iam.ListRolesInput{}
	for {
		resp, err := svc.ListRoles(params)
		if err != nil {
			return nil, err
		}

		for _, out := range resp.Roles {
			role, err := GetIAMRole(svc, out.RoleName)
			if err != nil {
				logrus.
					WithError(err).
					WithField("roleName", *out.RoleName).
					Error("Failed to get listed role")
				continue
			}

			resources = append(resources, &IAMRole{
				svc:          svc,
				Name:         role.RoleName,
				Path:         role.Path,
				CreateDate:   role.CreateDate,
				LastUsedDate: getLastUsedDate(role),
				Tags:         role.Tags,
			})
		}

		if !*resp.IsTruncated {
			break
		}

		params.Marker = resp.Marker
	}

	return resources, nil
}

// ---------

// GetIAMRole returns the IAM role with the given name
func GetIAMRole(svc iamiface.IAMAPI, roleName *string) (*iam.Role, error) {
	resp, err := svc.GetRole(&iam.GetRoleInput{
		RoleName: roleName,
	})
	if err != nil {
		return nil, err
	}

	return resp.Role, err
}

// getLastUsedDate returns the last used date of the role
func getLastUsedDate(role *iam.Role) *time.Time {
	var lastUsedDate *time.Time
	if role.RoleLastUsed == nil || role.RoleLastUsed.LastUsedDate == nil {
		lastUsedDate = role.CreateDate
	} else {
		lastUsedDate = role.RoleLastUsed.LastUsedDate
	}

	return ptr.Time(lastUsedDate.UTC())
}
