package resources

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/iam/iamiface"

	"github.com/ekristen/libnuke/pkg/registry"
	"github.com/ekristen/libnuke/pkg/resource"
	libsettings "github.com/ekristen/libnuke/pkg/settings"
	"github.com/ekristen/libnuke/pkg/types"

	"github.com/ekristen/aws-nuke/v3/pkg/nuke"
)

const IAMPolicyResource = "IAMPolicy"
const IAMPathName = "Path"
const IAMTagName = "Tag"

func init() {
	registry.Register(&registry.Registration{
		Name:     IAMPolicyResource,
		Scope:    nuke.Account,
		Resource: &IAMPolicy{},
		Lister:   &IAMPolicyLister{},
		DependsOn: []string{
			IAMUserPolicyAttachmentResource,
			IAMGroupPolicyAttachmentResource,
			IAMRolePolicyAttachmentResource,
		},
		DeprecatedAliases: []string{
			"IamPolicy",
		},
		Settings: []string{
			"CustomFilters",
		},
	})
}

type IAMPolicy struct {
	svc           iamiface.IAMAPI
	settings      *libsettings.Setting
	CustomFilters []CustomFilters
	Name          *string
	PolicyID      *string
	ARN           *string
	Path          *string
	CreateDate    *time.Time
	Tags          []*iam.Tag
}

func (r *IAMPolicy) Settings(settings *libsettings.Setting) {
	r.settings = settings
	r.CustomFilters = NewCustomFilters(settings.Get("CustomFilters"))
}

func (r *IAMPolicy) FilterbyCustomFilters() error {
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

func (r *IAMPolicy) Filter() error {
	return r.FilterbyCustomFilters()
}

type IAMPolicyLister struct{}

func (l *IAMPolicyLister) List(_ context.Context, o interface{}) ([]resource.Resource, error) {
	opts := o.(*nuke.ListerOpts)

	svc := iam.New(opts.Session)

	params := &iam.ListPoliciesInput{
		Scope: aws.String("Local"),
	}

	policies := make([]*iam.Policy, 0)

	if err := svc.ListPoliciesPages(params,
		func(page *iam.ListPoliciesOutput, lastPage bool) bool {
			for _, listedPolicy := range page.Policies {
				policy, err := GetIAMPolicy(svc, listedPolicy.Arn)
				if err != nil {
					logrus.Errorf("Failed to get listed policy %s: %v", *listedPolicy.PolicyName, err)
					continue
				}
				policies = append(policies, policy)
			}
			return true
		}); err != nil {
		return nil, err
	}

	resources := make([]resource.Resource, 0)

	for _, out := range policies {
		resources = append(resources, &IAMPolicy{
			svc:        svc,
			Name:       out.PolicyName,
			Path:       out.Path,
			ARN:        out.Arn,
			PolicyID:   out.PolicyId,
			CreateDate: out.CreateDate,
			Tags:       out.Tags,
		})
	}

	return resources, nil
}

func (r *IAMPolicy) Remove(_ context.Context) error {
	resp, err := r.svc.ListPolicyVersions(&iam.ListPolicyVersionsInput{
		PolicyArn: r.ARN,
	})
	if err != nil {
		return err
	}

	for _, version := range resp.Versions {
		if !*version.IsDefaultVersion {
			_, err = r.svc.DeletePolicyVersion(&iam.DeletePolicyVersionInput{
				PolicyArn: r.ARN,
				VersionId: version.VersionId,
			})
			if err != nil {
				return err
			}
		}
	}

	_, err = r.svc.DeletePolicy(&iam.DeletePolicyInput{
		PolicyArn: r.ARN,
	})
	if err != nil {
		return err
	}

	return nil
}

func (r *IAMPolicy) Properties() types.Properties {
	return types.NewPropertiesFromStruct(r)
}

func (r *IAMPolicy) String() string {
	return *r.ARN
}

// -------------

func GetIAMPolicy(svc *iam.IAM, policyArn *string) (*iam.Policy, error) {
	resp, err := svc.GetPolicy(&iam.GetPolicyInput{
		PolicyArn: policyArn,
	})
	if err != nil {
		return nil, err
	}

	return resp.Policy, nil
}
