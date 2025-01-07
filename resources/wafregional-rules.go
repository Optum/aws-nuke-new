package resources

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/wafregional"
	wafregionalTypes "github.com/aws/aws-sdk-go-v2/service/wafregional/types"

	"github.com/ekristen/libnuke/pkg/registry"
	"github.com/ekristen/libnuke/pkg/resource"
	"github.com/ekristen/libnuke/pkg/types"

	"github.com/ekristen/aws-nuke/v3/pkg/nuke"
)

const WAFRegionalRuleResource = "WAFRegionalRule"

func init() {
	registry.Register(&registry.Registration{
		Name:     WAFRegionalRuleResource,
		Scope:    nuke.Account,
		Resource: &WAFRegionalRule{},
		Lister:   &WAFRegionalRuleLister{},
	})
}

type WAFRegionalRuleLister struct{}

func (l *WAFRegionalRuleLister) List(ctx context.Context, o interface{}) ([]resource.Resource, error) {
	opts := o.(*nuke.ListerOpts)

	svc := wafregional.NewFromConfig(*opts.Config)
	resources := make([]resource.Resource, 0)

	params := &wafregional.ListRulesInput{
		Limit: 50,
	}

	for {
		resp, err := svc.ListRules(ctx, params)
		if err != nil {
			return nil, err
		}

		for _, rule := range resp.Rules {
			ruleResp, err := svc.GetRule(ctx, &wafregional.GetRuleInput{
				RuleId: rule.RuleId,
			})
			if err != nil {
				return nil, err
			}
			resources = append(resources, &WAFRegionalRule{
				svc:  svc,
				ID:   rule.RuleId,
				name: rule.Name,
				rule: ruleResp.Rule,
			})
		}

		if resp.NextMarker == nil {
			break
		}

		params.NextMarker = resp.NextMarker
	}

	return resources, nil
}

type WAFRegionalRule struct {
	svc  *wafregional.Client
	ID   *string
	name *string
	rule *wafregionalTypes.Rule
}

func (f *WAFRegionalRule) Remove(ctx context.Context) error {
	tokenOutput, err := f.svc.GetChangeToken(ctx, &wafregional.GetChangeTokenInput{})
	if err != nil {
		return err
	}

	ruleUpdates := []wafregionalTypes.RuleUpdate{}
	for _, predicate := range f.rule.Predicates {
		ruleUpdates = append(ruleUpdates, wafregionalTypes.RuleUpdate{
			Action:    wafregionalTypes.ChangeActionDelete,
			Predicate: &predicate,
		})
	}

	if len(ruleUpdates) > 0 {
		_, err = f.svc.UpdateRule(ctx, &wafregional.UpdateRuleInput{
			ChangeToken: tokenOutput.ChangeToken,
			RuleId:      f.ID,
			Updates:     ruleUpdates,
		})

		if err != nil {
			return err
		}
	}

	tokenOutput, err = f.svc.GetChangeToken(ctx, &wafregional.GetChangeTokenInput{})
	if err != nil {
		return err
	}

	_, err = f.svc.DeleteRule(ctx, &wafregional.DeleteRuleInput{
		RuleId:      f.ID,
		ChangeToken: tokenOutput.ChangeToken,
	})

	return err
}

func (f *WAFRegionalRule) String() string {
	return *f.ID
}

func (f *WAFRegionalRule) Properties() types.Properties {
	properties := types.NewProperties()

	properties.
		Set("ID", f.ID).
		Set("Name", f.name)
	return properties
}
