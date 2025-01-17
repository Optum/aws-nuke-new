package resources

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"

	"github.com/ekristen/aws-nuke/v3/pkg/nuke"
	"github.com/ekristen/libnuke/pkg/registry"
	"github.com/ekristen/libnuke/pkg/resource"
	"github.com/ekristen/libnuke/pkg/types"
)

const SageMakerAlgorithmResource = "SageMakerAlgorithm"

func init() {
	registry.Register(&registry.Registration{
		Name:     SageMakerAlgorithmResource,
		Scope:    nuke.Account,
		Resource: &SageMakerAlgorithm{},
		Lister:   &SageMakerAlgorithmLister{},
	})
}

type SageMakerAlgorithmLister struct{}

type SageMakerAlgorithm struct {
	svc           *sagemaker.Client
	algorithmName *string
}

func (l *SageMakerAlgorithmLister) List(ctx context.Context, o interface{}) ([]resource.Resource, error) {
	opts := o.(*nuke.ListerOpts)
	svc := sagemaker.NewFromConfig(*opts.Config)

	resources := make([]resource.Resource, 0)
	params := &sagemaker.ListAlgorithmsInput{
		MaxResults: aws.Int32(30),
	}
	for {
		resp, err := svc.ListAlgorithms(ctx, params)
		if err != nil {
			return nil, err
		}
		for _, algorithm := range resp.AlgorithmSummaryList {
			resources = append(resources, &SageMakerAlgorithm{
				svc:           svc,
				algorithmName: algorithm.AlgorithmName,
			})
		}
		if resp.NextToken == nil {
			break
		}
		params.NextToken = resp.NextToken
	}
	return resources, nil
}

func (f *SageMakerAlgorithm) Remove(ctx context.Context) error {
	_, err := f.svc.DeleteAlgorithm(ctx, &sagemaker.DeleteAlgorithmInput{
		AlgorithmName: f.algorithmName,
	})
	return err
}

func (f *SageMakerAlgorithm) String() string {
	return *f.algorithmName
}

func (f *SageMakerAlgorithm) Properties() types.Properties {
	return types.NewPropertiesFromStruct(f)
}
