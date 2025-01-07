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

const SageMakerTrainingJobListerResource = "SageMakerTrainingJobLister"

func init() {
	registry.Register(&registry.Registration{
		Name:     SageMakerTrainingJobListerResource,
		Scope:    nuke.Account,
		Resource: &SageMakerTrainingJobLister{},
		Lister:   &SageMakerTrainingJobLister{},
	})
}

type SageMakerTrainingJobLister struct{}

type SageMakerTrainingJob struct {
	svc             *sagemaker.Client
	trainingJobName *string
}

func (l *SageMakerTrainingJobLister) List(ctx context.Context, o interface{}) ([]resource.Resource, error) {
	opts := o.(*nuke.ListerOpts)
	svc := sagemaker.NewFromConfig(*opts.Config)

	resources := make([]resource.Resource, 0)
	params := &sagemaker.ListTrainingJobsInput{
		MaxResults: aws.Int32(30),
	}
	for {
		resp, err := svc.ListTrainingJobs(ctx, params)
		if err != nil {
			return nil, err
		}
		for _, trainingJob := range resp.TrainingJobSummaries {
			resources = append(resources, &SageMakerTrainingJob{
				svc:             svc,
				trainingJobName: trainingJob.TrainingJobName,
			})
		}
		if resp.NextToken == nil {
			break
		}
		params.NextToken = resp.NextToken
	}
	return resources, nil
}

func (f *SageMakerTrainingJob) Remove(ctx context.Context) error {
	_, err := f.svc.StopTrainingJob(ctx, &sagemaker.StopTrainingJobInput{
		TrainingJobName: f.trainingJobName,
	})
	return err
}

func (f *SageMakerTrainingJob) String() string {
	return *f.trainingJobName
}

func (f *SageMakerTrainingJob) Properties() types.Properties {
	properties := types.NewProperties()
	properties.Set("TrainingJobName", f.trainingJobName)
	return properties
}
