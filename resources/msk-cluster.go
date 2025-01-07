package resources

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kafka"

	"github.com/ekristen/libnuke/pkg/registry"
	"github.com/ekristen/libnuke/pkg/resource"
	"github.com/ekristen/libnuke/pkg/types"

	"github.com/ekristen/aws-nuke/v3/pkg/nuke"
)

const MSKClusterResource = "MSKCluster"

func init() {
	registry.Register(&registry.Registration{
		Name:     MSKClusterResource,
		Scope:    nuke.Account,
		Resource: &MSKCluster{},
		Lister:   &MSKClusterLister{},
	})
}

type MSKClusterLister struct{}

func (l *MSKClusterLister) List(ctx context.Context, o interface{}) ([]resource.Resource, error) {
	opts := o.(*nuke.ListerOpts)
	svc := kafka.NewFromConfig(*opts.Config)

	params := &kafka.ListClustersV2Input{}
	resp, err := svc.ListClustersV2(ctx, params)

	if err != nil {
		return nil, err
	}
	resources := make([]resource.Resource, 0)
	for _, cluster := range resp.ClusterInfoList {
		resources = append(resources, &MSKCluster{
			svc:     svc,
			context: ctx,
			arn:     *cluster.ClusterArn,
			name:    *cluster.ClusterName,
			tags:    cluster.Tags,
		})

	}
	return resources, nil
}

type MSKCluster struct {
	svc     *kafka.Client
	context context.Context

	arn  string
	name string
	tags map[string]string
}

func (m *MSKCluster) Remove(ctx context.Context) error {
	params := &kafka.DeleteClusterInput{
		ClusterArn: &m.arn,
	}

	_, err := m.svc.DeleteCluster(ctx, params)
	if err != nil {
		return err
	}
	return nil
}

func (m *MSKCluster) String() string {
	return m.arn
}

func (m *MSKCluster) Properties() types.Properties {
	properties := types.NewProperties()
	for tagKey, tagValue := range m.tags {
		properties.SetTag(aws.String(tagKey), tagValue)
	}
	properties.Set("ARN", m.arn)
	properties.Set("Name", m.name)

	return properties
}
