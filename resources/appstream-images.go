package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/gotidy/ptr"

	"github.com/aws/aws-sdk-go-v2/service/appstream"

	"github.com/ekristen/libnuke/pkg/registry"
	"github.com/ekristen/libnuke/pkg/resource"
	"github.com/ekristen/libnuke/pkg/types"

	"github.com/ekristen/aws-nuke/v3/pkg/nuke"
)

const AppStreamImageResource = "AppStreamImage"

func init() {
	registry.Register(&registry.Registration{
		Name:     AppStreamImageResource,
		Scope:    nuke.Account,
		Resource: &AppStreamImage{},
		Lister:   &AppStreamImageLister{},
	})
}

type AppStreamImageLister struct{}

func (l *AppStreamImageLister) List(ctx context.Context, o interface{}) ([]resource.Resource, error) {
	opts := o.(*nuke.ListerOpts)
	svc := appstream.NewFromConfig(*opts.Config)

	resources := make([]resource.Resource, 0)
	var nextToken *string

	for ok := true; ok; ok = (nextToken != nil) {
		params := &appstream.DescribeImagesInput{
			NextToken: nextToken,
		}

		output, err := svc.DescribeImages(ctx, params)
		if err != nil {
			return nil, err
		}
		nextToken = output.NextToken

		for i := range output.Images {
			sharedAccounts := []*string{}
			visibility := string(output.Images[i].Visibility)

			// Filter out public images
			if !strings.EqualFold(visibility, "PUBLIC") {
				imagePerms, err := svc.DescribeImagePermissions(ctx, &appstream.DescribeImagePermissionsInput{
					Name: output.Images[i].Name,
				})

				if err != nil {
					return nil, err
				}

				for _, permission := range imagePerms.SharedImagePermissionsList {
					sharedAccounts = append(sharedAccounts, permission.SharedAccountId)
				}

				resources = append(resources, &AppStreamImage{
					svc:            svc,
					name:           output.Images[i].Name,
					visibility:     &visibility,
					sharedAccounts: sharedAccounts,
				})
			}
		}
	}

	return resources, nil
}

type AppStreamImage struct {
	svc            *appstream.Client
	name           *string
	visibility     *string
	sharedAccounts []*string
}

func (f *AppStreamImage) Remove(ctx context.Context) error {
	for _, account := range f.sharedAccounts {
		_, err := f.svc.DeleteImagePermissions(ctx, &appstream.DeleteImagePermissionsInput{
			Name:            f.name,
			SharedAccountId: account,
		})
		if err != nil {
			fmt.Println("Error deleting image permissions", err)
			return err
		}
	}

	_, err := f.svc.DeleteImage(ctx, &appstream.DeleteImageInput{
		Name: f.name,
	})

	return err
}

func (f *AppStreamImage) String() string {
	return *f.name
}

func (f *AppStreamImage) Filter() error {
	if strings.EqualFold(ptr.ToString(f.visibility), "PUBLIC") {
		return fmt.Errorf("cannot delete public AWS images")
	}
	return nil
}

func (f *AppStreamImage) Properties() types.Properties {
	return types.NewPropertiesFromStruct(f)
}
