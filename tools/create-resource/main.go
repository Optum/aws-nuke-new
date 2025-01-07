package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"text/template"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/iancoleman/strcase"
)

const resourceTemplate = `package resources

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/{{.Service}}"

	"github.com/ekristen/libnuke/pkg/resource"
	"github.com/ekristen/libnuke/pkg/registry"
	"github.com/ekristen/libnuke/pkg/types"

	"github.com/ekristen/aws-nuke/v3/pkg/nuke"
)

const {{.Combined}}Resource = "{{.Combined}}"

func init() {
	registry.Register(&registry.Registration{
		Name:     {{.Combined}}Resource,
		Scope:    nuke.Account,
		Resource: &{{.Combined}}{},
		Lister:   &{{.Combined}}Lister{},
	})
}

type {{.Combined}}Lister struct{}

func (l *{{.Combined}}Lister) List(ctx context.Context, o interface{}) ([]resource.Resource, error) {
	opts := o.(*nuke.ListerOpts)
	svc := {{.Service}}.NewFromConfig(*opts.Config)
	var resources []resource.Resource

	// NOTE: you might have to modify the code below to actually work, this currently does not 
	// inspect the aws sdk instead is a jumping off point
	res, err := svc.List{{.ResourceTypeTitle}}s(ctx, &{{.Service}}.List{{.ResourceTypeTitle}}sInput{})
	if err != nil {
		return nil, err
	}

	for _, p := range res.{{.ResourceTypeTitle}}sList {
		resources = append(resources, &{{.Combined}}{
			svc:  svc,
			ID:   p.{{.ResourceTypeTitle}}Id,
			Tags: p.Tags,
		})
	}

	return resources, nil
}

type {{.Combined}} struct {
	svc  *{{.Service}}.Client
	ID   *string
	Tags []*{{.Service}}.Tag
}

func (r *{{.Combined}}) Remove(ctx context.Context) error {
	_, err := r.svc.Delete{{.ResourceTypeTitle}}(ctx, &{{.Service}}.Delete{{.ResourceTypeTitle}}Input{
		{{.ResourceTypeTitle}}Id: r.ID, 
	})
	return err
}

func (r *{{.Combined}}) Properties() types.Properties {
	return types.NewPropertiesFromStruct(r)
}

func (r *{{.Combined}}) String() string {
	return *r.ID
}
`

func main() {
	args := os.Args[1:]

	if len(args) != 2 {
		fmt.Println("usage: create-resource <service> <resource>")
		os.Exit(1)
	}

	service := args[0]
	resourceType := args[1]

	caser := cases.Title(language.English)

	data := struct {
		Service           string
		ServiceTitle      string
		ResourceType      string
		ResourceTypeTitle string
		Combined          string
	}{
		Service:           strings.ToLower(service),
		ServiceTitle:      caser.String(service),
		ResourceType:      resourceType,
		ResourceTypeTitle: strcase.ToCamel(resourceType),
		Combined:          fmt.Sprintf("%s%s", caser.String(service), strcase.ToCamel(resourceType)),
	}

	tmpl, err := template.New("resource").Parse(resourceTemplate)
	if err != nil {
		panic(err)
	}

	var tpl bytes.Buffer
	if err := tmpl.Execute(&tpl, data); err != nil {
		panic(err)
	}

	fmt.Println(tpl.String())
}
