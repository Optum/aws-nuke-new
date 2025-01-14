---
generated: true
---

# S3Bucket


## Resource

```text
S3Bucket
```

### Alternative Resource

!!! note - Cloud Control API - Alternative Resource
    This resource can also be controlled and used via Cloud Control API. Please refer to the documentation for
    [Cloud Control Resources](../config-cloud-control.md) for more information.

```text
AWS::S3::Bucket
```
## Properties


- `ObjectLock`: No Description

!!! note - Using Properties
    Properties are what [Filters](../config-filtering.md) are written against in your configuration. You use the property
    names to write filters for what you want to **keep** and omit from the nuke process.

### String Property

The string representation of a resource is generally the value of the Name, ID or ARN field of the resource. Not all
resources support properties. To write a filter against the string representation, simply omit the `property` field in
the filter.

The string value is always what is used in the output of the log format when a resource is identified.

## Settings

- `BypassGovernanceRetention`
- `RemoveObjectLegalHold`


### BypassGovernanceRetention

!!! note
    There is currently no description for this setting. Often times settings are fairly self-explanatory. However, we
    are working on adding descriptions for all settings.

```text
BypassGovernanceRetention
```


### RemoveObjectLegalHold

!!! note
    There is currently no description for this setting. Often times settings are fairly self-explanatory. However, we
    are working on adding descriptions for all settings.

```text
RemoveObjectLegalHold
```

### DependsOn

!!! important - Experimental Feature
    This resource depends on a resource using the experimental feature. This means that the resource will
    only be deleted if all the resources of a particular type are deleted first or reach a terminal state.

- [S3Object](./s3-object.md)

