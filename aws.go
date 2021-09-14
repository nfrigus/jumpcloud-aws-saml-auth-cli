package main

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
)

type AwsSamlSessionOutput struct {
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
}

type AwsSamlSessionInput struct {
	PrincipalArn    string
	RoleArn         string
	SAMLAssertion   string
	DurationSeconds int32
}

func (o *AwsSamlSessionInput) toAwsInput() sts.AssumeRoleWithSAMLInput {
	return sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(o.PrincipalArn),
		RoleArn:         aws.String(o.RoleArn),
		SAMLAssertion:   aws.String(o.SAMLAssertion),
		DurationSeconds: aws.Int32(o.DurationSeconds),
	}
}

func (o *AwsSamlSessionOutput) toEnv() []string {
	return []string{
		fmt.Sprintf("AWS_ACCESS_KEY_ID=%s", o.AccessKeyId),
		fmt.Sprintf("AWS_SECRET_ACCESS_KEY=%s", o.SecretAccessKey),
		fmt.Sprintf("AWS_SESSION_TOKEN=%s", o.SessionToken),
	}
}

func NewAwsSamlSessionOutput(credentials *types.Credentials) AwsSamlSessionOutput {
	return AwsSamlSessionOutput{
		aws.ToString(credentials.AccessKeyId),
		aws.ToString(credentials.SecretAccessKey),
		aws.ToString(credentials.SessionToken),
	}
}

func AwsSamlSession(input AwsSamlSessionInput) AwsSamlSessionOutput {
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatal(err)
	}

	client := sts.NewFromConfig(cfg)

	awsInput := input.toAwsInput()
	res, err := client.AssumeRoleWithSAML(ctx, &awsInput)
	if err != nil {
		log.Fatal(err)
	}

	return NewAwsSamlSessionOutput(res.Credentials)
}

func getCallerIdentity() {
	ctx := context.TODO()
	cfg, err := config.LoadDefaultConfig(ctx)

	if err != nil {
		log.Fatal(err)
	}

	client := sts.NewFromConfig(cfg)

	identity, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Account: %s, Arn: %s\n", aws.ToString(identity.Account), aws.ToString(identity.Arn))
}
