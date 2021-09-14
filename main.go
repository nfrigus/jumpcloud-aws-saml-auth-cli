package main

import (
	"log"
	"os"
	"os/exec"

	"github.com/urfave/cli/v2"
)

func main() {
	auth := AwsJumpCloudAuth{
		MFAToken:       "",
		SessionTimeout: 3600,
	}

	app := &cli.App{
		Name:      "aws-saml",
		Usage:     "Authenticate awscli with AWS JumpCloud saml assertion",
		UsageText: "aws-saml --email <email> --password <password> [...flags]",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Aliases:     []string{"e"},
				Destination: &auth.Email,
				Name:        "email",
				Required:    true,
				Usage:       "JumpCloud email",
			},
			&cli.StringFlag{
				Aliases:     []string{"p"},
				Destination: &auth.Password,
				Name:        "password",
				Required:    true,
				Usage:       "JumpCloud password",
			},
			&cli.StringFlag{
				Destination: &auth.PrincipalArn,
				Name:        "principal-arn",
				Required:    true,
				Usage:       "AWS SAML-provider ARN",
				Value:       auth.PrincipalArn,
			},
			&cli.StringFlag{
				Destination: &auth.RoleArn,
				Name:        "role-arn",
				Required:    true,
				Usage:       "AWS role ARN",
				Value:       auth.RoleArn,
			},
			&cli.IntFlag{
				Destination: &auth.SessionTimeout,
				Name:        "session-timeout",
				Usage:       "AWS session timeout in seconds",
				Value:       auth.SessionTimeout,
			},
			&cli.StringFlag{
				Aliases:     []string{"t"},
				Destination: &auth.MFAToken,
				Name:        "mfa-token",
				Usage:       "Time-based One Time Password (TOTP)",
				Value:       auth.MFAToken,
			},
		},
		Action: func(c *cli.Context) error {
			auth.shell()
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

type AwsJumpCloudAuth struct {
	Email          string
	Password       string
	PrincipalArn   string
	RoleArn        string
	SessionTimeout int
	MFAToken       string
}

func (auth *AwsJumpCloudAuth) shell() {
	iexec(auth.env())
}

func (auth *AwsJumpCloudAuth) env() []string {
	saml := NewJumpCloudSession().
		Login(auth.Email, auth.Password, auth.MFAToken).
		getSamlRequest()

	credentials := AwsSamlSession(AwsSamlSessionInput{
		auth.PrincipalArn,
		auth.RoleArn,
		saml,
		int32(auth.SessionTimeout),
	})

	return credentials.toEnv()
}

func iexec(env []string) {
	cmd := exec.Command("bash", "-i")

	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmd.Run()
}
