package provision

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// Input:
//
// Description:
//
//	Spins a new ec2 instance on AWS using the launchTemplate specified.
//	Returns the ip address of the created ec2 instance for further configuration of Opensearch
//
// Return:
//
//	(string, error): Returns the private ip address of the spinned node and error if any
func SpinNewVm(launchTemplateId string, launchTemplateVersion string) (string, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String("us-west-2"),
		Credentials: credentials.NewSharedCredentials("", ""),
	})

	// Create EC2 service client
	svc := ec2.New(sess)

	launchTemplate := &ec2.LaunchTemplateSpecification{
		LaunchTemplateId: &launchTemplateId,
		Version:          &launchTemplateVersion,
	}

	// Specify the details of the instance that you want to create.
	runResult, err := svc.RunInstances(&ec2.RunInstancesInput{
		// An Amazon Linux AMI ID for t2.micro instances in the us-west-2 region
		LaunchTemplate: launchTemplate,
		MinCount:       aws.Int64(1),
		MaxCount:       aws.Int64(1),
	})

	log.Info.Println("Creating new instance *************")

	if err != nil {
		log.Info.Println("Could not create instance", err)
		return "", err
	}

	log.Info.Println("Created instance, Instance ID: ", *runResult.Instances[0].InstanceId)
	private_ip := *runResult.Instances[0].PrivateIpAddress
	log.Info.Println("Created instance, Private IP: ", *runResult.Instances[0].PrivateIpAddress)

	// Add tags to the created instance
	_, errtag := svc.CreateTags(&ec2.CreateTagsInput{
		Resources: []*string{runResult.Instances[0].InstanceId},
		Tags: []*ec2.Tag{
			{
				Key:   aws.String("User"),
				Value: aws.String("meghana.r"),
			},
			{
				Key:   aws.String("Production"),
				Value: aws.String("Yes"),
			},
			{
				Key:   aws.String("Project"),
				Value: aws.String("Dev"),
			},
		},
	})
	if errtag != nil {
		log.Error.Println("Could not create tags for instance", runResult.Instances[0].InstanceId, errtag)
		return "", errtag
	}
	log.Info.Println("Tagged the instance")

	allInstances := true

	log.Info.Println("Waiting until instanceStatus to be Ok.......")
	errRunning := svc.WaitUntilInstanceStatusOk(&ec2.DescribeInstanceStatusInput{
		InstanceIds:         []*string{runResult.Instances[0].InstanceId},
		IncludeAllInstances: &allInstances,
	})
	if errRunning != nil {
		log.Error.Println("Instance state is nt okay even after maximum wait window")
		return "", errRunning
	}
	return private_ip, nil

}

// Input:
//
//	privateIp (string): private ip address of the instance that needs to be terminated
//
// Description:
//
//	Uses the private ip address passed as input to identify the instance id.
//	Terminates the ec2 instance.
//
// Return:
//
//	(error): Returns error if any while terminating the instance
func TerminateInstance(privateIp string) error {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String("us-west-2"),
		Credentials: credentials.NewSharedCredentials("", ""),
	})

	// Create EC2 service client
	svc := ec2.New(sess)

	describeInput := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("private-ip-address"),
				Values: []*string{
					aws.String(privateIp),
				},
			},
		},
	}

	describeResult, descErr := svc.DescribeInstances(describeInput)

	if descErr != nil {
		log.Info.Println("Could not get the description of instance", descErr)
		return err
	}

	instanceId := *describeResult.Reservations[0].Instances[0].InstanceId

	log.Info.Println("Terminating instance with ID: ", instanceId)

	input := &ec2.TerminateInstancesInput{
		InstanceIds: []*string{
			aws.String(instanceId),
		},
	}

	result, err := svc.TerminateInstances(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			default:
				log.Error.Println(aerr.Error())
			}
		}
		return err
	}

	log.Info.Println(result)
	return nil
}
