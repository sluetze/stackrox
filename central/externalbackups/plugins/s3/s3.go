package s3

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	awsS3 "github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/central/externalbackups/plugins"
	"github.com/stackrox/rox/central/externalbackups/plugins/types"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/errorhelpers"
	"github.com/stackrox/rox/pkg/logging"
)

const (
	backupMaxTimeout = 60 * time.Minute
	testMaxTimeout   = 5 * time.Second
)

var (
	log = logging.LoggerForModule()
)

type s3 struct {
	integration *storage.ExternalBackup
	uploader    *s3manager.Uploader
	svc         *awsS3.S3
}

func validate(conf *storage.S3Config) error {
	errorList := errorhelpers.NewErrorList("S3 Validation")
	if conf.GetBucket() == "" {
		errorList.AddString("Bucket must be specified")
	}
	if !conf.GetUseIam() {
		if conf.GetAccessKeyId() == "" {
			errorList.AddString("Access Key ID must be specified")
		}
		if conf.GetSecretAccessKey() == "" {
			errorList.AddString("Secret Access Key must be specified")
		}
	} else if conf.GetAccessKeyId() != "" || conf.GetSecretAccessKey() != "" {
		errorList.AddStrings("IAM and access/secret key use are mutually exclusive. Only specify one")
	}
	if conf.GetRegion() == "" {
		errorList.AddString("Region must be specified")
	}
	return errorList.ToError()
}

func newS3(integration *storage.ExternalBackup) (*s3, error) {
	s3Config, ok := integration.Config.(*storage.ExternalBackup_S3)
	if !ok {
		return nil, errors.New("S3 configuration required")
	}
	conf := s3Config.S3
	if err := validate(conf); err != nil {
		return nil, err
	}

	creds := credentials.NewStaticCredentials(conf.GetAccessKeyId(), conf.GetSecretAccessKey(), "")
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(conf.GetRegion()),
		Credentials: creds,
	})
	if err != nil {
		return nil, err
	}
	return &s3{
		integration: integration,
		uploader:    s3manager.NewUploader(sess),
		svc:         awsS3.New(sess),
	}, nil
}

func (s *s3) send(duration time.Duration, ui *s3manager.UploadInput) error {
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	_, err := s.uploader.UploadWithContext(aws.Context(ctx), ui)
	return err
}

func sortS3Objects(objects []*awsS3.Object) {
	sort.SliceStable(objects, func(i, j int) bool {
		o1, o2 := objects[i], objects[j]
		if o2.LastModified == nil {
			return true
		}
		if o1.LastModified == nil {
			return false
		}

		return o1.LastModified.After(*o2.LastModified)
	})
}

func (s *s3) pruneBackupsIfNecessary() error {
	objects, err := s.svc.ListObjects(&awsS3.ListObjectsInput{
		Bucket: aws.String(s.integration.GetS3().GetBucket()),
		Prefix: aws.String(s.prefixKey("backup")),
	})
	if err != nil {
		return errors.Wrap(err, "failed to list objects for s3 bucket")
	}
	sortS3Objects(objects.Contents)

	var objectsToRemove []*awsS3.Object
	if len(objects.Contents) > int(s.integration.GetBackupsToKeep()) {
		objectsToRemove = objects.Contents[s.integration.GetBackupsToKeep():]
	}

	for _, o := range objectsToRemove {
		_, err := s.svc.DeleteObject(&awsS3.DeleteObjectInput{
			Bucket: aws.String(s.integration.GetS3().GetBucket()),
			Key:    o.Key,
		})
		if err != nil {
			return errors.Wrapf(err, "failed to remove backup %q from bucket %q", *o.Key, s.integration.GetS3().GetBucket())
		}
	}
	return nil
}

func (s *s3) prefixKey(key string) string {
	return filepath.Join(s.integration.GetS3().GetObjectPrefix(), key)
}

func (s *s3) Backup(reader io.ReadCloser) error {
	log.Info("Starting S3 Backup")
	formattedTime := time.Now().Format("2006-01-02T15:04:05")
	key := fmt.Sprintf("backup_%s.zip", formattedTime)
	formattedKey := s.prefixKey(key)
	ui := &s3manager.UploadInput{
		Bucket: aws.String(s.integration.GetS3().GetBucket()),
		Key:    aws.String(formattedKey),
		Body:   reader,
	}
	if err := s.send(backupMaxTimeout, ui); err != nil {
		if err := reader.Close(); err != nil {
			log.Errorf("Error closing reader: %v", err)
		}
		return errors.Wrapf(err, "error creating backup in bucket %q with key %q", s.integration.GetS3().GetBucket(), formattedKey)
	}
	log.Info("Successfully backed up to S3")
	return s.pruneBackupsIfNecessary()
}

func (s *s3) Restore() error { return nil }

func (s *s3) Test() error {
	formattedKey := s.prefixKey("test")
	ui := &s3manager.UploadInput{
		Bucket: aws.String(s.integration.GetS3().GetBucket()),
		Key:    aws.String(formattedKey),
		Body:   strings.NewReader("This is a test of the StackRox integration with this bucket"),
	}
	if err := s.send(testMaxTimeout, ui); err != nil {
		return errors.Wrapf(err, "error creating test object %q in bucket %q", formattedKey, s.integration.GetS3().GetBucket())
	}
	_, err := s.svc.DeleteObject(&awsS3.DeleteObjectInput{
		Bucket: aws.String(s.integration.GetS3().GetBucket()),
		Key:    aws.String(formattedKey),
	})
	if err != nil {
		return errors.Wrapf(err, "failed to remove test object %q from bucket %q", formattedKey, s.integration.GetS3().GetBucket())
	}
	return nil
}

func init() {
	plugins.Add("s3", func(backup *storage.ExternalBackup) (types.ExternalBackup, error) {
		return newS3(backup)
	})
}
