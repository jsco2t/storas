package compat

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"

	"storas/test/integration"
)

func TestAWSSDKCompatibilitySuite(t *testing.T) {
	t.Parallel()
	env := integration.NewCompatEnv(t)

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-west-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("AKIAFULL", "secret-full", "")),
		awsconfig.WithBaseEndpoint(env.BaseURL()),
	)
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	bucket := "sdk-bucket"
	_, err = client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: &bucket})
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	if _, err := client.GetBucketAcl(context.Background(), &s3.GetBucketAclInput{Bucket: &bucket}); err != nil {
		t.Fatalf("GetBucketAcl: %v", err)
	}
	listBucketsOut, err := client.ListBuckets(context.Background(), &s3.ListBucketsInput{})
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if listBucketsOut.Owner == nil || listBucketsOut.Owner.ID == nil || *listBucketsOut.Owner.ID == "" {
		t.Fatalf("expected ListBuckets owner fields, got %#v", listBucketsOut.Owner)
	}
	if len(listBucketsOut.Buckets) == 0 || listBucketsOut.Buckets[0].CreationDate == nil {
		t.Fatalf("expected ListBuckets creation date fields, got %+v", listBucketsOut.Buckets)
	}

	body := "compat-body"
	putOut, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket:   &bucket,
		Key:      strp("key.txt"),
		Body:     strings.NewReader(body),
		ACL:      types.ObjectCannedACLPrivate,
		Metadata: map[string]string{"owner": "sdk"},
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if putOut.VersionId != nil && *putOut.VersionId != "" && *putOut.VersionId != "null" {
		t.Fatalf("expected null/non-versioned put response by default, got %q", *putOut.VersionId)
	}
	if _, err := client.GetObjectAcl(context.Background(), &s3.GetObjectAclInput{Bucket: &bucket, Key: strp("key.txt")}); err != nil {
		t.Fatalf("GetObjectAcl: %v", err)
	}

	list, err := client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{Bucket: &bucket})
	if err != nil {
		t.Fatalf("ListObjectsV2: %v", err)
	}
	if len(list.Contents) != 1 {
		t.Fatalf("expected one object, got %d", len(list.Contents))
	}

	get, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: strp("key.txt")})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	defer get.Body.Close()
	payload, err := io.ReadAll(get.Body)
	if err != nil {
		t.Fatalf("read get body: %v", err)
	}
	if string(payload) != body {
		t.Fatalf("unexpected payload: %q", string(payload))
	}

	_, err = client.CopyObject(context.Background(), &s3.CopyObjectInput{Bucket: &bucket, Key: strp("copied.txt"), CopySource: strp("/" + bucket + "/key.txt")})
	if err != nil {
		t.Fatalf("CopyObject: %v", err)
	}

	_, err = client.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: &bucket, Key: strp("key.txt")})
	if err != nil {
		t.Fatalf("DeleteObject: %v", err)
	}
	_, err = client.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: &bucket, Key: strp("copied.txt")})
	if err != nil {
		t.Fatalf("DeleteObject copied: %v", err)
	}

	_, err = client.DeleteBucket(context.Background(), &s3.DeleteBucketInput{Bucket: &bucket})
	if err != nil {
		t.Fatalf("DeleteBucket: %v", err)
	}

	policyBucket := "sdk-policy-cond"
	_, err = client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: &policyBucket})
	if err != nil {
		t.Fatalf("CreateBucket policy: %v", err)
	}
	_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: &policyBucket,
		Key:    strp("one.txt"),
		Body:   strings.NewReader("one"),
	})
	if err != nil {
		t.Fatalf("PutObject policy: %v", err)
	}
	policyDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:ListBucket","Resource":"arn:aws:s3:::sdk-policy-cond","Condition":{"NumericLessThanEquals":{"s3:max-keys":"1"},"DateGreaterThan":{"aws:CurrentTime":"2020-01-01T00:00:00Z"}}}]}`
	_, err = client.PutBucketPolicy(context.Background(), &s3.PutBucketPolicyInput{
		Bucket: &policyBucket,
		Policy: strp(policyDoc),
	})
	if err != nil {
		t.Fatalf("PutBucketPolicy: %v", err)
	}
	if _, err := client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{Bucket: &policyBucket, MaxKeys: int32p(1)}); err != nil {
		t.Fatalf("ListObjectsV2 max-keys=1: %v", err)
	}
	if _, err := client.ListObjectsV2(context.Background(), &s3.ListObjectsV2Input{Bucket: &policyBucket, MaxKeys: int32p(2)}); err == nil {
		t.Fatal("expected AccessDenied for ListObjectsV2 max-keys=2")
	} else {
		var apiErr smithy.APIError
		if !strings.Contains(err.Error(), "AccessDenied") && (!errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDenied") {
			t.Fatalf("expected AccessDenied for ListObjectsV2 max-keys=2, got %v", err)
		}
	}
	_, err = client.DeleteBucketPolicy(context.Background(), &s3.DeleteBucketPolicyInput{Bucket: &policyBucket})
	if err != nil {
		t.Fatalf("DeleteBucketPolicy cleanup: %v", err)
	}
	_, err = client.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: &policyBucket, Key: strp("one.txt")})
	if err != nil {
		t.Fatalf("DeleteObject policy cleanup: %v", err)
	}
	_, err = client.DeleteBucket(context.Background(), &s3.DeleteBucketInput{Bucket: &policyBucket})
	if err != nil {
		t.Fatalf("DeleteBucket policy: %v", err)
	}

	ifExistsBucket := "sdk-policy-ifexists"
	_, err = client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: &ifExistsBucket})
	if err != nil {
		t.Fatalf("CreateBucket ifexists: %v", err)
	}
	_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: &ifExistsBucket,
		Key:    strp("key.txt"),
		Body:   strings.NewReader("value"),
	})
	if err != nil {
		t.Fatalf("PutObject ifexists: %v", err)
	}
	ifExistsPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::sdk-policy-ifexists/*","Condition":{"StringEqualsIfExists":{"s3:VersionId":"v1"}}}]}`
	_, err = client.PutBucketPolicy(context.Background(), &s3.PutBucketPolicyInput{
		Bucket: &ifExistsBucket,
		Policy: strp(ifExistsPolicy),
	})
	if err != nil {
		t.Fatalf("PutBucketPolicy ifexists: %v", err)
	}
	if _, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &ifExistsBucket, Key: strp("key.txt")}); err != nil {
		t.Fatalf("GetObject IfExists policy: %v", err)
	}
	if _, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &ifExistsBucket, Key: strp("key.txt"), VersionId: strp("bad")}); err == nil {
		t.Fatal("expected AccessDenied for non-matching versionId under IfExists policy")
	} else {
		var apiErr smithy.APIError
		if !strings.Contains(err.Error(), "AccessDenied") && (!errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDenied") {
			t.Fatalf("expected AccessDenied for IfExists version mismatch, got %v", err)
		}
	}
	_, err = client.DeleteBucketPolicy(context.Background(), &s3.DeleteBucketPolicyInput{Bucket: &ifExistsBucket})
	if err != nil {
		t.Fatalf("DeleteBucketPolicy ifexists cleanup: %v", err)
	}
	_, err = client.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: &ifExistsBucket, Key: strp("key.txt")})
	if err != nil {
		t.Fatalf("DeleteObject ifexists cleanup: %v", err)
	}
	_, err = client.DeleteBucket(context.Background(), &s3.DeleteBucketInput{Bucket: &ifExistsBucket})
	if err != nil {
		t.Fatalf("DeleteBucket ifexists: %v", err)
	}

	arnBucket := "sdk-policy-arn"
	_, err = client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: &arnBucket})
	if err != nil {
		t.Fatalf("CreateBucket arn policy: %v", err)
	}
	_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: &arnBucket,
		Key:    strp("key.txt"),
		Body:   strings.NewReader("value"),
	})
	if err != nil {
		t.Fatalf("PutObject arn policy: %v", err)
	}
	arnPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::sdk-policy-arn/*","Condition":{"ArnLike":{"aws:PrincipalArn":"arn:storas:iam::local:user/full"}}}]}`
	_, err = client.PutBucketPolicy(context.Background(), &s3.PutBucketPolicyInput{
		Bucket: &arnBucket,
		Policy: strp(arnPolicy),
	})
	if err != nil {
		t.Fatalf("PutBucketPolicy arn: %v", err)
	}
	if _, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &arnBucket, Key: strp("key.txt")}); err != nil {
		t.Fatalf("GetObject arn policy: %v", err)
	}
	blockingArnPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::sdk-policy-arn/*","Condition":{"ArnEquals":{"aws:PrincipalArn":"arn:storas:iam::local:user/other"}}}]}`
	_, err = client.PutBucketPolicy(context.Background(), &s3.PutBucketPolicyInput{
		Bucket: &arnBucket,
		Policy: strp(blockingArnPolicy),
	})
	if err != nil {
		t.Fatalf("PutBucketPolicy arn blocking: %v", err)
	}
	if _, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &arnBucket, Key: strp("key.txt")}); err == nil {
		t.Fatal("expected AccessDenied for non-matching ArnEquals policy")
	} else {
		var apiErr smithy.APIError
		if !strings.Contains(err.Error(), "AccessDenied") && (!errors.As(err, &apiErr) || apiErr.ErrorCode() != "AccessDenied") {
			t.Fatalf("expected AccessDenied for arn condition mismatch, got %v", err)
		}
	}
	_, err = client.DeleteBucketPolicy(context.Background(), &s3.DeleteBucketPolicyInput{Bucket: &arnBucket})
	if err != nil {
		t.Fatalf("DeleteBucketPolicy arn cleanup: %v", err)
	}
	_, err = client.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: &arnBucket, Key: strp("key.txt")})
	if err != nil {
		t.Fatalf("DeleteObject arn cleanup: %v", err)
	}
	_, err = client.DeleteBucket(context.Background(), &s3.DeleteBucketInput{Bucket: &arnBucket})
	if err != nil {
		t.Fatalf("DeleteBucket arn: %v", err)
	}

	lifeBucket := "sdk-lifecycle"
	_, err = client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: &lifeBucket})
	if err != nil {
		t.Fatalf("CreateBucket lifecycle: %v", err)
	}
	_, err = client.PutBucketLifecycleConfiguration(context.Background(), &s3.PutBucketLifecycleConfigurationInput{
		Bucket: &lifeBucket,
		LifecycleConfiguration: &types.BucketLifecycleConfiguration{
			Rules: []types.LifecycleRule{
				{
					ID:     strp("expire-logs"),
					Status: types.ExpirationStatusEnabled,
					Prefix: strp("logs/"),
					Expiration: &types.LifecycleExpiration{
						Days: int32p(30),
					},
					AbortIncompleteMultipartUpload: &types.AbortIncompleteMultipartUpload{
						DaysAfterInitiation: int32p(7),
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("PutBucketLifecycleConfiguration: %v", err)
	}
	lifeOut, err := client.GetBucketLifecycleConfiguration(context.Background(), &s3.GetBucketLifecycleConfigurationInput{Bucket: &lifeBucket})
	if err != nil {
		t.Fatalf("GetBucketLifecycleConfiguration: %v", err)
	}
	if len(lifeOut.Rules) != 1 {
		t.Fatalf("expected one lifecycle rule, got %d", len(lifeOut.Rules))
	}
	_, err = client.DeleteBucketLifecycle(context.Background(), &s3.DeleteBucketLifecycleInput{Bucket: &lifeBucket})
	if err != nil {
		t.Fatalf("DeleteBucketLifecycle: %v", err)
	}
	_, err = client.DeleteBucket(context.Background(), &s3.DeleteBucketInput{Bucket: &lifeBucket})
	if err != nil {
		t.Fatalf("DeleteBucket lifecycle: %v", err)
	}

	verBucket := "sdk-versioned"
	_, err = client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: &verBucket})
	if err != nil {
		t.Fatalf("CreateBucket versioned: %v", err)
	}
	_, err = client.PutBucketVersioning(context.Background(), &s3.PutBucketVersioningInput{
		Bucket: &verBucket,
		VersioningConfiguration: &types.VersioningConfiguration{
			Status: types.BucketVersioningStatusEnabled,
		},
	})
	if err != nil {
		t.Fatalf("PutBucketVersioning: %v", err)
	}
	verPut1, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: &verBucket,
		Key:    strp("key.txt"),
		Body:   strings.NewReader("v1"),
	})
	if err != nil {
		t.Fatalf("PutObject versioned v1: %v", err)
	}
	verPut2, err := client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: &verBucket,
		Key:    strp("key.txt"),
		Body:   strings.NewReader("v2"),
	})
	if err != nil {
		t.Fatalf("PutObject versioned v2: %v", err)
	}
	if verPut1.VersionId == nil || verPut2.VersionId == nil || *verPut1.VersionId == "" || *verPut2.VersionId == "" || *verPut1.VersionId == *verPut2.VersionId {
		t.Fatalf("expected two distinct version ids, v1=%v v2=%v", verPut1.VersionId, verPut2.VersionId)
	}
	getV1, err := client.GetObject(context.Background(), &s3.GetObjectInput{
		Bucket:    &verBucket,
		Key:       strp("key.txt"),
		VersionId: verPut1.VersionId,
	})
	if err != nil {
		t.Fatalf("GetObject versioned v1: %v", err)
	}
	defer getV1.Body.Close()
	v1Bytes, err := io.ReadAll(getV1.Body)
	if err != nil {
		t.Fatalf("read v1 payload: %v", err)
	}
	if string(v1Bytes) != "v1" {
		t.Fatalf("expected v1 payload, got %q", string(v1Bytes))
	}
	versionList, err := client.ListObjectVersions(context.Background(), &s3.ListObjectVersionsInput{Bucket: &verBucket})
	if err != nil {
		t.Fatalf("ListObjectVersions: %v", err)
	}
	if len(versionList.Versions) < 2 {
		t.Fatalf("expected at least two versions, got %d", len(versionList.Versions))
	}
	_, err = client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
		Bucket:    &verBucket,
		Key:       strp("key.txt"),
		VersionId: verPut1.VersionId,
	})
	if err != nil {
		t.Fatalf("DeleteObject explicit version: %v", err)
	}
	cleanupVersions, err := client.ListObjectVersions(context.Background(), &s3.ListObjectVersionsInput{Bucket: &verBucket})
	if err != nil {
		t.Fatalf("ListObjectVersions cleanup: %v", err)
	}
	for _, v := range cleanupVersions.Versions {
		if v.VersionId == nil {
			continue
		}
		_, delErr := client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket:    &verBucket,
			Key:       v.Key,
			VersionId: v.VersionId,
		})
		if delErr != nil {
			t.Fatalf("DeleteObject cleanup version %q: %v", *v.VersionId, delErr)
		}
	}
	for _, v := range cleanupVersions.DeleteMarkers {
		if v.VersionId == nil {
			continue
		}
		_, delErr := client.DeleteObject(context.Background(), &s3.DeleteObjectInput{
			Bucket:    &verBucket,
			Key:       v.Key,
			VersionId: v.VersionId,
		})
		if delErr != nil {
			t.Fatalf("DeleteObject cleanup marker %q: %v", *v.VersionId, delErr)
		}
	}
	_, err = client.DeleteBucket(context.Background(), &s3.DeleteBucketInput{Bucket: &verBucket})
	if err != nil {
		t.Fatalf("DeleteBucket versioned: %v", err)
	}

	mpBucket := "sdk-multipart"
	_, err = client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: &mpBucket})
	if err != nil {
		t.Fatalf("CreateBucket multipart: %v", err)
	}
	createMP, err := client.CreateMultipartUpload(context.Background(), &s3.CreateMultipartUploadInput{
		Bucket: &mpBucket,
		Key:    strp("multi.txt"),
		ACL:    types.ObjectCannedACLPrivate,
	})
	if err != nil {
		t.Fatalf("CreateMultipartUpload: %v", err)
	}
	if createMP.UploadId == nil || *createMP.UploadId == "" {
		t.Fatal("expected UploadId")
	}
	up1, err := client.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:     &mpBucket,
		Key:        strp("multi.txt"),
		UploadId:   createMP.UploadId,
		PartNumber: int32p(1),
		Body:       strings.NewReader("hello-"),
	})
	if err != nil {
		t.Fatalf("UploadPart 1: %v", err)
	}
	up2, err := client.UploadPart(context.Background(), &s3.UploadPartInput{
		Bucket:     &mpBucket,
		Key:        strp("multi.txt"),
		UploadId:   createMP.UploadId,
		PartNumber: int32p(2),
		Body:       strings.NewReader("sdk"),
	})
	if err != nil {
		t.Fatalf("UploadPart 2: %v", err)
	}

	listMP, err := client.ListMultipartUploads(context.Background(), &s3.ListMultipartUploadsInput{Bucket: &mpBucket})
	if err != nil {
		t.Fatalf("ListMultipartUploads: %v", err)
	}
	if len(listMP.Uploads) == 0 {
		t.Fatal("expected at least one multipart upload")
	}

	parts, err := client.ListParts(context.Background(), &s3.ListPartsInput{
		Bucket:   &mpBucket,
		Key:      strp("multi.txt"),
		UploadId: createMP.UploadId,
	})
	if err != nil {
		t.Fatalf("ListParts: %v", err)
	}
	if len(parts.Parts) != 2 {
		t.Fatalf("expected two parts, got %d", len(parts.Parts))
	}

	_, err = client.CompleteMultipartUpload(context.Background(), &s3.CompleteMultipartUploadInput{
		Bucket:   &mpBucket,
		Key:      strp("multi.txt"),
		UploadId: createMP.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{
				{PartNumber: int32p(1), ETag: up1.ETag},
				{PartNumber: int32p(2), ETag: up2.ETag},
			},
		},
	})
	if err != nil {
		t.Fatalf("CompleteMultipartUpload: %v", err)
	}

	mpGet, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &mpBucket, Key: strp("multi.txt")})
	if err != nil {
		t.Fatalf("GetObject multipart: %v", err)
	}
	defer mpGet.Body.Close()
	mpPayload, err := io.ReadAll(mpGet.Body)
	if err != nil {
		t.Fatalf("read multipart payload: %v", err)
	}
	if string(mpPayload) != "hello-sdk" {
		t.Fatalf("unexpected multipart payload: %q", string(mpPayload))
	}

	aborted, err := client.CreateMultipartUpload(context.Background(), &s3.CreateMultipartUploadInput{
		Bucket: &mpBucket,
		Key:    strp("abort.txt"),
	})
	if err != nil {
		t.Fatalf("CreateMultipartUpload abort: %v", err)
	}
	_, err = client.AbortMultipartUpload(context.Background(), &s3.AbortMultipartUploadInput{
		Bucket:   &mpBucket,
		Key:      strp("abort.txt"),
		UploadId: aborted.UploadId,
	})
	if err != nil {
		t.Fatalf("AbortMultipartUpload: %v", err)
	}

	_, err = client.DeleteObject(context.Background(), &s3.DeleteObjectInput{Bucket: &mpBucket, Key: strp("multi.txt")})
	if err != nil {
		t.Fatalf("DeleteObject multipart: %v", err)
	}
	_, err = client.DeleteBucket(context.Background(), &s3.DeleteBucketInput{Bucket: &mpBucket})
	if err != nil {
		t.Fatalf("DeleteBucket multipart: %v", err)
	}

	_, err = client.HeadBucket(context.Background(), &s3.HeadBucketInput{Bucket: strp("missing")})
	if err == nil {
		t.Fatal("expected missing bucket error")
	}
}

func TestAWSSDKBucketPolicyConditionCompatibility(t *testing.T) {
	t.Parallel()
	env := integration.NewCompatEnv(t)

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-west-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("AKIAFULL", "secret-full", "")),
		awsconfig.WithBaseEndpoint(env.BaseURL()),
	)
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	bucket := "sdk-policy-cond"
	_, err = client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: &bucket})
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    strp("key.txt"),
		Body:   strings.NewReader("policy"),
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	secureOnlyPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::` + bucket + `/*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}`
	_, err = client.PutBucketPolicy(context.Background(), &s3.PutBucketPolicyInput{
		Bucket: &bucket,
		Policy: &secureOnlyPolicy,
	})
	if err != nil {
		t.Fatalf("PutBucketPolicy secure-only: %v", err)
	}

	_, err = client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: strp("key.txt")})
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for non-TLS sdk request under aws:SecureTransport policy, got %v", err)
	}

	sourceIPPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::` + bucket + `/*","Condition":{"IpAddress":{"aws:SourceIp":"127.0.0.1/32"}}}]}`
	_, err = client.PutBucketPolicy(context.Background(), &s3.PutBucketPolicyInput{
		Bucket: &bucket,
		Policy: &sourceIPPolicy,
	})
	if err != nil {
		t.Fatalf("PutBucketPolicy source-ip: %v", err)
	}
	get, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: strp("key.txt")})
	if err != nil {
		t.Fatalf("GetObject source-ip allowed: %v", err)
	}
	_ = get.Body.Close()
}

func TestAWSSDKBucketPolicyComplexPrincipalCompatibility(t *testing.T) {
	t.Parallel()
	env := integration.NewCompatEnv(t)

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-west-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("AKIAFULL", "secret-full", "")),
		awsconfig.WithBaseEndpoint(env.BaseURL()),
	)
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	bucket := "sdk-policy-complex"
	_, err = client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: &bucket})
	if err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	_, err = client.PutObject(context.Background(), &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    strp("key.txt"),
		Body:   strings.NewReader("value"),
	})
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	policyDoc := `{"Version":"2012-10-17","Statement":[
{"Effect":"Allow","Principal":{"AWS":"arn:storas:iam::local:user/*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::sdk-policy-complex/*","Condition":{"ArnLike":{"aws:PrincipalArn":"arn:storas:iam::local:user/full"}}},
{"Effect":"Deny","NotPrincipal":{"AWS":"AKIAFULL"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::sdk-policy-complex/*"}
]}`
	_, err = client.PutBucketPolicy(context.Background(), &s3.PutBucketPolicyInput{
		Bucket: &bucket,
		Policy: &policyDoc,
	})
	if err != nil {
		t.Fatalf("PutBucketPolicy complex: %v", err)
	}

	get, err := client.GetObject(context.Background(), &s3.GetObjectInput{Bucket: &bucket, Key: strp("key.txt")})
	if err != nil {
		t.Fatalf("GetObject complex policy: %v", err)
	}
	_ = get.Body.Close()
}

func strp(v string) *string { return &v }

func int32p(v int32) *int32 { return &v }
