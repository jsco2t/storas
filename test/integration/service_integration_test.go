package integration

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"

	"storas/internal/api"
	"storas/internal/authz"
	"storas/internal/config"
	"storas/internal/runtime"
	"storas/internal/sigv4"
	"storas/internal/storage"
	runtimeacme "storas/internal/tls/acme"
)

func TestIntegrationBucketLifecycle(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)

	env.mustReq(http.MethodPut, "/bk-lifecycle", nil, http.StatusOK)
	env.mustReq(http.MethodHead, "/bk-lifecycle", nil, http.StatusOK)
	env.mustReq(http.MethodDelete, "/bk-lifecycle", nil, http.StatusNoContent)
}

func TestIntegrationObjectLifecycle(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)
	env.mustReq(http.MethodPut, "/bk-obj", nil, http.StatusOK)
	env.mustReq(http.MethodPut, "/bk-obj/key.txt", bytes.NewBufferString("value"), http.StatusOK)
	get := env.mustReq(http.MethodGet, "/bk-obj/key.txt", nil, http.StatusOK)
	if get.Body.String() != "value" {
		t.Fatalf("unexpected payload: %q", get.Body.String())
	}
	env.mustReq(http.MethodDelete, "/bk-obj/key.txt", nil, http.StatusNoContent)
}

func TestIntegrationAuthorizationAllowDeny(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)
	env.mustReq(http.MethodPut, "/allow-bucket", nil, http.StatusOK)

	readonlyReq := env.newSignedRequest(http.MethodPut, "/deny-bucket", nil, "AKIAREAD", "secret-read", "")
	res := httptest.NewRecorder()
	env.handler.ServeHTTP(res, readonlyReq)
	if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "AccessDenied") {
		t.Fatalf("expected AccessDenied for readonly principal, got status=%d body=%s", res.Code, res.Body.String())
	}
}

func TestIntegrationPathAndVirtualHostedStyle(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)
	env.mustReq(http.MethodPut, "/vh-bucket", nil, http.StatusOK)
	env.mustReq(http.MethodPut, "/vh-bucket/path.txt", bytes.NewBufferString("vh"), http.StatusOK)

	vhReq := env.newSignedRequest(http.MethodGet, "/path.txt", nil, "AKIAFULL", "secret-full", "vh-bucket.storage.local")
	res := httptest.NewRecorder()
	env.handler.ServeHTTP(res, vhReq)
	if res.Code != http.StatusOK || res.Body.String() != "vh" {
		t.Fatalf("virtual-hosted style failed status=%d body=%s", res.Code, res.Body.String())
	}
}

func TestIntegrationRangeAndCopyBehavior(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)
	env.mustReq(http.MethodPut, "/src-b", nil, http.StatusOK)
	env.mustReq(http.MethodPut, "/dst-b", nil, http.StatusOK)
	env.mustReq(http.MethodPut, "/src-b/key.txt", bytes.NewBufferString("0123456789"), http.StatusOK)

	rangeReq := env.newSignedRequest(http.MethodGet, "/src-b/key.txt", nil, "AKIAFULL", "secret-full", "")
	rangeReq.Header.Set("Range", "bytes=3-5")
	res := httptest.NewRecorder()
	env.handler.ServeHTTP(res, rangeReq)
	if res.Code != http.StatusPartialContent || res.Body.String() != "345" {
		t.Fatalf("range get failed status=%d body=%s", res.Code, res.Body.String())
	}

	copyReq := env.newSignedRequest(http.MethodPut, "/dst-b/copied.txt", nil, "AKIAFULL", "secret-full", "")
	copyReq.Header.Set("X-Amz-Copy-Source", "/src-b/key.txt")
	copyRes := httptest.NewRecorder()
	env.handler.ServeHTTP(copyRes, copyReq)
	if copyRes.Code != http.StatusOK {
		t.Fatalf("copy failed status=%d body=%s", copyRes.Code, copyRes.Body.String())
	}
}

func TestIntegrationCanonicalErrorCases(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)

	unknownBucket := env.mustReq(http.MethodGet, "/missing-b/missing.txt", nil, http.StatusNotFound)
	if !strings.Contains(unknownBucket.Body.String(), "NoSuchBucket") {
		t.Fatalf("expected NoSuchBucket, got %s", unknownBucket.Body.String())
	}

	invalidSigReq := env.newSignedRequest(http.MethodGet, "/", nil, "AKIAFULL", "wrong-secret", "")
	res := httptest.NewRecorder()
	env.handler.ServeHTTP(res, invalidSigReq)
	if res.Code != http.StatusForbidden || !strings.Contains(res.Body.String(), "SignatureDoesNotMatch") {
		t.Fatalf("expected SignatureDoesNotMatch, got status=%d body=%s", res.Code, res.Body.String())
	}

	var parsed struct {
		XMLName xml.Name `xml:"Error"`
		Code    string   `xml:"Code"`
	}
	if err := xml.Unmarshal(res.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("error body is not valid XML: %v", err)
	}

	deleteMissingBucket := env.mustReq(http.MethodDelete, "/missing-b/ghost.txt", nil, http.StatusNotFound)
	if !strings.Contains(deleteMissingBucket.Body.String(), "NoSuchBucket") {
		t.Fatalf("expected NoSuchBucket on delete-object missing bucket, got %s", deleteMissingBucket.Body.String())
	}
}

func TestIntegrationVersioningPutGetDeleteMarkers(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)
	env.mustReq(http.MethodPut, "/ver-int", nil, http.StatusOK)
	enableBody := bytes.NewBufferString(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
	env.mustReq(http.MethodPut, "/ver-int?versioning", enableBody, http.StatusOK)

	put1 := env.mustReq(http.MethodPut, "/ver-int/key.txt", bytes.NewBufferString("v1"), http.StatusOK)
	v1 := put1.Header().Get("x-amz-version-id")
	if v1 == "" {
		t.Fatal("expected version id on first put")
	}
	put2 := env.mustReq(http.MethodPut, "/ver-int/key.txt", bytes.NewBufferString("v2"), http.StatusOK)
	v2 := put2.Header().Get("x-amz-version-id")
	if v2 == "" || v2 == v1 {
		t.Fatalf("expected distinct version id on second put, v1=%q v2=%q", v1, v2)
	}

	getV1 := env.mustReq(http.MethodGet, "/ver-int/key.txt?versionId="+url.QueryEscape(v1), nil, http.StatusOK)
	if getV1.Body.String() != "v1" {
		t.Fatalf("expected v1 body, got %q", getV1.Body.String())
	}
	headV2 := env.mustReq(http.MethodHead, "/ver-int/key.txt?versionId="+url.QueryEscape(v2), nil, http.StatusOK)
	if headV2.Header().Get("x-amz-version-id") != v2 {
		t.Fatalf("expected head version header %q, got %q", v2, headV2.Header().Get("x-amz-version-id"))
	}
	env.mustReq(http.MethodGet, "/ver-int?versions", nil, http.StatusOK)

	del := env.mustReq(http.MethodDelete, "/ver-int/key.txt", nil, http.StatusNoContent)
	if del.Header().Get("x-amz-delete-marker") != "true" {
		t.Fatalf("expected delete marker header, got %q", del.Header().Get("x-amz-delete-marker"))
	}

	suspendedBody := bytes.NewBufferString(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Suspended</Status></VersioningConfiguration>`)
	env.mustReq(http.MethodPut, "/ver-int?versioning", suspendedBody, http.StatusOK)
	delSuspended := env.mustReq(http.MethodDelete, "/ver-int/key.txt", nil, http.StatusNoContent)
	if delSuspended.Header().Get("x-amz-delete-marker") != "true" {
		t.Fatalf("expected delete marker header in suspended state, got %q", delSuspended.Header().Get("x-amz-delete-marker"))
	}
}

func TestIntegrationLifecycleConfigurationCRUD(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)
	env.mustReq(http.MethodPut, "/life-int", nil, http.StatusOK)

	missing := env.mustReq(http.MethodGet, "/life-int?lifecycle", nil, http.StatusNotFound)
	if !strings.Contains(missing.Body.String(), "NoSuchLifecycleConfiguration") {
		t.Fatalf("expected NoSuchLifecycleConfiguration, got %s", missing.Body.String())
	}

	body := bytes.NewBufferString(`<LifecycleConfiguration><Rule><ID>rule-1</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>14</Days></Expiration></Rule></LifecycleConfiguration>`)
	env.mustReq(http.MethodPut, "/life-int?lifecycle", body, http.StatusOK)

	got := env.mustReq(http.MethodGet, "/life-int?lifecycle", nil, http.StatusOK)
	if !strings.Contains(got.Body.String(), "<ID>rule-1</ID>") {
		t.Fatalf("expected persisted lifecycle rule, got %s", got.Body.String())
	}

	env.mustReq(http.MethodDelete, "/life-int?lifecycle", nil, http.StatusNoContent)

	missingAfterDelete := env.mustReq(http.MethodGet, "/life-int?lifecycle", nil, http.StatusNotFound)
	if !strings.Contains(missingAfterDelete.Body.String(), "NoSuchLifecycleConfiguration") {
		t.Fatalf("expected NoSuchLifecycleConfiguration after delete, got %s", missingAfterDelete.Body.String())
	}
}

func TestIntegrationLifecycleAdvancedFilterAndDateExpiration(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)
	env.mustReq(http.MethodPut, "/life-adv-int", nil, http.StatusOK)

	lifeBody := bytes.NewBufferString(`<LifecycleConfiguration><Rule><ID>advanced</ID><Status>Enabled</Status><Filter><And><Prefix>logs/</Prefix><Tag><Key>env</Key><Value>prod</Value></Tag><ObjectSizeGreaterThan>3</ObjectSizeGreaterThan><ObjectSizeLessThan>12</ObjectSizeLessThan></And></Filter><Expiration><Date>2026-02-16T00:00:00Z</Date></Expiration><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule></LifecycleConfiguration>`)
	env.mustReq(http.MethodPut, "/life-adv-int?lifecycle", lifeBody, http.StatusOK)

	getLife := env.mustReq(http.MethodGet, "/life-adv-int?lifecycle", nil, http.StatusOK)
	if !strings.Contains(getLife.Body.String(), "<ObjectSizeGreaterThan>3</ObjectSizeGreaterThan>") ||
		!strings.Contains(getLife.Body.String(), "<ObjectSizeLessThan>12</ObjectSizeLessThan>") ||
		!strings.Contains(getLife.Body.String(), "<Date>2026-02-16T00:00:00Z</Date>") {
		t.Fatalf("expected advanced lifecycle fields in response, got %s", getLife.Body.String())
	}

	enableBody := bytes.NewBufferString(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
	env.mustReq(http.MethodPut, "/life-adv-int?versioning", enableBody, http.StatusOK)
	putOne := env.newSignedRequest(http.MethodPut, "/life-adv-int/logs/match.txt", bytes.NewBufferString("v1111"), "AKIAFULL", "secret-full", "")
	putOne.Header.Set("x-amz-tagging", "env=prod")
	resOne := httptest.NewRecorder()
	env.handler.ServeHTTP(resOne, putOne)
	if resOne.Code != http.StatusOK {
		t.Fatalf("first advanced tagged put failed status=%d body=%s", resOne.Code, resOne.Body.String())
	}
	putTwo := env.newSignedRequest(http.MethodPut, "/life-adv-int/logs/match.txt", bytes.NewBufferString("v2222"), "AKIAFULL", "secret-full", "")
	putTwo.Header.Set("x-amz-tagging", "env=prod")
	resTwo := httptest.NewRecorder()
	env.handler.ServeHTTP(resTwo, putTwo)
	if resTwo.Code != http.StatusOK {
		t.Fatalf("second advanced tagged put failed status=%d body=%s", resTwo.Code, resTwo.Body.String())
	}
	putMiss := env.newSignedRequest(http.MethodPut, "/life-adv-int/logs/miss.txt", bytes.NewBufferString("no"), "AKIAFULL", "secret-full", "")
	putMiss.Header.Set("x-amz-tagging", "env=prod")
	resMiss := httptest.NewRecorder()
	env.handler.ServeHTTP(resMiss, putMiss)
	if resMiss.Code != http.StatusOK {
		t.Fatalf("third advanced tagged put failed status=%d body=%s", resMiss.Code, resMiss.Body.String())
	}

	res, err := env.backend.SweepLifecycle(context.Background(), time.Date(2026, 2, 17, 0, 0, 0, 0, time.UTC), storage.LifecycleSweepOptions{})
	if err != nil {
		t.Fatalf("SweepLifecycle error: %v", err)
	}
	if res.ActionsExecuted == 0 {
		t.Fatalf("expected advanced lifecycle sweep actions, got %+v", res)
	}

	matchGet := env.mustReq(http.MethodGet, "/life-adv-int/logs/match.txt", nil, http.StatusNotFound)
	if !strings.Contains(matchGet.Body.String(), "NoSuchKey") {
		t.Fatalf("expected advanced filter object expiration, got %s", matchGet.Body.String())
	}
	remain := env.mustReq(http.MethodGet, "/life-adv-int/logs/miss.txt", nil, http.StatusOK)
	if remain.Body.String() != "no" {
		t.Fatalf("expected non-matching object to remain, got %q", remain.Body.String())
	}
}

func TestIntegrationLifecycleExpirationDeterministicSweep(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)
	env.mustReq(http.MethodPut, "/life-expire", nil, http.StatusOK)
	enableBody := bytes.NewBufferString(`<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
	env.mustReq(http.MethodPut, "/life-expire?versioning", enableBody, http.StatusOK)
	env.mustReq(http.MethodPut, "/life-expire/logs/key.txt", bytes.NewBufferString("v1"), http.StatusOK)
	env.mustReq(http.MethodPut, "/life-expire/logs/key.txt", bytes.NewBufferString("v2"), http.StatusOK)

	create := env.mustReq(http.MethodPost, "/life-expire/logs/mp.txt?uploads=", nil, http.StatusOK)
	var created struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create multipart response: %v", err)
	}
	if created.UploadID == "" {
		t.Fatal("expected multipart upload id")
	}

	lifeBody := bytes.NewBufferString(`<LifecycleConfiguration><Rule><ID>rule-expire</ID><Status>Enabled</Status><Filter><Prefix>logs/</Prefix></Filter><Expiration><Days>1</Days></Expiration><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration><AbortIncompleteMultipartUpload><DaysAfterInitiation>1</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule></LifecycleConfiguration>`)
	env.mustReq(http.MethodPut, "/life-expire?lifecycle", lifeBody, http.StatusOK)

	sweepAt := time.Now().UTC().Add(72 * time.Hour)
	res, err := env.backend.SweepLifecycle(context.Background(), sweepAt, storage.LifecycleSweepOptions{})
	if err != nil {
		t.Fatalf("SweepLifecycle error: %v", err)
	}
	if res.ActionsExecuted == 0 {
		t.Fatal("expected lifecycle sweep actions")
	}

	notFound := env.mustReq(http.MethodGet, "/life-expire/logs/key.txt", nil, http.StatusNotFound)
	if !strings.Contains(notFound.Body.String(), "NoSuchKey") {
		t.Fatalf("expected NoSuchKey after expiration, got %s", notFound.Body.String())
	}
	versions := env.mustReq(http.MethodGet, "/life-expire?versions", nil, http.StatusOK)
	if strings.Count(versions.Body.String(), "<Version>") > 1 {
		t.Fatalf("expected noncurrent version cleanup, got %s", versions.Body.String())
	}
	mp := env.mustReq(http.MethodGet, "/life-expire?uploads=", nil, http.StatusOK)
	if strings.Contains(mp.Body.String(), created.UploadID) {
		t.Fatalf("expected multipart upload aborted by lifecycle, got %s", mp.Body.String())
	}
}

func TestIntegrationListBucketsSDKParsesOwnerAndCreationDate(t *testing.T) {
	t.Parallel()
	env := NewCompatEnv(t)

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-west-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("AKIAFULL", "secret-full", "")),
		awsconfig.WithBaseEndpoint(env.BaseURL()),
	)
	if err != nil {
		t.Fatalf("load aws config: %v", err)
	}
	client := awss3.NewFromConfig(cfg, func(o *awss3.Options) {
		o.UsePathStyle = true
	})

	bucket := "sdk-list-bucket"
	if _, err := client.CreateBucket(context.Background(), &awss3.CreateBucketInput{Bucket: &bucket}); err != nil {
		t.Fatalf("CreateBucket: %v", err)
	}
	out, err := client.ListBuckets(context.Background(), &awss3.ListBucketsInput{})
	if err != nil {
		t.Fatalf("ListBuckets: %v", err)
	}
	if out.Owner == nil || out.Owner.ID == nil || *out.Owner.ID == "" {
		t.Fatalf("expected owner fields, got %#v", out.Owner)
	}
	if len(out.Buckets) == 0 || out.Buckets[0].CreationDate == nil {
		t.Fatalf("expected creation date fields, got %+v", out.Buckets)
	}
}

func TestIntegrationHTTPAndTLSStartupPaths(t *testing.T) {
	cfg := config.Default()
	cfg.Server.ListenAddress = freeListenAddr(t)
	cfg.Storage.DataDir = filepath.Join(t.TempDir(), "data")
	cfg.Auth.AuthorizationFile = filepath.Join(t.TempDir(), "authorization.yaml")

	h := http.NewServeMux()
	h.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })

	httpCfg := cfg
	httpCfg.TLS.Enabled = false
	httpSrv, err := runtime.New(httpCfg, h, nil)
	if err != nil {
		t.Fatalf("runtime.New HTTP: %v", err)
	}
	go func() { _ = httpSrv.Start() }()
	time.Sleep(80 * time.Millisecond)
	resp, err := http.Get("http://" + httpCfg.Server.ListenAddress + "/healthz")
	if err != nil {
		t.Fatalf("http startup request failed: %v", err)
	}
	_ = resp.Body.Close()
	_ = httpSrv.Shutdown(context.Background())

	tlsCfg := cfg
	tlsCfg.Server.ListenAddress = freeListenAddr(t)
	tlsCfg.TLS.Enabled = true
	tlsCfg.TLS.Mode = "self_signed"
	tlsSrv, err := runtime.New(tlsCfg, h, nil)
	if err != nil {
		t.Fatalf("runtime.New TLS: %v", err)
	}
	go func() { _ = tlsSrv.Start() }()
	time.Sleep(80 * time.Millisecond)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec
	resp, err = client.Get("https://" + tlsCfg.Server.ListenAddress + "/healthz")
	if err != nil {
		t.Fatalf("tls startup request failed: %v", err)
	}
	_ = resp.Body.Close()
	_ = tlsSrv.Shutdown(context.Background())

	manualCfg := cfg
	manualCfg.Server.ListenAddress = freeListenAddr(t)
	manualCfg.TLS.Enabled = true
	manualCfg.TLS.Mode = "manual"
	certFile := filepath.Join(t.TempDir(), "cert.pem")
	keyFile := filepath.Join(t.TempDir(), "key.pem")
	certPEM, keyPEM, certErr := generateCertPair("localhost")
	if certErr != nil {
		t.Fatalf("generate cert pair: %v", certErr)
	}
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	manualCfg.TLS.CertFile = certFile
	manualCfg.TLS.KeyFile = keyFile
	manualSrv, err := runtime.New(manualCfg, h, nil)
	if err != nil {
		t.Fatalf("runtime.New manual TLS: %v", err)
	}
	go func() { _ = manualSrv.Start() }()
	time.Sleep(80 * time.Millisecond)
	resp, err = client.Get("https://" + manualCfg.Server.ListenAddress + "/healthz")
	if err != nil {
		t.Fatalf("manual tls startup request failed: %v", err)
	}
	_ = resp.Body.Close()
	_ = manualSrv.Shutdown(context.Background())

	acmeCfg := cfg
	acmeCfg.Server.ListenAddress = freeListenAddr(t)
	acmeCfg.TLS.Enabled = true
	acmeCfg.TLS.Mode = "acme_dns"
	acmeCfg.TLS.ACMEDNS.Email = "ops@example.com"
	acmeCfg.TLS.ACMEDNS.DirectoryURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	acmeCfg.TLS.ACMEDNS.Provider = "cloudflare"
	acmeCfg.TLS.ACMEDNS.Domain = "storage.example.com"
	acmeCfg.TLS.ACMEDNS.Credentials.EnvPrefix = "STORAS_ACME_"
	acmeCfg.TLS.ACMEDNS.PropagationTimeoutSeconds = 60
	acmeCfg.TLS.ACMEDNS.RenewBeforeSeconds = 3600
	t.Setenv("STORAS_ACME_API_TOKEN", "token")
	restore := runtime.SetACMEManagerFactoryForTesting(func(config runtimeacme.Config, _ *slog.Logger) (runtimeacme.Manager, error) {
		return fakeIntegrationACMEManager{}, nil
	})
	defer restore()
	acmeSrv, err := runtime.New(acmeCfg, h, nil)
	if err != nil {
		t.Fatalf("runtime.New ACME DNS: %v", err)
	}
	go func() { _ = acmeSrv.Start() }()
	time.Sleep(80 * time.Millisecond)
	resp, err = client.Get("https://" + acmeCfg.Server.ListenAddress + "/healthz")
	if err != nil {
		t.Fatalf("acme tls startup request failed: %v", err)
	}
	_ = resp.Body.Close()
	_ = acmeSrv.Shutdown(context.Background())
}

type fakeIntegrationACMEManager struct{}

func (fakeIntegrationACMEManager) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	certPEM, keyPEM, err := generateCertPair("localhost")
	if err != nil {
		return nil, err
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &pair, nil
}

func (fakeIntegrationACMEManager) Stop() {}

func TestIntegrationHealthReadinessAndUnauthenticatedRequest(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)

	healthReq := httptest.NewRequest(http.MethodGet, "http://storage.local/healthz", nil)
	healthRes := httptest.NewRecorder()
	env.handler.ServeHTTP(healthRes, healthReq)
	if healthRes.Code != http.StatusOK {
		t.Fatalf("health status=%d body=%s", healthRes.Code, healthRes.Body.String())
	}

	readyReq := httptest.NewRequest(http.MethodGet, "http://storage.local/readyz", nil)
	readyRes := httptest.NewRecorder()
	env.handler.ServeHTTP(readyRes, readyReq)
	if readyRes.Code != http.StatusOK {
		t.Fatalf("ready status=%d body=%s", readyRes.Code, readyRes.Body.String())
	}

	unauthReq := httptest.NewRequest(http.MethodGet, "http://storage.local/", nil)
	unauthRes := httptest.NewRecorder()
	env.handler.ServeHTTP(unauthRes, unauthReq)
	if unauthRes.Code != http.StatusForbidden || !strings.Contains(unauthRes.Body.String(), "SignatureDoesNotMatch") {
		t.Fatalf("expected unauth request to be rejected, got status=%d body=%s", unauthRes.Code, unauthRes.Body.String())
	}
}

func TestIntegrationMultipartLifecycle(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)
	env.mustReq(http.MethodPut, "/mp-bucket", nil, http.StatusOK)

	create := env.mustReq(http.MethodPost, "/mp-bucket/obj.txt?uploads=", nil, http.StatusOK)
	var created struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create multipart: %v", err)
	}
	if created.UploadID == "" {
		t.Fatal("expected upload id")
	}

	p1 := env.mustReq(http.MethodPut, "/mp-bucket/obj.txt?partNumber=1&uploadId="+created.UploadID, bytes.NewBufferString("abc"), http.StatusOK)
	p2 := env.mustReq(http.MethodPut, "/mp-bucket/obj.txt?partNumber=2&uploadId="+created.UploadID, bytes.NewBufferString("123"), http.StatusOK)

	env.mustReq(http.MethodGet, "/mp-bucket?uploads=", nil, http.StatusOK)
	env.mustReq(http.MethodGet, "/mp-bucket/obj.txt?uploadId="+created.UploadID, nil, http.StatusOK)

	payload := `<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>` + p1.Header().Get("ETag") + `</ETag></Part><Part><PartNumber>2</PartNumber><ETag>` + p2.Header().Get("ETag") + `</ETag></Part></CompleteMultipartUpload>`
	env.mustReq(http.MethodPost, "/mp-bucket/obj.txt?uploadId="+created.UploadID, bytes.NewBufferString(payload), http.StatusOK)

	get := env.mustReq(http.MethodGet, "/mp-bucket/obj.txt", nil, http.StatusOK)
	if get.Body.String() != "abc123" {
		t.Fatalf("unexpected multipart object payload: %q", get.Body.String())
	}
}

func TestIntegrationMultipartInvalidPartOrder(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)
	env.mustReq(http.MethodPut, "/mp-order", nil, http.StatusOK)

	create := env.mustReq(http.MethodPost, "/mp-order/obj.txt?uploads=", nil, http.StatusOK)
	var created struct {
		UploadID string `xml:"UploadId"`
	}
	if err := xml.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create multipart: %v", err)
	}

	p1 := env.mustReq(http.MethodPut, "/mp-order/obj.txt?partNumber=1&uploadId="+created.UploadID, bytes.NewBufferString("abc"), http.StatusOK)
	p2 := env.mustReq(http.MethodPut, "/mp-order/obj.txt?partNumber=2&uploadId="+created.UploadID, bytes.NewBufferString("123"), http.StatusOK)

	payload := `<CompleteMultipartUpload><Part><PartNumber>2</PartNumber><ETag>` + p2.Header().Get("ETag") + `</ETag></Part><Part><PartNumber>1</PartNumber><ETag>` + p1.Header().Get("ETag") + `</ETag></Part></CompleteMultipartUpload>`
	res := env.mustReq(http.MethodPost, "/mp-order/obj.txt?uploadId="+created.UploadID, bytes.NewBufferString(payload), http.StatusBadRequest)
	if !strings.Contains(res.Body.String(), "InvalidPartOrder") {
		t.Fatalf("expected InvalidPartOrder, got %s", res.Body.String())
	}
}

func TestIntegrationStreamingSigV4Upload(t *testing.T) {
	t.Parallel()
	env := newIntegrationEnv(t)
	env.mustReq(http.MethodPut, "/stream-bucket", nil, http.StatusOK)

	req := env.newSignedRequestWithPayloadHash(http.MethodPut, "/stream-bucket/file.txt", nil, "AKIAFULL", "secret-full", "", sigv4.StreamingPayload)
	body := buildStreamingPayloadForRequest(req, "secret-full", []string{"alpha-", "beta"})
	req.Body = io.NopCloser(strings.NewReader(body))
	req.Header.Set("X-Amz-Decoded-Content-Length", strconv.Itoa(len("alpha-beta")))
	res := httptest.NewRecorder()
	env.handler.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("streaming put failed status=%d body=%s", res.Code, res.Body.String())
	}

	get := env.mustReq(http.MethodGet, "/stream-bucket/file.txt", nil, http.StatusOK)
	if get.Body.String() != "alpha-beta" {
		t.Fatalf("unexpected payload: %q", get.Body.String())
	}
}

type integrationEnv struct {
	t        *testing.T
	handler  http.Handler
	backend  *storage.FSBackend
	now      time.Time
	dataRoot string
}

func newIntegrationEnv(t *testing.T) *integrationEnv {
	t.Helper()
	now := time.Date(2026, 2, 13, 10, 0, 0, 0, time.UTC)
	dataRoot := filepath.Join(t.TempDir(), "data")
	backend, err := storage.NewFSBackend(dataRoot, 25*1024*1024*1024)
	if err != nil {
		t.Fatalf("NewFSBackend error: %v", err)
	}
	authPath := filepath.Join(t.TempDir(), "authorization.yaml")
	if err := os.WriteFile(authPath, []byte(authYAML), 0o600); err != nil {
		t.Fatalf("write auth file: %v", err)
	}
	engine, err := authz.LoadFile(authPath)
	if err != nil {
		t.Fatalf("LoadFile authz error: %v", err)
	}
	svc := &api.Service{Backend: backend, Authz: engine, Region: "us-west-1", ServiceName: "s3", ClockSkew: 15 * time.Minute, ServiceHost: "storage.local", Now: func() time.Time { return now }}
	return &integrationEnv{t: t, handler: svc.Handler(), backend: backend, now: now, dataRoot: dataRoot}
}

func (e *integrationEnv) mustReq(method, path string, body io.Reader, want int) *httptest.ResponseRecorder {
	e.t.Helper()
	req := e.newSignedRequest(method, path, body, "AKIAFULL", "secret-full", "")
	res := httptest.NewRecorder()
	e.handler.ServeHTTP(res, req)
	if res.Code != want {
		e.t.Fatalf("unexpected status=%d want=%d path=%s body=%s", res.Code, want, path, res.Body.String())
	}
	return res
}

func (e *integrationEnv) newSignedRequest(method, path string, body io.Reader, accessKey, secret, host string) *http.Request {
	e.t.Helper()
	req := httptest.NewRequest(method, "http://storage.local"+path, body)
	if host != "" {
		req.Host = host
	}
	signRequestWithPayloadHash(e.t, req, e.now, accessKey, secret, "us-west-1", "s3", "UNSIGNED-PAYLOAD")
	return req
}

func (e *integrationEnv) newSignedRequestWithPayloadHash(method, path string, body io.Reader, accessKey, secret, host, payloadHash string) *http.Request {
	e.t.Helper()
	req := httptest.NewRequest(method, "http://storage.local"+path, body)
	if host != "" {
		req.Host = host
	}
	signRequestWithPayloadHash(e.t, req, e.now, accessKey, secret, "us-west-1", "s3", payloadHash)
	return req
}

func signRequestWithPayloadHash(t *testing.T, req *http.Request, now time.Time, accessKey, secret, region, service, payloadHash string) {
	t.Helper()
	req.Header.Set("X-Amz-Date", now.UTC().Format(sigv4.DateFormat))
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}

	canonical, err := sigv4.BuildCanonicalRequest(req, signedHeaders, payloadHash)
	if err != nil {
		t.Fatalf("BuildCanonicalRequest: %v", err)
	}
	scope := sigv4.CredentialScope{AccessKey: accessKey, Date: now.UTC().Format("20060102"), Region: region, Service: service, Terminal: "aws4_request"}
	stringToSign := sigv4.BuildStringToSign(canonical, now.UTC(), scope)
	sig := sigv4.SignatureHex(sigv4.SigningKey(secret, scope.Date, scope.Region, scope.Service), stringToSign)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+scope.AccessKey+"/"+scope.Date+"/"+scope.Region+"/"+scope.Service+"/"+scope.Terminal+", SignedHeaders="+strings.Join(signedHeaders, ";")+", Signature="+sig)
}

func buildStreamingPayloadForRequest(req *http.Request, secret string, chunks []string) string {
	auth, err := sigv4.ParseAuthorizationHeader(req.Header.Get("Authorization"))
	if err != nil {
		return ""
	}
	signingKey := sigv4.SigningKey(secret, auth.Credential.Date, auth.Credential.Region, auth.Credential.Service)
	scope := fmt.Sprintf("%s/%s/%s/%s", auth.Credential.Date, auth.Credential.Region, auth.Credential.Service, auth.Credential.Terminal)
	requestDate := req.Header.Get("X-Amz-Date")
	prev := auth.Signature
	var out strings.Builder

	for _, chunk := range chunks {
		data := []byte(chunk)
		chunkSig := sigv4.SignatureHex(signingKey, strings.Join([]string{
			"AWS4-HMAC-SHA256-PAYLOAD",
			requestDate,
			scope,
			prev,
			sha256Hex(nil),
			sha256Hex(data),
		}, "\n"))
		_, _ = fmt.Fprintf(&out, "%x;chunk-signature=%s\r\n", len(data), chunkSig)
		out.Write(data)
		out.WriteString("\r\n")
		prev = chunkSig
	}
	finalSig := sigv4.SignatureHex(signingKey, strings.Join([]string{
		"AWS4-HMAC-SHA256-PAYLOAD",
		requestDate,
		scope,
		prev,
		sha256Hex(nil),
		sha256Hex(nil),
	}, "\n"))
	_, _ = fmt.Fprintf(&out, "0;chunk-signature=%s\r\n\r\n", finalSig)
	return out.String()
}

func sha256Hex(v []byte) string {
	sum := sha256.Sum256(v)
	return hex.EncodeToString(sum[:])
}

const authYAML = `users:
  - name: "full"
    access_key: "AKIAFULL"
    secret_key: "secret-full"
    allow:
      - action: "bucket:list"
        resource: "*"
      - action: "bucket:create"
        resource: "*"
      - action: "bucket:delete"
        resource: "*"
      - action: "bucket:head"
        resource: "*"
      - action: "object:list"
        resource: "*/*"
      - action: "object:put"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
      - action: "object:head"
        resource: "*/*"
      - action: "object:delete"
        resource: "*/*"
      - action: "object:copy"
        resource: "*/*"
  - name: "readonly"
    access_key: "AKIAREAD"
    secret_key: "secret-read"
    allow:
      - action: "bucket:list"
        resource: "*"
      - action: "bucket:head"
        resource: "*"
      - action: "object:list"
        resource: "*/*"
      - action: "object:get"
        resource: "*/*"
      - action: "object:head"
        resource: "*/*"
`

func freeListenAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate listen addr: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func generateCertPair(commonName string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{commonName, "localhost"},
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
