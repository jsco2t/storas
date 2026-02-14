package policy

import (
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseAndEvaluatePolicy(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[
    {"Effect":"Allow","Principal":{"AWS":"AKIAFULL"},"Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::bucket-a/*"]},
    {"Effect":"Deny","Principal":"*","Action":"s3:DeleteObject","Resource":"arn:aws:s3:::bucket-a/private/*"}
  ]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	allow := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{})
	if !allow.Allowed || allow.Denied {
		t.Fatalf("expected allow decision, got %+v", allow)
	}
	deny := Evaluate(doc, []string{"AKIAFULL"}, "s3:DeleteObject", "arn:aws:s3:::bucket-a/private/file.txt", EvaluationContext{})
	if !deny.Denied {
		t.Fatalf("expected explicit deny decision, got %+v", deny)
	}
}

func TestParseAndEvaluateNotPrincipal(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[
    {"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-a/*"},
    {"Effect":"Deny","NotPrincipal":{"AWS":"AKIAFULL"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-a/*"}
  ]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	allowed := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{})
	if !allowed.Allowed || allowed.Denied {
		t.Fatalf("expected allow without deny for excluded NotPrincipal, got %+v", allowed)
	}
	denied := Evaluate(doc, []string{"AKIAOTHER"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{})
	if !denied.Allowed || !denied.Denied {
		t.Fatalf("expected allow+deny decision for non-excluded NotPrincipal, got %+v", denied)
	}
}

func TestParseAndValidateRejectsPrincipalAndNotPrincipalTogether(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":{"Effect":"Allow","Principal":"*","NotPrincipal":{"AWS":"AKIAFULL"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-a/*"}
}`)
	if _, err := ParseAndValidate(raw, "bucket-a"); err == nil {
		t.Fatal("expected Principal+NotPrincipal rejection")
	}
}

func TestParseAndValidateRejectsCrossBucketResource(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::other-bucket/*"}
}`)
	if _, err := ParseAndValidate(raw, "bucket-a"); err == nil {
		t.Fatal("expected cross-bucket policy resource rejection")
	}
}

func TestIsPublic(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-a/*"}
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	if !IsPublic(doc) {
		t.Fatal("expected public policy status")
	}
}

func TestParseAndEvaluatePolicyConditions(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Principal":"*",
      "Action":"s3:GetObject",
      "Resource":"arn:aws:s3:::bucket-a/*",
      "Condition":{"Bool":{"aws:SecureTransport":"true"}}
    },
    {
      "Effect":"Deny",
      "Principal":"*",
      "Action":"s3:GetObject",
      "Resource":"arn:aws:s3:::bucket-a/*",
      "Condition":{"IpAddress":{"aws:SourceIp":["10.0.0.0/8","192.168.1.5"]}}
    }
  ]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}

	allowed := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		SecureTransport: true,
		SourceIP:        net.ParseIP("203.0.113.20"),
	})
	if !allowed.Allowed || allowed.Denied {
		t.Fatalf("expected allow decision for secure public access, got %+v", allowed)
	}

	insecure := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		SecureTransport: false,
		SourceIP:        net.ParseIP("203.0.113.20"),
	})
	if insecure.Allowed || insecure.Denied {
		t.Fatalf("expected implicit deny for insecure transport, got %+v", insecure)
	}

	deniedByIP := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		SecureTransport: true,
		SourceIP:        net.ParseIP("10.2.3.4"),
	})
	if !deniedByIP.Denied {
		t.Fatalf("expected explicit deny for blocked source ip, got %+v", deniedByIP)
	}
}

func TestEvaluatePolicyConditionsWithMultipleOperators(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{
      "Bool":{"aws:SecureTransport":"true"},
      "NotIpAddress":{"aws:SourceIp":"10.0.0.0/8"},
      "StringEquals":{"s3:RequestHeader/X-Env":"prod"}
    }
  }]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	match := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		SecureTransport: true,
		SourceIP:        net.ParseIP("203.0.113.10"),
		Headers:         map[string][]string{"X-Env": []string{"prod"}},
	})
	if !match.Allowed {
		t.Fatalf("expected allow for matching multi-operator conditions, got %+v", match)
	}
	noHeader := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		SecureTransport: true,
		SourceIP:        net.ParseIP("203.0.113.10"),
	})
	if noHeader.Allowed || noHeader.Denied {
		t.Fatalf("expected implicit deny when header condition missing, got %+v", noHeader)
	}
}

func TestParseAndValidateRejectsUnsupportedConditionOperator(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"BinaryEquals":{"s3:max-keys":"1"}}
  }]
}`)
	if _, err := ParseAndValidate(raw, "bucket-a"); err == nil {
		t.Fatal("expected unsupported condition operator rejection")
	}
}

func TestParseAndValidateRejectsMalformedCIDRCondition(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"IpAddress":{"aws:SourceIp":"not-a-cidr"}}
  }]
}`)
	if _, err := ParseAndValidate(raw, "bucket-a"); err == nil {
		t.Fatal("expected malformed cidr condition rejection")
	}
}

func TestParseAndEvaluateStringLikeConditions(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:ListBucket",
    "Resource":"arn:aws:s3:::bucket-a",
    "Condition":{"StringLike":{"s3:prefix":"photos/*"}}
  }]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	allow := Evaluate(doc, []string{"AKIAFULL"}, "s3:ListBucket", "arn:aws:s3:::bucket-a", EvaluationContext{
		Attributes: map[string]string{"s3:prefix": "photos/2026/"},
	})
	if !allow.Allowed || allow.Denied {
		t.Fatalf("expected StringLike allow decision, got %+v", allow)
	}
	deny := Evaluate(doc, []string{"AKIAFULL"}, "s3:ListBucket", "arn:aws:s3:::bucket-a", EvaluationContext{
		Attributes: map[string]string{"s3:prefix": "videos/"},
	})
	if deny.Allowed || deny.Denied {
		t.Fatalf("expected implicit deny for non-matching StringLike, got %+v", deny)
	}
}

func TestParseAndEvaluateNullConditions(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"Null":{"s3:VersionId":"true"}}
  }]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	noVersion := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		Attributes: map[string]string{},
	})
	if !noVersion.Allowed || noVersion.Denied {
		t.Fatalf("expected allow when versionId is absent, got %+v", noVersion)
	}
	withVersion := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		Attributes: map[string]string{"s3:VersionId": "v1"},
	})
	if withVersion.Allowed || withVersion.Denied {
		t.Fatalf("expected implicit deny when versionId is present, got %+v", withVersion)
	}
}

func TestParseAndEvaluatePrincipalConditionKeys(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{
      "StringEquals":{"aws:userid":"AKIAFULL"},
      "StringLike":{"aws:PrincipalArn":"arn:storas:iam::local:user/*"}
    }
  }]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	allow := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		Attributes: map[string]string{
			"aws:userid":       "AKIAFULL",
			"aws:PrincipalArn": "arn:storas:iam::local:user/full",
		},
	})
	if !allow.Allowed || allow.Denied {
		t.Fatalf("expected allow for matching principal attributes, got %+v", allow)
	}
	deny := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		Attributes: map[string]string{
			"aws:userid":       "AKIAOTHER",
			"aws:PrincipalArn": "arn:storas:iam::local:user/other",
		},
	})
	if deny.Allowed || deny.Denied {
		t.Fatalf("expected implicit deny for non-matching principal attributes, got %+v", deny)
	}
}

func TestParseAndEvaluateAdditionalStringConditionKeys(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{
      "StringEquals":{
        "aws:PrincipalAccount":"local",
        "s3:authType":"REST-HEADER",
        "s3:signatureversion":"AWS4-HMAC-SHA256"
      }
    }
  }]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	allow := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		Attributes: map[string]string{
			"aws:PrincipalAccount": "local",
			"s3:authType":          "REST-HEADER",
			"s3:signatureversion":  "AWS4-HMAC-SHA256",
		},
	})
	if !allow.Allowed || allow.Denied {
		t.Fatalf("expected allow for supported extra condition keys, got %+v", allow)
	}
}

func TestParseAndEvaluatePrincipalObjectForms(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[
    {"Effect":"Allow","Principal":{"AWS":["arn:storas:iam::local:user/*","AKIA*"],"CanonicalUser":"canon-1","Federated":"fed-user","Service":"storage.local"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::bucket-a/*"}
  ]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	allowByArnWildcard := Evaluate(doc, []string{"arn:storas:iam::local:user/full"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{})
	if !allowByArnWildcard.Allowed {
		t.Fatalf("expected allow by arn wildcard principal, got %+v", allowByArnWildcard)
	}
	allowByAccessKeyWildcard := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{})
	if !allowByAccessKeyWildcard.Allowed {
		t.Fatalf("expected allow by access-key wildcard principal, got %+v", allowByAccessKeyWildcard)
	}
}

func TestParseAndValidateConditionDiagnosticsIncludeOperatorAndKey(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"BinaryEquals":{"s3:max-keys":"1"}}
  }]
}`)
	_, err := ParseAndValidate(raw, "bucket-a")
	if err == nil {
		t.Fatal("expected unsupported operator rejection")
	}
	if !strings.Contains(err.Error(), "BinaryEquals") {
		t.Fatalf("expected operator name in diagnostic, got: %v", err)
	}

	raw = []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"ArnLike":{"aws:SourceIp":"arn:storas:iam::local:user/*"}}
  }]
}`)
	_, err = ParseAndValidate(raw, "bucket-a")
	if err == nil {
		t.Fatal("expected unsupported arn key rejection")
	}
	if !strings.Contains(err.Error(), "aws:SourceIp") {
		t.Fatalf("expected condition key in diagnostic, got: %v", err)
	}
}

func TestParseAndValidateRejectsInvalidNullConditionValue(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"Null":{"s3:VersionId":"maybe"}}
  }]
}`)
	if _, err := ParseAndValidate(raw, "bucket-a"); err == nil {
		t.Fatal("expected invalid Null condition value rejection")
	}
}

func TestIsPublicWithCondition(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"Bool":{"aws:SecureTransport":"true"}}
  }]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	if !IsPublic(doc) {
		t.Fatal("expected conditional secure-transport policy to be public")
	}
}

func TestParseAndEvaluateNumericConditions(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:ListBucket",
    "Resource":"arn:aws:s3:::bucket-a",
    "Condition":{
      "NumericLessThanEquals":{"s3:max-keys":"100"},
      "NumericGreaterThan":{"s3:signatureAge":"0"}
    }
  }]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	allow := Evaluate(doc, []string{"AKIAFULL"}, "s3:ListBucket", "arn:aws:s3:::bucket-a", EvaluationContext{
		Attributes: map[string]string{
			"s3:max-keys":     "50",
			"s3:signatureAge": "2500",
		},
	})
	if !allow.Allowed || allow.Denied {
		t.Fatalf("expected numeric condition allow decision, got %+v", allow)
	}
	deny := Evaluate(doc, []string{"AKIAFULL"}, "s3:ListBucket", "arn:aws:s3:::bucket-a", EvaluationContext{
		Attributes: map[string]string{
			"s3:max-keys":     "500",
			"s3:signatureAge": "2500",
		},
	})
	if deny.Allowed || deny.Denied {
		t.Fatalf("expected implicit deny for non-matching numeric condition, got %+v", deny)
	}
}

func TestParseAndEvaluateDateConditions(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{
      "DateGreaterThanEquals":{"aws:CurrentTime":"2026-02-14T12:00:00Z"},
      "DateLessThan":{"aws:CurrentTime":"2026-02-14T13:00:00Z"}
    }
  }]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	allow := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		CurrentTime: time.Date(2026, 2, 14, 12, 30, 0, 0, time.UTC),
	})
	if !allow.Allowed || allow.Denied {
		t.Fatalf("expected date condition allow decision, got %+v", allow)
	}
	deny := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		CurrentTime: time.Date(2026, 2, 14, 14, 0, 0, 0, time.UTC),
	})
	if deny.Allowed || deny.Denied {
		t.Fatalf("expected implicit deny for non-matching date condition, got %+v", deny)
	}
}

func TestParseAndValidateRejectsMalformedNumericCondition(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:ListBucket",
    "Resource":"arn:aws:s3:::bucket-a",
    "Condition":{"NumericGreaterThan":{"s3:max-keys":"ten"}}
  }]
}`)
	if _, err := ParseAndValidate(raw, "bucket-a"); err == nil {
		t.Fatal("expected malformed numeric condition rejection")
	}
}

func TestParseAndValidateRejectsMalformedDateCondition(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"DateLessThan":{"aws:CurrentTime":"2026-02-14"}}
  }]
}`)
	if _, err := ParseAndValidate(raw, "bucket-a"); err == nil {
		t.Fatal("expected malformed date condition rejection")
	}
}

func TestParseAndValidateRejectsUnsupportedNumericConditionKey(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"NumericEquals":{"aws:SecureTransport":"1"}}
  }]
}`)
	if _, err := ParseAndValidate(raw, "bucket-a"); err == nil {
		t.Fatal("expected unsupported numeric condition key rejection")
	}
}

func TestParseAndValidateRejectsUnsupportedDateConditionKey(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"DateGreaterThan":{"s3:VersionId":"2026-02-14T12:00:00Z"}}
  }]
}`)
	if _, err := ParseAndValidate(raw, "bucket-a"); err == nil {
		t.Fatal("expected unsupported date condition key rejection")
	}
}

func TestParseAndEvaluateStringEqualsIfExistsCondition(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"StringEqualsIfExists":{"s3:VersionId":"v1"}}
  }]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	missing := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{})
	if !missing.Allowed || missing.Denied {
		t.Fatalf("expected allow when key missing with IfExists, got %+v", missing)
	}
	mismatch := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		Attributes: map[string]string{"s3:VersionId": "v2"},
	})
	if mismatch.Allowed || mismatch.Denied {
		t.Fatalf("expected implicit deny for non-matching IfExists key value, got %+v", mismatch)
	}
}

func TestParseAndEvaluateForAnyValueStringEquals(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"ForAnyValue:StringEquals":{"s3:RequestHeader/X-Role":["prod","ops"]}}
  }]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	allow := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		Headers: map[string][]string{
			"X-Role": {"dev", "prod"},
		},
	})
	if !allow.Allowed || allow.Denied {
		t.Fatalf("expected allow for ForAnyValue:StringEquals, got %+v", allow)
	}
}

func TestParseAndEvaluateForAllValuesStringLike(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"ForAllValues:StringLike":{"s3:RequestHeader/X-Team":"ops-*"}}
  }]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	allow := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		Headers: map[string][]string{
			"X-Team": {"ops-core", "ops-prod"},
		},
	})
	if !allow.Allowed || allow.Denied {
		t.Fatalf("expected allow for ForAllValues:StringLike, got %+v", allow)
	}
	deny := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		Headers: map[string][]string{
			"X-Team": {"ops-core", "dev"},
		},
	})
	if deny.Allowed || deny.Denied {
		t.Fatalf("expected implicit deny for ForAllValues mismatch, got %+v", deny)
	}
}

func TestParseAndValidateRejectsUnsupportedQualifierOperatorCombo(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"ForAnyValue:StringNotEquals":{"s3:VersionId":"v1"}}
  }]
}`)
	if _, err := ParseAndValidate(raw, "bucket-a"); err == nil {
		t.Fatal("expected unsupported qualifier/operator combo rejection")
	}
}

func TestParseAndValidateRejectsNullIfExists(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"NullIfExists":{"s3:VersionId":"true"}}
  }]
}`)
	if _, err := ParseAndValidate(raw, "bucket-a"); err == nil {
		t.Fatal("expected unsupported IfExists operator rejection")
	}
}

func TestParseAndEvaluateArnConditionOperators(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Principal":"*",
      "Action":"s3:GetObject",
      "Resource":"arn:aws:s3:::bucket-a/*",
      "Condition":{"ArnLike":{"aws:PrincipalArn":"arn:storas:iam::local:user/*"}}
    },
    {
      "Effect":"Deny",
      "Principal":"*",
      "Action":"s3:GetObject",
      "Resource":"arn:aws:s3:::bucket-a/*",
      "Condition":{"ArnEquals":{"aws:PrincipalArn":"arn:storas:iam::local:user/blocked"}}
    }
  ]
}`)
	doc, err := ParseAndValidate(raw, "bucket-a")
	if err != nil {
		t.Fatalf("ParseAndValidate error: %v", err)
	}
	allowed := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		Attributes: map[string]string{"aws:PrincipalArn": "arn:storas:iam::local:user/full"},
	})
	if !allowed.Allowed || allowed.Denied {
		t.Fatalf("expected ArnLike allow decision, got %+v", allowed)
	}
	denied := Evaluate(doc, []string{"AKIAFULL"}, "s3:GetObject", "arn:aws:s3:::bucket-a/file.txt", EvaluationContext{
		Attributes: map[string]string{"aws:PrincipalArn": "arn:storas:iam::local:user/blocked"},
	})
	if !denied.Denied {
		t.Fatalf("expected ArnEquals explicit deny decision, got %+v", denied)
	}
}

func TestParseAndValidateRejectsUnsupportedArnConditionKey(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
  "Version":"2012-10-17",
  "Statement":[{
    "Effect":"Allow",
    "Principal":"*",
    "Action":"s3:GetObject",
    "Resource":"arn:aws:s3:::bucket-a/*",
    "Condition":{"ArnLike":{"aws:SourceIp":"arn:storas:iam::local:user/*"}}
  }]
}`)
	if _, err := ParseAndValidate(raw, "bucket-a"); err == nil {
		t.Fatal("expected unsupported Arn condition key rejection")
	}
}
