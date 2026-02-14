package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"storas/internal/storage"
)

const (
	s3ARNPrefix   = "arn:aws:s3:::"
	currentPolicy = "2012-10-17"
)

type Document struct {
	Version    string      `json:"Version,omitempty"`
	Statements []Statement `json:"-"`
}

type Statement struct {
	Effect           string
	PrincipalMatches principalMatcher
	Actions          []string
	Resources        []string
	Conditions       []Condition
}

type Condition struct {
	Operator    string
	Key         string
	Values      []string
	Qualifier   string
	IfExists    bool
	RawOperator string
}

type EvaluationContext struct {
	SecureTransport bool
	SourceIP        net.IP
	Headers         map[string][]string
	Attributes      map[string]string
	CurrentTime     time.Time
}

type parsedDocument struct {
	Version   string          `json:"Version"`
	Statement json.RawMessage `json:"Statement"`
}

type parsedStatement struct {
	Effect       string          `json:"Effect"`
	Principal    json.RawMessage `json:"Principal"`
	NotPrincipal json.RawMessage `json:"NotPrincipal"`
	Action       json.RawMessage `json:"Action"`
	Resource     json.RawMessage `json:"Resource"`
	Condition    json.RawMessage `json:"Condition"`
}

type awsPrincipal struct {
	AWS           json.RawMessage `json:"AWS"`
	CanonicalUser json.RawMessage `json:"CanonicalUser"`
	Federated     json.RawMessage `json:"Federated"`
	Service       json.RawMessage `json:"Service"`
}

type principalMatcher struct {
	Values []string
	Negate bool
}

type Decision struct {
	Allowed bool
	Denied  bool
}

func ParseAndValidate(raw []byte, bucket string) (Document, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return Document{}, storage.ErrInvalidRequest
	}
	var in parsedDocument
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return Document{}, fmt.Errorf("%w: parse bucket policy json", storage.ErrInvalidRequest)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return Document{}, fmt.Errorf("%w: trailing bucket policy content", storage.ErrInvalidRequest)
	}
	if in.Version != "" && in.Version != currentPolicy && in.Version != "2008-10-17" {
		return Document{}, fmt.Errorf("%w: unsupported bucket policy version", storage.ErrInvalidRequest)
	}
	stmts, err := parseStatements(in.Statement)
	if err != nil {
		return Document{}, err
	}
	if len(stmts) == 0 {
		return Document{}, fmt.Errorf("%w: bucket policy requires at least one statement", storage.ErrInvalidRequest)
	}
	out := Document{Version: in.Version, Statements: make([]Statement, 0, len(stmts))}
	for _, stmt := range stmts {
		matcher, err := parsePrincipalMatcher(stmt.Principal, stmt.NotPrincipal)
		if err != nil {
			return Document{}, err
		}
		actions, err := parseStringOrList(stmt.Action)
		if err != nil || len(actions) == 0 {
			return Document{}, fmt.Errorf("%w: invalid bucket policy action", storage.ErrInvalidRequest)
		}
		resources, err := parseStringOrList(stmt.Resource)
		if err != nil || len(resources) == 0 {
			return Document{}, fmt.Errorf("%w: invalid bucket policy resource", storage.ErrInvalidRequest)
		}
		effect := strings.TrimSpace(stmt.Effect)
		if effect != "Allow" && effect != "Deny" {
			return Document{}, fmt.Errorf("%w: invalid bucket policy effect", storage.ErrInvalidRequest)
		}
		conditions, err := parseConditions(stmt.Condition)
		if err != nil {
			return Document{}, err
		}
		for _, resource := range resources {
			if err := validateResourceBucket(resource, bucket); err != nil {
				return Document{}, err
			}
		}
		out.Statements = append(out.Statements, Statement{
			Effect:           effect,
			PrincipalMatches: matcher,
			Actions:          actions,
			Resources:        resources,
			Conditions:       conditions,
		})
	}
	return out, nil
}

func IsPublic(doc Document) bool {
	publicProbeContexts := []EvaluationContext{
		{
			SecureTransport: true,
			SourceIP:        net.ParseIP("203.0.113.10"),
			Headers:         map[string][]string{},
		},
		{
			SecureTransport: true,
			SourceIP:        net.ParseIP("198.51.100.10"),
			Headers:         map[string][]string{},
		},
	}
	for _, stmt := range doc.Statements {
		if stmt.Effect != "Allow" {
			continue
		}
		if !stmt.PrincipalMatches.matches([]string{}) {
			continue
		}
		if len(stmt.Conditions) == 0 {
			return true
		}
		for _, evalCtx := range publicProbeContexts {
			if conditionsMatch(stmt.Conditions, evalCtx) {
				return true
			}
		}
	}
	return false
}

func Evaluate(doc Document, principalCandidates []string, action string, resource string, evalCtx EvaluationContext) Decision {
	decision := Decision{}
	for _, stmt := range doc.Statements {
		if !stmt.PrincipalMatches.matches(principalCandidates) {
			continue
		}
		if !matchesAny(stmt.Actions, action) {
			continue
		}
		if !matchesAny(stmt.Resources, resource) {
			continue
		}
		if !conditionsMatch(stmt.Conditions, evalCtx) {
			continue
		}
		if stmt.Effect == "Deny" {
			decision.Denied = true
		}
		if stmt.Effect == "Allow" {
			decision.Allowed = true
		}
	}
	return decision
}

func parseStatements(raw json.RawMessage) ([]parsedStatement, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("%w: missing bucket policy statement", storage.ErrInvalidRequest)
	}
	var list []parsedStatement
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var one parsedStatement
	if err := json.Unmarshal(raw, &one); err == nil {
		return []parsedStatement{one}, nil
	}
	return nil, fmt.Errorf("%w: invalid bucket policy statements", storage.ErrInvalidRequest)
}

func parsePrincipalMatcher(principalRaw, notPrincipalRaw json.RawMessage) (principalMatcher, error) {
	hasPrincipal := len(bytes.TrimSpace(principalRaw)) > 0
	hasNotPrincipal := len(bytes.TrimSpace(notPrincipalRaw)) > 0
	switch {
	case hasPrincipal && hasNotPrincipal:
		return principalMatcher{}, fmt.Errorf("%w: Principal and NotPrincipal are mutually exclusive", storage.ErrInvalidRequest)
	case !hasPrincipal && !hasNotPrincipal:
		return principalMatcher{}, fmt.Errorf("%w: missing bucket policy principal", storage.ErrInvalidRequest)
	case hasNotPrincipal:
		values, err := parsePrincipals(notPrincipalRaw)
		if err != nil {
			return principalMatcher{}, err
		}
		return principalMatcher{Values: values, Negate: true}, nil
	default:
		values, err := parsePrincipals(principalRaw)
		if err != nil {
			return principalMatcher{}, err
		}
		return principalMatcher{Values: values, Negate: false}, nil
	}
}

func parsePrincipals(raw json.RawMessage) ([]string, error) {
	var direct string
	if err := json.Unmarshal(raw, &direct); err == nil {
		if strings.TrimSpace(direct) == "" {
			return nil, fmt.Errorf("%w: principal cannot be empty", storage.ErrInvalidRequest)
		}
		return []string{direct}, nil
	}
	var obj awsPrincipal
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("%w: invalid bucket policy principal", storage.ErrInvalidRequest)
	}
	values, err := parsePrincipalObject(obj)
	if err != nil || len(values) == 0 {
		return nil, fmt.Errorf("%w: invalid bucket policy principal", storage.ErrInvalidRequest)
	}
	return values, nil
}

func parsePrincipalObject(obj awsPrincipal) ([]string, error) {
	out := make([]string, 0, 4)
	appendValues := func(raw json.RawMessage) error {
		if len(bytes.TrimSpace(raw)) == 0 {
			return nil
		}
		values, err := parseStringOrList(raw)
		if err != nil {
			return err
		}
		out = append(out, values...)
		return nil
	}
	if err := appendValues(obj.AWS); err != nil {
		return nil, err
	}
	if err := appendValues(obj.CanonicalUser); err != nil {
		return nil, err
	}
	if err := appendValues(obj.Federated); err != nil {
		return nil, err
	}
	if err := appendValues(obj.Service); err != nil {
		return nil, err
	}
	return out, nil
}

func parseStringOrList(raw json.RawMessage) ([]string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, fmt.Errorf("%w: empty value", storage.ErrInvalidRequest)
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		if strings.TrimSpace(one) == "" {
			return nil, fmt.Errorf("%w: empty value", storage.ErrInvalidRequest)
		}
		return []string{one}, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("%w: empty value", storage.ErrInvalidRequest)
		}
		out = append(out, v)
	}
	return out, nil
}

func parseConditions(raw json.RawMessage) ([]Condition, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	var operators map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &operators); err != nil {
		return nil, fmt.Errorf("%w: invalid bucket policy condition", storage.ErrInvalidRequest)
	}
	conditions := make([]Condition, 0)
	for rawOperator, keys := range operators {
		operator, qualifier, ifExists, err := parseConditionOperator(rawOperator)
		if err != nil {
			return nil, err
		}
		if !isSupportedConditionOperator(operator) {
			return nil, fmt.Errorf("%w: unsupported bucket policy condition operator %q", storage.ErrInvalidRequest, rawOperator)
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("%w: empty bucket policy condition operator block", storage.ErrInvalidRequest)
		}
		for key, rawValue := range keys {
			values, err := parseStringOrList(rawValue)
			if err != nil || len(values) == 0 {
				return nil, fmt.Errorf("%w: invalid bucket policy condition value", storage.ErrInvalidRequest)
			}
			cond := Condition{
				Operator:    operator,
				Key:         strings.TrimSpace(key),
				Values:      values,
				Qualifier:   qualifier,
				IfExists:    ifExists,
				RawOperator: rawOperator,
			}
			if err := validateCondition(cond); err != nil {
				return nil, err
			}
			conditions = append(conditions, cond)
		}
	}
	return conditions, nil
}

func parseConditionOperator(raw string) (string, string, bool, error) {
	operator := strings.TrimSpace(raw)
	if operator == "" {
		return "", "", false, fmt.Errorf("%w: unsupported bucket policy condition operator", storage.ErrInvalidRequest)
	}
	qualifier := ""
	switch {
	case strings.HasPrefix(operator, "ForAnyValue:"):
		qualifier = "ForAnyValue"
		operator = strings.TrimPrefix(operator, "ForAnyValue:")
	case strings.HasPrefix(operator, "ForAllValues:"):
		qualifier = "ForAllValues"
		operator = strings.TrimPrefix(operator, "ForAllValues:")
	}
	ifExists := strings.HasSuffix(operator, "IfExists")
	if ifExists {
		operator = strings.TrimSuffix(operator, "IfExists")
	}
	if strings.Contains(operator, ":") || strings.TrimSpace(operator) == "" {
		return "", "", false, fmt.Errorf("%w: unsupported bucket policy condition operator", storage.ErrInvalidRequest)
	}
	return operator, qualifier, ifExists, nil
}

func isSupportedConditionOperator(operator string) bool {
	switch operator {
	case "Bool", "IpAddress", "NotIpAddress",
		"StringEquals", "StringNotEquals", "StringLike", "StringNotLike",
		"ArnEquals", "ArnNotEquals", "ArnLike", "ArnNotLike",
		"Null",
		"NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals",
		"DateEquals", "DateNotEquals", "DateLessThan", "DateLessThanEquals", "DateGreaterThan", "DateGreaterThanEquals":
		return true
	default:
		return false
	}
}

func validateCondition(cond Condition) error {
	if cond.Key == "" {
		return fmt.Errorf("%w: bucket policy condition key cannot be empty", storage.ErrInvalidRequest)
	}
	if cond.Qualifier != "" && !supportsQualifier(cond.Operator) {
		return fmt.Errorf("%w: unsupported condition qualifier", storage.ErrInvalidRequest)
	}
	if cond.IfExists && !supportsIfExists(cond.Operator) {
		return fmt.Errorf("%w: unsupported IfExists condition operator", storage.ErrInvalidRequest)
	}
	switch cond.Operator {
	case "Bool":
		if cond.Key != "aws:SecureTransport" {
			return fmt.Errorf("%w: unsupported Bool condition key %q", storage.ErrInvalidRequest, cond.Key)
		}
		for _, value := range cond.Values {
			lower := strings.ToLower(strings.TrimSpace(value))
			if lower != "true" && lower != "false" {
				return fmt.Errorf("%w: invalid Bool condition value", storage.ErrInvalidRequest)
			}
		}
	case "IpAddress", "NotIpAddress":
		if cond.Key != "aws:SourceIp" {
			return fmt.Errorf("%w: unsupported IP condition key %q", storage.ErrInvalidRequest, cond.Key)
		}
		for _, value := range cond.Values {
			if _, _, err := parseCIDROrIP(value); err != nil {
				return fmt.Errorf("%w: invalid CIDR in condition", storage.ErrInvalidRequest)
			}
		}
	case "StringEquals", "StringNotEquals":
		if !isSupportedStringConditionKey(cond.Key) {
			return fmt.Errorf("%w: unsupported String condition key %q", storage.ErrInvalidRequest, cond.Key)
		}
	case "StringLike", "StringNotLike":
		if !isSupportedStringConditionKey(cond.Key) {
			return fmt.Errorf("%w: unsupported StringLike condition key %q", storage.ErrInvalidRequest, cond.Key)
		}
	case "ArnEquals", "ArnNotEquals", "ArnLike", "ArnNotLike":
		if !isSupportedARNConditionKey(cond.Key) {
			return fmt.Errorf("%w: unsupported Arn condition key %q", storage.ErrInvalidRequest, cond.Key)
		}
	case "NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals":
		if !isSupportedNumericConditionKey(cond.Key) {
			return fmt.Errorf("%w: unsupported Numeric condition key %q", storage.ErrInvalidRequest, cond.Key)
		}
		for _, value := range cond.Values {
			if _, err := parseConditionNumber(value); err != nil {
				return fmt.Errorf("%w: invalid Numeric condition value", storage.ErrInvalidRequest)
			}
		}
	case "DateEquals", "DateNotEquals", "DateLessThan", "DateLessThanEquals", "DateGreaterThan", "DateGreaterThanEquals":
		if cond.Key != "aws:CurrentTime" {
			return fmt.Errorf("%w: unsupported Date condition key %q", storage.ErrInvalidRequest, cond.Key)
		}
		for _, value := range cond.Values {
			if _, err := parseConditionTime(value); err != nil {
				return fmt.Errorf("%w: invalid Date condition value", storage.ErrInvalidRequest)
			}
		}
	case "Null":
		if !isSupportedStringConditionKey(cond.Key) {
			return fmt.Errorf("%w: unsupported Null condition key %q", storage.ErrInvalidRequest, cond.Key)
		}
		for _, value := range cond.Values {
			lower := strings.ToLower(strings.TrimSpace(value))
			if lower != "true" && lower != "false" {
				return fmt.Errorf("%w: invalid Null condition value", storage.ErrInvalidRequest)
			}
		}
	default:
		return fmt.Errorf("%w: unsupported bucket policy condition operator", storage.ErrInvalidRequest)
	}
	return nil
}

func supportsQualifier(operator string) bool {
	switch operator {
	case "StringEquals", "StringLike", "ArnEquals", "ArnLike", "NumericEquals", "DateEquals":
		return true
	default:
		return false
	}
}

func supportsIfExists(operator string) bool {
	switch operator {
	case "Null":
		return false
	default:
		return true
	}
}

func isSupportedNumericConditionKey(key string) bool {
	switch key {
	case "s3:max-keys", "s3:signatureAge":
		return true
	default:
		return false
	}
}

func isSupportedARNConditionKey(key string) bool {
	switch key {
	case "aws:PrincipalArn":
		return true
	default:
		return false
	}
}

func isSupportedStringConditionKey(key string) bool {
	if strings.HasPrefix(key, "s3:RequestHeader/") {
		return true
	}
	switch key {
	case "aws:SecureTransport",
		"aws:SourceIp",
		"aws:PrincipalArn",
		"aws:PrincipalAccount",
		"aws:PrincipalType",
		"aws:userid",
		"aws:username",
		"s3:authType",
		"s3:signatureversion",
		"s3:prefix",
		"s3:delimiter",
		"s3:max-keys",
		"s3:VersionId",
		"s3:x-amz-acl":
		return true
	default:
		return false
	}
}

func conditionsMatch(conditions []Condition, evalCtx EvaluationContext) bool {
	for _, cond := range conditions {
		if !conditionMatch(cond, evalCtx) {
			return false
		}
	}
	return true
}

func conditionMatch(cond Condition, evalCtx EvaluationContext) bool {
	switch cond.Operator {
	case "Bool":
		actual := strconv.FormatBool(evalCtx.SecureTransport)
		return matchesStringValues(actual, cond.Values)
	case "IpAddress":
		if evalCtx.SourceIP == nil {
			return false
		}
		return ipInRanges(evalCtx.SourceIP, cond.Values)
	case "NotIpAddress":
		if evalCtx.SourceIP == nil {
			return false
		}
		return !ipInRanges(evalCtx.SourceIP, cond.Values)
	case "StringEquals":
		actualValues, ok := lookupConditionStringValues(cond.Key, evalCtx)
		if !ok {
			return cond.IfExists
		}
		return matchesStringCondition(actualValues, cond)
	case "StringNotEquals":
		actual, ok := lookupConditionStringValue(cond.Key, evalCtx)
		if !ok {
			return cond.IfExists
		}
		return !matchesStringValues(actual, cond.Values)
	case "StringLike":
		actualValues, ok := lookupConditionStringValues(cond.Key, evalCtx)
		if !ok {
			return cond.IfExists
		}
		return matchesStringCondition(actualValues, cond)
	case "StringNotLike":
		actual, ok := lookupConditionStringValue(cond.Key, evalCtx)
		if !ok {
			return cond.IfExists
		}
		return !matchesStringLikeValues(actual, cond.Values)
	case "ArnEquals":
		actualValues, ok := lookupConditionStringValues(cond.Key, evalCtx)
		if !ok {
			return cond.IfExists
		}
		return matchesStringCondition(actualValues, Condition{
			Operator:  "StringEquals",
			Values:    cond.Values,
			Qualifier: cond.Qualifier,
		})
	case "ArnNotEquals":
		actual, ok := lookupConditionStringValue(cond.Key, evalCtx)
		if !ok {
			return cond.IfExists
		}
		return !matchesStringValues(actual, cond.Values)
	case "ArnLike":
		actualValues, ok := lookupConditionStringValues(cond.Key, evalCtx)
		if !ok {
			return cond.IfExists
		}
		return matchesStringCondition(actualValues, Condition{
			Operator:  "StringLike",
			Values:    cond.Values,
			Qualifier: cond.Qualifier,
		})
	case "ArnNotLike":
		actual, ok := lookupConditionStringValue(cond.Key, evalCtx)
		if !ok {
			return cond.IfExists
		}
		return !matchesStringLikeValues(actual, cond.Values)
	case "Null":
		isPresent := conditionKeyPresent(cond.Key, evalCtx)
		return matchesNullConditionValue(isPresent, cond.Values)
	case "NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals":
		actual, ok := lookupConditionNumericValues(cond.Key, evalCtx)
		if !ok {
			return cond.IfExists
		}
		return matchesNumericCondition(actual, cond)
	case "DateEquals", "DateNotEquals", "DateLessThan", "DateLessThanEquals", "DateGreaterThan", "DateGreaterThanEquals":
		actual, ok := lookupConditionTimeValues(cond.Key, evalCtx)
		if !ok {
			return cond.IfExists
		}
		return matchesTimeCondition(actual, cond)
	default:
		return false
	}
}

func lookupConditionStringValue(key string, evalCtx EvaluationContext) (string, bool) {
	values, ok := lookupConditionStringValues(key, evalCtx)
	if !ok || len(values) == 0 {
		return "", false
	}
	return values[0], true
}

func lookupConditionStringValues(key string, evalCtx EvaluationContext) ([]string, bool) {
	if value, ok := lookupConditionAttribute(key, evalCtx.Attributes); ok {
		return []string{value}, true
	}
	switch key {
	case "aws:SecureTransport":
		return []string{strconv.FormatBool(evalCtx.SecureTransport)}, true
	case "aws:SourceIp":
		if evalCtx.SourceIP == nil {
			return nil, false
		}
		return []string{evalCtx.SourceIP.String()}, true
	default:
		const headerPrefix = "s3:RequestHeader/"
		if !strings.HasPrefix(key, headerPrefix) {
			return nil, false
		}
		if evalCtx.Headers == nil {
			return nil, false
		}
		headerName := strings.TrimSpace(strings.TrimPrefix(key, headerPrefix))
		if headerName == "" {
			return nil, false
		}
		for name, values := range evalCtx.Headers {
			if !strings.EqualFold(name, headerName) || len(values) == 0 {
				continue
			}
			out := make([]string, 0, len(values))
			for _, value := range values {
				out = append(out, value)
			}
			return out, true
		}
		return nil, false
	}
}

func lookupConditionNumericValues(key string, evalCtx EvaluationContext) ([]float64, bool) {
	actual, ok := lookupConditionStringValues(key, evalCtx)
	if !ok {
		return nil, false
	}
	out := make([]float64, 0, len(actual))
	for _, value := range actual {
		parsed, err := parseConditionNumber(value)
		if err != nil {
			return nil, false
		}
		out = append(out, parsed)
	}
	return out, true
}

func lookupConditionTimeValues(key string, evalCtx EvaluationContext) ([]time.Time, bool) {
	switch key {
	case "aws:CurrentTime":
		if !evalCtx.CurrentTime.IsZero() {
			return []time.Time{evalCtx.CurrentTime.UTC()}, true
		}
		if value, ok := lookupConditionAttribute(key, evalCtx.Attributes); ok {
			parsed, err := parseConditionTime(value)
			if err == nil {
				return []time.Time{parsed}, true
			}
		}
		return nil, false
	default:
		return nil, false
	}
}

func conditionKeyPresent(key string, evalCtx EvaluationContext) bool {
	if _, ok := lookupConditionAttribute(key, evalCtx.Attributes); ok {
		return true
	}
	switch key {
	case "aws:SecureTransport":
		return true
	case "aws:SourceIp":
		return evalCtx.SourceIP != nil
	default:
		const headerPrefix = "s3:RequestHeader/"
		if !strings.HasPrefix(key, headerPrefix) {
			return false
		}
		if evalCtx.Headers == nil {
			return false
		}
		headerName := strings.TrimSpace(strings.TrimPrefix(key, headerPrefix))
		if headerName == "" {
			return false
		}
		for name := range evalCtx.Headers {
			if strings.EqualFold(name, headerName) {
				return true
			}
		}
		return false
	}
}

func lookupConditionAttribute(key string, attrs map[string]string) (string, bool) {
	if attrs == nil {
		return "", false
	}
	value, ok := attrs[key]
	if !ok {
		return "", false
	}
	return value, true
}

func matchesStringValues(actual string, candidates []string) bool {
	for _, candidate := range candidates {
		if actual == strings.TrimSpace(candidate) {
			return true
		}
	}
	return false
}

func matchesStringLikeValues(actual string, patterns []string) bool {
	for _, pattern := range patterns {
		if wildcardMatch(strings.TrimSpace(pattern), actual) {
			return true
		}
	}
	return false
}

func matchesNullConditionValue(isPresent bool, expected []string) bool {
	for _, value := range expected {
		trimmed := strings.ToLower(strings.TrimSpace(value))
		switch trimmed {
		case "true":
			if !isPresent {
				return true
			}
		case "false":
			if isPresent {
				return true
			}
		}
	}
	return false
}

func matchesStringCondition(actualValues []string, cond Condition) bool {
	if len(actualValues) == 0 {
		return false
	}
	switch cond.Qualifier {
	case "":
		if cond.Operator == "StringEquals" {
			return matchesStringValues(actualValues[0], cond.Values)
		}
		if cond.Operator == "StringLike" {
			return matchesStringLikeValues(actualValues[0], cond.Values)
		}
		return false
	case "ForAnyValue":
		for _, actual := range actualValues {
			if cond.Operator == "StringEquals" && matchesStringValues(actual, cond.Values) {
				return true
			}
			if cond.Operator == "StringLike" && matchesStringLikeValues(actual, cond.Values) {
				return true
			}
		}
		return false
	case "ForAllValues":
		for _, actual := range actualValues {
			if cond.Operator == "StringEquals" && !matchesStringValues(actual, cond.Values) {
				return false
			}
			if cond.Operator == "StringLike" && !matchesStringLikeValues(actual, cond.Values) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func matchesNumericCondition(actualValues []float64, cond Condition) bool {
	parsedValues := make([]float64, 0, len(cond.Values))
	for _, raw := range cond.Values {
		parsed, err := parseConditionNumber(raw)
		if err != nil {
			return false
		}
		parsedValues = append(parsedValues, parsed)
	}
	if cond.Qualifier != "" && cond.Operator != "NumericEquals" {
		return false
	}
	switch cond.Operator {
	case "NumericEquals":
		switch cond.Qualifier {
		case "":
			if len(actualValues) == 0 {
				return false
			}
			for _, expected := range parsedValues {
				if actualValues[0] == expected {
					return true
				}
			}
			return false
		case "ForAnyValue":
			for _, actual := range actualValues {
				for _, expected := range parsedValues {
					if actual == expected {
						return true
					}
				}
			}
			return false
		case "ForAllValues":
			if len(actualValues) == 0 {
				return false
			}
			for _, actual := range actualValues {
				matched := false
				for _, expected := range parsedValues {
					if actual == expected {
						matched = true
						break
					}
				}
				if !matched {
					return false
				}
			}
			return true
		default:
			return false
		}
	case "NumericNotEquals":
		if len(actualValues) == 0 {
			return false
		}
		actual := actualValues[0]
		for _, expected := range parsedValues {
			if actual == expected {
				return false
			}
		}
		return true
	case "NumericLessThan":
		if len(actualValues) == 0 {
			return false
		}
		actual := actualValues[0]
		for _, expected := range parsedValues {
			if actual < expected {
				return true
			}
		}
		return false
	case "NumericLessThanEquals":
		if len(actualValues) == 0 {
			return false
		}
		actual := actualValues[0]
		for _, expected := range parsedValues {
			if actual <= expected {
				return true
			}
		}
		return false
	case "NumericGreaterThan":
		if len(actualValues) == 0 {
			return false
		}
		actual := actualValues[0]
		for _, expected := range parsedValues {
			if actual > expected {
				return true
			}
		}
		return false
	case "NumericGreaterThanEquals":
		if len(actualValues) == 0 {
			return false
		}
		actual := actualValues[0]
		for _, expected := range parsedValues {
			if actual >= expected {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func matchesTimeCondition(actualValues []time.Time, cond Condition) bool {
	parsedValues := make([]time.Time, 0, len(cond.Values))
	for _, raw := range cond.Values {
		parsed, err := parseConditionTime(raw)
		if err != nil {
			return false
		}
		parsedValues = append(parsedValues, parsed)
	}
	if cond.Qualifier != "" && cond.Operator != "DateEquals" {
		return false
	}
	switch cond.Operator {
	case "DateEquals":
		switch cond.Qualifier {
		case "":
			if len(actualValues) == 0 {
				return false
			}
			for _, expected := range parsedValues {
				if actualValues[0].Equal(expected) {
					return true
				}
			}
			return false
		case "ForAnyValue":
			for _, actual := range actualValues {
				for _, expected := range parsedValues {
					if actual.Equal(expected) {
						return true
					}
				}
			}
			return false
		case "ForAllValues":
			if len(actualValues) == 0 {
				return false
			}
			for _, actual := range actualValues {
				matched := false
				for _, expected := range parsedValues {
					if actual.Equal(expected) {
						matched = true
						break
					}
				}
				if !matched {
					return false
				}
			}
			return true
		default:
			return false
		}
	case "DateNotEquals":
		if len(actualValues) == 0 {
			return false
		}
		actual := actualValues[0]
		for _, expected := range parsedValues {
			if actual.Equal(expected) {
				return false
			}
		}
		return true
	case "DateLessThan":
		if len(actualValues) == 0 {
			return false
		}
		actual := actualValues[0]
		for _, expected := range parsedValues {
			if actual.Before(expected) {
				return true
			}
		}
		return false
	case "DateLessThanEquals":
		if len(actualValues) == 0 {
			return false
		}
		actual := actualValues[0]
		for _, expected := range parsedValues {
			if actual.Before(expected) || actual.Equal(expected) {
				return true
			}
		}
		return false
	case "DateGreaterThan":
		if len(actualValues) == 0 {
			return false
		}
		actual := actualValues[0]
		for _, expected := range parsedValues {
			if actual.After(expected) {
				return true
			}
		}
		return false
	case "DateGreaterThanEquals":
		if len(actualValues) == 0 {
			return false
		}
		actual := actualValues[0]
		for _, expected := range parsedValues {
			if actual.After(expected) || actual.Equal(expected) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func parseConditionNumber(input string) (float64, error) {
	parsed, err := strconv.ParseFloat(strings.TrimSpace(input), 64)
	if err != nil {
		return 0, err
	}
	if math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return 0, fmt.Errorf("invalid numeric value")
	}
	return parsed, nil
}

func parseConditionTime(input string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(input))
	if err != nil {
		return time.Time{}, err
	}
	return parsed.UTC(), nil
}

func ipInRanges(ip net.IP, ranges []string) bool {
	for _, cidr := range ranges {
		_, network, err := parseCIDROrIP(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func parseCIDROrIP(input string) (net.IP, *net.IPNet, error) {
	cidr := strings.TrimSpace(input)
	if strings.Contains(cidr, "/") {
		ip, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, nil, err
		}
		return ip, network, nil
	}
	ip := net.ParseIP(cidr)
	if ip == nil {
		return nil, nil, fmt.Errorf("invalid ip")
	}
	if ip.To4() != nil {
		return ip, &net.IPNet{
			IP:   ip.Mask(net.CIDRMask(32, 32)),
			Mask: net.CIDRMask(32, 32),
		}, nil
	}
	return ip, &net.IPNet{
		IP:   ip.Mask(net.CIDRMask(128, 128)),
		Mask: net.CIDRMask(128, 128),
	}, nil
}

func validateResourceBucket(resource string, bucket string) error {
	if !strings.HasPrefix(resource, s3ARNPrefix) {
		return fmt.Errorf("%w: bucket policy resource must use arn:aws:s3:::", storage.ErrInvalidRequest)
	}
	withoutPrefix := strings.TrimPrefix(resource, s3ARNPrefix)
	bucketPart := withoutPrefix
	if idx := strings.IndexByte(withoutPrefix, '/'); idx >= 0 {
		bucketPart = withoutPrefix[:idx]
	}
	if bucketPart != bucket {
		return fmt.Errorf("%w: bucket policy resource must target the request bucket", storage.ErrInvalidRequest)
	}
	return nil
}

func (m principalMatcher) matches(candidates []string) bool {
	match := false
	for _, principal := range m.Values {
		if principal == "*" {
			match = true
			break
		}
		for _, candidate := range candidates {
			if wildcardMatch(principal, candidate) {
				match = true
				break
			}
		}
		if match {
			break
		}
	}
	if m.Negate {
		return !match
	}
	return match
}

func matchesAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		if wildcardMatch(pattern, value) {
			return true
		}
	}
	return false
}

func wildcardMatch(pattern string, value string) bool {
	var b strings.Builder
	b.Grow(len(pattern) + 4)
	b.WriteString("^")
	for _, ch := range pattern {
		switch ch {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(ch)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String()).MatchString(value)
}
