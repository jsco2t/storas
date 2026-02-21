package authz

import (
	"errors"
	"fmt"
	"os"
	"sort"

	"gopkg.in/yaml.v3"
)

var allowedActions = map[string]struct{}{
	"bucket:list":   {},
	"bucket:create": {},
	"bucket:delete": {},
	"bucket:head":   {},
	"object:list":   {},
	"object:put":    {},
	"object:get":    {},
	"object:head":   {},
	"object:delete": {},
	"object:copy":   {},
}

type File struct {
	Users []User `yaml:"users"`
}

type User struct {
	Name      string `yaml:"name"`
	AccessKey string `yaml:"access_key"`
	SecretKey string `yaml:"secret_key"`
	Allow     []Rule `yaml:"allow"`
}

type Rule struct {
	Action   string `yaml:"action"`
	Resource string `yaml:"resource"`
}

type Principal struct {
	Name      string
	AccessKey string
}

type Engine struct {
	usersByKey map[string]User
}

func AllowedActions() []string {
	actions := make([]string, 0, len(allowedActions))
	for action := range allowedActions {
		actions = append(actions, action)
	}
	sort.Strings(actions)
	return actions
}

func LoadFile(path string) (*Engine, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authorization file %q: %w", path, err)
	}

	var file File
	if err := yaml.Unmarshal(content, &file); err != nil {
		return nil, fmt.Errorf("parse authorization file %q: %w", path, err)
	}

	if err := validate(file); err != nil {
		return nil, err
	}

	usersByKey := make(map[string]User, len(file.Users))
	for _, user := range file.Users {
		usersByKey[user.AccessKey] = user
	}

	return &Engine{usersByKey: usersByKey}, nil
}

func (e *Engine) ResolvePrincipal(accessKey string) (Principal, bool) {
	user, ok := e.usersByKey[accessKey]
	if !ok {
		return Principal{}, false
	}
	return Principal{Name: user.Name, AccessKey: user.AccessKey}, true
}

func (e *Engine) SecretForAccessKey(accessKey string) (string, Principal, bool) {
	user, ok := e.usersByKey[accessKey]
	if !ok {
		return "", Principal{}, false
	}
	return user.SecretKey, Principal{Name: user.Name, AccessKey: user.AccessKey}, true
}

func (e *Engine) IsAllowed(principal Principal, action, resource string) bool {
	user, ok := e.usersByKey[principal.AccessKey]
	if !ok {
		return false
	}

	for _, rule := range user.Allow {
		if rule.Action != action {
			continue
		}
		if MatchResource(rule.Resource, resource) {
			return true
		}
	}

	return false
}

func validate(file File) error {
	var errs []error
	if len(file.Users) == 0 {
		errs = append(errs, errors.New("authorization validation: at least one user is required"))
	}

	seenAccessKeys := make(map[string]struct{}, len(file.Users))
	for idx, user := range file.Users {
		prefix := fmt.Sprintf("authorization validation: users[%d]", idx)
		if user.Name == "" {
			errs = append(errs, fmt.Errorf("%s.name is required", prefix))
		}
		if user.AccessKey == "" {
			errs = append(errs, fmt.Errorf("%s.access_key is required", prefix))
		} else {
			if _, exists := seenAccessKeys[user.AccessKey]; exists {
				errs = append(errs, fmt.Errorf("%s.access_key %q is duplicated", prefix, user.AccessKey))
			}
			seenAccessKeys[user.AccessKey] = struct{}{}
		}
		if user.SecretKey == "" {
			errs = append(errs, fmt.Errorf("%s.secret_key is required", prefix))
		}
		if len(user.Allow) == 0 {
			errs = append(errs, fmt.Errorf("%s.allow must contain at least one rule", prefix))
		}

		for ruleIdx, rule := range user.Allow {
			rulePrefix := fmt.Sprintf("%s.allow[%d]", prefix, ruleIdx)
			if _, ok := allowedActions[rule.Action]; !ok {
				errs = append(errs, fmt.Errorf("%s.action %q is invalid", rulePrefix, rule.Action))
			}
			if rule.Resource == "" {
				errs = append(errs, fmt.Errorf("%s.resource is required", rulePrefix))
			}
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func MatchResource(pattern, resource string) bool {
	return globMatch(pattern, resource)
}

// globMatch reports whether value matches pattern, where '*' matches any
// sequence of characters and '?' matches exactly one character.
// It uses an iterative approach with no allocations.
func globMatch(pattern, value string) bool {
	p, v := 0, 0
	starIdx := -1
	match := 0
	for v < len(value) {
		if p < len(pattern) && (pattern[p] == '?' || pattern[p] == value[v]) {
			p++
			v++
		} else if p < len(pattern) && pattern[p] == '*' {
			starIdx = p
			match = v
			p++
		} else if starIdx != -1 {
			p = starIdx + 1
			match++
			v = match
		} else {
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
