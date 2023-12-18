package jira

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"text/template"
	"time"

	jiraLib "github.com/andygrunwald/go-jira"
	"github.com/pkg/errors"
	"github.com/stackrox/rox/central/notifiers/metadatagetter"
	notifierUtils "github.com/stackrox/rox/central/notifiers/utils"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/administration/events/codes"
	"github.com/stackrox/rox/pkg/cryptoutils/cryptocodec"
	"github.com/stackrox/rox/pkg/env"
	"github.com/stackrox/rox/pkg/errorhelpers"
	"github.com/stackrox/rox/pkg/httputil/proxy"
	"github.com/stackrox/rox/pkg/logging"
	mitreDataStore "github.com/stackrox/rox/pkg/mitre/datastore"
	"github.com/stackrox/rox/pkg/notifiers"
	"github.com/stackrox/rox/pkg/urlfmt"
	"github.com/stackrox/rox/pkg/utils"
)

const (
	timeout = 5 * time.Second
)

var (
	log = logging.LoggerForModule()

	severities = []storage.Severity{
		storage.Severity_CRITICAL_SEVERITY,
		storage.Severity_HIGH_SEVERITY,
		storage.Severity_MEDIUM_SEVERITY,
		storage.Severity_LOW_SEVERITY,
	}

	defaultPriorities = map[storage.Severity]string{
		storage.Severity_CRITICAL_SEVERITY: "P0",
		storage.Severity_HIGH_SEVERITY:     "P1",
		storage.Severity_MEDIUM_SEVERITY:   "P2",
		storage.Severity_LOW_SEVERITY:      "P3",
	}
	pattern = regexp.MustCompile(`^(P[0-9])\b`)
)

// jira notifier plugin.
type jira struct {
	client   *jiraLib.Client
	conf     *storage.Jira
	notifier *storage.Notifier

	metadataGetter notifiers.MetadataGetter
	mitreStore     mitreDataStore.AttackReadOnlyDataStore

	severityToPriority map[storage.Severity]string
	needsPriority      bool

	unknownMap map[string]interface{}
}

type issueTypeResult struct {
	StartAt         int                      `json:"startAt"`
	MaxResults      int                      `json:"maxResults"`
	Total           int                      `json:"total"`
	IssueTypes      []*jiraLib.MetaIssueType `json:"values"`
	IssueTypesCloud []*jiraLib.MetaIssueType `json:"issueTypes"`
}

type issueField struct {
	Name    string `json:"name"`
	Key     string `json:"key"`
	FieldId string `json:"fieldId"`
}

type issueFieldsResult struct {
	StartAt          int           `json:"startAt"`
	MaxResults       int           `json:"maxResults"`
	Total            int           `json:"total"`
	IssueFields      []*issueField `json:"values"`
	IssueFieldsCloud []*issueField `json:"fields"`
}

type permissionResult struct {
	Permissions map[string]struct {
		HavePermission bool
	}
}

type jiraField struct {
	Name string
}

func callJira(client *jiraLib.Client, urlPath string, result interface{}, startAt int) error {
	if strings.Contains(urlPath, "?") {
		urlPath = urlPath + fmt.Sprintf("&startAt=%d", startAt)
	} else {
		urlPath = urlPath + fmt.Sprintf("?startAt=%d", startAt)
	}

	req, err := client.NewRequest("GET", urlPath, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req, nil)
	if err != nil {
		return err
	}

	defer utils.IgnoreError(resp.Body.Close)
	err = json.NewDecoder(resp.Body).Decode(result)
	if err != nil {
		return err
	}

	return nil
}

func getIssueTypes(client *jiraLib.Client, project string) ([]*jiraLib.MetaIssueType, error) {
	urlPath := fmt.Sprintf("rest/api/2/issue/createmeta/%s/issuetypes", project)

	result := issueTypeResult{}

	err := callJira(client, urlPath, &result, 0)

	if err != nil {
		return []*jiraLib.MetaIssueType{}, err
	}

	returnList := make([]*jiraLib.MetaIssueType, result.Total)

	if len(result.IssueTypes) == 0 {
		returnList = result.IssueTypesCloud
	} else {
		returnList = result.IssueTypes
	}

	for result.Total != len(returnList) {
		result = issueTypeResult{}
		callJira(client, urlPath, &result, len(returnList))

		if err != nil {
			return []*jiraLib.MetaIssueType{}, err
		}

		var actualIssueTypes []*jiraLib.MetaIssueType
		if len(result.IssueTypes) == 0 {
			actualIssueTypes = result.IssueTypesCloud
		} else {
			actualIssueTypes = result.IssueTypes
		}

		returnList = append(returnList, actualIssueTypes...)
	}

	return returnList, nil
}

func getIssueFields(client *jiraLib.Client, project, issueId string) ([]*issueField, error) {
	urlPath := fmt.Sprintf("rest/api/2/issue/createmeta/%s/issuetypes/%s", project, issueId)

	result := issueFieldsResult{}

	err := callJira(client, urlPath, &result, 0)

	if err != nil {
		return []*issueField{}, err
	}

	returnList := make([]*issueField, result.Total)

	if len(result.IssueFields) == 0 {
		returnList = result.IssueFieldsCloud
	} else {
		returnList = result.IssueFields
	}

	for result.Total != len(returnList) {
		result = issueFieldsResult{}
		callJira(client, urlPath, &result, len(returnList))

		if err != nil {
			return []*issueField{}, err
		}

		var actualIssueTypes []*issueField
		if len(result.IssueFields) == 0 {
			actualIssueTypes = result.IssueFieldsCloud
		} else {
			actualIssueTypes = result.IssueFields
		}

		returnList = append(returnList, actualIssueTypes...)
	}

	return returnList, nil
}

func isPriorityFieldOnIssueType(client *jiraLib.Client, project, issueType string) (bool, error) {
	// Get issue types

	// Low level HTTP client call is used here due to the deprecation/removal of the Jira endpoint used by the Jira library
	// to fetch the CreateMeta data, and there is no API call for the suggested endpoint to use in place of the removed one.
	// Info here:
	// https://confluence.atlassian.com/jiracore/createmeta-rest-endpoint-to-be-removed-975040986.html
	issueTypes, err := getIssueTypes(client, project)
	if err != nil {
		return false, errors.Wrapf(err, "could not get meta information for JIRA project %q", project)
	}

	// Validate that the desired type exists and get its ID
	var issueId string
	for _, issue := range issueTypes {
		if strings.EqualFold(issue.Name, issueType) {
			issueId = issue.Id
		}
	}

	if issueId == "" {
		return false, errors.Errorf("could not find issue type %q in project %q.", issueType, project)
	}

	// Fetch its fields
	issueTypeFields, err := getIssueFields(client, project, issueId)

	if err != nil {
		return false, errors.Wrapf(err, "could not get meta information for JIRA project %q and issue type %s", project, issueType)
	}

	// Validate priority is one of the fields
	for _, field := range issueTypeFields {
		if strings.EqualFold("priority", field.Name) {
			return true, nil
		}
	}

	return false, nil
}

func (j *jira) getAlertDescription(alert *storage.Alert) (string, error) {
	funcMap := template.FuncMap{
		"header": func(s string) string {
			return fmt.Sprintf("\r\n h4. %v\r\n", s)
		},
		"subheader": func(s string) string {
			return fmt.Sprintf("\r\n h5. %v\r\n", s)
		},
		"line": func(s string) string {
			return fmt.Sprintf("%v\r\n", s)
		},
		"list": func(s string) string {
			return fmt.Sprintf("* %v\r\n", s)
		},
		"nestedList": func(s string) string {
			return fmt.Sprintf("** %v\r\n", s)
		},
		"section": func(s string) string {
			return fmt.Sprintf("\r\n * %v", s)
		},
		"group": func(s string) string {
			return fmt.Sprintf("\r\n ** %s", s)
		},
		"valuePrinter": func(values []*storage.PolicyValue, op storage.BooleanOperator, negated bool) string {
			var opString string
			if op == storage.BooleanOperator_OR {
				opString = " OR "
			} else {
				opString = " AND "
			}

			var valueStrings []string
			for _, value := range values {
				valueStrings = append(valueStrings, value.GetValue())
			}

			valuesString := strings.Join(valueStrings, opString)
			if negated {
				valuesString = fmt.Sprintf("NOT (%s)", valuesString)
			}

			return valuesString
		},
	}
	alertLink := notifiers.AlertLink(j.notifier.UiEndpoint, alert)
	return notifiers.FormatAlert(alert, alertLink, funcMap, j.mitreStore)
}

func (j *jira) Close(_ context.Context) error {
	return nil
}

// AlertNotify takes in an alert and generates the notification.
func (j *jira) AlertNotify(ctx context.Context, alert *storage.Alert) error {
	description, err := j.getAlertDescription(alert)
	if err != nil {
		return err
	}

	project := j.metadataGetter.GetAnnotationValue(ctx, alert, j.notifier.GetLabelKey(), j.notifier.GetLabelDefault())
	i := &jiraLib.Issue{
		Fields: &jiraLib.IssueFields{
			Summary: notifiers.SummaryForAlert(alert),
			Type: jiraLib.IssueType{
				Name: j.conf.GetIssueType(),
			},
			Project: jiraLib.Project{
				Key: project,
			},
			Description: description,
		},
	}
	err = j.createIssue(ctx, alert.GetPolicy().GetSeverity(), i)
	if err != nil {
		log.Errorw("failed to create JIRA issue for alert",
			logging.Err(err), logging.NotifierName(j.notifier.GetName()), logging.ErrCode(codes.JIRAGeneric),
			logging.AlertID(alert.GetId()))
	}
	return err
}

func (j *jira) NetworkPolicyYAMLNotify(ctx context.Context, yaml string, clusterName string) error {
	funcMap := template.FuncMap{
		"codeBlock": func(s string) string {
			return fmt.Sprintf("{code:title=Network Policy YAML|theme=FadeToGrey|language=yaml}%s{code}", s)
		},
	}

	description, err := notifiers.FormatNetworkPolicyYAML(yaml, clusterName, funcMap)
	if err != nil {
		return err
	}

	project := j.notifier.GetLabelDefault()
	i := &jiraLib.Issue{
		Fields: &jiraLib.IssueFields{
			Summary: fmt.Sprintf("Network policy yaml to apply on cluster %s", clusterName),
			Type: jiraLib.IssueType{
				Name: j.conf.GetIssueType(),
			},
			Project: jiraLib.Project{
				Key: project,
			},
			Description: description,
		},
	}
	err = j.createIssue(ctx, storage.Severity_MEDIUM_SEVERITY, i)
	if err != nil {
		log.Errorw("failed to create JIRA issue for network policy",
			logging.Err(err), logging.NotifierName(j.notifier.GetName()), logging.ErrCode(codes.JIRAGeneric))
	}
	return err
}

// Validate Jira notifier
func Validate(jira *storage.Jira, validateSecret bool) error {
	errorList := errorhelpers.NewErrorList("Jira validation")
	if jira.GetIssueType() == "" {
		errorList.AddString("Issue Type must be specified")
	}
	if jira.GetUrl() == "" {
		errorList.AddString("URL must be specified")
	}
	if jira.GetUsername() == "" {
		errorList.AddString("Username must be specified")
	}
	if validateSecret && jira.GetPassword() == "" {
		errorList.AddString("Password or API Token must be specified")
	}

	if len(jira.GetPriorityMappings()) != 0 {
		unfoundSeverities := make(map[storage.Severity]struct{})
		for _, sev := range severities {
			unfoundSeverities[sev] = struct{}{}
		}
		for _, mapping := range jira.GetPriorityMappings() {
			delete(unfoundSeverities, mapping.GetSeverity())
		}
		for sev := range unfoundSeverities {
			errorList.AddStringf("mapping for severity %s required", sev.String())
		}
	}
	return errorList.ToError()
}

func newJira(notifier *storage.Notifier, metadataGetter notifiers.MetadataGetter, mitreStore mitreDataStore.AttackReadOnlyDataStore,
	cryptoCodec cryptocodec.CryptoCodec, cryptoKey string) (*jira, error) {
	conf := notifier.GetJira()
	if conf == nil {
		return nil, errors.New("Jira configuration required")
	}
	if err := Validate(conf, !env.EncNotifierCreds.BooleanSetting()); err != nil {
		return nil, err
	}

	client, err := createClient(notifier, cryptoCodec, cryptoKey)

	if err != nil {
		return nil, err
	}

	canCreateIssues, err := canCreateIssuesInProject(client, notifier.GetLabelDefault())

	if err != nil {
		return nil, err
	}

	if !canCreateIssues {
		return nil, fmt.Errorf("Cannot create issues in project %s", notifier.GetLabelDefault())
	}

	var priorityMapping map[storage.Severity]string
	if !conf.DisablePriority {
		priorityMapping, err = configurePriority(client, conf, notifier.GetLabelDefault())

		if err != nil {
			return nil, err
		}
	}

	// marshal unknowns
	var unknownMap map[string]interface{}
	if conf.GetDefaultFieldsJson() != "" {
		if err := json.Unmarshal([]byte(conf.GetDefaultFieldsJson()), &unknownMap); err != nil {
			return nil, errors.Wrap(err, "could not unmarshal default fields JSON")
		}
	}

	return &jira{
		client:             client,
		conf:               notifier.GetJira(),
		notifier:           notifier,
		metadataGetter:     metadataGetter,
		mitreStore:         mitreStore,
		severityToPriority: priorityMapping,

		needsPriority: !conf.DisablePriority,
		unknownMap:    unknownMap,
	}, nil
}

func createClient(notifier *storage.Notifier, cryptoCodec cryptocodec.CryptoCodec, cryptoKey string) (*jiraLib.Client, error) {
	conf := notifier.GetJira()
	decCreds := conf.GetPassword()

	var err error
	if env.EncNotifierCreds.BooleanSetting() {
		if notifier.GetNotifierSecret() == "" {
			return nil, errors.Errorf("encrypted notifier credentials for notifier '%s' empty", notifier.GetName())
		}
		decCreds, err = cryptoCodec.Decrypt(cryptoKey, notifier.GetNotifierSecret())
		if err != nil {
			return nil, errors.Errorf("Error decrypting notifier secret for notifier '%s'", notifier.GetName())
		}
	}

	url := urlfmt.FormatURL(conf.GetUrl(), urlfmt.HTTPS, urlfmt.TrailingSlash)

	httpClient := &http.Client{
		Timeout: timeout,
		Transport: &jiraLib.BasicAuthTransport{
			Username:  conf.GetUsername(),
			Password:  decCreds,
			Transport: proxy.RoundTripper(),
		},
	}

	client, err := jiraLib.NewClient(httpClient, url)
	if err != nil {
		return nil, errors.Wrap(err, "could not create JIRA client")
	}

	// Test auth

	urlPath := fmt.Sprintf("rest/api/2/configuration")

	req, err := client.NewRequest("GET", urlPath, nil)
	if err != nil {
		return nil, err
	}

	log.Debugf("Making request to %s", urlPath)
	_, err = client.Do(req, nil)

	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "401") || strings.Contains(errStr, "403") {
			log.Debug("Retrying request using bearer auth")
			httpClient := &http.Client{
				Timeout: timeout,
				Transport: &jiraLib.BearerAuthTransport{
					Token:     decCreds,
					Transport: proxy.RoundTripper(),
				},
			}

			client, err = jiraLib.NewClient(httpClient, url)
			if err != nil {
				return nil, errors.Wrap(err, "could not create JIRA client")
			}

			req, err := client.NewRequest("GET", urlPath, nil)
			if err != nil {
				return nil, err
			}
			_, err = client.Do(req, nil)
		}
		if err != nil {
			if strings.HasPrefix(errStr, "401") || strings.HasPrefix(errStr, "403") {
				return nil, errors.Wrap(err, "Could not authenticate to Jira")
			}
		}
	}

	return client, nil
}

func canCreateIssuesInProject(client *jiraLib.Client, project string) (bool, error) {
	urlPath := fmt.Sprintf("rest/api/2/mypermissions/?projectKey=%s&permissions=CREATE_ISSUES", project)

	req, err := client.NewRequest("GET", urlPath, nil)
	if err != nil {
		return false, err
	}

	log.Debugf("Making request to %s", urlPath)
	resp, err := client.Do(req, nil)
	if err != nil {
		log.Debugf("Raw error message from jira lib: %s", err.Error())
		if resp != nil && resp.StatusCode == 404 {
			return false, fmt.Errorf("Project %s not found", project)
		}
		return false, err
	}

	result := &permissionResult{}

	defer utils.IgnoreError(resp.Body.Close)
	err = json.NewDecoder(resp.Body).Decode(result)
	if err != nil {
		return false, err
	}

	return result.Permissions["CREATE_ISSUES"].HavePermission, nil
}

func configurePriority(client *jiraLib.Client, jiraConf *storage.Jira, project string) (map[storage.Severity]string, error) {
	hasPriority, err := isPriorityFieldOnIssueType(client, project, jiraConf.GetIssueType())
	if err != nil {
		return nil, errors.Wrapf(err, "could not determine if priority is a required field for project %q issue type %q", project, jiraConf.GetIssueType())
	}

	if !hasPriority {
		errMsg := "Priority field not found on requested issue type %s in project %s. Consider checking the 'Disable setting priority' box."
		return nil, fmt.Errorf(errMsg, jiraConf.GetIssueType(), project)
	}

	prios, _, err := client.Priority.GetList()
	if err != nil {
		return nil, errors.Wrap(err, "could not get the priority list")
	}

	return mapPriorities(prios, jiraConf.GetPriorityMappings())
}

func mapPriorities(prios []jiraLib.Priority, storageMapping []*storage.Jira_PriorityMapping) (map[storage.Severity]string, error) {
	prioNameSet := map[string]string{}
	for _, prio := range prios {
		prioNameSet[prio.Name] = ""
	}

	if len(storageMapping) == 0 {
		return nil, fmt.Errorf("Please define priority mappings")
	}

	finalizedMapping := map[storage.Severity]string{}
	missingFromJira := []string{}
	for _, prioMapping := range storageMapping {
		if _, exists := prioNameSet[prioMapping.PriorityName]; exists {
			finalizedMapping[prioMapping.Severity] = prioMapping.PriorityName
		} else {
			missingFromJira = append(missingFromJira, prioMapping.PriorityName)
		}
	}

	if len(missingFromJira) > 0 {
		return nil, fmt.Errorf("Priority mappings that do not exist in Jira: %v", missingFromJira)
	}

	return finalizedMapping, nil
}

func (j *jira) ProtoNotifier() *storage.Notifier {
	return j.notifier
}

func (j *jira) createIssue(_ context.Context, severity storage.Severity, i *jiraLib.Issue) error {
	i.Fields.Unknowns = j.unknownMap

	if !j.conf.DisablePriority {
		i.Fields.Priority = &jiraLib.Priority{
			Name: j.severityToPriority[severity],
		}
	}

	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(i)
	if err != nil {
		return err
	}
	log.Info(buf)

	_, resp, err := j.client.Issue.Create(i)
	if err != nil && resp == nil {
		return errors.Errorf("Error creating issue. Response: %v", err)
	}
	if err != nil {
		bytes, readErr := io.ReadAll(resp.Body)
		if readErr == nil {
			return errors.Wrapf(err, "error creating issue. Response: %s", bytes)
		}
	}
	return err
}

func (j *jira) Test(ctx context.Context) error {
	i := &jiraLib.Issue{
		Fields: &jiraLib.IssueFields{
			Description: "StackRox Test Issue",
			Type: jiraLib.IssueType{
				Name: j.conf.GetIssueType(),
			},
			Project: jiraLib.Project{
				Key: j.notifier.GetLabelDefault(),
			},
			Summary: "This is a test issue created to test integration with StackRox.",
		},
	}
	return j.createIssue(ctx, storage.Severity_LOW_SEVERITY, i)
}

func init() {
	cryptoKey := ""
	var err error
	if env.EncNotifierCreds.BooleanSetting() {
		cryptoKey, _, err = notifierUtils.GetActiveNotifierEncryptionKey()
		if err != nil {
			utils.Should(errors.Wrap(err, "Error reading encryption key, notifier will be unable to send notifications"))
		}
	}
	notifiers.Add(notifiers.JiraType, func(notifier *storage.Notifier) (notifiers.Notifier, error) {
		j, err := newJira(notifier, metadatagetter.Singleton(), mitreDataStore.Singleton(), cryptocodec.Singleton(), cryptoKey)
		return j, err
	})
}
