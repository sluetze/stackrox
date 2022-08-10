// Code generated by pg-bindings generator. DO NOT EDIT.

package schema

import (
	"fmt"
	"reflect"
	"time"

	"github.com/lib/pq"
	v1 "github.com/stackrox/rox/generated/api/v1"
	"github.com/stackrox/rox/generated/storage"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/walker"
	"github.com/stackrox/rox/pkg/search"
)

var (
	// CreateTableAlertsStmt holds the create statement for table `alerts`.
	CreateTableAlertsStmt = &postgres.CreateStmts{
		Table: `
               create table if not exists alerts (
                   Id varchar,
                   Policy_Id varchar,
                   Policy_Name varchar,
                   Policy_Description varchar,
                   Policy_Disabled bool,
                   Policy_Categories text[],
                   Policy_LifecycleStages int[],
                   Policy_Severity integer,
                   Policy_EnforcementActions int[],
                   Policy_LastUpdated timestamp,
                   Policy_SORTName varchar,
                   Policy_SORTLifecycleStage varchar,
                   Policy_SORTEnforcement bool,
                   LifecycleStage integer,
                   ClusterId varchar,
                   ClusterName varchar,
                   Namespace varchar,
                   NamespaceId varchar,
                   Deployment_Id varchar,
                   Deployment_Name varchar,
                   Deployment_Inactive bool,
                   Image_Id varchar,
                   Image_Name_Registry varchar,
                   Image_Name_Remote varchar,
                   Image_Name_Tag varchar,
                   Image_Name_FullName varchar,
                   Resource_ResourceType integer,
                   Resource_Name varchar,
                   Enforcement_Action integer,
                   Time timestamp,
                   State integer,
                   Tags text[],
                   serialized bytea,
                   PRIMARY KEY(Id),
                   CONSTRAINT fk_parent_table_0 FOREIGN KEY (ClusterId) REFERENCES clusters(Id) ON DELETE CASCADE
               )
               `,
		GormModel: (*Alerts)(nil),
		Indexes: []string{
			"create index if not exists alerts_LifecycleStage on alerts using btree(LifecycleStage)",
			"create index if not exists alerts_Deployment_Id on alerts using hash(Deployment_Id)",
			"create index if not exists alerts_State on alerts using btree(State)",
		},
		Children: []*postgres.CreateStmts{
			&postgres.CreateStmts{
				Table: `
               create table if not exists alerts_processes (
                   alerts_Id varchar,
                   idx integer,
                   ClusterId varchar,
                   PRIMARY KEY(alerts_Id, idx),
                   CONSTRAINT fk_parent_table_0 FOREIGN KEY (alerts_Id) REFERENCES alerts(Id) ON DELETE CASCADE,
                   CONSTRAINT fk_parent_table_1 FOREIGN KEY (ClusterId) REFERENCES clusters(Id) ON DELETE CASCADE
               )
               `,
				GormModel: (*AlertsProcesses)(nil),
				Indexes: []string{
					"create index if not exists alertsProcesses_idx on alerts_processes using btree(idx)",
				},
				Children: []*postgres.CreateStmts{},
			},
		},
	}

	// AlertsSchema is the go schema for table `alerts`.
	AlertsSchema = func() *walker.Schema {
		schema := GetSchemaForTable("alerts")
		if schema != nil {
			return schema
		}
		schema = walker.Walk(reflect.TypeOf((*storage.Alert)(nil)), "alerts")
		referencedSchemas := map[string]*walker.Schema{
			"storage.Cluster": ClustersSchema,
		}

		schema.ResolveReferences(func(messageTypeName string) *walker.Schema {
			return referencedSchemas[fmt.Sprintf("storage.%s", messageTypeName)]
		})
		schema.SetOptionsMap(search.Walk(v1.SearchCategory_ALERTS, "alert", (*storage.ListAlert)(nil)))
		RegisterTable(schema, CreateTableAlertsStmt)
		return schema
	}()
)

const (
	AlertsTableName          = "alerts"
	AlertsProcessesTableName = "alerts_processes"
)

// Alerts holds the Gorm model for Postgres table `alerts`.
type Alerts struct {
	Id                       string                              `gorm:"column:id;type:varchar;primaryKey"`
	PolicyId                 string                              `gorm:"column:policy_id;type:varchar"`
	PolicyName               string                              `gorm:"column:policy_name;type:varchar"`
	PolicyDescription        string                              `gorm:"column:policy_description;type:varchar"`
	PolicyDisabled           bool                                `gorm:"column:policy_disabled;type:bool"`
	PolicyCategories         *pq.StringArray                     `gorm:"column:policy_categories;type:text[]"`
	PolicyLifecycleStages    *pq.Int32Array                      `gorm:"column:policy_lifecyclestages;type:int[]"`
	PolicySeverity           storage.Severity                    `gorm:"column:policy_severity;type:integer"`
	PolicyEnforcementActions *pq.Int32Array                      `gorm:"column:policy_enforcementactions;type:int[]"`
	PolicyLastUpdated        *time.Time                          `gorm:"column:policy_lastupdated;type:timestamp"`
	PolicySORTName           string                              `gorm:"column:policy_sortname;type:varchar"`
	PolicySORTLifecycleStage string                              `gorm:"column:policy_sortlifecyclestage;type:varchar"`
	PolicySORTEnforcement    bool                                `gorm:"column:policy_sortenforcement;type:bool"`
	LifecycleStage           storage.LifecycleStage              `gorm:"column:lifecyclestage;type:integer;index:alerts_lifecyclestage,type:btree"`
	ClusterId                string                              `gorm:"column:clusterid;type:varchar"`
	ClusterName              string                              `gorm:"column:clustername;type:varchar"`
	Namespace                string                              `gorm:"column:namespace;type:varchar"`
	NamespaceId              string                              `gorm:"column:namespaceid;type:varchar"`
	DeploymentId             string                              `gorm:"column:deployment_id;type:varchar;index:alerts_deployment_id,type:hash"`
	DeploymentName           string                              `gorm:"column:deployment_name;type:varchar"`
	DeploymentInactive       bool                                `gorm:"column:deployment_inactive;type:bool"`
	ImageId                  string                              `gorm:"column:image_id;type:varchar"`
	ImageNameRegistry        string                              `gorm:"column:image_name_registry;type:varchar"`
	ImageNameRemote          string                              `gorm:"column:image_name_remote;type:varchar"`
	ImageNameTag             string                              `gorm:"column:image_name_tag;type:varchar"`
	ImageNameFullName        string                              `gorm:"column:image_name_fullname;type:varchar"`
	ResourceResourceType     storage.Alert_Resource_ResourceType `gorm:"column:resource_resourcetype;type:integer"`
	ResourceName             string                              `gorm:"column:resource_name;type:varchar"`
	EnforcementAction        storage.EnforcementAction           `gorm:"column:enforcement_action;type:integer"`
	Time                     *time.Time                          `gorm:"column:time;type:timestamp"`
	State                    storage.ViolationState              `gorm:"column:state;type:integer;index:alerts_state,type:btree"`
	Tags                     *pq.StringArray                     `gorm:"column:tags;type:text[]"`
	Serialized               []byte                              `gorm:"column:serialized;type:bytea"`
	ClustersRef              Clusters                            `gorm:"foreignKey:clusterid;references:id;belongsTo;constraint:OnDelete:CASCADE"`
}

// AlertsProcesses holds the Gorm model for Postgres table `alerts_processes`.
type AlertsProcesses struct {
	AlertsId    string   `gorm:"column:alerts_id;type:varchar;primaryKey"`
	Idx         int      `gorm:"column:idx;type:integer;primaryKey;index:alertsprocesses_idx,type:btree"`
	ClusterId   string   `gorm:"column:clusterid;type:varchar"`
	AlertsRef   Alerts   `gorm:"foreignKey:alerts_id;references:id;belongsTo;constraint:OnDelete:CASCADE"`
	ClustersRef Clusters `gorm:"foreignKey:clusterid;references:id;belongsTo;constraint:OnDelete:CASCADE"`
}
