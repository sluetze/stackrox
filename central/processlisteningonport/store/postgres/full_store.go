package postgres

import (
	"context"
	"reflect"
	"time"

	// "unsafe"
	"github.com/gogo/protobuf/proto"
	"github.com/jackc/pgx/v4"
	metrics "github.com/stackrox/rox/central/metrics"
	"github.com/stackrox/rox/central/processlisteningonport/store"
	"github.com/stackrox/rox/generated/storage"
	ops "github.com/stackrox/rox/pkg/metrics"
	"github.com/stackrox/rox/pkg/postgres"
	"github.com/stackrox/rox/pkg/postgres/pgutils"
)

// NewFullStore augments the generated store with GetProcessListeningOnPort functions.
func NewFullStore(db postgres.DB) store.Store {
	return &fullStoreImpl{
		Store: New(db),
		db:    db,
	}
}

type fullStoreImpl struct {
	Store
	db postgres.DB
}

// SQL query to join process_listening_on_port together with
// process_indicators. Used to provide information for queries like 'give
// me all PLOP by this deployment'.
// XXX: Verify the query plan to make sure needed indexes are in use.
const getByDeploymentStmt = "SELECT plop.serialized, " +
	"proc.serialized as proc_serialized " +
	"FROM listening_endpoints plop " +
	"LEFT OUTER JOIN process_indicators proc " +
	"ON plop.processindicatorid = proc.id " +
	"WHERE plop.deploymentid = $1 AND plop.closed = false"

// Manually written function to get PLOP joined with ProcessIndicators
func (s *fullStoreImpl) GetProcessListeningOnPort(
	ctx context.Context,
	deploymentID string,
) ([]*storage.ProcessListeningOnPort, error) {
	defer metrics.SetPostgresOperationDurationTime(
		time.Now(),
		ops.GetProcessListeningOnPort,
		"ProcessListeningOnPortStorage",
	)

	return pgutils.Retry2(func() ([]*storage.ProcessListeningOnPort, error) {
		return s.retryableGetPLOP(ctx, deploymentID)
	})
}

func (s *fullStoreImpl) retryableGetPLOP(
	ctx context.Context,
	deploymentID string,
) ([]*storage.ProcessListeningOnPort, error) {
	var rows pgx.Rows
	var err error

	startTime := time.Now()
	rows, err = s.db.Query(ctx, getByDeploymentStmt, deploymentID)
	endTime := time.Now()

	duration := endTime.Sub(startTime)

	log.Infof("Plop query took %+v", duration)

	if err != nil {
		// Do not be alarmed if the error is simply NoRows
		err = pgutils.ErrNilIfNoRows(err)
		if err != nil {
			log.Warnf("%s: %s", getByDeploymentStmt, err)
		}
		return nil, err
	}
	defer rows.Close()

	startTime = time.Now()
	results, err := s.readRows(rows)
	endTime = time.Now()

	duration = endTime.Sub(startTime)
	log.Infof("readRow took %+v", duration)

	if err != nil {
		return nil, err
	}

	return results, rows.Err()
}

func memoryUsage(v interface{}) int {
	size := int(reflect.TypeOf(v).Size())
	return size
}

// Manual converting of raw data from SQL query to ProcessListeningOnPort (not
// ProcessListeningOnPortStorage) object enriched with ProcessIndicator info.
func (s *fullStoreImpl) readRows(
	rows pgx.Rows,
) ([]*storage.ProcessListeningOnPort, error) {
	var plops []*storage.ProcessListeningOnPort
	var totalAppendDuration time.Duration
	var memSerialized = 0
	var memProcSerialized = 0

	totalAppendDuration = 0

	startTime := time.Now()
	for rows.Next() {
		var serialized []byte
		var procSerialized []byte
		var podID string
		var podUID string
		var containerName string
		var name string
		var args string
		var execFilePath string

		// We're getting ProcessIndicator directly from the SQL query, PLOP
		// parts have to be extra deserialized.
		if err := rows.Scan(&serialized, &procSerialized); err != nil {
			return nil, pgutils.ErrNilIfNoRows(err)
		}

		memSerialized += len(serialized)
		memProcSerialized += len(procSerialized)
		var msg storage.ProcessListeningOnPortStorage
		if err := proto.Unmarshal(serialized, &msg); err != nil {
			return nil, err
		}

		var procMsg storage.ProcessIndicator
		if err := proto.Unmarshal(procSerialized, &procMsg); err != nil {
			return nil, err
		}

		podUID = msg.GetPodUid()

		if procMsg.GetPodId() != "" {
			podID = procMsg.GetPodId()
			containerName = procMsg.GetContainerName()
			name = procMsg.GetSignal().GetName()
			args = procMsg.GetSignal().GetArgs()
			execFilePath = procMsg.GetSignal().GetExecFilePath()
		} else {
			podID = msg.GetProcess().GetPodId()
			containerName = msg.GetProcess().GetContainerName()
			name = msg.GetProcess().GetProcessName()
			args = msg.GetProcess().GetProcessArgs()
			execFilePath = msg.GetProcess().GetProcessExecFilePath()
		}

		// If we don't have any of this information from either the process indicator side or
		// processes listening on ports side, the process indicator has been deleted and the
		// port has been closed. Central just hasn't gotten the message yet.
		if podID == "" && containerName == "" && name == "" && args == "" && execFilePath == "" {
			continue
		}

		plop := &storage.ProcessListeningOnPort{
			Endpoint: &storage.ProcessListeningOnPort_Endpoint{
				Port:     msg.GetPort(),
				Protocol: msg.GetProtocol(),
			},
			DeploymentId:  msg.GetDeploymentId(),
			PodId:         podID,
			PodUid:        podUID,
			ContainerName: containerName,
			Signal: &storage.ProcessSignal{
				Id:           procMsg.GetSignal().GetId(),
				ContainerId:  procMsg.GetSignal().GetContainerId(),
				Time:         procMsg.GetSignal().GetTime(),
				Name:         name,
				Args:         args,
				ExecFilePath: execFilePath,
				Pid:          procMsg.GetSignal().GetPid(),
				Uid:          procMsg.GetSignal().GetUid(),
				Gid:          procMsg.GetSignal().GetGid(),
				Lineage:      procMsg.GetSignal().GetLineage(),
				Scraped:      procMsg.GetSignal().GetScraped(),
				LineageInfo:  procMsg.GetSignal().GetLineageInfo(),
			},
			ClusterId:          procMsg.GetClusterId(),
			Namespace:          procMsg.GetNamespace(),
			ContainerStartTime: procMsg.GetContainerStartTime(),
			ImageId:            procMsg.GetImageId(),
		}

		appendStartTime := time.Now()
		plops = append(plops, plop)
		appendEndTime := time.Now()
		appendDuration := appendEndTime.Sub(appendStartTime)
		totalAppendDuration += appendDuration
	}

	endTime := time.Now()

	duration := endTime.Sub(startTime)

	log.Infof("loop took %+v", duration)
	log.Infof("appending in loop took %+v", totalAppendDuration)

	if len(plops) > 0 {
		memorySize := memoryUsage(plops[0]) * len(plops)
		memorySizeValue := memoryUsage(*plops[0]) * len(plops)
		memorySizeSignal := memoryUsage(*(plops[0].Signal)) * len(plops)
		memorySizeEndpoint := memoryUsage(*(plops[0].Endpoint)) * len(plops)
		memoryTotal := memorySize + memorySizeValue + memorySizeSignal + memorySizeEndpoint
		memoryTotalTotal := memoryTotal + memSerialized + memProcSerialized
		log.Infof("plops memorySize= %+v", memorySize)
		log.Infof("plops memorySizeValue= %+v", memorySizeValue)
		log.Infof("plops memorySizeSignal= %+v", memorySizeSignal)
		log.Infof("plops memorySizeEndpoint= %v", memorySizeEndpoint)
		log.Infof("memoryTotal= %+v", memoryTotal)
		log.Infof("memorySerialized= %+v", memSerialized)
		log.Infof("memoryProcSerialized= %+v", memProcSerialized)
		log.Infof("memoryTotalTotal= %+v", memoryTotalTotal)
	}

	log.Debugf("Read returned %+v plops", len(plops))
	return plops, nil
}
