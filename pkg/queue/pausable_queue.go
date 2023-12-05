package queue

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stackrox/rox/pkg/concurrency"
	"github.com/stackrox/rox/pkg/sync"
)

// PausableQueue defines a queue that can be paused.
// Given aggregate functions (AggregateFunc), pushed items can be aggregate with items already in the queue.
type PausableQueue[T comparable] interface {
	Push(T)
	Pull() T
	PullBlocking() T
	Pause()
	Resume()
	Stop()
	AddAggregator(AggregateFunc[T])
	SetSize(int)
	SetMetric(*prometheus.CounterVec)
}

// AggregateFunc aggregates two comparable variables.
// Returns the aggregate and a boolean indicating whether the aggregation took place or not.
type AggregateFunc[T comparable] func(x, y T) (T, bool)

type pausableQueueImpl[T comparable] struct {
	mu            sync.Mutex
	internalQueue *Queue[T]
	isRunning     concurrency.Signal
	stop          concurrency.Signal
	aggregators   []AggregateFunc[T]
}

// PausableQueueOption provides options for the queue.
type PausableQueueOption[T comparable] func(PausableQueue[T])

// WithAggregator provides an AggregateFunc for the queue.
func WithAggregator[T comparable](aggregator AggregateFunc[T]) PausableQueueOption[T] {
	return func(q PausableQueue[T]) {
		q.AddAggregator(aggregator)
	}
}

// WithPausableMaxSize provides a maximum size for the queue. By default, no size limit is set.
func WithPausableMaxSize[T comparable](size int) PausableQueueOption[T] {
	return func(q PausableQueue[T]) {
		q.SetSize(size)
	}
}

// WithPausableQueueMetric provides a counter vec which tracks added and removed items from the queue.
func WithPausableQueueMetric[T comparable](metric *prometheus.CounterVec) PausableQueueOption[T] {
	return func(q PausableQueue[T]) {
		q.SetMetric(metric)
	}
}

// NewPausableQueue creates a new PausableQueue.
func NewPausableQueue[T comparable](opts ...PausableQueueOption[T]) PausableQueue[T] {
	q := &pausableQueueImpl[T]{
		internalQueue: NewQueue[T](),
		isRunning:     concurrency.NewSignal(),
		stop:          concurrency.NewSignal(),
	}
	for _, opt := range opts {
		opt(q)
	}
	return q
}

// SetSize sets the maximum size of the queue. Once we reach the maximum any call to Push will be ignored.
func (q *pausableQueueImpl[T]) SetSize(size int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.internalQueue.maxSize = size
}

// SetMetric sets the counter metric.
func (q *pausableQueueImpl[T]) SetMetric(metric *prometheus.CounterVec) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.internalQueue.counterMetric = metric
}

// AddAggregator appends a new AggregatorFunc.
func (q *pausableQueueImpl[T]) AddAggregator(aggregator AggregateFunc[T]) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.aggregators = append(q.aggregators, aggregator)
}

// Push adds an item to the queue.
// If the queue has aggregator functions (AggregateFunc) the queue will try to aggregate with the items already in the queue.
// Note that we only aggregate once.
func (q *pausableQueueImpl[T]) Push(item T) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.aggregators) == 0 {
		q.internalQueue.Push(item)
		return
	}

	wasAggregated := false
	for e := q.internalQueue.queue.Front(); e != nil; e = e.Next() {
		element, ok := e.Value.(T)
		if !ok {
			continue
		}
		for _, fn := range q.aggregators {
			val, aggregated := fn(element, item)
			if aggregated {
				e.Value = val
				wasAggregated = true
				break
			}
		}
		if wasAggregated {
			break
		}
	}

	if !wasAggregated {
		q.internalQueue.Push(item)
	}
}

// Pull will pull an item from the queue. If the queue is empty or paused, the default value of T will be returned.
// Note that his does not wait for items to be available in the queue, use PullBlocking instead.
func (q *pausableQueueImpl[T]) Pull() T {
	var ret T
	if !q.isRunning.IsDone() {
		return ret
	}

	return q.internalQueue.Pull()
}

// PullBlocking will pull an item from the queue, potentially waiting until one is available.
// In case the queue is stopped, the default value of T will be returned.
func (q *pausableQueueImpl[T]) PullBlocking() T {
	var ret T
	select {
	case <-q.stop.Done():
		return ret
	case <-q.isRunning.Done():
		return q.internalQueue.PullBlocking(&q.stop)
	}
}

// Pause the queue.
func (q *pausableQueueImpl[T]) Pause() {
	q.isRunning.Reset()
}

// Resume the queue.
func (q *pausableQueueImpl[T]) Resume() {
	q.isRunning.Signal()
}

// Stop the queue permanently.
func (q *pausableQueueImpl[T]) Stop() {
	q.stop.Signal()
}
