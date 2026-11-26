package control

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"imon/internal/store"
)

type collectionObserver interface {
	Collection(context.Context, *sql.Tx, string, int64, string, string, time.Time) error
}

type collectionIncident struct {
	targetID, group, code string
	rev                   int64
	observed              time.Time
}

const maxPendingCollectionIncidents = 256

func (c *Control) observeCollection(q *collection, group, code string) {
	observer, ok := c.observer.(collectionObserver)
	if !ok || code == "canceled" {
		return
	}
	c.incidentMu.Lock()
	defer c.incidentMu.Unlock()
	if len(c.incidents) == maxPendingCollectionIncidents {
		copy(c.incidents, c.incidents[1:])
		c.incidents = c.incidents[:len(c.incidents)-1]
	}
	c.incidents = append(c.incidents, collectionIncident{q.target.ID, group, code, q.target.ConnectionRev, time.Now()})
	c.flushIncidentsLocked(observer)
}

func (c *Control) flushCollectionIncidents() {
	if observer, ok := c.observer.(collectionObserver); ok {
		c.incidentMu.Lock()
		defer c.incidentMu.Unlock()
		c.flushIncidentsLocked(observer)
	}
}

func (c *Control) flushIncidentsLocked(observer collectionObserver) {
	if len(c.incidents) == 0 {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 16 && len(c.incidents) > 0; i++ {
		item := c.incidents[0]
		err := c.db.Write(ctx, func(tx *sql.Tx) error {
			return observer.Collection(ctx, tx, item.targetID, item.rev, item.group, item.code, item.observed)
		})
		if err != nil && !errors.Is(err, store.ErrStaleTarget) && !errors.Is(err, store.ErrNotFound) {
			return
		}
		c.incidents[0] = collectionIncident{}
		c.incidents = c.incidents[1:]
	}
	if len(c.incidents) == 0 {
		c.incidents = nil
	}
}
