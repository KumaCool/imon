package control

import (
	"context"
	"database/sql"
	"maps"
	"time"
)

type scheduledRules struct {
	kind   string
	rev    int64
	groups map[string]map[string]int64 // collector group -> rule revisions
}

type scheduledGroup struct {
	jobID string
	done  bool
}

type scheduledTarget struct {
	kind   string
	rev    int64
	groups map[string]*scheduledGroup
}

func (c *Control) scheduledRules(ctx context.Context) (map[string]scheduledRules, error) {
	out := map[string]scheduledRules{}
	err := c.db.Read(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT t.target_id,t.kind,t.connection_rev,r.group_name,r.id,r.revision
			FROM alert_rules r JOIN targets t ON t.target_id=r.target_id AND t.connection_rev=r.connection_rev
			WHERE t.enabled=1 AND t.identity<>'' AND r.enabled=1`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, kind, group, ruleID string
			var rev, ruleRev int64
			if err := rows.Scan(&id, &kind, &rev, &group, &ruleID, &ruleRev); err != nil {
				return err
			}
			if group == "metrics" {
				group = "host_metrics"
			}
			target, ok := out[id]
			if !ok {
				target = scheduledRules{kind, rev, map[string]map[string]int64{}}
				out[id] = target
			}
			if target.groups[group] == nil {
				target.groups[group] = map[string]int64{}
			}
			target.groups[group][ruleID] = ruleRev
		}
		return rows.Err()
	})
	return out, err
}

func currentRules(ctx context.Context, tx *sql.Tx, q *collection, group string) bool {
	if !q.groups[group] {
		return true
	}
	expected := q.rules[group]
	if len(expected) == 0 {
		return false
	}
	if group == "host_metrics" {
		group = "metrics"
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,revision FROM alert_rules WHERE enabled=1 AND target_id=? AND connection_rev=? AND group_name=?`, q.target.ID, q.target.ConnectionRev, group)
	if err != nil {
		return false
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var id string
		var rev int64
		if rows.Scan(&id, &rev) != nil || expected[id] != rev {
			return false
		}
		count++
	}
	return rows.Err() == nil && count == len(expected)
}

func (c *Control) effectiveDue(id, group string) time.Time {
	due := c.due[id][group]
	if backoff := c.backoff[id]; backoff.After(due) {
		return backoff
	}
	return due
}

// plan is called with mu held and permits one global scheduled round at a time.
func (c *Control) plan(now time.Time) {
	var rules map[string]scheduledRules
	if c.settings.Enabled {
		var err error
		rules, err = c.scheduledRules(c.ctx)
		if err != nil {
			return
		}
	}
	for id, due := range c.due {
		before, after := c.ruleSet[id], rules[id]
		if len(after.groups) == 0 || before.rev != after.rev {
			delete(c.due, id)
			delete(c.backoff, id)
			delete(c.failures, id)
			continue
		}
		for group := range due {
			if !maps.Equal(before.groups[group], after.groups[group]) {
				delete(due, group)
			}
		}
	}
	c.ruleSet = rules
	for id, target := range c.round {
		for group, task := range target.groups {
			if task.done || hasJob(c.active[id], task.jobID) {
				continue
			}
			if rule := rules[id]; rule.rev == target.rev && len(rule.groups[group]) > 0 {
				continue
			}
			if !c.cancelPlannedGroup(id, group, task) {
				continue
			}
			task.done = true
		}
	}
	c.clearFinishedRound()
	if c.round == nil {
		for id, rule := range rules {
			for group := range rule.groups {
				if now.Before(c.effectiveDue(id, group)) {
					continue
				}
				if c.round == nil {
					c.round = map[string]*scheduledTarget{}
				}
				if c.round[id] == nil {
					c.round[id] = &scheduledTarget{rule.kind, rule.rev, map[string]*scheduledGroup{}}
				}
				c.round[id].groups[group] = &scheduledGroup{}
			}
		}
	}
	for id, target := range c.round {
		if c.active[id] != nil {
			continue // Never relabel an executing manual sample as scheduled.
		}
		groups := map[string]bool{}
		for group, task := range target.groups {
			if !task.done && task.jobID == "" {
				groups[group] = true
			}
		}
		if len(groups) == 0 {
			continue
		}
		if c.due[id] == nil {
			c.due[id] = map[string]time.Time{}
		}
		b, err := c.target(c.ctx, id)
		if err == nil && b.ConnectionRev != target.rev {
			err = errConflict
		}
		var jobID string
		if err == nil {
			jobID, err = c.enqueue(c.ctx, b, groups, false)
		}
		for group := range groups {
			task := target.groups[group]
			task.jobID, task.done = jobID, err != nil
			c.due[id][group] = now.Add(c.settings.period(target.kind, group))
		}
	}
	c.clearFinishedRound()
}

func (c *Control) cancelPlannedGroup(id, group string, task *scheduledGroup) bool {
	q := c.queued[id]
	if !hasJob(q, task.jobID) {
		return true
	}
	if q.manual[group] {
		q.groups[group] = false
		return true
	}
	if len(q.groups) == 1 {
		if err := c.db.Write(c.ctx, func(tx *sql.Tx) error { return finishJob(c.ctx, tx, q.job.ID, "canceled", nil, "rule_changed") }); err != nil {
			// Keep the stale group out of dispatch even when persisting the cancellation fails.
			delete(c.queued, id)
			return true
		}
		delete(c.queued, id)
		return true
	}
	delete(q.groups, group)
	return true
}

func (c *Control) isPlanned(q *collection) bool {
	for _, scheduled := range q.groups {
		if scheduled {
			return true
		}
	}
	return false
}

func (c *Control) markGroupDone(q *collection, group string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if target := c.round[q.target.ID]; target != nil {
		if task := target.groups[group]; task != nil && task.jobID == q.job.ID {
			task.done = true
		}
	}
}

func (c *Control) finishPlanned(q *collection) {
	if target := c.round[q.target.ID]; target != nil {
		for _, task := range target.groups {
			if task.jobID == q.job.ID {
				task.done = true
			}
		}
	}
}

func (c *Control) clearFinishedRound() {
	for _, target := range c.round {
		for _, task := range target.groups {
			if !task.done {
				return
			}
		}
	}
	c.round = nil
}
