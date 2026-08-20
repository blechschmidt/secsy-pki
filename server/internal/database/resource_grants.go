package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/blechschmidt/secsy-pki/server/internal/models"
	"github.com/blechschmidt/secsy-pki/server/internal/rbac"
)

// Resource-scoped grant storage (Task 191). See internal/rbac/grant.go for the
// authorization model these rows feed.

const resourceGrantColumns = `id, resource_type, resource_id, entity_type, entity_id, role, scope, created_at, created_by`

func scanResourceGrant(s interface{ Scan(...any) error }) (*models.ResourceGrant, error) {
	var g models.ResourceGrant
	var createdBy sql.NullString
	if err := s.Scan(&g.ID, &g.ResourceType, &g.ResourceID, &g.EntityType, &g.EntityID,
		&g.Role, &g.Scope, &g.CreatedAt, &createdBy); err != nil {
		return nil, err
	}
	g.CreatedBy = createdBy.String
	g.CreatedAt = g.CreatedAt.UTC()
	return &g, nil
}

func collectResourceGrants(rows *sql.Rows, err error) ([]models.ResourceGrant, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ResourceGrant
	for rows.Next() {
		g, err := scanResourceGrant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *g)
	}
	return out, rows.Err()
}

// PutResourceGrant stores a grant, replacing any existing grant with the same
// natural key (resource + entity + role) so re-granting with a wider scope is an
// update rather than a duplicate. The caller is responsible for having
// validated the grant; this rejects a malformed one anyway, because an
// unvalidated row would be silently dropped by the evaluator and the operator
// would see a grant that exists in the table but authorizes nothing.
func (db *DB) PutResourceGrant(g *models.ResourceGrant) error {
	rule := g.Grant()
	if err := rule.Validate(); err != nil {
		return fmt.Errorf("invalid resource grant: %w", err)
	}
	g.Scope = rule.Scope // apply the "self" default
	if g.CreatedAt.IsZero() {
		g.CreatedAt = time.Now().UTC()
	} else {
		g.CreatedAt = g.CreatedAt.UTC()
	}
	_, err := db.exec(
		`INSERT INTO resource_grants (`+resourceGrantColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(resource_type, resource_id, entity_type, entity_id, role)
		 DO UPDATE SET scope = excluded.scope, created_at = excluded.created_at, created_by = excluded.created_by`,
		g.ID, string(g.ResourceType), g.ResourceID, g.EntityType, g.EntityID,
		string(g.Role), string(g.Scope), g.CreatedAt, g.CreatedBy,
	)
	return err
}

// DeleteResourceGrant removes one grant by its natural key. It reports whether a
// row was actually removed so the API can answer 404 for a grant that was never
// there, rather than silently confirming a revocation that did nothing.
func (db *DB) DeleteResourceGrant(res rbac.Resource, entityType, entityID string, role rbac.ResourceRole) (bool, error) {
	r, err := db.exec(
		`DELETE FROM resource_grants WHERE resource_type = ? AND resource_id = ? AND entity_type = ? AND entity_id = ? AND role = ?`,
		string(res.Type), res.ID, entityType, entityID, string(role),
	)
	if err != nil {
		return false, err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// DeleteResourceGrantsFor removes every grant recorded on a resource. It is
// called when the underlying CA or key is deleted so a later resource that
// happens to reuse the identifier cannot inherit stale authority.
func (db *DB) DeleteResourceGrantsFor(res rbac.Resource) error {
	_, err := db.exec(
		`DELETE FROM resource_grants WHERE resource_type = ? AND resource_id = ?`,
		string(res.Type), res.ID,
	)
	return err
}

// ListResourceGrants returns the grants recorded directly on one resource.
func (db *DB) ListResourceGrants(res rbac.Resource) ([]models.ResourceGrant, error) {
	return collectResourceGrants(db.query(
		`SELECT `+resourceGrantColumns+` FROM resource_grants WHERE resource_type = ? AND resource_id = ?
		 ORDER BY entity_type, entity_id, role`,
		string(res.Type), res.ID,
	))
}

// ListResourceGrantsAt returns the grants recorded on any of the given
// resources, in one round trip per resource type. The authorization path calls
// it with a resource plus its ancestors, so a subtree-scoped delegation is
// resolved without issuing a query per level of the CA hierarchy.
func (db *DB) ListResourceGrantsAt(resources []rbac.Resource) ([]models.ResourceGrant, error) {
	byType := make(map[rbac.ResourceType][]string)
	seen := make(map[string]bool, len(resources))
	for _, r := range resources {
		if !r.Valid() || seen[r.String()] {
			continue
		}
		seen[r.String()] = true
		byType[r.Type] = append(byType[r.Type], r.ID)
	}
	var out []models.ResourceGrant
	for typ, ids := range byType {
		args := make([]any, 0, len(ids)+1)
		args = append(args, string(typ))
		placeholders := make([]string, len(ids))
		for i, id := range ids {
			placeholders[i] = "?"
			args = append(args, id)
		}
		got, err := collectResourceGrants(db.query(
			`SELECT `+resourceGrantColumns+` FROM resource_grants
			 WHERE resource_type = ? AND resource_id IN (`+strings.Join(placeholders, ", ")+`)`,
			args...,
		))
		if err != nil {
			return nil, err
		}
		out = append(out, got...)
	}
	return out, nil
}

// ListAllResourceGrants returns every stored grant, ordered deterministically.
// The table holds one row per delegation — a handful per CA at most — so the
// authorization path loads it whole rather than issuing a query per ancestor on
// every request.
func (db *DB) ListAllResourceGrants() ([]models.ResourceGrant, error) {
	return collectResourceGrants(db.query(
		`SELECT ` + resourceGrantColumns + ` FROM resource_grants
		 ORDER BY resource_type, resource_id, entity_type, entity_id, role`,
	))
}

// SetCAParentForTest rewires a CA's parent link. It exists so tests can build a
// deliberately corrupt hierarchy — notably a parent cycle — and prove the
// ancestry walk that every per-CA authorization decision performs still
// terminates. Production code sets parent_id at creation and never moves a CA.
func (db *DB) SetCAParentForTest(caID, parentID string) error {
	_, err := db.exec(`UPDATE cas SET parent_id = ? WHERE id = ?`, parentID, caID)
	return err
}

// GetCAAncestors returns the IDs of a CA's parents, nearest first, walking up
// the issuance hierarchy. It is what makes a subtree-scoped grant on a parent CA
// reach its subordinates.
//
// The walk is bounded by maxCAHierarchyDepth and guards against a cycle, so a
// corrupted parent chain degrades to "no ancestors" — denying inherited
// authority — instead of spinning inside an authorization check.
func (db *DB) GetCAAncestors(caID string) ([]string, error) {
	const maxCAHierarchyDepth = 32
	var out []string
	seen := map[string]bool{caID: true}
	cur := caID
	for range maxCAHierarchyDepth {
		var parent sql.NullString
		err := db.queryRow(`SELECT parent_id FROM cas WHERE id = ?`, cur).Scan(&parent)
		if err == sql.ErrNoRows {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		if !parent.Valid || parent.String == "" || seen[parent.String] {
			return out, nil
		}
		seen[parent.String] = true
		out = append(out, parent.String)
		cur = parent.String
	}
	return out, nil
}
