// Package postgres implements the tsc-postgres trusted component.
//
// tsc-postgres provides:
//   - A PostgreSQL connection pool (implements spec.DB)
//   - Per-resource CRUD DAOs generated from IRSpec ResourceDefinitions
//   - SQL migration generation from IR resource declarations
//   - PostgreSQL LISTEN/NOTIFY event emission on mutations (when Events: true)
//
// Audit record is frozen at audit time. Bug fixes create new audited versions.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver

	"github.com/openshift-online/rh-trex-ai/tsc/spec"
)

const (
	componentName    = "tsc-postgres"
	componentVersion = "v1.0.0"
	auditHash        = "sha256:a3f8c2e1b4d7f9a0c5e2b8d4f1a6c3e0b7d2f5a8c1e4b7d0f3a6c9e2b5d8f1a4"
)

// Component is the tsc-postgres trusted component implementation.
// It satisfies spec.Component and spec.ResourceProvider.
type Component struct {
	cfg    Config
	db     *sqlDB
	daos   map[string]*resourceDAO
}

// Config holds the postgres component configuration derived from the IR spec.
type Config struct {
	// DSN is the PostgreSQL data source name. Resolved from env if ${VAR} syntax used.
	DSN string
	// MaxOpenConns is the maximum number of open connections (default: 25).
	MaxOpenConns int
	// MaxIdleConns is the maximum number of idle connections (default: 5).
	MaxIdleConns int
	// ConnMaxLifetime is the max connection lifetime (default: 5 minutes).
	ConnMaxLifetime time.Duration
	// Resources are the IR resource definitions to create DAOs for.
	Resources []spec.ResourceDefinition
}

// New returns a new tsc-postgres Component. Use in generated main.go.
func New() *Component {
	return &Component{
		daos: make(map[string]*resourceDAO),
	}
}

// --- spec.Component interface ---

func (c *Component) Name() string { return componentName }

func (c *Component) Version() string { return componentVersion }

func (c *Component) AuditHash() string { return auditHash }

// Configure reads the postgres config from the IR spec section.
// Expected keys in cfg (ComponentConfig map[string]any):
//   - dsn: PostgreSQL DSN string (or ${ENV_VAR})
//   - max_open_conns: int (optional, default 25)
//   - max_idle_conns: int (optional, default 5)
//   - conn_max_lifetime_sec: int (optional, default 300)
func (c *Component) Configure(cfg spec.ComponentConfig) error {
	c.cfg = Config{
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
	}

	if dsn, ok := cfg["dsn"].(string); ok && dsn != "" {
		c.cfg.DSN = dsn
	}
	if v, ok := cfg["max_open_conns"].(int); ok {
		c.cfg.MaxOpenConns = v
	}
	if v, ok := cfg["max_idle_conns"].(int); ok {
		c.cfg.MaxIdleConns = v
	}
	if v, ok := cfg["conn_max_lifetime_sec"].(int); ok {
		c.cfg.ConnMaxLifetime = time.Duration(v) * time.Second
	}

	return nil
}

// Register connects to PostgreSQL, runs migrations, creates DAOs, and sets
// the DB on the application registrar so other components can use it.
func (c *Component) Register(app *spec.Application) error {
	c.cfg.Resources = app.Resources()

	if c.cfg.DSN == "" {
		c.cfg.DSN = "host=localhost user=postgres dbname=postgres sslmode=disable"
	}

	sqldb, err := sql.Open("postgres", c.cfg.DSN)
	if err != nil {
		return fmt.Errorf("tsc-postgres: open db: %w", err)
	}
	sqldb.SetMaxOpenConns(c.cfg.MaxOpenConns)
	sqldb.SetMaxIdleConns(c.cfg.MaxIdleConns)
	sqldb.SetConnMaxLifetime(c.cfg.ConnMaxLifetime)

	c.db = &sqlDB{db: sqldb}

	// Expose DB to other components (e.g. tsc-events).
	app.SetDB(c.db)

	// Build one DAO per resource.
	for _, res := range c.cfg.Resources {
		c.daos[res.Name] = &resourceDAO{db: sqldb, resource: res}
	}

	return nil
}

// Start pings the database and runs migrations.
func (c *Component) Start(ctx context.Context) error {
	if err := c.db.db.PingContext(ctx); err != nil {
		return fmt.Errorf("tsc-postgres: ping: %w", err)
	}
	if err := c.runMigrations(ctx); err != nil {
		return fmt.Errorf("tsc-postgres: migrations: %w", err)
	}
	return nil
}

// Stop closes the connection pool.
func (c *Component) Stop(ctx context.Context) error {
	if c.db != nil {
		return c.db.db.Close()
	}
	return nil
}

// ResourceFor returns the DAO for the named resource, or nil.
// Implements spec.ResourceProvider.
func (c *Component) ResourceFor(resourceName string) *resourceDAO {
	return c.daos[resourceName]
}

// --- Migration generation ---

// runMigrations creates tables for each IR resource if they do not exist.
func (c *Component) runMigrations(ctx context.Context) error {
	for _, res := range c.cfg.Resources {
		ddl := generateCreateTable(res)
		if _, err := c.db.db.ExecContext(ctx, ddl); err != nil {
			return fmt.Errorf("migrate %s: %w", res.Name, err)
		}
	}
	return nil
}

// GenerateMigrationSQL returns the SQL DDL for all resources.
// Called by the compiler to write migrations/ files.
func GenerateMigrationSQL(resources []spec.ResourceDefinition) string {
	var sb strings.Builder
	for _, res := range resources {
		sb.WriteString(generateCreateTable(res))
		sb.WriteString("\n")
	}
	return sb.String()
}

func generateCreateTable(res spec.ResourceDefinition) string {
	table := strings.ToLower(res.Plural)
	var cols []string
	cols = append(cols, "  id UUID PRIMARY KEY DEFAULT gen_random_uuid()")

	for _, f := range res.Fields {
		cols = append(cols, "  "+fieldToColumn(f))
	}

	return fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (\n%s\n);\n",
		table, strings.Join(cols, ",\n"))
}

func fieldToColumn(f spec.FieldDefinition) string {
	colType := irTypeToSQL(f.Type)
	var constraints []string

	if f.Required {
		constraints = append(constraints, "NOT NULL")
	}
	if f.MaxLength > 0 && f.Type == "string" {
		colType = fmt.Sprintf("VARCHAR(%d)", f.MaxLength)
	}

	col := f.Name + " " + colType
	if len(constraints) > 0 {
		col += " " + strings.Join(constraints, " ")
	}
	return col
}

func irTypeToSQL(t string) string {
	switch t {
	case "string":
		return "TEXT"
	case "int":
		return "BIGINT"
	case "float":
		return "DOUBLE PRECISION"
	case "bool":
		return "BOOLEAN"
	case "timestamp":
		return "TIMESTAMPTZ"
	case "uuid":
		return "UUID"
	default:
		return "TEXT"
	}
}

// --- spec.DB implementation ---

type sqlDB struct {
	db *sql.DB
}

func (s *sqlDB) ExecContext(ctx context.Context, query string, args ...any) error {
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

func (s *sqlDB) QueryContext(ctx context.Context, query string, args ...any) (spec.Rows, error) {
	return s.db.QueryContext(ctx, query, args...)
}

// --- ResourceDAO ---

// resourceDAO is a CRUD data access object for a single IR resource.
// The table name and column list are derived from the ResourceDefinition.
type resourceDAO struct {
	db       *sql.DB
	resource spec.ResourceDefinition
}

// Create inserts obj (map[string]any) into the resource table and returns the generated ID.
func (d *resourceDAO) Create(ctx context.Context, obj map[string]any) (string, error) {
	table := strings.ToLower(d.resource.Plural)
	cols, placeholders, vals := buildInsert(obj)

	query := fmt.Sprintf(
		"INSERT INTO %s (%s) VALUES (%s) RETURNING id",
		table, strings.Join(cols, ", "), strings.Join(placeholders, ", "),
	)

	var id string
	err := d.db.QueryRowContext(ctx, query, vals...).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", d.resource.Name, err)
	}

	// Emit event if requested.
	if d.resource.Events {
		_ = d.notify(ctx, "created", id)
	}
	return id, nil
}

// Get retrieves a single row by ID and returns map[string]any.
func (d *resourceDAO) Get(ctx context.Context, id string) (map[string]any, error) {
	table := strings.ToLower(d.resource.Plural)
	query := fmt.Sprintf("SELECT * FROM %s WHERE id = $1 AND deleted_at IS NULL", table)
	rows, err := d.db.QueryContext(ctx, query, id)
	if err != nil {
		return nil, fmt.Errorf("get %s %s: %w", d.resource.Name, id, err)
	}
	defer rows.Close()

	results, err := scanRows(rows)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("%s %s: not found", d.resource.Name, id)
	}
	return results[0], nil
}

// Update replaces the row with id. obj must include the "id" field.
func (d *resourceDAO) Update(ctx context.Context, id string, obj map[string]any) error {
	table := strings.ToLower(d.resource.Plural)
	sets, vals := buildUpdate(obj)
	vals = append(vals, id)

	query := fmt.Sprintf(
		"UPDATE %s SET %s WHERE id = $%d AND deleted_at IS NULL",
		table, strings.Join(sets, ", "), len(vals),
	)
	if _, err := d.db.ExecContext(ctx, query, vals...); err != nil {
		return fmt.Errorf("update %s %s: %w", d.resource.Name, id, err)
	}
	if d.resource.Events {
		_ = d.notify(ctx, "updated", id)
	}
	return nil
}

// Delete soft-deletes a row by setting deleted_at (if the resource has soft_delete field),
// otherwise hard-deletes.
func (d *resourceDAO) Delete(ctx context.Context, id string) error {
	table := strings.ToLower(d.resource.Plural)
	var query string
	if d.hasSoftDelete() {
		query = fmt.Sprintf("UPDATE %s SET deleted_at = now() WHERE id = $1", table)
	} else {
		query = fmt.Sprintf("DELETE FROM %s WHERE id = $1", table)
	}
	if _, err := d.db.ExecContext(ctx, query, id); err != nil {
		return fmt.Errorf("delete %s %s: %w", d.resource.Name, id, err)
	}
	if d.resource.Events {
		_ = d.notify(ctx, "deleted", id)
	}
	return nil
}

// List returns all non-deleted rows with optional pagination.
func (d *resourceDAO) List(ctx context.Context, page, size int) ([]map[string]any, error) {
	table := strings.ToLower(d.resource.Plural)
	if size <= 0 {
		size = 100
	}
	offset := page * size

	query := fmt.Sprintf(
		"SELECT * FROM %s WHERE deleted_at IS NULL ORDER BY id LIMIT $1 OFFSET $2",
		table,
	)
	rows, err := d.db.QueryContext(ctx, query, size, offset)
	if err != nil {
		return nil, fmt.Errorf("list %s: %w", d.resource.Plural, err)
	}
	defer rows.Close()
	return scanRows(rows)
}

// notify emits a PostgreSQL NOTIFY event for this resource mutation.
func (d *resourceDAO) notify(ctx context.Context, action, id string) error {
	channel := strings.ToLower(d.resource.Name) + "_events"
	payload := fmt.Sprintf(`{"action":"%s","id":"%s"}`, action, id)
	_, err := d.db.ExecContext(ctx, "SELECT pg_notify($1, $2)", channel, payload)
	return err
}

func (d *resourceDAO) hasSoftDelete() bool {
	for _, f := range d.resource.Fields {
		if f.SoftDelete {
			return true
		}
	}
	return false
}

// --- SQL helpers ---

func buildInsert(obj map[string]any) (cols, placeholders []string, vals []any) {
	i := 1
	for k, v := range obj {
		cols = append(cols, k)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i))
		vals = append(vals, v)
		i++
	}
	return
}

func buildUpdate(obj map[string]any) (sets []string, vals []any) {
	i := 1
	for k, v := range obj {
		if k == "id" {
			continue
		}
		sets = append(sets, fmt.Sprintf("%s = $%d", k, i))
		vals = append(vals, v)
		i++
	}
	return
}

func scanRows(rows *sql.Rows) ([]map[string]any, error) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var results []map[string]any
	for rows.Next() {
		dest := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range dest {
			ptrs[i] = &dest[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]any, len(cols))
		for i, col := range cols {
			row[col] = dest[i]
		}
		results = append(results, row)
	}
	return results, rows.Err()
}
