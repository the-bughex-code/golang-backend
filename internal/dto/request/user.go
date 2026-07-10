package request

import "strings"

// UpdateProfile changes the caller's own name.
//
// Note what is NOT here: Email, IsActive, Roles, ID. A user may not change
// their own email without re-verification, may not activate themselves, and
// may not grant themselves the admin role. Those fields are absent from the
// struct, so no request can set them regardless of what JSON it sends.
type UpdateProfile struct {
	FirstName string `json:"firstName" validate:"required,min=1,max=100"`
	LastName  string `json:"lastName"  validate:"required,min=1,max=100"`
}

// Normalize trims the name fields, so a submission of "   " is rejected as
// empty rather than stored as whitespace.
func (u *UpdateProfile) Normalize() {
	u.FirstName = strings.TrimSpace(u.FirstName)
	u.LastName = strings.TrimSpace(u.LastName)
}

// AssignRole grants a role to a user. Requires the roles:assign permission.
type AssignRole struct {
	RoleName string `json:"roleName" validate:"required,min=1,max=100"`
}

// Normalize trims and lowercases the role name to match the seeded values.
func (a *AssignRole) Normalize() {
	a.RoleName = strings.ToLower(strings.TrimSpace(a.RoleName))
}

// ListUsers carries the query-string parameters of GET /users.
//
// # Why offset pagination, and when it stops working
//
// `LIMIT n OFFSET m` is simple and lets a client jump to page 50 directly.
// Its cost is that Postgres must walk and discard all m preceding rows, so
// page 5,000 is genuinely slow. It also skips or repeats rows when the
// underlying data changes between requests.
//
// Cursor (keyset) pagination — `WHERE id > $last ORDER BY id LIMIT n` — has
// neither problem, but cannot jump to an arbitrary page.
//
// Offset is the right default for an admin table that people actually page
// through by hand. Switch to cursors for infinite-scroll feeds and for
// anything a machine iterates.
type ListUsers struct {
	Page    int    `json:"page"    validate:"gte=1"`
	PerPage int    `json:"perPage" validate:"gte=1,lte=100"`
	Search  string `json:"search"  validate:"max=100"`
}

// Defaults for pagination. A client that sends no page/perPage gets page 1
// with 20 rows rather than an error, because those are obvious intentions.
//
// PerPage is capped at 100 by the validate tag above. Without a cap, a client
// can ask for perPage=1000000 and turn one request into a full table scan —
// an unauthenticated denial of service that costs the attacker nothing.
const (
	DefaultPage    = 1
	DefaultPerPage = 20
	MaxPerPage     = 100
)

// ApplyDefaults fills unset pagination fields. Called by the handler after
// parsing the query string and before validation.
func (l *ListUsers) ApplyDefaults() {
	if l.Page < 1 {
		l.Page = DefaultPage
	}
	if l.PerPage < 1 {
		l.PerPage = DefaultPerPage
	}
	if l.PerPage > MaxPerPage {
		l.PerPage = MaxPerPage
	}
}

// Offset converts a page number into the SQL OFFSET.
func (l *ListUsers) Offset() int { return (l.Page - 1) * l.PerPage }
