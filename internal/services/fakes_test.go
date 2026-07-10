package services

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/the-bughex-code/golang-backend/internal/apperrors"
	"github.com/the-bughex-code/golang-backend/internal/models"
	"github.com/the-bughex-code/golang-backend/internal/repositories"
)

// These fakes are the payoff for declaring interfaces in the consumer.
//
// AuthService depends on AuthUserStore, RoleStore, RefreshTokenStore, TxRunner
// and Clock — five interfaces this package owns. So every test below runs with
// no PostgreSQL, no Docker, no network, and no mocking framework. `go test
// ./internal/services/` is fast enough to run on every save.
//
// Had the interfaces lived in a shared `interfaces/` package, or had the
// services depended on *repositories.UserRepository directly, none of this
// would be possible without a live database.

// ---------------------------------------------------------------------------

type fakeUserStore struct {
	mu      sync.Mutex
	byID    map[uuid.UUID]*models.User
	byEmail map[string]*models.User

	// forceCreateErr lets a test simulate a storage failure mid-transaction.
	forceCreateErr error
}

func newFakeUserStore() *fakeUserStore {
	return &fakeUserStore{
		byID:    make(map[uuid.UUID]*models.User),
		byEmail: make(map[string]*models.User),
	}
}

func (f *fakeUserStore) Create(_ context.Context, u *models.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.forceCreateErr != nil {
		return f.forceCreateErr
	}
	if _, exists := f.byEmail[u.Email]; exists {
		return apperrors.Conflict("EMAIL_TAKEN", "An account with this email already exists")
	}

	u.CreatedAt = time.Now().UTC()
	u.UpdatedAt = u.CreatedAt

	// Store a copy. The real repository hands back rows from the database, not
	// the caller's pointer; a fake that aliases the caller's struct would hide
	// bugs where the service mutates what it just saved.
	stored := *u
	f.byID[u.ID] = &stored
	f.byEmail[u.Email] = &stored
	return nil
}

func (f *fakeUserStore) GetByID(_ context.Context, id uuid.UUID) (*models.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.byID[id]
	if !ok {
		return nil, apperrors.NotFound("user")
	}
	clone := *u
	return &clone, nil
}

func (f *fakeUserStore) GetByEmail(_ context.Context, email string) (*models.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.byEmail[email]
	if !ok {
		return nil, apperrors.NotFound("user")
	}
	clone := *u
	return &clone, nil
}

func (f *fakeUserStore) ExistsByEmail(_ context.Context, email string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	_, ok := f.byEmail[email]
	return ok, nil
}

func (f *fakeUserStore) UpdatePassword(_ context.Context, id uuid.UUID, hash string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.byID[id]
	if !ok {
		return apperrors.NotFound("user")
	}
	u.PasswordHash = hash
	return nil
}

// Unused by AuthService, present so the same fake can back UserService tests.
func (f *fakeUserStore) List(context.Context, repositories.ListFilter) ([]models.User, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]models.User, 0, len(f.byID))
	for _, u := range f.byID {
		out = append(out, *u)
	}
	return out, int64(len(out)), nil
}

func (f *fakeUserStore) UpdateProfile(_ context.Context, id uuid.UUID, first, last string) (*models.User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.byID[id]
	if !ok {
		return nil, apperrors.NotFound("user")
	}
	u.FirstName, u.LastName = first, last
	u.UpdatedAt = time.Now().UTC()
	clone := *u
	return &clone, nil
}

func (f *fakeUserStore) SoftDelete(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	u, ok := f.byID[id]
	if !ok || u.DeletedAt != nil {
		return apperrors.NotFound("user")
	}
	now := time.Now().UTC()
	u.DeletedAt = &now
	return nil
}

func (f *fakeUserStore) MarkEmailVerified(_ context.Context, id uuid.UUID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	// byID and byEmail hold the SAME pointer (see Create), so one write updates
	// both views, exactly as a single database row would.
	u, ok := f.byID[id]
	if !ok {
		return apperrors.NotFound("user")
	}
	verified := at
	u.EmailVerifiedAt = &verified
	return nil
}

// Compile-time proof that the fake satisfies every interface it stands in for.
// Without these, a signature change would surface as a confusing error at the
// call site instead of a clear one here.
var (
	_ AuthUserStore         = (*fakeUserStore)(nil)
	_ UserStore             = (*fakeUserStore)(nil)
	_ VerificationUserStore = (*fakeUserStore)(nil)
)

// ---------------------------------------------------------------------------

type fakeRoleStore struct {
	mu          sync.Mutex
	byName      map[string]models.Role
	assignments map[uuid.UUID][]uuid.UUID // userID -> roleIDs
}

func newFakeRoleStore() *fakeRoleStore {
	userRole := models.Role{ID: uuid.New(), Name: models.RoleUser, Description: "Standard"}
	adminRole := models.Role{
		ID: uuid.New(), Name: models.RoleAdmin, Description: "Admin",
		Permissions: []models.Permission{
			{ID: uuid.New(), Name: models.PermissionUsersRead},
			{ID: uuid.New(), Name: models.PermissionUsersDelete},
		},
	}
	return &fakeRoleStore{
		byName:      map[string]models.Role{userRole.Name: userRole, adminRole.Name: adminRole},
		assignments: make(map[uuid.UUID][]uuid.UUID),
	}
}

func (f *fakeRoleStore) GetByName(_ context.Context, name string) (*models.Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	r, ok := f.byName[name]
	if !ok {
		return nil, apperrors.NotFound("role")
	}
	return &r, nil
}

func (f *fakeRoleStore) ForUser(_ context.Context, userID uuid.UUID) ([]models.Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	ids := f.assignments[userID]
	out := make([]models.Role, 0, len(ids))
	for _, id := range ids {
		for _, r := range f.byName {
			if r.ID == id {
				out = append(out, r)
			}
		}
	}
	return out, nil
}

func (f *fakeRoleStore) AssignToUser(_ context.Context, userID, roleID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, existing := range f.assignments[userID] {
		if existing == roleID {
			return nil // idempotent, like ON CONFLICT DO NOTHING
		}
	}
	f.assignments[userID] = append(f.assignments[userID], roleID)
	return nil
}

func (f *fakeRoleStore) ListAll(context.Context) ([]models.Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]models.Role, 0, len(f.byName))
	for _, r := range f.byName {
		out = append(out, r)
	}
	return out, nil
}

var _ RoleStore = (*fakeRoleStore)(nil)

// ---------------------------------------------------------------------------

type fakeRefreshStore struct {
	mu     sync.Mutex
	byHash map[string]*models.RefreshToken
}

func newFakeRefreshStore() *fakeRefreshStore {
	return &fakeRefreshStore{byHash: make(map[string]*models.RefreshToken)}
}

func (f *fakeRefreshStore) Create(_ context.Context, t *models.RefreshToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	t.CreatedAt = time.Now().UTC()
	stored := *t
	f.byHash[t.TokenHash] = &stored
	return nil
}

func (f *fakeRefreshStore) GetByHash(_ context.Context, hash string) (*models.RefreshToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	t, ok := f.byHash[hash]
	if !ok {
		return nil, apperrors.NotFound("refresh token")
	}
	clone := *t
	return &clone, nil
}

func (f *fakeRefreshStore) Revoke(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, t := range f.byHash {
		if t.ID == id && t.RevokedAt == nil {
			now := time.Now().UTC()
			t.RevokedAt = &now
		}
	}
	return nil
}

func (f *fakeRefreshStore) RevokeAllForUser(_ context.Context, userID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	now := time.Now().UTC()
	for _, t := range f.byHash {
		if t.UserID == userID && t.RevokedAt == nil {
			revoked := now
			t.RevokedAt = &revoked
		}
	}
	return nil
}

func (f *fakeRefreshStore) liveCount(userID uuid.UUID) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	n := 0
	for _, t := range f.byHash {
		if t.UserID == userID && t.RevokedAt == nil {
			n++
		}
	}
	return n
}

var _ RefreshTokenStore = (*fakeRefreshStore)(nil)

// ---------------------------------------------------------------------------

type fakeVerificationTokenStore struct {
	mu     sync.Mutex
	byHash map[string]*models.EmailVerificationToken
}

func newFakeVerificationTokenStore() *fakeVerificationTokenStore {
	return &fakeVerificationTokenStore{byHash: make(map[string]*models.EmailVerificationToken)}
}

func (f *fakeVerificationTokenStore) Create(_ context.Context, t *models.EmailVerificationToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	t.CreatedAt = time.Now().UTC()
	stored := *t
	f.byHash[t.TokenHash] = &stored
	return nil
}

func (f *fakeVerificationTokenStore) GetByHash(_ context.Context, hash string) (*models.EmailVerificationToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	t, ok := f.byHash[hash]
	if !ok {
		return nil, apperrors.NotFound("verification token")
	}
	clone := *t
	return &clone, nil
}

// MarkUsed mirrors the repository's `AND used_at IS NULL` guard: a token that is
// already used cannot be used again, and the caller learns so via NotFound.
func (f *fakeVerificationTokenStore) MarkUsed(_ context.Context, id uuid.UUID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, t := range f.byHash {
		if t.ID == id {
			if t.UsedAt != nil {
				return apperrors.NotFound("verification token")
			}
			used := at
			t.UsedAt = &used
			return nil
		}
	}
	return apperrors.NotFound("verification token")
}

func (f *fakeVerificationTokenStore) InvalidateAllForUser(_ context.Context, userID uuid.UUID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	for _, t := range f.byHash {
		if t.UserID == userID && t.UsedAt == nil {
			used := at
			t.UsedAt = &used
		}
	}
	return nil
}

func (f *fakeVerificationTokenStore) liveCount(userID uuid.UUID) int {
	f.mu.Lock()
	defer f.mu.Unlock()

	n := 0
	for _, t := range f.byHash {
		if t.UserID == userID && t.UsedAt == nil {
			n++
		}
	}
	return n
}

var _ VerificationTokenStore = (*fakeVerificationTokenStore)(nil)

// ---------------------------------------------------------------------------

type sentMail struct {
	to      string
	subject string
	body    string
}

// fakeMailer records what would have been sent, and can be told to fail.
type fakeMailer struct {
	mu   sync.Mutex
	sent []sentMail
	err  error
}

func (m *fakeMailer) Send(_ context.Context, to, subject, textBody string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, sentMail{to: to, subject: subject, body: textBody})
	return nil
}

func (m *fakeMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sent)
}

func (m *fakeMailer) last() sentMail {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.sent) == 0 {
		return sentMail{}
	}
	return m.sent[len(m.sent)-1]
}

var _ Mailer = (*fakeMailer)(nil)

// ---------------------------------------------------------------------------

// fakeVerificationSender stands in for VerificationService in AuthService tests.
//
// AuthService only ever calls SendFor, which is why the port is a one-method
// interface — and why this fake is six lines rather than sixty.
type fakeVerificationSender struct {
	mu    sync.Mutex
	calls []uuid.UUID
	err   error
}

func (f *fakeVerificationSender) SendFor(_ context.Context, user *models.User) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, user.ID)
	return nil
}

func (f *fakeVerificationSender) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

var _ VerificationSender = (*fakeVerificationSender)(nil)

// ---------------------------------------------------------------------------

// fakeTx runs the function without any transaction.
//
// It cannot test rollback — that needs a real database, and lives in
// tests/integration_test.go. What it does test is that the service calls InTx
// at all, and that a failure inside the closure propagates out.
type fakeTx struct {
	calls int
}

func (f *fakeTx) InTx(ctx context.Context, fn func(context.Context) error) error {
	f.calls++
	return fn(ctx)
}

var _ TxRunner = (*fakeTx)(nil)

// ---------------------------------------------------------------------------

// fixedClock makes time-dependent behaviour testable without sleeping.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

var _ Clock = fixedClock{}
