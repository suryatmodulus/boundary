// Package credential defines interfaces shared by other packages that
// manage credentials for Boundary sessions.
package credential

import "github.com/hashicorp/boundary/internal/db/timestamp"

// An Entity is an object distinguished by its identity, rather than its
// attributes. It can contain value objects and other entities.
type Entity interface {
	GetPublicId() string
}

// An Aggregate is an entity that is the root of a transactional
// consistency boundary.
type Aggregate interface {
	Entity
	GetVersion() uint32
	GetCreateTime() *timestamp.Timestamp
	GetUpdateTime() *timestamp.Timestamp
}

// A Resource is an aggregate with a name and description.
type Resource interface {
	Aggregate
	GetName() string
	GetDescription() string
}

// A Store is a resource that can store, retrieve, and potentially generate
// credentials of differing types and access levels. It belongs to a scope
// and must support the principle of least privilege by providing
// mechanisms to limit the credentials it can access to the minimum
// necessary for the scope it is in.
type Store interface {
	Resource
	GetScopeId() string
}

// A Library is a resource that provides credentials that are of the same
// type and access level from a single store.
type Library interface {
	Resource
	GetStoreId() string
}

// SecretData represents secret data.
type SecretData interface{}

// Credential is an entity containing secret data.
type Credential interface {
	Entity
	Secret() SecretData
}

// Dynamic is a credential generated by a library for a specific session.
type Dynamic interface {
	Credential
	GetSessionId() string
	Library() Library
}