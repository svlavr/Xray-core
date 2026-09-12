package outbound

import (
	"context"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/features"
	"github.com/xtls/xray-core/transport"
)

// Handler is the interface for handlers that process outbound connections.
//
// xray:api:stable
type Handler interface {
	common.Runnable
	Tag() string
	Dispatch(ctx context.Context, link *transport.Link)
	SenderSettings() *serial.TypedMessage
	ProxySettings() *serial.TypedMessage
}

type HandlerSelector interface {
	Select([]string) []string
}

// HandlerEntry is one exact-generation admission returned by an optional
// GenerationManager. The stable Manager API remains unchanged for external
// implementations; in-tree callers use this additive seam when available.
type HandlerEntry interface {
	Handler() Handler
	Context() context.Context
	Release()
}

type GenerationManager interface {
	EnterHandler(context.Context, string) (HandlerEntry, error)
	EnterDefaultHandler(context.Context) (HandlerEntry, error)
}

// ExactHandlerRemover removes only the currently registered exact handler.
// It is an additive lifecycle seam; the stable Manager API remains unchanged.
type ExactHandlerRemover interface {
	RemoveHandlerInstance(context.Context, Handler) error
}

// VLESSReverseRegistration is an exact lease for a fork-owned synthetic
// handler. It is deliberately narrow: callers cannot look a handler up by tag
// and therefore cannot accidentally retire a replacement generation.
type VLESSReverseRegistration interface {
	Handler() Handler
	Enter(context.Context) (HandlerEntry, error)
	Release(context.Context) error
}

// VLESSReverseRegistrationManager owns VLESS reverse synthetic-handler
// creation, sharing, and retirement. It is not a general handler framework.
type VLESSReverseRegistrationManager interface {
	RegisterVLESSReverse(context.Context, string, func(context.Context) (Handler, error)) (VLESSReverseRegistration, error)
}

// Manager is a feature that manages outbound.Handlers.
//
// xray:api:stable
type Manager interface {
	features.Feature
	// GetHandler returns an outbound.Handler for the given tag.
	GetHandler(tag string) Handler
	// GetDefaultHandler returns the default outbound.Handler. It is usually the first outbound.Handler specified in the configuration.
	GetDefaultHandler() Handler
	// AddHandler adds a handler into this outbound.Manager.
	AddHandler(ctx context.Context, handler Handler) error

	// RemoveHandler removes a handler from outbound.Manager.
	RemoveHandler(ctx context.Context, tag string) error

	// ListHandlers returns a list of outbound.Handler.
	ListHandlers(ctx context.Context) []Handler
}

// ManagerType returns the type of Manager interface. Can be used to implement common.HasType.
//
// xray:api:stable
func ManagerType() interface{} {
	return (*Manager)(nil)
}
