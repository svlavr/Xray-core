package session

import (
	"context"
	"sync"
	_ "unsafe"

	"github.com/xtls/xray-core/common/ctx"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
)

//go:linkname IndependentCancelCtx context.newCancelCtx
func IndependentCancelCtx(parent context.Context) context.Context

const (
	inboundSessionKey         ctx.SessionKey = 1
	outboundSessionKey        ctx.SessionKey = 2
	contentSessionKey         ctx.SessionKey = 3
	isReverseMuxKey           ctx.SessionKey = 4  // is reverse mux
	sockoptSessionKey         ctx.SessionKey = 5  // used by dokodemo to only receive sockopt.Mark
	trackedConnectionErrorKey ctx.SessionKey = 6  // used by observer to get outbound error
	dispatcherKey             ctx.SessionKey = 7  // used by ss2022 inbounds to get dispatcher
	timeoutOnlyKey            ctx.SessionKey = 8  // mux context's child contexts to only cancel when its own traffic times out
	allowedNetworkKey         ctx.SessionKey = 9  // muxcool server control incoming request tcp/udp
	fullHandlerKey            ctx.SessionKey = 10 // outbound gets full handler
	mitmAlpn11Key             ctx.SessionKey = 11 // used by TLS dialer
	mitmServerNameKey         ctx.SessionKey = 12 // used by TLS dialer

	streamSettingsKey          ctx.SessionKey = 13
	forcedOutboundSelectionKey ctx.SessionKey = 14
	trafficOriginKey           ctx.SessionKey = 15
)

func ContextWithInbound(ctx context.Context, inbound *Inbound) context.Context {
	return context.WithValue(ctx, inboundSessionKey, inbound)
}

func InboundFromContext(ctx context.Context) *Inbound {
	if inbound, ok := ctx.Value(inboundSessionKey).(*Inbound); ok {
		return inbound
	}
	return nil
}

func ContextWithOutbounds(ctx context.Context, outbounds []*Outbound) context.Context {
	return context.WithValue(ctx, outboundSessionKey, outbounds)
}

func SubContextFromMuxInbound(ctx context.Context) context.Context {
	newOutbounds := []*Outbound{{}}

	content := ContentFromContext(ctx)
	newContent := Content{}
	if content != nil {
		newContent = *content
		if content.Attributes != nil {
			panic("content.Attributes != nil")
		}
	}
	return ContextWithContent(ContextWithOutbounds(ctx, newOutbounds), &newContent)
}

func OutboundsFromContext(ctx context.Context) []*Outbound {
	if outbounds, ok := ctx.Value(outboundSessionKey).([]*Outbound); ok {
		return outbounds
	}
	return nil
}

func ContextWithContent(ctx context.Context, content *Content) context.Context {
	return context.WithValue(ctx, contentSessionKey, content)
}

func ContentFromContext(ctx context.Context) *Content {
	if content, ok := ctx.Value(contentSessionKey).(*Content); ok {
		return content
	}
	return nil
}

func ContextWithIsReverseMux(ctx context.Context, isReverseMux bool) context.Context {
	return context.WithValue(ctx, isReverseMuxKey, isReverseMux)
}

func IsReverseMuxFromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(isReverseMuxKey).(bool); ok {
		return val
	}
	return false
}

func ContextWithSockopt(ctx context.Context, s *Sockopt) context.Context {
	return context.WithValue(ctx, sockoptSessionKey, s)
}

func SockoptFromContext(ctx context.Context) *Sockopt {
	if sockopt, ok := ctx.Value(sockoptSessionKey).(*Sockopt); ok {
		return sockopt
	}
	return nil
}

func GetForcedOutboundTagFromContext(ctx context.Context) string {
	if ContentFromContext(ctx) == nil {
		return ""
	}
	return ContentFromContext(ctx).Attribute("forcedOutboundTag")
}

func SetForcedOutboundTagToContext(ctx context.Context, tag string) context.Context {
	if contentFromContext := ContentFromContext(ctx); contentFromContext == nil {
		ctx = ContextWithContent(ctx, &Content{})
	}
	ContentFromContext(ctx).SetAttribute("forcedOutboundTag", tag)
	return ctx
}

// ForcedOutboundSelection reports the one top-level result of a forced-tag
// dispatch. It does not prove a terminal handler, physical carrier or delivery.
type ForcedOutboundSelection struct {
	RequestedTag string
	SelectedTag  string
	Found        bool
	Origin       TrafficOrigin
}

// ForcedOutboundSelectionMailbox is a non-blocking one-shot receipt. Its
// private channel cannot be closed by callers while dispatch is still running.
type ForcedOutboundSelectionMailbox struct {
	initOnce   sync.Once
	submitOnce sync.Once
	receipt    chan ForcedOutboundSelection
}

func NewForcedOutboundSelectionMailbox() *ForcedOutboundSelectionMailbox {
	return new(ForcedOutboundSelectionMailbox)
}

func (m *ForcedOutboundSelectionMailbox) receiptChannel() chan ForcedOutboundSelection {
	m.initOnce.Do(func() { m.receipt = make(chan ForcedOutboundSelection, 1) })
	return m.receipt
}

func (m *ForcedOutboundSelectionMailbox) submit(selection ForcedOutboundSelection) {
	if m == nil {
		return
	}
	m.submitOnce.Do(func() { m.receiptChannel() <- selection })
}

func (m *ForcedOutboundSelectionMailbox) Wait(ctx context.Context) (ForcedOutboundSelection, bool) {
	if m == nil {
		return ForcedOutboundSelection{}, false
	}
	select {
	case selection := <-m.receiptChannel():
		return selection, true
	case <-ctx.Done():
		return ForcedOutboundSelection{}, false
	}
}

func ContextWithForcedOutboundSelection(ctx context.Context, mailbox *ForcedOutboundSelectionMailbox) context.Context {
	return context.WithValue(ctx, forcedOutboundSelectionKey, mailbox)
}

// SubmitForcedOutboundSelection publishes at most one forced-tag selection
// without blocking dispatch.
func SubmitForcedOutboundSelection(ctx context.Context, selection ForcedOutboundSelection) {
	mailbox, _ := ctx.Value(forcedOutboundSelectionKey).(*ForcedOutboundSelectionMailbox)
	mailbox.submit(selection)
}

// TrafficOrigin is a technical admission fact. Unknown must never be promoted
// to USER or CONTROLLED_MEASUREMENT by inference.
type TrafficOrigin uint8

const (
	TrafficOriginUnknown TrafficOrigin = iota
	TrafficOriginUser
	TrafficOriginInternal
	TrafficOriginControlledMeasurement
)

func ContextWithTrafficOrigin(ctx context.Context, origin TrafficOrigin) context.Context {
	return context.WithValue(ctx, trafficOriginKey, origin)
}

func TrafficOriginFromContext(ctx context.Context) TrafficOrigin {
	origin, _ := ctx.Value(trafficOriginKey).(TrafficOrigin)
	return origin
}

type TrackedRequestErrorFeedback interface {
	SubmitError(err error)
}

func SubmitOutboundErrorToOriginator(ctx context.Context, err error) {
	if errorTracker := ctx.Value(trackedConnectionErrorKey); errorTracker != nil {
		errorTracker := errorTracker.(TrackedRequestErrorFeedback)
		errorTracker.SubmitError(err)
	}
}

func TrackedConnectionError(ctx context.Context, tracker TrackedRequestErrorFeedback) context.Context {
	return context.WithValue(ctx, trackedConnectionErrorKey, tracker)
}

func ContextWithDispatcher(ctx context.Context, dispatcher routing.Dispatcher) context.Context {
	return context.WithValue(ctx, dispatcherKey, dispatcher)
}

func DispatcherFromContext(ctx context.Context) routing.Dispatcher {
	if dispatcher, ok := ctx.Value(dispatcherKey).(routing.Dispatcher); ok {
		return dispatcher
	}
	return nil
}

func ContextWithTimeoutOnly(ctx context.Context, only bool) context.Context {
	return context.WithValue(ctx, timeoutOnlyKey, only)
}

func TimeoutOnlyFromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(timeoutOnlyKey).(bool); ok {
		return val
	}
	return false
}

func ContextWithAllowedNetwork(ctx context.Context, network net.Network) context.Context {
	return context.WithValue(ctx, allowedNetworkKey, network)
}

func AllowedNetworkFromContext(ctx context.Context) net.Network {
	if val, ok := ctx.Value(allowedNetworkKey).(net.Network); ok {
		return val
	}
	return net.Network_Unknown
}

func ContextWithFullHandler(ctx context.Context, handler outbound.Handler) context.Context {
	return context.WithValue(ctx, fullHandlerKey, handler)
}

func FullHandlerFromContext(ctx context.Context) outbound.Handler {
	if val, ok := ctx.Value(fullHandlerKey).(outbound.Handler); ok {
		return val
	}
	return nil
}

func ContextWithMitmAlpn11(ctx context.Context, alpn11 bool) context.Context {
	return context.WithValue(ctx, mitmAlpn11Key, alpn11)
}

func MitmAlpn11FromContext(ctx context.Context) bool {
	if val, ok := ctx.Value(mitmAlpn11Key).(bool); ok {
		return val
	}
	return false
}

func ContextWithMitmServerName(ctx context.Context, serverName string) context.Context {
	return context.WithValue(ctx, mitmServerNameKey, serverName)
}

func MitmServerNameFromContext(ctx context.Context) string {
	if val, ok := ctx.Value(mitmServerNameKey).(string); ok {
		return val
	}
	return ""
}

func ContextWithStreamSettings(ctx context.Context, streamSettings any) context.Context {
	return context.WithValue(ctx, streamSettingsKey, streamSettings)
}

func StreamSettingsFromContext(ctx context.Context) any {
	return ctx.Value(streamSettingsKey)
}
