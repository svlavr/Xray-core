package router

import (
	"context"
	"time"

	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/log"
	xlua "github.com/xtls/xray-core/common/lua"
	"github.com/xtls/xray-core/features/routing"
	routingdns "github.com/xtls/xray-core/features/routing/dns"
	lua "github.com/yuin/gopher-lua"
)

const scriptExecutionTimeout = 6 * time.Second

type scriptEngine struct {
	pool      *xlua.Pool
	ctx       context.Context
	cancel    context.CancelFunc
	dnsClient *Router
	ownerKey  *lua.LUserData
}

func newScriptEngine(path string, router *Router) (*scriptEngine, error) {
	program, err := xlua.CompileFile(path)
	if err != nil {
		return nil, err
	}

	engineCtx, cancel := context.WithCancel(router.ctx)
	e := &scriptEngine{ctx: engineCtx, cancel: cancel, dnsClient: router, ownerKey: &lua.LUserData{}}
	factory := func(ctx context.Context) (state *lua.LState, err error) {
		ctx, stop := e.joinContext(ctx)
		defer stop()
		err = dns.WithLuaDNS(ctx, router.dns, func(ctx context.Context, owner any) error {
			ctx, cancel := context.WithTimeout(ctx, scriptExecutionTimeout*20)
			defer cancel()
			var createErr error
			state, createErr = program.NewState(ctx, func(L *lua.LState) {
				geodata.RegisterLua(L)
				log.RegisterLua(L)
				router.RegisterLua(L)
				dns.RegisterLua(L, router.dns)
				marker := L.NewUserData()
				marker.Value = owner
				L.G.Registry.RawSet(e.ownerKey, marker)
			}, func(L *lua.LState) error {
				if L.GetGlobal("HandleRoute").Type() != lua.LTFunction {
					return errors.New("routing script must define HandleRoute(...)")
				}
				return nil
			})
			return createErr
		})
		return
	}
	pool, err := xlua.NewPool(engineCtx, scriptExecutionTimeout, factory)
	if err != nil {
		cancel()
		return nil, err
	}

	errors.LogInfo(router.ctx, "routing script initialized from ", path)
	e.pool = pool
	return e, nil
}

func (e *scriptEngine) close() {
	e.cancel()
	e.pool.Close()
}

func (e *scriptEngine) joinContext(ctx context.Context) (context.Context, func()) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.ctx, cancel)
	if e.ctx.Err() != nil {
		cancel()
	}
	return ctx, func() { stop(); cancel() }
}

func routeOrigin(ctx routing.Context, fallback context.Context) context.Context {
	for {
		if origin, ok := ctx.(interface{ OriginatingContext() context.Context }); ok {
			if source := origin.OriginatingContext(); source != nil {
				return source
			}
		}
		wrapped, ok := ctx.(*routingdns.ResolvableContext)
		if !ok {
			return fallback
		}
		ctx = wrapped.Context
	}
}

func (e *scriptEngine) pickRoute(ctx routing.Context) (routing.Route, error) {
	var outboundTag, ruleTag string
	var routeErr error

	caller, finish := e.joinContext(routeOrigin(ctx, e.ctx))
	defer finish()
	if err := dns.WithLuaDNS(caller, e.dnsClient.dns, func(bound context.Context, owner any) error {
		for {
			if err := bound.Err(); err != nil {
				return err
			}
			L, err := e.pool.Acquire(bound)
			if err != nil {
				return err
			}
			marker, ok := L.G.Registry.RawGet(e.ownerKey).(*lua.LUserData)
			if !ok || marker.Value != owner {
				e.pool.Release(L, false)
				continue
			}
			return func() error {
				execution, cancel := context.WithTimeout(bound, scriptExecutionTimeout)
				defer cancel()
				L.SetContext(execution)
				reusable := false
				defer func() { e.pool.Release(L, reusable && bound.Err() == nil) }()
				if err := bound.Err(); err != nil {
					return err
				}
				if err := callLuaRoute(L, ctx); err != nil {
					return err
				}
				outboundTag, ruleTag, routeErr = readLuaRouteResult(L)
				reusable = true
				return nil
			}()
		}
	}); err != nil {
		return nil, err
	}

	if routeErr != nil {
		return nil, routeErr
	}
	if outboundTag == "" {
		return nil, common.ErrNoClue
	}

	return &Route{Context: ctx, outboundTag: outboundTag, ruleTag: ruleTag}, nil
}
