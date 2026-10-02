package measurement

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
)

var ErrIdentityResponse = errors.New("invalid reflector identity response")

type AddressFamily uint8

const (
	IPv4 AddressFamily = 4
	IPv6 AddressFamily = 6
)

type IdentityRequest struct {
	HTTPS  HTTPSRequest
	Family AddressFamily // Zero accepts the family actually reported.
}

// Country values are endpoint declarations. The caller interprets them;
// the executor does not impose another reflector/version/freshness protocol.
type IdentityReceipt struct {
	HTTPS         HTTPSReceipt
	Address       netip.Addr
	Family        AddressFamily
	Country       string
	CountrySource string
}

func (e *Executor) EgressIdentity(ctx context.Context, request IdentityRequest) (IdentityReceipt, error) {
	response, err := e.HTTPS(ctx, request.HTTPS)
	if err != nil {
		return IdentityReceipt{HTTPS: response}, err
	}
	return IdentityFromHTTPS(response, request.Family)
}

// IdentityFromHTTPS reuses a completed exchange whose transport error the caller
// already handled. TLS timing and duplicate byte counts are not trust flags.
func IdentityFromHTTPS(response HTTPSReceipt, expected AddressFamily) (result IdentityReceipt, err error) {
	result.HTTPS = response
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return result, ErrIdentityResponse
	}
	var body struct {
		IP            string `json:"ip"`
		Country       string `json:"country"`
		CountrySource string `json:"countrySource"`
	}
	if json.Unmarshal(response.Body, &body) != nil {
		return result, ErrIdentityResponse
	}
	address, err := netip.ParseAddr(body.IP)
	if err != nil {
		return result, ErrIdentityResponse
	}
	address = address.Unmap()
	family := IPv6
	if address.Is4() {
		family = IPv4
	}
	if expected != 0 && family != expected {
		return result, ErrIdentityResponse
	}
	result.Address, result.Family = address, family
	result.Country, result.CountrySource = body.Country, body.CountrySource
	return result, nil
}
