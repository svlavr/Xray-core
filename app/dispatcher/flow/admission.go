package flow

import (
	"context"
	"errors"
)

type admissionKey struct{}

type Admission struct {
	Coordinate       []byte
	OpaqueAndroidUID OptionalUint64
}

type admissionMarker struct {
	admission Admission
	origin    Origin
	proof     OriginProof
}

func WithUserAdmission(ctx context.Context, admission Admission) (context.Context, error) {
	return withAdmission(ctx, admission, OriginUser, OriginProofTrustedIngressMarker)
}

func WithControlledMeasurementAdmission(ctx context.Context, admission Admission) (context.Context, error) {
	return withAdmission(ctx, admission, OriginControlledMeasurement, OriginProofMeasurementAdmission)
}

func withAdmission(ctx context.Context, admission Admission, origin Origin, proof OriginProof) (context.Context, error) {
	if ctx == nil {
		return nil, errors.New("flow admission requires a non-nil context")
	}
	if _, exists := ctx.Value(admissionKey{}).(admissionMarker); exists {
		return nil, errors.New("flow admission marker is immutable")
	}
	if len(admission.Coordinate) > MaxAdmissionCoordinateBytes {
		return nil, errors.New("flow admission coordinate exceeds limit")
	}
	if admission.OpaqueAndroidUID.Known && origin != OriginUser {
		return nil, errors.New("opaque Android UID requires trusted user admission")
	}
	opaqueAndroidUID := admission.OpaqueAndroidUID
	if !opaqueAndroidUID.Known {
		opaqueAndroidUID.Value = 0
	}
	marker := admissionMarker{
		admission: Admission{
			Coordinate:       cloneBytes(admission.Coordinate),
			OpaqueAndroidUID: opaqueAndroidUID,
		},
		origin: origin,
		proof:  proof,
	}
	return context.WithValue(ctx, admissionKey{}, marker), nil
}

func admissionFromContext(ctx context.Context) admissionMarker {
	if ctx == nil {
		return admissionMarker{origin: OriginUnknown, proof: OriginProofNone}
	}
	if marker, ok := ctx.Value(admissionKey{}).(admissionMarker); ok {
		marker.admission.Coordinate = cloneBytes(marker.admission.Coordinate)
		return marker
	}
	return admissionMarker{origin: OriginUnknown, proof: OriginProofNone}
}

func cloneBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}
	return append([]byte(nil), value...)
}
