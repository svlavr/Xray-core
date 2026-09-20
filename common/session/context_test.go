package session

import (
	"context"
	"testing"
	"time"
)

func TestForcedOutboundSelectionMailboxZeroValueIsOneShot(t *testing.T) {
	mailbox := new(ForcedOutboundSelectionMailbox)
	ctx := ContextWithForcedOutboundSelection(context.Background(), mailbox)
	SubmitForcedOutboundSelection(ctx, ForcedOutboundSelection{RequestedTag: "first", Found: true})
	SubmitForcedOutboundSelection(ctx, ForcedOutboundSelection{RequestedTag: "second", Found: true})

	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	selection, ok := mailbox.Wait(waitCtx)
	if !ok || selection.RequestedTag != "first" {
		t.Fatalf("selection = %+v, ok=%v", selection, ok)
	}
}
