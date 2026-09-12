package pubsub_test

import (
	"testing"

	. "github.com/xtls/xray-core/common/signal/pubsub"
)

func TestPubsub(t *testing.T) {
	service := NewService()

	sub := service.Subscribe("a")
	service.Publish("a", 1)

	select {
	case v := <-sub.Wait():
		if v != 1 {
			t.Error("expected subscribed value 1, but got ", v)
		}
	default:
		t.Fail()
	}

	sub.Close()
	service.Publish("a", 2)

	select {
	case <-sub.Wait():
		t.Fail()
	default:
	}

	service.Cleanup()
}

func TestSignalStopRejectsLatePublication(t *testing.T) {
	service := NewService()
	subscriber := service.Subscribe("generation")
	service.SignalStop()
	service.Publish("generation", "late")
	if !subscriber.IsClosed() {
		t.Fatal("subscriber remained open after service seal")
	}
	select {
	case message := <-subscriber.Wait():
		t.Fatalf("late message published after seal: %v", message)
	default:
	}
	if err := service.CloseAndWait(); err != nil {
		t.Fatal(err)
	}
}
