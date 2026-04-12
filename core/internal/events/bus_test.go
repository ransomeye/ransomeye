package events

import (
	"reflect"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ransomeye/core/internal/contracts"
)

func TestInMemoryBus_PublishDeliversToSubscriber(t *testing.T) {
	bus := NewInMemoryBus(8)
	var received []contracts.EnforcementEvent
	var mu sync.Mutex
	done := make(chan struct{})

	bus.SubscribeEnforcementEvent(func(e contracts.EnforcementEvent) {
		mu.Lock()
		received = append(received, e)
		mu.Unlock()
		done <- struct{}{}
	})
	bus.Run()

	event := contracts.EnforcementEvent{
		Seq: 1, Action: "KILL_PROCESS", Target: "agent-1", Status: "DISPATCHED", Timestamp: time.Now().Unix(),
	}
	if err := bus.Publish(event); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("subscriber did not receive event within 2s")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) != 1 {
		t.Fatalf("want 1 event, got %d", len(received))
	}
	if received[0].Seq != 1 {
		t.Errorf("want Seq=1, got Seq=%d", received[0].Seq)
	}
	if received[0].Action != event.Action || received[0].Target != event.Target {
		t.Errorf("got %+v", received[0])
	}
}

func TestInMemoryBus_NoDirectCoupling(t *testing.T) {
	bus := NewInMemoryBus(2)
	count := 0
	bus.SubscribeEnforcementEvent(func(contracts.EnforcementEvent) { count++ })
	bus.Run()

	err := bus.Publish(contracts.EnforcementEvent{Seq: 1, Action: "A", Target: "T", Status: "S", Timestamp: 1})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if count != 1 {
		t.Errorf("subscriber should receive 1 event, got count=%d", count)
	}
}

func TestInMemoryBus_BlockingBehavior_SlowSubscriberBlocksPublisher(t *testing.T) {
	bus := NewInMemoryBus(0)
	blockHandler := make(chan struct{})
	bus.SubscribeEnforcementEvent(func(contracts.EnforcementEvent) {
		<-blockHandler
	})
	bus.Run()

	done1 := make(chan struct{})
	go func() { _ = bus.Publish(contracts.EnforcementEvent{Seq: 1, Action: "A", Target: "T", Status: "S", Timestamp: 1}); close(done1) }()
	select {
	case <-done1:
	case <-time.After(50 * time.Millisecond):
		t.Fatal("first publish should complete while receiver is waiting")
	}

	done2 := make(chan struct{})
	go func() { _ = bus.Publish(contracts.EnforcementEvent{Seq: 2, Action: "A", Target: "T", Status: "S", Timestamp: 2}); close(done2) }()
	select {
	case <-done2:
		t.Fatal("second publish must block under slow subscriber")
	case <-time.After(100 * time.Millisecond):
		// expected blocking
	}

	close(blockHandler)
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("second publish did not progress after subscriber resumed")
	}
}

func TestInMemoryBus_ZeroLoss_PublishNConsumeN(t *testing.T) {
	const n = 200
	bus := NewInMemoryBus(4)
	received := make(chan int64, n)
	bus.SubscribeEnforcementEvent(func(e contracts.EnforcementEvent) {
		received <- e.Seq
	})
	bus.Run()

	for i := 0; i < n; i++ {
		if err := bus.Publish(contracts.EnforcementEvent{
			Seq:       int64(i + 1),
			Action:    "A",
			Target:    "T",
			Status:    "S",
			Timestamp: int64(i + 1),
		}); err != nil {
			t.Fatalf("publish %d failed: %v", i+1, err)
		}
	}

	got := make(map[int64]int, n)
	timeout := time.After(3 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case seq := <-received:
			got[seq]++
		case <-timeout:
			t.Fatalf("timeout waiting for event %d/%d", i+1, n)
		}
	}
	if len(got) != n {
		t.Fatalf("received unique=%d want=%d", len(got), n)
	}
	for i := 1; i <= n; i++ {
		if got[int64(i)] != 1 {
			t.Fatalf("seq=%d count=%d want=1", i, got[int64(i)])
		}
	}
}

func TestInMemoryBus_FIFO_GlobalOrderFromConcurrentProducers(t *testing.T) {
	const producers = 4
	const perProducer = 50
	total := producers * perProducer

	bus := NewInMemoryBus(8)
	var mu sync.Mutex
	receivedOrder := make([]int64, 0, total)
	doneRecv := make(chan struct{})
	bus.SubscribeEnforcementEvent(func(e contracts.EnforcementEvent) {
		mu.Lock()
		receivedOrder = append(receivedOrder, e.Seq)
		if len(receivedOrder) == total {
			select {
			case <-doneRecv:
			default:
				close(doneRecv)
			}
		}
		mu.Unlock()
	})
	bus.Run()

	admission := make(chan int64, total)
	var admittedOrder []int64
	dispatchDone := make(chan struct{})
	go func() {
		admittedOrder = make([]int64, 0, total)
		for seq := range admission {
			admittedOrder = append(admittedOrder, seq)
			_ = bus.Publish(contracts.EnforcementEvent{
				Seq:       seq,
				Action:    "A",
				Target:    "T",
				Status:    "S",
				Timestamp: int64(seq),
			})
		}
		close(dispatchDone)
	}()

	var counter uint64
	var wg sync.WaitGroup
	wg.Add(producers)
	for p := 0; p < producers; p++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				admission <- int64(atomic.AddUint64(&counter, 1))
			}
		}()
	}
	wg.Wait()
	close(admission)
	<-dispatchDone

	select {
	case <-doneRecv:
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for all events")
	}

	mu.Lock()
	got := append([]int64(nil), receivedOrder...)
	mu.Unlock()
	if !reflect.DeepEqual(got, admittedOrder) {
		t.Fatalf("fifo mismatch between admitted and received order")
	}
}

func TestInMemoryBus_NoDropGuarantee_UnderSaturation(t *testing.T) {
	const producers = 6
	const perProducer = 40
	total := producers * perProducer

	bus := NewInMemoryBus(1)
	received := make(chan int64, total)
	bus.SubscribeEnforcementEvent(func(e contracts.EnforcementEvent) {
		time.Sleep(1 * time.Millisecond)
		received <- e.Seq
	})
	bus.Run()

	var seq uint64
	var wg sync.WaitGroup
	wg.Add(producers)
	for i := 0; i < producers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < perProducer; j++ {
				id := int64(atomic.AddUint64(&seq, 1))
				_ = bus.Publish(contracts.EnforcementEvent{
					Seq:       id,
					Action:    "A",
					Target:    "T",
					Status:    "S",
					Timestamp: int64(id),
				})
			}
		}()
	}
	wg.Wait()

	got := make([]int64, 0, total)
	timeout := time.After(6 * time.Second)
	for i := 0; i < total; i++ {
		select {
		case id := <-received:
			got = append(got, id)
		case <-timeout:
			t.Fatalf("timeout waiting for all saturated deliveries")
		}
	}

	if len(got) != total {
		t.Fatalf("received_count=%d sent_count=%d", len(got), total)
	}
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	for i := 1; i <= total; i++ {
		if got[i-1] != int64(i) {
			t.Fatalf("missing/duplicate seq at pos=%d got=%d want=%d", i-1, got[i-1], i)
		}
	}
}
