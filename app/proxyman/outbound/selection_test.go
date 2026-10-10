package outbound

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/proxyman"
)

func TestInspectionNativeSelectorCacheIdentity(t *testing.T) {
	m, err := New(context.Background(), &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range []string{"a,b-x", "b-x", "1:a1:b-x"} {
		if err = m.AddHandler(context.Background(), &inspectionHandler{tag: tag}); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name      string
		selectors []string
		want      []string
	}{
		{"none", nil, []string{}}, {"all", []string{""}, []string{"1:a1:b-x", "a,b-x", "b-x"}},
		{"comma-literal", []string{"a,b"}, []string{"a,b-x"}}, {"two-prefixes", []string{"a", "b"}, []string{"a,b-x", "b-x"}},
		{"framed-scalar", []string{"1:a1:b"}, []string{"1:a1:b-x"}},
	}
	for round := 0; round < 3; round++ {
		for _, c := range cases {
			got := m.Select(c.selectors)
			if got == nil || !reflect.DeepEqual(got, c.want) {
				t.Errorf("%s round%d: %q want %q", c.name, round, got, c.want)
			}
		}
	}
	input := []string{"a", "b"}
	first := m.Select(input)
	input[1] = "a"
	if got := m.Select(input); !reflect.DeepEqual(got, []string{"a,b-x"}) {
		t.Fatal("input mutation", got)
	}
	first[0] = "borrowed-mutation"
	if got := m.Select([]string{"a", "b"}); got[0] != "borrowed-mutation" {
		t.Fatal("existing mutable cached return behavior changed", got)
	}
	if err = m.RemoveHandler(context.Background(), "absent"); err != nil {
		t.Fatal(err)
	}
	if got := m.Select([]string{"a", "b"}); !reflect.DeepEqual(got, []string{"a,b-x", "b-x"}) {
		t.Fatal("native no-op cache invalidation lost", got)
	}
}

func TestInspectionNativeSelectorCacheBytes(t *testing.T) {
	ctx := context.Background()
	m, err := New(ctx, &proxyman.OutboundConfig{})
	if err != nil {
		t.Fatal(err)
	}
	tags := []string{"a,b-node", "a-node", "b,c-node", "c-node", "1:a1:b-node", "a\x00,b-node", "\xff:,-node"}
	for _, tag := range tags {
		if err = m.AddHandler(ctx, &inspectionHandler{tag: tag}); err != nil {
			t.Fatal(err)
		}
	}
	lists := [][]string{nil, {}, {""}, {"a,b", "c"}, {"a", "b,c"}, {"1:a1:b"}, {"a", "b"}, {"a", "a,b", "a"}, {"a\x00,", "b"}, {"a", "\x00,b"}, {"\xff:,"}, {"absent"}}
	for round := 0; round < 3; round++ {
		for _, list := range lists {
			want := []string{}
			for _, tag := range tags {
				for _, prefix := range list {
					if strings.HasPrefix(tag, prefix) {
						want = append(want, tag)
						break
					}
				}
			}
			sort.Strings(want)
			if got := m.Select(list); got == nil || !reflect.DeepEqual(got, want) {
				t.Errorf("selectors%q got%q want%q", list, got, want)
			}
		}
	}
}
