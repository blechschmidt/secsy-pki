package agent

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// fakeRoute53 is an in-memory route53API for tests.
type fakeRoute53 struct {
	zones      []types.HostedZone
	changes    []types.Change
	lastZoneID string
}

func (f *fakeRoute53) ListHostedZonesByName(_ context.Context, _ *route53.ListHostedZonesByNameInput, _ ...func(*route53.Options)) (*route53.ListHostedZonesByNameOutput, error) {
	return &route53.ListHostedZonesByNameOutput{HostedZones: f.zones}, nil
}

func (f *fakeRoute53) ChangeResourceRecordSets(_ context.Context, in *route53.ChangeResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error) {
	f.lastZoneID = aws.ToString(in.HostedZoneId)
	f.changes = append(f.changes, in.ChangeBatch.Changes...)
	return &route53.ChangeResourceRecordSetsOutput{}, nil
}

func TestRoute53PresentDiscoversPublicZone(t *testing.T) {
	fake := &fakeRoute53{zones: []types.HostedZone{
		{Id: aws.String("/hostedzone/ZOTHER"), Name: aws.String("example.org.")},
		// A private zone with a matching name must be skipped.
		{Id: aws.String("/hostedzone/ZPRIVATE"), Name: aws.String("example.com."), Config: &types.HostedZoneConfig{PrivateZone: true}},
		{Id: aws.String("/hostedzone/ZPUBLIC"), Name: aws.String("example.com.")},
	}}
	p := &route53Provider{api: fake, ttl: 60}

	fqdn := "_acme-challenge.host.example.com."
	value := "route53-digest"
	if err := p.Present(context.Background(), fqdn, value); err != nil {
		t.Fatalf("Present: %v", err)
	}
	if fake.lastZoneID != "ZPUBLIC" {
		t.Fatalf("used hosted zone %q, want ZPUBLIC (the public example.com zone)", fake.lastZoneID)
	}
	if len(fake.changes) != 1 {
		t.Fatalf("recorded %d changes, want 1", len(fake.changes))
	}
	change := fake.changes[0]
	if change.Action != types.ChangeActionUpsert {
		t.Errorf("action = %s, want UPSERT", change.Action)
	}
	rr := change.ResourceRecordSet
	if aws.ToString(rr.Name) != fqdn {
		t.Errorf("record name = %q, want %q", aws.ToString(rr.Name), fqdn)
	}
	if rr.Type != types.RRTypeTxt {
		t.Errorf("record type = %s, want TXT", rr.Type)
	}
	if aws.ToInt64(rr.TTL) != 60 {
		t.Errorf("record ttl = %d, want 60", aws.ToInt64(rr.TTL))
	}
	if len(rr.ResourceRecords) != 1 || aws.ToString(rr.ResourceRecords[0].Value) != `"`+value+`"` {
		t.Errorf("record value = %+v, want quoted %q", rr.ResourceRecords, value)
	}
}

func TestRoute53CleanUpDeletes(t *testing.T) {
	fake := &fakeRoute53{}
	p := &route53Provider{api: fake, hostedZoneID: "ZFIXED", ttl: 60}
	if err := p.CleanUp(context.Background(), "_acme-challenge.host.example.com.", "v"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}
	if fake.lastZoneID != "ZFIXED" {
		t.Errorf("used hosted zone %q, want the pinned ZFIXED", fake.lastZoneID)
	}
	if len(fake.changes) != 1 || fake.changes[0].Action != types.ChangeActionDelete {
		t.Fatalf("expected a single DELETE change, got %+v", fake.changes)
	}
}

func TestRoute53NoZoneFound(t *testing.T) {
	fake := &fakeRoute53{zones: []types.HostedZone{
		{Id: aws.String("/hostedzone/ZOTHER"), Name: aws.String("somewhere.else.")},
	}}
	p := &route53Provider{api: fake, ttl: 60}
	err := p.Present(context.Background(), "_acme-challenge.host.example.com.", "v")
	if err == nil {
		t.Fatal("expected an error when no hosted zone matches")
	}
}
