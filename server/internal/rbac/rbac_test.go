package rbac

import "testing"

func TestRoleCapabilities(t *testing.T) {
	cases := []struct {
		role   Role
		can    []Action
		cannot []Action
	}{
		{
			role:   RoleAdmin,
			can:    []Action{ActionIssue, ActionReadAudit, ActionManageCA, ActionManageRBAC, ActionManageHSM, ActionEncrypt, ActionDecrypt, ActionConfigureCA},
			cannot: nil,
		},
		{
			role:   RoleIssuer,
			can:    []Action{ActionIssue, ActionReadAudit, ActionEncrypt, ActionDecrypt},
			cannot: []Action{ActionManageCA, ActionManageRBAC, ActionManageHSM, ActionConfigureCA},
		},
		{
			role:   RoleAuditor,
			can:    []Action{ActionReadAudit},
			cannot: []Action{ActionIssue, ActionManageCA, ActionManageRBAC, ActionManageHSM, ActionEncrypt, ActionDecrypt},
		},
	}
	for _, tc := range cases {
		for _, a := range tc.can {
			if !RoleGrants(tc.role, a) {
				t.Errorf("%s should grant %s", tc.role, a)
			}
		}
		for _, a := range tc.cannot {
			if RoleGrants(tc.role, a) {
				t.Errorf("%s should NOT grant %s", tc.role, a)
			}
		}
	}
}

func TestCanUnionOfRoles(t *testing.T) {
	roles := []Role{RoleAuditor, RoleIssuer}
	if !Can(roles, ActionIssue) {
		t.Error("issuer within the set should grant cert:issue")
	}
	if !Can(roles, ActionReadAudit) {
		t.Error("both roles grant audit:read")
	}
	if Can(roles, ActionManageCA) {
		t.Error("neither auditor nor issuer grants ca:manage")
	}
}

func TestAssignmentsSubjectAndGroup(t *testing.T) {
	as := NewAssignments(
		map[string][]Role{"alice": {RoleAuditor}},
		map[string][]Role{"grp-ops": {RoleIssuer}},
	)

	// Alice directly gets auditor.
	roles := as.RolesFor("alice", nil)
	if !HasRole(roles, RoleAuditor) || HasRole(roles, RoleIssuer) {
		t.Errorf("alice roles = %v", roles)
	}

	// Via group membership she also becomes an issuer; roles are the union.
	roles = as.RolesFor("alice", []string{"grp-ops"})
	if !HasRole(roles, RoleAuditor) || !HasRole(roles, RoleIssuer) {
		t.Errorf("alice+group roles = %v", roles)
	}
	if !Can(roles, ActionIssue) {
		t.Error("group-derived issuer role should grant cert:issue")
	}

	// Unknown subject has no roles.
	if r := as.RolesFor("nobody", nil); len(r) != 0 {
		t.Errorf("unknown subject roles = %v", r)
	}
}

func TestAssignmentsIgnoresInvalidRoles(t *testing.T) {
	as := NewAssignments(
		map[string][]Role{"alice": {"supergod", RoleAuditor}},
		nil,
	)
	roles := as.RolesFor("alice", nil)
	if len(roles) != 1 || roles[0] != RoleAuditor {
		t.Errorf("invalid role not filtered: %v", roles)
	}
}

func TestAssignmentsDedup(t *testing.T) {
	as := NewAssignments(
		map[string][]Role{"alice": {RoleIssuer}},
		map[string][]Role{"g1": {RoleIssuer}, "g2": {RoleIssuer}},
	)
	roles := as.RolesFor("alice", []string{"g1", "g2"})
	if len(roles) != 1 {
		t.Errorf("expected deduplicated single issuer role, got %v", roles)
	}
}

func TestEmpty(t *testing.T) {
	var nilA *Assignments
	if !nilA.Empty() {
		t.Error("nil assignments should be Empty")
	}
	if !NewAssignments(nil, nil).Empty() {
		t.Error("no-op assignments should be Empty")
	}
	if NewAssignments(map[string][]Role{"x": {RoleAdmin}}, nil).Empty() {
		t.Error("populated assignments should not be Empty")
	}
}
