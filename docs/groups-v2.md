# Groups v2 (SDK notes for the CLI)

CNJR-15228. Contract audited against `secrets-manager-conjur-service`
(`config/routes.rb`, `app/controllers/v2/group/v2_group_controller.rb`,
`app/controllers/v2/groups_membership_controller.rb`,
`app/domain/commands/groups/manage.rb`).

## Endpoints

| Operation | Method & path | SDK method |
| --- | --- | --- |
| Create | `POST /groups` | `CreateGroup(Group) (*Group, error)` |
| Read   | `GET /groups/*identifier` | `ReadGroup(id) (*Group, error)` |
| List   | `GET /groups` | `ReadGroups(*GroupFilter) (GroupsResponse, error)` |
| Update | `PATCH /groups/*identifier` | `UpdateGroup(Group) (*Group, error)` |
| Delete | `DELETE /groups/*identifier` | `DeleteGroup(id) error` |
| Add member | `POST /groups/*identifier/members` | `AddGroupMember(id, GroupMember)` (existing) |
| Remove member | `DELETE /groups/*identifier/members/:kind/(*id)` | `RemoveGroupMember(id, GroupMember)` (existing) |
| List members | `GET /groups/*identifier/members` | `ListGroupMembers(id, *GroupFilter) (GroupMembersResponse, error)` |

All requests carry `v2APIHeaderBeta`. Groups are finalized v2 (not `beta do`).

## Platform gate — permissive

Groups exist on Self-Hosted as a policy concept, and the service exposes the v2
routes unconditionally, so the gate is the permissive style — matching the
existing membership methods, which this task keeps:

```go
if !c.config.IsSaaS() && c.VerifyMinServerVersion(MinVersion) != nil {
    return fmt.Errorf(NotSupportedInOldVersions, "Group API", MinVersion)
}
```

`MinVersion` is `"1.23.0"`. (The existing membership gate was already permissive;
this task confirmed that is correct rather than "correcting" it to SaaS-only.)

## Group model

A `Group` mirrors `Branch` — the service returns the same
`Response::ResourceResponse` envelope: `name`, `branch`, `annotations`,
`created_at`. A group's only mutable state is its annotations.

- **Create** permits only `name`, `branch`, `annotations`. `Owner` on the struct
  is not sent (the create endpoint does not accept it).
- **Update** (PATCH) and **Replace** (PUT) permit only `annotations`; the SDK
  exposes the PATCH path as `UpdateGroup`. As with branches and workloads, the
  service runs `action_on_unpermitted_parameters = :raise`, so sending anything
  else is a 422.

## Identifier format

Group identifiers are the full resource id — branch path plus name, e.g.
`data/my-group`. Pass verbatim; it maps to the route's `*identifier` glob.

## Members

`ListGroupMembers` returns `GroupMembersResponse{ Members []GroupMember, Count }`.
Each member is `{ kind, id }`. `Count` is the grand total, so
`GroupMembersResponse.HasMore(filter)` is the auto-pagination termination signal
(same as `GroupsResponse.HasMore`).

The CLI's `group members add --id <group> --role <member>` maps `--role` onto the
`GroupMember` **ID**; `--kind` maps onto `GroupMember.Kind`. Keep that mapping in
one place in the CLI.

### Member-id URL escaping (bug fixed here)

`RemoveGroupMember` builds `.../members/{kind}/{id}` where `{id}` is the route's
`*id` glob. A member id's own slashes are meaningful path separators and are
preserved, but other URL-significant characters (spaces, `#`, `?`, …) are now
percent-escaped per segment via `escapeIdentifierPath`. Before this fix an id
like `data/my host` produced a malformed URL. Kinds are escaped with
`url.PathEscape`.

## Pagination

`ReadGroups` returns `GroupsResponse{ Groups, Count }`; `Count` is the
server-computed grand total (before limit/offset). Drive auto-pagination with
`HasMore` exactly as documented for branches.

## Error signals

Shared predicates from `errors_v2.go`:

| Predicate | HTTP | Group case |
| --- | --- | --- |
| `IsConflict(err)` | 409 | duplicate group on create |
| `IsNotFound(err)` | 404 | read/update/delete of a missing group; adding a non-existent role as a member |
| `IsForbidden(err)` | 403 | operation without the required privilege |

## Relationship to v1

This is additive. The v1 role/membership APIs in `role.go` and the `conjur role`
commands are untouched and undeprecated.
