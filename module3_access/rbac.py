"""
module3_access/rbac.py - Role-based access control (RBAC).

Instead of giving permissions to each user, we give them to ROLES and give
each user exactly one role (principle of least privilege):

    viewer    read devices and readings
    operator  everything a viewer can + send lock/unlock commands
    admin     everything + manage users/devices + read the audit log and alerts
"""

READ_READINGS = "read_readings"
SEND_COMMAND = "send_command"
MANAGE_DEVICES = "manage_devices"
MANAGE_USERS = "manage_users"
VIEW_AUDIT = "view_audit"

ROLE_PERMISSIONS = {
    "viewer": {READ_READINGS},
    "operator": {READ_READINGS, SEND_COMMAND},
    "admin": {READ_READINGS, SEND_COMMAND, MANAGE_DEVICES, MANAGE_USERS, VIEW_AUDIT},
}
ROLES = tuple(ROLE_PERMISSIONS)


def has_permission(role, permission):
    """True if the role includes the permission. Unknown roles have no permissions."""
    return permission in ROLE_PERMISSIONS.get(role, set())


def permission_matrix():
    """Return rows (permission, {role: bool}) for printing a table."""
    all_permissions = [READ_READINGS, SEND_COMMAND, MANAGE_DEVICES, MANAGE_USERS, VIEW_AUDIT]
    return [(perm, {role: has_permission(role, perm) for role in ROLES})
            for perm in all_permissions]
