import ckan.authz as authz


def role_in_org(organization_id, user_name):
    return authz.users_role_for_group_or_org(organization_id, user_name)
