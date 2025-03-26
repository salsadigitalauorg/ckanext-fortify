import ckan.authz as authz
import logging

log = logging.getLogger(__name__)


def role_in_org(organization_id, user_name):
    return authz.users_role_for_group_or_org(organization_id, user_name)
