import ckan.authz as authz
import logging

from ckan.common import config
from ckanext.fortify import validators
from paste.deploy.converters import asbool

log = logging.getLogger(__name__)


def role_in_org(organization_id, user_name):
    return authz.users_role_for_group_or_org(organization_id, user_name)


def get_password_error_message():
    error_messages = [validators.MIN_LEN_ERROR.format(validators.MIN_PASSWORD_LENGTH)]
    if not asbool(config.get('ckan.fortify.password_policy.allow_repeated_chars', True)):
        error_messages.append(validators.REPEATING_CHAR_ERROR)
    return error_messages
