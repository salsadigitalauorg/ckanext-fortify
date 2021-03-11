import ckan.plugins.toolkit as toolkit
import logging

from ckan.common import _, request

log = logging.getLogger(__name__)


def disallow_non_image_uploads(next_auth, context, data_dict):
    try:
        if request.files:
            files_dict = dict(request.files)
            image_upload = files_dict.get('image_upload')
            if image_upload and image_upload.mimetype and 'image' not in image_upload.mimetype:
                log.error('User {0} upload attempt blocked - file: {1}'.format(
                    context['user'],
                    image_upload
                ))
                return {'success': False, 'msg': _('Invalid filetype')}
    except Exception as e:
        log.error(str(e))

    return next_auth(context, data_dict)


@toolkit.chained_auth_function
def user_update(next_auth, context, data_dict):
    return disallow_non_image_uploads(next_auth, context, data_dict)


@toolkit.chained_auth_function
def organization_update(next_auth, context, data_dict):
    return disallow_non_image_uploads(next_auth, context, data_dict)


@toolkit.chained_auth_function
def group_update(next_auth, context, data_dict):
    return disallow_non_image_uploads(next_auth, context, data_dict)
