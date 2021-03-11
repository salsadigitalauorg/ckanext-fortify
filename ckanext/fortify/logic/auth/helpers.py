import logging

from ckan.common import _, request

log = logging.getLogger(__name__)
invalid_filetype_response = {'success': False, 'msg': _('Invalid filetype')}


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
                return invalid_filetype_response
    except Exception as e:
        log.error(str(e))

    return next_auth(context, data_dict)
