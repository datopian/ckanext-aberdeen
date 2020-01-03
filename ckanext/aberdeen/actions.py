import logging
import requests
import json
from datetime import datetime, timedelta
import threading
import time
import sqlalchemy as sqla

import ckan.lib.jobs as jobs
import ckan.logic
import ckan.logic.action
import ckan.plugins as plugins
import ckan.lib.dictization.model_dictize as model_dictize
from ckan import authz
import ckan.plugins.toolkit as toolkit
from ckan.lib import mailer

from ckan.common import _


log = logging.getLogger(__name__)

validate = ckan.lib.navl.dictization_functions.validate

# Define some shortcuts
# Ensure they are module-private so that they don't get loaded as available
# actions in the action API.
ValidationError = ckan.logic.ValidationError
NotFound = ckan.logic.NotFound
_check_access = ckan.logic.check_access
_get_or_bust = ckan.logic.get_or_bust
_get_action = ckan.logic.get_action

def _group_or_org_delete(context, data_dict, is_org=False):
    '''Delete a group.
    You must be authorized to delete the group.
    :param id: the name or id of the group
    :type id: string
    '''
    from sqlalchemy import or_

    model = context['model']
    user = context['user']
    id = _get_or_bust(data_dict, 'id')

    group = model.Group.get(id)
    context['group'] = group
    if group is None:
        raise NotFound('Group was not found.')

    revisioned_details = 'Group: %s' % group.name

    if is_org:
        _check_access('organization_delete', context, data_dict)
    else:
        _check_access('group_delete', context, data_dict)

    # organization delete will delete all datasets for that org
    if is_org:
        datasets = model.Session.query(model.Package) \
                        .filter_by(owner_org=group.id) \
                        .filter(model.Package.state != 'deleted').all()
        if len(datasets):
            if authz.check_config_permission('ckan.auth.create_unowned_dataset'):
                pkg_table = model.package_table
                # using Core SQLA instead of the ORM should be faster
                model.Session.execute(
                    pkg_table.update().where(
                        sqla.and_(pkg_table.c.owner_org == group.id,
                                  pkg_table.c.state != 'deleted')
                    ).values(owner_org=None)
                )
            else:
                for dataset in datasets:
                    ckan.logic.get_action('dataset_purge')(context, {'id': dataset.id})

    rev = model.repo.new_revision()
    rev.author = user
    rev.message = _(u'REST API: Delete %s') % revisioned_details

    # The group's Member objects are deleted
    # (including hierarchy connections to parent and children groups)
    for member in model.Session.query(model.Member).\
            filter(or_(model.Member.table_id == id,
                       model.Member.group_id == id)).\
            filter(model.Member.state == 'active').all():
        member.delete()

    group.delete()

    if is_org:
        plugin_type = plugins.IOrganizationController
    else:
        plugin_type = plugins.IGroupController

    for item in plugins.PluginImplementations(plugin_type):
        item.delete(group)

    model.repo.commit()


def group_delete(context, data_dict):
    '''Delete a group.
    You must be authorized to delete the group.
    :param id: the name or id of the group
    :type id: string
    '''
    return _group_or_org_delete(context, data_dict)

def organization_delete(context, data_dict):
    '''Delete an organization.
    You must be authorized to delete the organization.
    :param id: the name or id of the organization
    :type id: string
    '''
    return _group_or_org_delete(context, data_dict, is_org=True)


def _group_or_org_purge(context, data_dict, is_org=False):
    '''Purge a group or organization.
    The group or organization will be completely removed from the database.
    This cannot be undone!
    Only sysadmins can purge groups or organizations.
    :param id: the name or id of the group or organization to be purged
    :type id: string
    :param is_org: you should pass is_org=True if purging an organization,
        otherwise False (optional, default: False)
    :type is_org: boolean
    '''
    model = context['model']
    id = _get_or_bust(data_dict, 'id')

    group = model.Group.get(id)
    context['group'] = group
    if group is None:
        if is_org:
            raise NotFound('Organization was not found')
        else:
            raise NotFound('Group was not found')

    if is_org:
        _check_access('organization_purge', context, data_dict)
    else:
        _check_access('group_purge', context, data_dict)

    if is_org:
        # Clear the owner_org field
        datasets = model.Session.query(model.Package) \
                        .filter_by(owner_org=group.id) \
                        .filter(model.Package.state != 'deleted').all()
        if len(datasets):
            if authz.check_config_permission('ckan.auth.create_unowned_dataset'):
                pkg_table = model.package_table
                # using Core SQLA instead of the ORM should be faster
                model.Session.execute(
                    pkg_table.update().where(
                        sqla.and_(pkg_table.c.owner_org == group.id,
                                  pkg_table.c.state != 'deleted')
                    ).values(owner_org=None)
                )
            else:
                for dataset in datasets:
                    ckan.logic.get_action('dataset_purge')(context, {'id': dataset.id})

    # Delete related Memberships
    members = model.Session.query(model.Member) \
                   .filter(sqla.or_(model.Member.group_id == group.id,
                                    model.Member.table_id == group.id))
    if members.count() > 0:
        # no need to do new_revision() because Member is not revisioned, nor
        # does it cascade delete any revisioned objects
        for m in members.all():
            m.purge()
        model.repo.commit_and_remove()

    group = model.Group.get(id)
    model.repo.new_revision()
    group.purge()
    model.repo.commit_and_remove()


def group_purge(context, data_dict):
    return _group_or_org_purge(context, data_dict, is_org=False)


def organization_purge(context, data_dict):
    return _group_or_org_purge(context, data_dict, is_org=True)


@toolkit.side_effect_free
def inactive_users(context, data_dict):
    #if not authz.is_sysadmin(toolkit.c.user):
    #    log.error('-------------------')
    #    toolkit.abort(403, _('You are not authorized to access this list'))

    #user_list = ckan.logic.get_action('user_list')(context, data_dict)
    user_list = json.loads(requests.get(
        ('https://data.aberdeencity.gov.uk/api/3/action/user_list'),
        headers={'Authorization': ''}
        ).content.decode('utf-8'))['result']

    inactive_users = []
    threads = []
    data_dict['limit'] = 1

    times = []

    def user_activity_threads(user, inactive_users):
        user_info = json.loads(requests.get(
            ('https://data.aberdeencity.gov.uk/api/3/action/user_activity_list?'
             'limit=1&id={}').format(user['id']),
            headers={'Authorization': ''}
            ).content.decode('utf-8'))['result']
        log.error(user_info)

        #data_dict['id'] = user['id']
        #user_info = ckan.logic.get_action(
        #    'user_activity_list')(context, data_dict)
        #log.error(user_info)

        if not user_info:
            return
        times.append(user_info[0]['timestamp'])

        timestamp = datetime.strptime(
            user_info[0]['timestamp'], '%Y-%m-%dT%H:%M:%S.%f')

        if timestamp < datetime.today() - timedelta(days=365):
            user['last_activity'] = user_info[0]['timestamp']
            inactive_users.append(user)
        return inactive_users

    for user in user_list:
        thread = threading.Thread(
            target=user_activity_threads, args=(user, inactive_users))
        threads.append(thread)
        thread.start()

    for user, thread in enumerate(threads):
        thread.join()

    return inactive_users


@toolkit.side_effect_free
def send_inactive_users_email(context, data_dict):
    log.error('it is working!!!!!!!!!!!!!!!!!!!!')

    inactive_users = toolkit.get_action('inactive_users')(context, data_dict)
    inactive_users = '\n\n'.join(
        '\n'.join(info + ': ' + str(user_info[info]) for info in user_info)
        for user_info in inactive_users)

    mailer.mail_recipient(
        toolkit.c.user, 'dareislowdown@gmail.com',
        'Inactive user list', inactive_users)
