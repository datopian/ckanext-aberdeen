import logging
from datetime import datetime, timedelta
import threading
import sqlalchemy as sqla
from pylons import config

import json
import requests

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
    '''Returns a list of users that have been inactive for the last year'''

    if not authz.is_sysadmin(toolkit.c.user):
        toolkit.abort(403, _('You are not authorized to access this list'))

    user_list = ckan.logic.get_action('user_list')(context, data_dict)
    inactive_users = []
    threads = []

    # Limit the user activity results to the most recent event
    data_dict['limit'] = 1

    # Default to 365 days if days isn't specified in the call
    days = data_dict.get('days', 365)

    # Check for non integers passed to days
    try:
        days = int(days)
    except ValueError:
        toolkit.abort(
            400, _('"{}" is an invalid option for days.'.format(days)))

    # Use threading to speed up the inactive user collection
    def user_activity_threads(user, inactive_users):
        data_dict['id'] = user['id']
        user_info = ckan.logic.get_action(
            'user_activity_list')(context, data_dict)
        inactive_limit = datetime.today() - timedelta(days=days)

        # If the user has no activity, and the account was created before
        # inactive_limit, we add the user to our list
        if not user_info:
            creation_date = datetime.strptime(
                user['created'], '%Y-%m-%dT%H:%M:%S.%f')

            if creation_date < inactive_limit:
                user['last_activity'] = user['created']
                inactive_users.append(user)

            return

        timestamp = datetime.strptime(
            user_info[0]['timestamp'], '%Y-%m-%dT%H:%M:%S.%f')

        if timestamp < inactive_limit:
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
    '''Sends the inactive users list to all site system administrators'''

    # Remove hours, minutes, and seconds from dates
    def format_dates(date):
        date = datetime.strptime(
            date, '%Y-%m-%dT%H:%M:%S.%f')
        date = '{}-{}-{}'.format(
            date.year, date.month, date.day)

        return date

    user_list = ckan.logic.get_action('user_list')(context, data_dict)
    admin_list = [user for user in user_list if user['sysadmin'] is True]
    inactive_users = ckan.logic.get_action(
        'inactive_users')(context, data_dict)
    number_of_users = len(inactive_users)

    if not inactive_users:
        inactive_users_email = \
            'Hello {},\n\nThere are no inactive users to report this week.'
    else:
        inactive_users_email = \
            'Hello {},\n\nThere are currently {} inactive users:\n\n'

        # Format the inactive users list for better readability in an email
        for user in inactive_users:
            inactive_users_email += """
            Profile URL: {}
            Last activity date: {}
            Account creation date: {}
            Full name: {}
            Email address: {}\n
            """.format(
                '{}/user/{}'.format(config.get('ckan.site_url'), user['name']),
                format_dates(user['last_activity']),
                format_dates(user['created']),
                user['fullname'],
                user['email'])

    for admin in admin_list:
        email = admin['email']

        # Check names available - since some of these might be None,
        # we go in order of preference
        name_options = [
            name for name in [
                admin['fullname'],
                admin['display_name'],
                admin['name']]
            if name not in [None, '']]

        if email:
            mailer.mail_recipient(
                name_options[0], email,
                'Inactive users list - weekly update',
                inactive_users_email.format(name_options[0], number_of_users))
