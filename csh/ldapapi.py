import ldap as pyldap
import ldap.sasl as sasl
from copy import deepcopy
from member import Member


class LDAP:
    def __init__(self, user, password,
                 host='ldaps://ldap.csh.rit.edu:636',
                 base='ou=Users,dc=csh,dc=rit,dc=edu',
                 app=False,
                 objects=False):
        self.host = host
        self.base = base
        self.users = 'ou=Users,dc=csh,dc=rit,dc=edu'
        self.groups = 'ou=Groups,dc=csh,dc=rit,dc=edu'
        self.committees = 'ou=Committees,dc=csh,dc=rit,dc=edu'
        self.ldap = pyldap.initialize(host)
        self.ldap.set_option(pyldap.OPT_X_TLS_DEMAND, True)
        self.ldap.set_option(pyldap.OPT_DEBUG_LEVEL, 255)
        self.objects = objects

        if app:
            self.ldap.simple_bind('uid=' + user + ',' + base, password)
        else:
            try:
                auth = sasl.gssapi("")

                self.ldap.sasl_interactive_bind_s("", auth)
                self.ldap.set_option(pyldap.OPT_DEBUG_LEVEL, 0)
            except pyldap.LDAPError, e:
                print 'Are you sure you\'ve run kinit?'
                print e

    def members(self, uid='*'):
        """ members() issues an ldap query for all users, and returns a dict
            for each matching entry. This can be quite slow, and takes roughly
            3s to complete. You may optionally restrict the scope by specifying
            a uid, which is roughly equivalent to a search(uid='foo')
        """
        entries = self.search(uid=uid)
        if self.objects:
            return self.member_objects(entries)
        result = []
        for entry in entries:
            result.append(entry[1])
        return result

    def member(self, user):
        """ Returns a user as a dict of attributes
        """
        try:
            member = self.search(uid=user)[0]
        except IndexError:
            return None
        if self.objects:
            return member
        return member[1]

    def eboard(self):
        """ Returns a list of eboard members formatted as a search
            inserts an extra ['commmittee'] attribute
        """
        # self.committee used as base because that's where eboard
        # info is kept
        committees = self.search(base=self.committees, cn='*')
        directors = []
        for committee in committees:
            for head in committee[1]['head']:
                director = self.search(dn=head)[0]
                director[1]['committee'] = committee[1]['cn'][0]
                directors.append(director)
        if self.objects:
            return self.member_objects(directors)
        return directors

    def group(self, group_cn):
        members = self.search(base=self.groups, cn=group_cn)
        if len(members) == 0:
            return members
        else:
            member_dns = members[0][1]['member']
        members = []
        for member_dn in member_dns:
            members.append(self.search(dn=member_dn)[0])
        if self.objects:
            return self.member_objects(members)
        return members

    def groups_for_member(self, member_dn):
        search_result = self.search(base=self.groups, member=member_dn)
        if len(search_result) == 0:
            return []

        group_list = []
        for group in search_result:
            group_list.append(group[1]['cn'][0])
        return group_list

    def drink_admins(self):
        """ Returns a list of drink admins uids
        """
        admins = self.group('drink')
        return admins

    def rtps(self):
        rtps = self.group('rtp')
        return rtps

    @staticmethod
    def trim_result(result):
        return [x[1] for x in result]

    def search(self, base=None, trim=False, **kwargs):
        """ Returns matching entries for search in ldap
            structured as [(dn, {attributes})]
            UNLESS searching by dn, in which case the first match
            is returned
        """
        scope = pyldap.SCOPE_SUBTREE
        if not base:
            base = self.users

        filterstr = ''
        for key, value in kwargs.iteritems():
            filterstr += '({0}={1})'.format(key, value)
            if key == 'dn':
                filterstr = '(objectClass=*)'
                base = value
                scope = pyldap.SCOPE_BASE
                break

        if len(kwargs) > 1:
            filterstr = '(&' + filterstr + ')'

        result = self.ldap.search_s(base,
                                    scope,
                                    filterstr,
                                    ['*', '+'])
        if base == self.users:
            for member in result:
                groups = self.groups_for_member(member[0])
                member[1]['groups'] = groups
                if 'eboard' in member[1]['groups']:
                    eboard_search = self.search(base=self.committees,
                                                head=member[0])
                    if eboard_search:
                        member[1]['committee'] = eboard_search[0][1]['cn'][0]
            if self.objects:
                return self.member_objects(result)
        final_result = self.trim_result(result) if trim else result
        return final_result

    def modify(self, uid, **kwargs):
        dn = 'uid=' + uid + ',ou=Users,dc=csh,dc=rit,dc=edu'
        old_attrs = self.member(uid)
        new_attrs = deepcopy(old_attrs)

        for field, value in kwargs.iteritems():
            if field in old_attrs:
                new_attrs[field] = [str(value)]
        modlist = pyldap.modlist.modifyModlist(old_attrs, new_attrs)

        self.ldap.modify_s(dn, modlist)

    def member_objects(self, search_results):
        results = []
        for result in search_results:
            new_member = Member(result, ldap=self)
            results.append(new_member)
        return results


