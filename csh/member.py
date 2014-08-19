from csh.utils import date_from_ldap_timestamp
from datetime import date


class Member(object):
    def __init__(self, member, ldap=None):
        """ Creates and returns a member object from which LDAP fields
            are accessible as properties. If you supply an LDAP connection,
            the object will use that connection to reload its data and
            modify its fields if you choose.
        """
        self.special_fields = ("member_dict", "ldap", "special_fields")
        if len(member) < 2:
            self.member_dict = {}
        else:
            self.member_dict = member[1]
        self.ldap = ldap

    def __getattr__(self, attribute):
        """ Accesses the internal dictionary representation of
            a member and returns whatever data type it represents.
        """
        if attribute in self.special_fields:
            return object.__getattribute__(self, attribute)
        try:
            # Grab the object at that key. It will be a list,
            # if it exists.
            attributes = self.member_dict[attribute]

            # If we do get a list, and it only
            # contains one thing, just return that
            # one thing.
            if len(attributes) == 1:
                attribute = attributes[0]
                if attribute.isdigit():
                    attribute = int(attribute)
                return attribute
            return attributes
        # If there was an error (i.e. that member doesn't have that
        # key in their LDAP store), then return None. We couldn't get it.
        except (KeyError, IndexError):
            return None

    def __setattr__(self, attribute, value):
        """ When setting an attribute with 'member.field = "value"',
            access the internal ldap connection from the constructor
            and modify that parameter.
        """
        if attribute in self.special_fields:
            return object.__setattr__(self, attribute, value)
        if attribute in ("member_dict", "ldap"):
            object.__setattr__(self, attribute, value)
            return
        if not self.ldap:
            return
        kwargs = {attribute: value}
        self.ldap.modify(uid=self.uid, **kwargs)
        self.member_dict[attribute] = value

    def fields(self):
        """ Returns all of the keys in the internal dictionary.
        """
        return self.member_dict.keys()

    def is_active(self):
        """ Is the user active?
        """
        return bool(self.active)

    def is_alumni(self):
        """ Is the user an alumnus/a?
        """
        return bool(self.alumni)

    def is_drink_admin(self):
        """ Is the user a drink admin?
        """
        return bool(self.drinkAdmin)

    def is_on_floor(self):
        """ Is the user on floor?
        """
        return bool(self.onfloor)

    def is_eboard(self):
        """ Is the user on Eboard?
        """
        return 'eboard' in self.groups

    def is_rtp(self):
        """ Is the user an RTP?
        """
        return 'rtp' in self.groups

    def is_birthday(self):
        """ Is it the user's birthday today?
        """
        if not self.birthday:
            return False
        birthday = self.birthdate()
        today = date.today()
        return (birthday.month == today.month and
                birthday.day == today.day)

    def birth_date(self):
        """ Converts the user's birthday (if it exists) to a datetime.date
            object that can easily be compared with other dates.
        """
        if not self.birthday:
            return None
        return date_from_ldap_timestamp(self.birthday)

    def join_date(self):
        """ Converts the user's join date (if it exists) to a datetime.date
            object that can easily be compared with other dates.
        """
        if not self.memberSince:
            return None
        return date_from_ldap_timestamp(self.memberSince)

    def age(self):
        """ Returns the user's age, determined by their birthdate()
        """
        if not self.birthdate():
            return -1
        adjuster = 0
        today = date.today()
        birthday = self.birthdate()
        if today.month == birthday.month:
            if today.day < birthday.day:
                adjuster -= 1
        elif today.month < birthday.month:
            adjuster -= 1
        return (today.year - birthday.year) + adjuster

    def reload(self):
        """ If there is an LDAP connection, query it for another
            instance of this member and set its internal dictionary
            to that result.
        """
        if not self.ldap:
            return
        self.member_dict = self.ldap.member(self.uid)

    def full_name(self):
        """ Returns a reliable full name (firstName lastName) for every
            member (as of the writing of this comment.)
        """
        if self.givenName and self.sn:
            return "{0} {1}".format(self.givenName, self.sn)
        return self.givenName or self.sn or self.uid

    def __str__(self):
        """ Constructs a string representation of this person, containing
            every key and value in their internal dictionary.
        """
        string = ""
        for key in self.member_dict.keys():
            value = self.__getattr__(key)
            string += str(key) + ": " + str(value) + "\n"
        return string
