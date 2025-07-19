EMAIL_REGEX = r'^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$'
PHONE_REGEX = r"""
    ^                         # start of string
    (?:
        (\+91[\-\s]?)?        # optional +91 country code with optional space or hyphen
        | (0)?                # or optional 0 prefix
    )
    [6-9]                     # Indian mobile numbers start with 6,7,8,9
    \d{9}                     # followed by 9 digits
    $                         # end of string
"""