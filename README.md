This is the source code for the [London Hackspace web site](https://london.hackspace.org.uk)

## Getting Started

We use Vagrant to deploy a consistent development environment. To get
your development environment set up:

* Install [Vagrant](https://www.vagrantup.com/downloads.html) and [Virtualbox](https://www.virtualbox.org/)
* Run `vagrant up` in this directory. This will create and configure a virtual machine.
* Create config file (the defaults are fine): `cp etc/config.php.example etc/config.php`
* Fetch libraries: `git submodule update --init`

You should now be able to connect to http://localhost:8000 to view your
development site. Changes you make on your machine will be reflected
on the VM.

If you need to log into the VM for any reason, you can just run
`vagrant ssh`. To access the postgres database, run `psql
hackspace` from the SSH shell.

## Making yourself an admin
In the postgres shell:

    hackspace=# update users set subscribed=True;
    hackspace=# update users set admin=True;

to make yourself a member and an admin

## letting apache add ldap users (!)
use visudo to add this:

    www-data ALL=(www-data:ldapadmin) NOPASSWD:NOSETENV: /var/www/hackspace-foundation-sites/bin/ldap-add.sh, /var/www/hackspace-foundation-sites/bin/ldap-delete.sh

and then:

    groupadd ldapadmin
    chgrp ldapadmin /etc/smbldap-tools/smbldap_bind.conf
    chmod 0640 /etc/smbldap-tools/smbldap_bind.conf

## Enabling Calendar management
1. Enable the Calendar API at https://console.developers.google.com/.../apiui/api
2. Create a service account for OAuth at https://console.developers.google.com/.../apiui/credential
3. Put the OAuth certificate in ./var, and correct the service_account_name and key_file_location in lib/calendar.php
4. Go to the Hackspace calendar on Google and share it with the same service_account_name address

API documentation https://developers.google.com/api-client-library/php/
