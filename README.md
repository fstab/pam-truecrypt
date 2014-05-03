pam-truecrypt
=============

This is pam_truecrypt, a pam module that lets you mount truecrypt-encrypted home directories at login.

Installation
----------------

run `make`

copy `pam_truecrypt.so` to `/lib/security/`

Note that you need to install the development files for PAM.

Prerequisites
----------------

My set up is the following:

  * user: `fabian`
  * password: `ezai4aiF`
  * home directory: `/home/fabian`
  * encrypted device: `/dev/hda6`

The device is encrypted with my login password, and I can mount it manually using the command (as root):

	echo 'ezai4aiF' | truecrypt /dev/hda6 /home/fabian

Attention: If you try this, the password will be stored in `/root/.bash_history` in plain text.

The configuration file for pam authentication is `/etc/pam.d/common-auth`,
the configuration file for pam sessions is `/etc/pam.d/common-session`.
(You might have a single configuration file in `/etc/pam.conf`. This is OK.)

Configuration
----------------

Edit `/etc/pam.d/common-auth` and add the following line:

	auth required pam_truecrypt.so fabian /dev/hda6 /home/fabian

Edit `/etc/pam.d/common-session` and add the following line:

	session required pam_truecrypt.so fabian /dev/hda6 /home/fabian

DON'T log out now. Press ALT-CTRL-F1 and try if the login works.
If something is wrong, delete the new config.

Debug
----------------

Error messages are logged in `/var/log/auth.log`.

Logout
----------------

The home directory is not unmounted when the user logs out.
This has two reasons:

1. Usually I turn off my laptop when I log out, so I don't need it.
2. I sometimes start long-running processes using `nohup(1)` before I log out. So my disk may still be busy after logout.

Acknowledgements
----------------

Reading the following code helped me implementing pam_truecrypt:

   * pam_cifs
   * qryptix
   * pam-mount

Unix pipes and much more is explained in

   * Stevens: Advanced Programmint in the Unix Environment.

Status
----------------

This is an old project of mine and I don't maintain it anymore. I've just put it to GitHub to keep it somewhere.

