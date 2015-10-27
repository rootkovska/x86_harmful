#!/bin/sh

export QUBES_GPG_DOMAIN=keys-blog
exec qubes-gpg-client "$@"
