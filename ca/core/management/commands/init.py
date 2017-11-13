import secrets

from django.contrib.auth.models import User
from django.core.management import call_command
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = 'Installs initial data and create superuser.'

    def handle(self, *args, **options):
        if User.objects.count() > 0:
            raise CommandError('CA has been setup already!')

        password = secrets.token_hex(10)
        User.objects.create_superuser('sysop', 'sysop@nyang.ca', password)

        call_command('loaddata', 'key_usages')
        call_command('loaddata', 'extended_key_usages')
        call_command('loaddata', 'profiles')

        self.stdout.write(self.style.SUCCESS('Successfully setup CA'))
        self.stdout.write(f'SYSOP Credential: sysop / {password}')
