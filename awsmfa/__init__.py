import argparse
try:
    import configparser
    from configparser import NoOptionError, NoSectionError
except ImportError:
    import ConfigParser as configparser
    from ConfigParser import NoOptionError, NoSectionError
import datetime
import getpass
import logging
import os
import sys
import boto3

from botocore.exceptions import ClientError, ParamValidationError
from awsmfa.config import initial_setup
from awsmfa.util import log_error_and_exit, prompter
from awsmfa.writer import ConfigFileWriter

logger = logging.getLogger('aws-mfa')

# AWS_CREDS_PATH = '%s/.aws/credentials' % (os.path.expanduser('~'),)
# AWS_CONF_PATH = '%s/.aws/config' % (os.path.expanduser('~'),)

AWS_CONF_PATH = {
    "CREDS" : '%s/.aws/credentials' % (os.path.expanduser('~'),),
    "CONFS" : '%s/.aws/config' % (os.path.expanduser('~'),)
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--device', '--serial',
                        required=False,
                        metavar='arn:aws:iam::123456788990:mfa/dudeman',
                        help="The MFA Device ARN. This value can also be "
                        "provided via the environment variable 'MFA_SERIAL' or"
                        " the ~/.aws/config variable 'mfa_serial'.")
    parser.add_argument('--duration',
                        type=int,
                        help="The duration, in seconds, that the temporary "
                             "credentials should remain valid. Minimum value: "
                             "900 (15 minutes). Maximum: 129600 (36 hours). "
                             "Defaults to 43200 (12 hours), or 3600 (one "
                             "hour) when using '--assume-role'. This value "
                             "can also be provided via the environment "
                             "variable 'MFA_STS_DURATION'. ")
    parser.add_argument('--profile',
                        help="If using profiles, specify the name here. The "
                        "default profile name is 'default'. The value can "
                        "also be provided via the environment variable "
                        "'AWS_PROFILE'.",
                        required=False)
    parser.add_argument('--long-term-suffix', '--long-suffix',
                        help="The suffix appended to the profile name to"
                        "identify the long term credential section",
                        required=False)
    parser.add_argument('--short-term-suffix', '--short-suffix',
                        help="The suffix appended to the profile name to"
                        "identify the short term credential section",
                        required=False)
    parser.add_argument('--assume-role', '--assume',
                        metavar='arn:aws:iam::123456788990:role/RoleName',
                        help="The ARN of the AWS IAM Role you would like to "
                        "assume, if specified. This value can also be provided"
                        " via the environment variable 'MFA_ASSUME_ROLE'",
                        required=False)
    parser.add_argument('--role-session-name',
                        help="Friendly session name required when using "
                        "--assume-role",
                        default=getpass.getuser(),
                        required=False)
    parser.add_argument('--force',
                        help="Refresh credentials even if currently valid.",
                        action="store_true",
                        required=False)
    parser.add_argument('--log-level',
                        help="Set log level",
                        choices=[
                            'CRITICAL', 'ERROR', 'WARNING',
                            'INFO', 'DEBUG', 'NOTSET'
                        ],
                        required=False,
                        default='DEBUG')
    parser.add_argument('--setup',
                        help="Setup a new log term credentials section",
                        action="store_true",
                        required=False)
    parser.add_argument('--token', '--mfa-token',
                        type=str,
                        help="Provide MFA token as an argument",
                        required=False)
    args = parser.parse_args()

    level = getattr(logging, args.log_level)
    setup_logger(level)

    if not os.path.isfile(AWS_CONF_PATH["CREDS"]):
        console_input = prompter()
        create = console_input("Could not locate credentials file at {}, "
                               "would you like to create one? "
                               "[y/n]".format(AWS_CONF_PATH["CREDS"]))
        if create.lower() == "y":
            with open(AWS_CONF_PATH["CREDS"], 'a'):
                pass
        else:
            log_error_and_exit(logger, 'Could not locate credentials file at '
                               '%s' % (AWS_CONF_PATH["CREDS"],))

    # config = get_config(AWS_CREDS_PATH)
    config = {}
    config['creds'] = get_config(AWS_CONF_PATH["CREDS"])
    config['confs'] = get_config(AWS_CONF_PATH["CONFS"])

    if args.setup:
        initial_setup(logger, AWS_CONF_PATH)
        return

    validate(args, config)


def get_config(path):
    config = configparser.RawConfigParser()
    try:
        config.read(path)
    except configparser.ParsingError:
        e = sys.exc_info()[1]
        log_error_and_exit(logger, "There was a problem reading or parsing "
                           "your credentials file: %s" % (e.args[0],))
    return config


def validate(args, config):
    if not args.profile:
        if os.environ.get('AWS_PROFILE'):
            args.profile = os.environ.get('AWS_PROFILE')
        else:
            args.profile = 'default'

    if not args.long_term_suffix:
        long_term_name = '%s-long-term' % (args.profile,)
    elif args.long_term_suffix.lower() == 'none':
        long_term_name = args.profile
    else:
        long_term_name = '%s-%s' % (args.profile, args.long_term_suffix)

    if not args.short_term_suffix or args.short_term_suffix.lower() == 'none':
        short_term_name = args.profile
    else:
        short_term_name = '%s-%s' % (args.profile, args.short_term_suffix)

    if long_term_name == short_term_name:
        log_error_and_exit(logger,
                           "The value for '--long-term-suffix' cannot "
                           "be equal to the value for '--short-term-suffix'")

    if args.assume_role:
        role_msg = "with assumed role: %s" % (args.assume_role,)
    elif config['creds'].has_option(args.profile, 'assumed_role_arn'):
        role_msg = "with assumed role: %s" % (
            config['creds'].get(args.profile, 'assumed_role_arn'))
    else:
        role_msg = ""
    logger.info('Validating credentials for profile: %s %s' %
                (short_term_name, role_msg))
    reup_message = "Obtaining credentials for a new role or profile."

    try:
        key_id = config['creds'].get(long_term_name, 'aws_access_key_id')
        access_key = config['creds'].get(long_term_name, 'aws_secret_access_key')
    except NoSectionError:
        log_error_and_exit(logger,
                           "Long term credentials session '[%s]' is missing. "
                           "You must add this section to your credentials file "
                           "along with your long term 'aws_access_key_id' and "
                           "'aws_secret_access_key'" % (long_term_name,))
    except NoOptionError as e:
        log_error_and_exit(logger, e)
    
    # now you should have got key_id and access_key, it is time to get region_name
    try:
        region_name = config['confs'].get("profile {}".format(long_term_name), 'region')
    except NoSectionError:
        region_name = 'us-east-2' # default region

    # get device from param, env var or config
    if not args.device:
        if os.environ.get('MFA_SERIAL'):
            args.device = os.environ.get('MFA_SERIAL')
        elif config['confs'].has_option("profile {}".format(long_term_name), 'mfa_serial'):
            # https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html
            args.device = config['confs'].get("profile {}".format(long_term_name), 'mfa_serial')
        else:
            log_error_and_exit(logger,
                               'You must provide --device or MFA_DEVICE or set '
                               '"mfa_serial" in ".aws/config"')

    # get assume_role from param or env var
    if not args.assume_role:
        if os.environ.get('MFA_ASSUME_ROLE'):
            args.assume_role = os.environ.get('MFA_ASSUME_ROLE')
        elif config['creds'].has_option(long_term_name, 'assume_role'):
            args.assume_role = config['creds'].get(long_term_name, 'assume_role')

    # get duration from param, env var or set default
    if not args.duration:
        if os.environ.get('MFA_STS_DURATION'):
            args.duration = int(os.environ.get('MFA_STS_DURATION'))
        else:
            args.duration = 3600 if args.assume_role else 43200

    # If this is False, only refresh credentials if expired. Otherwise
    # always refresh.
    force_refresh = False

    # Validate presence of short-term section
    if not config['creds'].has_section(short_term_name):
        logger.info("Short term credentials section %s is missing, "
                    "obtaining new credentials." % (short_term_name,))
        force_refresh = True
    # Validate option integrity of short-term section
    else:
        required_options = ['assumed_role',
                            'aws_access_key_id', 'aws_secret_access_key',
                            'aws_session_token', 'aws_security_token',
                            'expiration']
        try:
            short_term = {}
            for option in required_options:
                short_term[option] = config['creds'].get(short_term_name, option)
        except NoOptionError:
            logger.warn("Your existing credentials are missing or invalid, "
                        "obtaining new credentials.")
            force_refresh = True

        try:
            current_role = config['creds'].get(short_term_name, 'assumed_role_arn')
        except NoOptionError:
            current_role = None

        if args.force:
            logger.info("Forcing refresh of credentials.")
            force_refresh = True
        # There are not credentials for an assumed role,
        # but the user is trying to assume one
        elif current_role is None and args.assume_role:
            logger.info(reup_message)
            force_refresh = True
        # There are current credentials for a role and
        # the role arn being provided is the same.
        elif (current_role is not None and
                args.assume_role and current_role == args.assume_role):
            pass
        # There are credentials for a current role and the role
        # that is attempting to be assumed is different
        elif (current_role is not None and
              args.assume_role and current_role != args.assume_role):
            logger.info(reup_message)
            force_refresh = True
        # There are credentials for a current role and no role arn is
        # being supplied
        elif current_role is not None and args.assume_role is None:
            logger.info(reup_message)
            force_refresh = True

    should_refresh = True

    # Unless we're forcing a refresh, check expiration.
    if not force_refresh:
        exp = datetime.datetime.strptime(
            config['creds'].get(short_term_name, 'expiration'), '%Y-%m-%d %H:%M:%S')
        diff = exp - datetime.datetime.utcnow()
        if diff.total_seconds() <= 0:
            logger.info("Your credentials have expired, renewing.")
        else:
            should_refresh = False
            logger.info(
                "Your credentials are still valid for %s seconds"
                " they will expire at %s"
                % (diff.total_seconds(), exp))

    if should_refresh:
        get_credentials(short_term_name, key_id, access_key, region_name, args, config)


def get_credentials(short_term_name, lt_key_id, lt_access_key, lt_region, args, config):
    if args.token:
        logger.debug("Received token as argument")
        mfa_token = '%s' % (args.token)
    else:
        console_input = prompter()
        mfa_token = console_input('Enter AWS MFA code for device [%s] '
                                  '(renewing for %s seconds):' %
                                  (args.device, args.duration))
    client = boto3.client(
        'sts',
        aws_access_key_id=lt_key_id,
        aws_secret_access_key=lt_access_key,
        region_name = lt_region
    )

    conf_writer = ConfigFileWriter()

    if args.assume_role:

        logger.info("Assuming Role - Profile: %s, Role: %s, Duration: %s",
                    short_term_name, args.assume_role, args.duration)
        if args.role_session_name is None:
            log_error_and_exit(logger, "You must specify a role session name "
                               "via --role-session-name")

        try:
            response = client.assume_role(
                RoleArn=args.assume_role,
                RoleSessionName=args.role_session_name,
                DurationSeconds=args.duration,
                SerialNumber=args.device,
                TokenCode=mfa_token
            )
        except ClientError as e:
            log_error_and_exit(logger,
                               "An error occured while calling "
                               "assume role: {}".format(e))
        except ParamValidationError:
            log_error_and_exit(logger, "Token must be six digits")

        assumed_role_config = {
            "__section__": short_term_name,
            'assumed_role': "True"
        }
        conf_writer.update_config(assumed_role_config, AWS_CONF_PATH['CREDS'])
        assumed_role_arn_config = {
            "__section__": short_term_name,
            'assumed_role_arn': args.assume_role
        }
        conf_writer.update_config(assumed_role_arn_config, AWS_CONF_PATH['CREDS'])

    else:
        logger.info("Fetching Credentials - Profile: %s, Duration: %s",
                    short_term_name, args.duration)
        try:
            response = client.get_session_token(
                DurationSeconds=args.duration,
                SerialNumber=args.device,
                TokenCode=mfa_token
            )
        except ClientError as e:
            log_error_and_exit(
                logger,
                "An error occured while calling assume role: {}".format(e))
        except ParamValidationError:
            log_error_and_exit(
                logger,
                "Token must be six digits")

        assumed_role_config = {
            "__section__": short_term_name,
            'assumed_role': "False"
        }
        # conf_writer.update_config(assumed_role_config, AWS_CONF_PATH['CREDS'])
        # assumed_role_arn_config = {
        #     "__section__": short_term_name,
        #     'assumed_role_arn': ''
        # }
        # conf_writer.update_config(assumed_role_arn_config, AWS_CONF_PATH['CREDS'])

    # aws_session_token and aws_security_token are both added
    # to support boto and boto3
    options = [
        ('aws_access_key_id', 'AccessKeyId'),
        ('aws_secret_access_key', 'SecretAccessKey'),
        ('aws_session_token', 'SessionToken'),
        ('aws_security_token', 'SessionToken'),
    ]

    
    for option, value in options:
        option_conf = {
            "__section__": short_term_name,
            option: response['Credentials'][value]
        }
        conf_writer.update_config(option_conf, AWS_CONF_PATH['CREDS'])
    # Save expiration individiually, so it can be manipulated
    expiration_conf = {
        "__section__": short_term_name,
        "expiration": response['Credentials']['Expiration'].strftime('%Y-%m-%d %H:%M:%S')
    }
    conf_writer.update_config(expiration_conf, AWS_CONF_PATH['CREDS'])

    region_config = {
        "__section__": short_term_name,
        'region': lt_region
    }
    conf_writer.update_config(region_config, AWS_CONF_PATH['CONFS'])
    logger.info(
        "Success! Your credentials will expire in %s seconds at: %s"
        % (args.duration, response['Credentials']['Expiration']))
    sys.exit(0)


def setup_logger(level=logging.DEBUG):
    stdout_handler = logging.StreamHandler(stream=sys.stdout)
    stdout_handler.setFormatter(
        logging.Formatter('%(levelname)s - %(message)s'))
    stdout_handler.setLevel(level)
    logger.addHandler(stdout_handler)
    logger.setLevel(level)


if __name__ == "__main__":
    main()
