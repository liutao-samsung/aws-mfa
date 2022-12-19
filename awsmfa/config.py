import getpass
from awsmfa.util import log_error_and_exit, prompter
from awsmfa.writer import ConfigFileWriter


def initial_setup(logger, config_path):
    console_input = prompter()

    profile_name = console_input('Profile name to [%s]: ' % ("default"))
    if profile_name is None or profile_name == "":
        profile_name = "default"

    profile_name = "{}-long-term".format(profile_name)
    aws_access_key_id = getpass.getpass('aws_access_key_id: ')
    if aws_access_key_id is None or aws_access_key_id == "":
        log_error_and_exit(logger, "You must supply aws_access_key_id")
    aws_secret_access_key = getpass.getpass('aws_secret_access_key: ')
    if aws_secret_access_key is None or aws_secret_access_key == "":
        log_error_and_exit(logger, "You must supply aws_secret_access_key")
    
    aws_region_name = input('aws_region_name: ')
    aws_mfa_serial = input('aws_mfa_serial: ')

    conf_writer = ConfigFileWriter()
    access_keyid_config = {
        "__section__": profile_name,
        "aws_access_key_id": aws_access_key_id,
    }
    secret_key_config = {
        "__section__": profile_name,
        "aws_secret_access_key": aws_secret_access_key,
    }
    conf_writer.update_config(access_keyid_config, config_path['CREDS'])
    conf_writer.update_config(secret_key_config, config_path['CREDS'])

    region_config = {
        "__section__": "profile %s" % profile_name,
        'region': aws_region_name
    }
    conf_writer.update_config(region_config, config_path['CONFS'])

    if aws_mfa_serial:
        mfa_serial_config = {
        "__section__": "profile %s" % profile_name,
        'mfa_serial': aws_mfa_serial
        }
        conf_writer.update_config(mfa_serial_config, config_path['CONFS'])
