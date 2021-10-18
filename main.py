import sys
from pathlib import Path
import os
from typing import List, Dict, Tuple
import json
import jsonschema
import boto3
import telegram

FREEZEFILE_PREFIX = '.freeze.'
FROZENFILE = '.frozen'
FREEZEFILE_TAGS = {
    'storage-class': 'infrequent-access'
}

CONFIG_SCHEMA = {
    'type': 'object',
    'properties': {
        'rule-at': {
            'type': 'object'
        },
        'freezefile-tags': {
            'type': 'object'
        },
        'applied-tags': {
            'type': 'object'
        },
        'affected-files': {
            'type': 'array',
            'items': {
                'type': 'string'
            }
        }
    },
    'required': ['rule-at', 'applied-tags', 'affected-files', 'freezefile-tags']
}
BASE_CONFIG = {
    'rule-at': '',
    'applied-tags': {},
    'affected-files': [],
    'freezefile-tags': {}
}


S3_BUCKET_NAME = os.environ.get('S3_BUCKET_NAME')
S3_MOUNT_PATH = str(Path(os.environ.get('S3_MOUNT_PATH')).resolve())
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID')


def parse_freezefile(freezefile: str) -> Dict[str, str]:
    key_values = [x.split('=') for x in freezefile[len(FREEZEFILE_PREFIX):].split(';')]
    return {
        x[0]: x[1] for x in key_values
    }


def apply_tag(target_path: str, rule_path: str, tags: dict) -> Tuple[bool, List[str], List[str]]:
    directories = [target_path]
    processed_files = []
    failed_files = []
    state = True

    s3 = boto3.client('s3')

    while True:
        if len(directories) == 0:
            return state, processed_files, failed_files

        path = directories.pop()
        # If this directory contains freezefile
        # Process this directory recursively
        if path != target_path:
            freezefiles = [x for x in Path(path).glob(f'{FREEZEFILE_PREFIX}*')]
            if len(freezefiles) != 0:
                parsed_tag = parse_freezefile(freezefiles[0].name)
                ret = apply_tag(path, rule_path, parsed_tag)
                state = state and ret[0]
                processed_files += ret[1]
                failed_files += ret[2]
                os.remove(os.path.join(path, freezefiles[0].name))
                continue

        # Parse frozen metadata
        try:
            with open(os.path.join(path, FROZENFILE)) as conf_file:
                frozen = json.load(conf_file)
            jsonschema.validate(instance=frozen, schema=CONFIG_SCHEMA)
        except:
            frozen = dict(BASE_CONFIG)
            frozen['affected-files'] = []
            state = False
        else:
            if frozen['rule-at'] != rule_path:
                # Do not apply
                return True, [], []

        for file in os.listdir(path):
            # Ignore hidden files
            if file.startswith('.'):
                continue

            file_abs_path = str(Path(os.path.join(path, file)).resolve())
            if os.path.isdir(file_abs_path):
                # Process path recursively, add to directories list, then continue
                directories.append(file_abs_path)
                continue

            if file.startswith(FREEZEFILE_PREFIX) or file == FROZENFILE:
                # Shouldn't be frozen to Glacier, using pre-defined tags
                using_tag = FREEZEFILE_TAGS
                old_tag = frozen['freezefile-tags']
            else:
                using_tag = tags
                old_tag = frozen['applied-tags']

            if using_tag == old_tag and file in frozen['affected-files']:
                continue

            file_s3_key = file_abs_path.replace(S3_MOUNT_PATH + '/', '')

            try:
                s3.put_object_tagging(Bucket=S3_BUCKET_NAME, Key=file_s3_key, Tagging={
                    'TagSet': [
                        {'Key': k, 'Value': v} for k, v in tags.items()
                    ]
                })
            except:
                state = False
                failed_files.append(file_abs_path)
            else:
                processed_files.append(file_abs_path)
                if using_tag == tags:
                    frozen['affected-files'].append(file)

        with open(os.path.join(path, FROZENFILE), 'wt') as conf_file:
            frozen['rule-at'] = rule_path
            frozen['applied-tags'] = tags
            frozen['freezefile-tags'] = FREEZEFILE_TAGS
            json.dump(frozen, conf_file, indent=4, sort_keys=True)

    return state, processed_files, failed_files

if __name__ == '__main__':
    freeze_paths = Path(S3_MOUNT_PATH).rglob(f'{FREEZEFILE_PREFIX}*')
    tgt_folder_candidates = sorted([str(x.parent) for x in freeze_paths], key=lambda x: len(x))
    tgt_folders = []
    for tgt_folder in tgt_folder_candidates:
        if any([tgt_folder.startswith(f'{x}{os.path.sep}') for x in tgt_folders]):
            continue
        else:
            tgt_folders.append(tgt_folder)

    for tgt_folder in tgt_folders:
        freezefile = [x.name for x in Path(tgt_folder).glob(f'{FREEZEFILE_PREFIX}*')][0]
        tag = parse_freezefile(freezefile)
        state, _, _ = apply_tag(tgt_folder, tgt_folder, tag)
        os.remove(os.path.join(tgt_folder, freezefile))
        telegram.Bot(TELEGRAM_BOT_TOKEN).send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text='Freezing path ' + (tgt_folder if len(tgt_folder) <= 4000 else tgt_folder[:3997] + '...') + ' ' + ('Succeeded' if state else 'Failed')
        )

    sys.exit(0)
