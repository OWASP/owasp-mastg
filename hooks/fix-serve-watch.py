import logging

log = logging.getLogger('mkdocs')

def on_serve(server, config, **kwargs):

    # Remove the default watch on /docs because it clashes with the combine-repos hook
    try:
        server.unwatch("docs")
    except ValueError:
        pass

    # Add the masvs and maswe directories to the watch list
    if config.get('extra', {}).get('maswe_repo'):
        log.info(f"Watching MASWE repo at {config['extra']['maswe_repo']}")
        server.watch(config['extra']['maswe_repo'])

    if config.get('extra', {}).get('masvs_repo'):
        log.info(f"Watching MASVS repo at {config['extra'].get('masvs_repo')}")
        server.watch(config['extra']['masvs_repo'])
