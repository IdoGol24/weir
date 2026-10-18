# Standard credential locations (list v1)

Generated from `weir.inventory.locations.STANDARD_LOCATIONS`; do not edit by hand.
Paths are relative to the home directory given to `weir inventory --home`.
Variables are read from the launch environment being inventoried; the default
paths are checked as well.

| id | paths | format | credential fields | moved by |
| --- | --- | --- | --- | --- |
| aws_credentials | `~/.aws/credentials` | ini | `aws_access_key_id`, `aws_secret_access_key`, `aws_security_token`, `aws_session_token` | `AWS_SHARED_CREDENTIALS_FILE` |
| aws_config | `~/.aws/config` | ini | `aws_access_key_id`, `aws_secret_access_key`, `aws_security_token`, `aws_session_token` | `AWS_CONFIG_FILE` |
| aws_sso_cache | `~/.aws/sso/cache/*.json` | json | `accesstoken`, `clientsecret`, `refreshtoken` | - |
| aws_cli_cache | `~/.aws/cli/cache/*.json` | json | `accesskeyid`, `secretaccesskey`, `sessiontoken` | - |
| google_application_default_credentials | `~/.config/gcloud/application_default_credentials.json`<br>`~/AppData/Roaming/gcloud/application_default_credentials.json` | json | `client_secret`, `private_key`, `private_key_id`, `refresh_token` | `GOOGLE_APPLICATION_CREDENTIALS`, `CLOUDSDK_CONFIG`/`application_default_credentials.json` |
| gcloud_legacy_credentials | `~/.config/gcloud/legacy_credentials/*/adc.json`<br>`~/AppData/Roaming/gcloud/legacy_credentials/*/adc.json` | json | `client_secret`, `private_key`, `private_key_id`, `refresh_token` | `CLOUDSDK_CONFIG`/`legacy_credentials/*/adc.json` |
| gcloud_token_databases | `~/.config/gcloud/credentials.db`<br>`~/.config/gcloud/access_tokens.db`<br>`~/AppData/Roaming/gcloud/credentials.db`<br>`~/AppData/Roaming/gcloud/access_tokens.db` | opaque | - | `CLOUDSDK_CONFIG`/`credentials.db`, `CLOUDSDK_CONFIG`/`access_tokens.db` |
| npmrc | `~/.npmrc` | npmrc | `_auth`, `_authtoken`, `_password`, `password` | `NPM_CONFIG_USERCONFIG`, `npm_config_userconfig` |
| yarnrc | `~/.yarnrc.yml` | yaml | `npmauthident`, `npmauthtoken` | - |
| kube_config | `~/.kube/config` | yaml | `access-token`, `client-key-data`, `client-secret`, `id-token`, `password`, `refresh-token`, `token` | `KUBECONFIG` (list) |
| docker_config | `~/.docker/config.json` | json | `auth`, `identitytoken`, `password`, `registrytoken` | `DOCKER_CONFIG`/`config.json` |
| netrc | `~/.netrc`<br>`~/_netrc` | netrc | `account`, `password` | `NETRC` |
| git_credentials | `~/.git-credentials`<br>`~/.config/git/credentials` | git_credentials | - | `XDG_CONFIG_HOME`/`git/credentials` |
| gh_hosts | `~/.config/gh/hosts.yml`<br>`~/AppData/Roaming/GitHub CLI/hosts.yml` | yaml | `oauth_token` | `GH_CONFIG_DIR`/`hosts.yml`, `XDG_CONFIG_HOME`/`gh/hosts.yml` |
| hub | `~/.config/hub` | yaml | `oauth_token` | - |
| ssh_private_keys | `~/.ssh/id_rsa`<br>`~/.ssh/id_dsa`<br>`~/.ssh/id_ecdsa`<br>`~/.ssh/id_ed25519`<br>`~/.ssh/id_ecdsa_sk`<br>`~/.ssh/id_ed25519_sk` | private_key | - | - |
| pypirc | `~/.pypirc` | ini | `password` | - |
| cargo_credentials | `~/.cargo/credentials.toml`<br>`~/.cargo/credentials` | toml | `token` | `CARGO_HOME`/`credentials.toml`, `CARGO_HOME`/`credentials` |
| gem_credentials | `~/.gem/credentials`<br>`~/.local/share/gem/credentials` | yaml | - | - |
| terraform_credentials | `~/.terraform.d/credentials.tfrc.json` | json | `token` | - |
| pgpass | `~/.pgpass` | pgpass | - | `PGPASSFILE` |
| mysql_options | `~/.my.cnf` | ini | `password` | - |
| vault_token | `~/.vault-token` | token_file | - | - |
| huggingface_token | `~/.cache/huggingface/token`<br>`~/.huggingface/token` | token_file | - | `HF_HOME`/`token` |
| claude_json | `~/.claude.json` | json | - | - |
| claude_credentials | `~/.claude/.credentials.json` | json | `accesstoken`, `refreshtoken` | - |
| azure_tokens | `~/.azure/msal_token_cache.json`<br>`~/.azure/accessTokens.json`<br>`~/.azure/service_principal_entries.json` | json | `accesstoken`, `client_secret`, `refreshtoken`, `secret` | - |

Any other field of these files also counts when its name suggests a secret or
its value has a credential shape (docs/inventory.md, "Classification").

## Shell startup files

Read for exported assignments that put a variable into the agent's launch
environment:

`~/.bashrc`, `~/.bash_profile`, `~/.bash_login`, `~/.profile`, `~/.bash_aliases`, `~/.zshrc`, `~/.zshenv`, `~/.zprofile`, `~/.zlogin`, `~/.config/fish/config.fish`, `~/.cshrc`, `~/.tcshrc`
