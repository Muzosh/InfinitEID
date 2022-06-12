# InfinitEID-card-management

This project provides management console for JavaCard applet capable of communicating with [Web-eID](https://web-eid.eu/) solution.

## Project functionality

* initialize the card
    * create and upload certificates of card's public keys
    * requires root CA for creating anchor of trust of card's certificates
* handle PINs
    * auth
    * sign
    * admin
* handle individual APDU commands
* test Web-eID compatibility

## File structure description

* `bin/cli` = management console
* `config` = contains config .yaml files
    * `apdulist.yaml` = definitions of necessary APDUs
    * `config.yaml` = other configuration values
* `data` = contains root self-signed certificate files
    * `MAKECERT.md` = instructions how to create such certificate files
* `tests` = constains unit tests, can be run by `pytest`
    * `test_web_eid_app_compatibility` = test whether connected card handles all operations required by Web-eID
* `src` = source files for package installation
* `setup.py` = definition of package installation

## Usage

1. install package
   * `pip install <path-to-folder-containing-setup.py>`
1. run console
   * `python bin/cli`
1. (after fresh load of JavaCard applet) initialize the card using first cli option
1. (if applet already initialized) run other commands according to user's need
   * for example to unblock user's auth PIN, first verify admin PIN, then set auth PIN
1. (to test if card is working with Web-eID) run `pytest tests` (`-s` for printing APDU commands used)
