# eurosportplayer-dl
Download videos of games from eurosportplayer.com

## Requirements
A Python 3 interpreter is required. Moreover, some Python packages are required too. You can install them using pip:

`pip3 install pycrypto jsonpickle natsort`

## Examples
`python3 eurosportplayer-dl.py --url URL --user USERNAME --password PASSWORD`

where

`URL` is the full eurosportplayer.com URL of the video to download

`USERNAME` is the email address of your eurosportplayer.com account

`PASSWORD` is the password associated with your eurosportplayer.com account

## Optional arguments
- `--nprocesses NUM`

Use `NUM` parallel processes. Defaults to 1

- `--resolution AxB`

Download the resolution `AxB`. Returns an error if a video stream with that resolution is not found. Defaults to 1280x760

- `--load`

Continue the last (interrupted) download, using a session file which is saved everytime you don't use this option. You still need to pass a password, since the password is not stored in the session file.
