# eurosportplayer-dl
Download videos of games from eurosportplayer.com

## Required Python packages
A python 3 interpreter is required. Moreover, some Python packages are required too. You can install them using pip:

`pip3 install pycrypto jsonpickle`

## Examples
`eurosportplayer-dl --url URL -u USERNAME -p PASSWORD`

where

`URL` is the full eurosportplayer.com URL of the video to download

`USERNAME` is the email address of your eurosportplayer.com account

`PASSWORD` is the password associated with your eurosportplayer.com account

##Optional arguments
- `--nprocesses NUM`

Use `NUM` parallel processes. Defaults to 1

- `--resolution AxB`

Download the resolution `AxB`. Returns an error if a video stream with that resolution is not found. Defaults to 1280x760

- `--load`

Continue the last (interrupted) download.
