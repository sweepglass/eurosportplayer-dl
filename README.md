# eurosportplayer-dl
Download videos of games from eurosportplayer.com

## Windows binary
On the [release](https://github.com/raffam/eurosportplayer-dl/releases) page, there is a binary release for Windows. There should be no additional requirements to run the software from this release.

*Note that these releases are generally behind the source code release.*

## Source code Requirements
In order yo run the script from the source code, a [Python 3](www.python.org) interpreter is required. Moreover, some Python packages are required too. You can install them using pip:

`pip3 install -r requirements.txt`

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
