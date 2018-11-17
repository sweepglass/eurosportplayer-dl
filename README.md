# eurosportplayer-dl
Download videos of games from eurosportplayer.com

## Examples
`eurosportplayer-dl URL -u USERNAME -p PASSWORD`

where

`URL` is the full eurosportplayer.com URL of the video to download

`USERNAME` is the email address of your eurosportplayer.com account

`PASSWORD` is the password associated with your eurosportplayer.com account

##Optional arguments
- `--nprocesses NUM` 

Use `NUM` parallel processes. Defaults to 1

- `--resolution AxB`

Download the resolution `AxB`. Returns an error if a video stream with that resolution is not found. Defaults to 1280x760
