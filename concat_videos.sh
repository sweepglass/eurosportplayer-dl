cd ./download/videos
rm "./mylist.txt"
for i in `ls ./*.mp4 | sort -V`; do echo "file '$i'" >> "./mylist.txt"; done; 
ffmpeg -loglevel panic -hide_banner -f concat -safe 0 -i mylist.txt -c copy ../../final.mp4
